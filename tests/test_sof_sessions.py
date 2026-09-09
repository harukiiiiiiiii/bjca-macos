"""
Tests for independent SOF session isolation across WebSocket connections and HTTP,
WS parse errors, device reset session purging, capacity bounds, and CMS signing.
"""
import asyncio
import datetime
import json
import secrets
import time
import unittest
from unittest.mock import MagicMock, patch

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from asn1crypto import cms

from bjca_service.api_handlers import APIHandler, _REQUEST_TOKEN, _REQUEST_CONNECTION
from bjca_service.config import ServiceConfig, get_config, set_config
from bjca_service.server import create_app


def _generate_test_ec_certificate():
    """Generate a test EC certificate for CMS structure testing only."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test Signer Cert"),
        x509.NameAttribute(x509.oid.NameOID.SERIAL_NUMBER, "SN1234567890"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


class FakeGM3000Device:
    def __init__(self, pin="123456", cert_der=None):
        self._correct_pin = pin
        self.cert_der = cert_der or _generate_test_ec_certificate()
        self.signature_calls = []

    def verify_pin(self, pin: str):
        if pin == self._correct_pin:
            return True, 10
        return False, 5

    def ecc_sign(self, digest: bytes) -> bytes:
        self.signature_calls.append(digest)
        return b"\x30" * 64


class FakeDeviceManager:
    def __init__(self, gm_device=None):
        self.gm3000 = gm_device or FakeGM3000Device()
        self.gm3000_cert = self.gm3000.cert_der
        self._dev_count = 1

    def init_device(self, idx=0, pin=""):
        return True

    def get_device_count(self):
        return self._dev_count

    def list_devices(self):
        return [{"device_sn": "FAKE-SN-001", "serial_number": "FAKE-SN-001"}]

    def close_device(self):
        self.gm3000 = None
        self.gm3000_cert = None
        self._dev_count = 0


class TestSOFSessionsAndIsolation(AioHTTPTestCase):
    async def get_application(self):
        self.orig_config = get_config()
        self.test_config = ServiceConfig(
            listen_port=0,
            websocket_path="/xtxapp",
            api_prefix="/api",
        )
        set_config(self.test_config)

        self.fake_gm = FakeGM3000Device()
        self.fake_dev = FakeDeviceManager(self.fake_gm)

        # Patch ALL hardware factories before handler instantiation
        import bjca_service.api_handlers as api_mod
        self.orig_handler = api_mod._handler
        api_mod._handler = None

        self.fake_cert_mgr = MagicMock()
        self.fake_bridge = MagicMock()

        self.patch_dev = patch("bjca_service.api_handlers.get_device_manager", return_value=self.fake_dev)
        self.patch_cert = patch("bjca_service.api_handlers.get_cert_manager", return_value=self.fake_cert_mgr)
        self.patch_bridge = patch("bjca_service.api_handlers.get_bridge", return_value=self.fake_bridge)
        self.patch_dev.start()
        self.patch_cert.start()
        self.patch_bridge.start()

        self.app = create_app(self.test_config)
        self.api_handler = self.app["api_handler"]
        # Mock _sm2_message_digest to deterministic 32 bytes in transport tests
        self.api_handler._sm2_message_digest = lambda data, cert, user_id=b"1234567812345678": b"\x07" * 32
        return self.app

    async def tearDownAsync(self):
        self.patch_bridge.stop()
        self.patch_cert.stop()
        self.patch_dev.stop()
        import bjca_service.api_handlers as api_mod
        api_mod._handler = self.orig_handler
        set_config(self.orig_config)
        await super().tearDownAsync()

    async def test_two_websockets_isolation_and_cms_wire(self):
        """
        Verify:
        - Actual TWO WebSockets A and B
        - Both login and get tokens; both can sign
        - Sign wire and decoded CMS content verified
        - B wrong PIN / logout / disconnect does NOT revoke A
        - Missing/bogus/cross-socket token rejected for signing
        - Old token after disconnect invalid
        - Own WS IsLogin works without token; requires own returned token on HTTP
        """
        headers = {"Origin": "https://jspec.com.cn"}
        ws_a = await self.client.ws_connect("/xtxapp", protocols=("cryptokit-kdets-protocol",), headers=headers)
        ws_b = await self.client.ws_connect("/xtxapp", protocols=("cryptokit-kdets-protocol",), headers=headers)

        try:
            # 1. Login on WS A
            await ws_a.send_json({
                "call_cmd_id": "a_1",
                "xtx_func_name": "SOF_LoginEx",
                "param": ["cert1", "123456", 0],
            })
            resp_a1 = await ws_a.receive_json()
            self.assertEqual(resp_a1.get("call_cmd_id"), "a_1")
            self.assertTrue(resp_a1.get("retVal"))
            token_a = resp_a1.get("token")
            self.assertTrue(token_a)

            # WS A IsLogin without token -> True
            await ws_a.send_json({
                "call_cmd_id": "a_is_login",
                "xtx_func_name": "SOF_IsLogin",
                "param": [],
            })
            resp_islogin = await ws_a.receive_json()
            self.assertTrue(resp_islogin.get("retVal"))

            # 2. Login on WS B
            await ws_b.send_json({
                "call_cmd_id": "b_1",
                "xtx_func_name": "SOF_LoginEx",
                "param": ["cert2", "123456", 0],
            })
            resp_b1 = await ws_b.receive_json()
            self.assertEqual(resp_b1.get("call_cmd_id"), "b_1")
            self.assertTrue(resp_b1.get("retVal"))
            token_b = resp_b1.get("token")
            self.assertTrue(token_b)
            self.assertNotEqual(token_a, token_b)

            # WS B IsLogin without token -> True
            await ws_b.send_json({
                "call_cmd_id": "b_is_login",
                "xtx_func_name": "SOF_IsLogin",
                "param": [],
            })
            resp_b_islogin = await ws_b.receive_json()
            self.assertTrue(resp_b_islogin.get("retVal"))

            # 3. Cross-socket token: WS A presents token_b -> Sign rejected
            await ws_a.send_json({
                "call_cmd_id": "a_cross",
                "xtx_func_name": "SOF_SignData",
                "param": ["cert1", "hello world", 0, ""],
                "token": token_b,
            })
            resp_cross = await ws_a.receive_json()
            self.assertEqual(resp_cross.get("retVal"), "")

            # Missing token on WS A -> Sign rejected
            await ws_a.send_json({
                "call_cmd_id": "a_notoken",
                "xtx_func_name": "SOF_SignData",
                "param": ["cert1", "hello world", 0, ""],
            })
            resp_notoken = await ws_a.receive_json()
            self.assertEqual(resp_notoken.get("retVal"), "")

            # Bogus token on WS A -> Sign rejected
            await ws_a.send_json({
                "call_cmd_id": "a_bogus",
                "xtx_func_name": "SOF_SignData",
                "param": ["cert1", "hello world", 0, ""],
                "token": "bogus-token-1234",
            })
            resp_bogus = await ws_a.receive_json()
            self.assertEqual(resp_bogus.get("retVal"), "")

            # 4. Valid sign on WS A with token_a
            test_content = "Hello BJCA SM2 CMS Signature"
            await ws_a.send_json({
                "call_cmd_id": "a_sign_msg",
                "xtx_func_name": "SOF_SignMessage",
                "param": [0, "cert1", test_content, ""],
                "token": token_a,
            })
            resp_a_sign = await ws_a.receive_json()
            sig_b64 = resp_a_sign.get("retVal")
            self.assertTrue(sig_b64)

            # Validate CMS structure & content
            import base64
            cms_bytes = base64.b64decode(sig_b64)
            parsed = cms.ContentInfo.load(cms_bytes)
            self.assertEqual(parsed["content_type"].native, "signed_data")
            signed_data = parsed["content"]
            self.assertEqual(
                bytes(signed_data["encap_content_info"]["content"].native),
                test_content.encode("utf-8"),
            )

            # Valid sign on WS B with token_b
            await ws_b.send_json({
                "call_cmd_id": "b_sign_data",
                "xtx_func_name": "SOF_SignData",
                "param": ["cert2", "test b data", 0, ""],
                "token": token_b,
            })
            resp_b_sign = await ws_b.receive_json()
            self.assertTrue(resp_b_sign.get("retVal"))

            # 5. B tries wrong PIN login -> B revoked, A still valid
            await ws_b.send_json({
                "call_cmd_id": "b_wrong_pin",
                "xtx_func_name": "SOF_LoginEx",
                "param": ["cert2", "wrong_pin", 0],
            })
            resp_b_wrong = await ws_b.receive_json()
            self.assertFalse(resp_b_wrong.get("retVal"))

            # WS B can no longer sign with token_b
            await ws_b.send_json({
                "call_cmd_id": "b_sign_after_fail",
                "xtx_func_name": "SOF_SignData",
                "param": ["cert2", "test", 0, ""],
                "token": token_b,
            })
            resp_b_fail = await ws_b.receive_json()
            self.assertEqual(resp_b_fail.get("retVal"), "")

            # WS A can STILL sign with token_a
            await ws_a.send_json({
                "call_cmd_id": "a_sign_after_b_fail",
                "xtx_func_name": "SOF_SignData",
                "param": ["cert1", "test a still ok", 0, ""],
                "token": token_a,
            })
            resp_a_still_ok = await ws_a.receive_json()
            self.assertTrue(resp_a_still_ok.get("retVal"))

            # 6. Re-login B with correct PIN
            await ws_b.send_json({
                "call_cmd_id": "b_relogin",
                "xtx_func_name": "SOF_LoginEx",
                "param": ["cert2", "123456", 0],
            })
            resp_b_relogin = await ws_b.receive_json()
            self.assertTrue(resp_b_relogin.get("retVal"))
            token_b2 = resp_b_relogin.get("token")
            self.assertTrue(token_b2)

            # WS B logout without explicit token -> logs out WS B session
            await ws_b.send_json({
                "call_cmd_id": "b_logout",
                "xtx_func_name": "SOF_Logout",
                "param": [],
            })
            resp_b_logout = await ws_b.receive_json()
            self.assertTrue(resp_b_logout.get("retVal"))

            # WS B IsLogin is now False
            await ws_b.send_json({
                "call_cmd_id": "b_islogin2",
                "xtx_func_name": "SOF_IsLogin",
                "param": [],
            })
            resp_b_islogin2 = await ws_b.receive_json()
            self.assertFalse(resp_b_islogin2.get("retVal"))

            # WS A can STILL sign with token_a
            await ws_a.send_json({
                "call_cmd_id": "a_sign_after_b_logout",
                "xtx_func_name": "SOF_SignData",
                "param": ["cert1", "test a still ok after logout", 0, ""],
                "token": token_a,
            })
            resp_a_logout_check = await ws_a.receive_json()
            self.assertTrue(resp_a_logout_check.get("retVal"))

            # 7. Re-login B immediately before closing, then assert B active token removed and A still signs
            await ws_b.send_json({
                "call_cmd_id": "b_relogin_before_close",
                "xtx_func_name": "SOF_LoginEx",
                "param": ["cert2", "123456", 0],
            })
            resp_b_relogin2 = await ws_b.receive_json()
            self.assertTrue(resp_b_relogin2.get("retVal"))
            token_b3 = resp_b_relogin2.get("token")
            self.assertTrue(token_b3)
            self.assertIn(token_b3, self.api_handler._sessions)

            # Disconnect WS B -> WS A still valid, WS B token invalid on reconnect
            await ws_b.close()
            await asyncio.sleep(0.05)  # Allow finally handler to clean up WS B

            # Assert B active token removed
            self.assertNotIn(token_b3, self.api_handler._sessions)

            # WS A can STILL sign
            await ws_a.send_json({
                "call_cmd_id": "a_sign_after_b_disconnect",
                "xtx_func_name": "SOF_SignData",
                "param": ["cert1", "test a after b disconnect", 0, ""],
                "token": token_a,
            })
            resp_a_disc_check = await ws_a.receive_json()
            self.assertTrue(resp_a_disc_check.get("retVal"))

            # New WS B2 reconnects; old token_b3 cannot be used
            ws_b2 = await self.client.ws_connect("/xtxapp", protocols=("cryptokit-kdets-protocol",), headers=headers)
            try:
                self.assertEqual(ws_b2.protocol, "cryptokit-kdets-protocol")
                await ws_b2.send_json({
                    "call_cmd_id": "b2_old_token",
                    "xtx_func_name": "SOF_SignData",
                    "param": ["cert2", "test", 0, ""],
                    "token": token_b3,
                })
                resp_b2_old = await ws_b2.receive_json()
                self.assertEqual(resp_b2_old.get("retVal"), "")
            finally:
                await ws_b2.close()

        finally:
            self.assertEqual(ws_a.protocol, "cryptokit-kdets-protocol")
            await ws_a.close()

    async def test_http_sessions_and_tokenless_logout_safe(self):
        """HTTP independent tokens, params:null rejection, and tokenless logout safety."""
        # 1. Login via HTTP 1
        resp1 = await self.client.post(
            "/api",
            json={"method": "SOF_LoginEx", "params": ["cert-h1", "123456", 0], "id": 1},
            headers={"Content-Type": "application/json"},
        )
        data1 = await resp1.json()
        token1 = data1["result"]["token"]
        self.assertTrue(token1)

        # 2. Login via HTTP 2
        resp2 = await self.client.post(
            "/api",
            json={"method": "SOF_LoginEx", "params": ["cert-h2", "123456", 0], "id": 2},
            headers={"Content-Type": "application/json"},
        )
        data2 = await resp2.json()
        token2 = data2["result"]["token"]
        self.assertTrue(token2)
        self.assertNotEqual(token1, token2)

        # 3. HTTP tokenless IsLogin -> False (HTTP requires own token)
        resp_is_login = await self.client.post(
            "/api",
            json={"method": "SOF_IsLogin", "params": [], "id": 3},
            headers={"Content-Type": "application/json"},
        )
        data_is_login = await resp_is_login.json()
        self.assertFalse(data_is_login["result"]["retVal"])

        # HTTP IsLogin with token1 -> True
        resp_is_login_t1 = await self.client.post(
            "/api",
            json={"method": "SOF_IsLogin", "params": [], "token": token1, "id": 4},
            headers={"Content-Type": "application/json"},
        )
        data_is_login_t1 = await resp_is_login_t1.json()
        self.assertTrue(data_is_login_t1["result"]["retVal"])

        # 4. Tokenless HTTP logout -> no-op; tokens 1 and 2 still valid
        resp_logout_no_token = await self.client.post(
            "/api",
            json={"method": "SOF_Logout", "params": [], "id": 5},
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(resp_logout_no_token.status, 200)

        # Token 1 still signs
        resp_sign_t1 = await self.client.post(
            "/api",
            json={
                "method": "SOF_SignData",
                "params": ["cert-h1", "data-1", 0, ""],
                "token": token1,
                "id": 6,
            },
            headers={"Content-Type": "application/json"},
        )
        data_sign_t1 = await resp_sign_t1.json()
        self.assertTrue(data_sign_t1["result"]["retVal"])

        # 5. params: null must be rejected with 400
        resp_null_params = await self.client.post(
            "/api",
            json={"method": "SOF_GetVersion", "params": None, "id": 7},
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(resp_null_params.status, 400)
        err = await resp_null_params.json()
        self.assertIn("params must be a dict or list", err["error"]["message"])

        # Missing params allowed
        resp_no_params = await self.client.post(
            "/api",
            json={"method": "SOF_GetVersion", "id": 8},
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(resp_no_params.status, 200)

    async def test_session_ttl_device_reset_and_capacity_bound(self):
        """TTL expiry, device reset / close_device, and session capacity bound 256."""
        # 1. Login to get a token
        login_res = await self.api_handler.sof_login(["cert", "123456", 0])
        token = login_res["token"]
        self.assertTrue(token)

        # Verify valid
        ctx = _REQUEST_TOKEN.set(token)
        try:
            self.assertTrue(self.api_handler._token_valid())
        finally:
            _REQUEST_TOKEN.reset(ctx)

        # Test TTL expiration: set expires_at in the past
        self.api_handler._sessions[token]["expires_at"] = time.monotonic() - 10
        ctx = _REQUEST_TOKEN.set(token)
        try:
            self.assertFalse(self.api_handler._token_valid())
        finally:
            _REQUEST_TOKEN.reset(ctx)
        self.assertNotIn(token, self.api_handler._sessions)

        # Test GM object identity change (device reset)
        login_res2 = await self.api_handler.sof_login(["cert", "123456", 0])
        token2 = login_res2["token"]
        self.api_handler._dev.gm3000 = FakeGM3000Device()  # new object identity
        ctx2 = _REQUEST_TOKEN.set(token2)
        try:
            self.assertFalse(self.api_handler._token_valid())
        finally:
            _REQUEST_TOKEN.reset(ctx2)
        self.assertNotIn(token2, self.api_handler._sessions)

        # Test close_device clears all sessions even if close raises
        login_res3 = await self.api_handler.sof_login(["cert", "123456", 0])
        self.assertEqual(len(self.api_handler._sessions), 1)
        with patch.object(self.api_handler._dev, "close_device", side_effect=RuntimeError("close fail")):
            with self.assertRaises(RuntimeError):
                await self.api_handler.close_device()
        self.assertEqual(len(self.api_handler._sessions), 0)

        # Restore fake gm
        self.api_handler._dev.gm3000 = FakeGM3000Device()

        # Test capacity bound 256: cannot exceed 256
        for i in range(256):
            self.api_handler._sessions[f"dummy_{i}"] = {
                "connection_id": "",
                "expires_at": time.monotonic() + 1800,
                "gm3000": self.api_handler._dev.gm3000,
                "cert_id": "dummy",
            }
        cap_login = await self.api_handler.sof_login(["cert", "123456", 0])
        self.assertFalse(cap_login["retVal"])
        self.api_handler._clear_all_sessions()

    async def test_websocket_malformed_json_and_error_recovery(self):
        """Collapse duplicate WS JSONDecodeError branch, -32700 response, socket continues."""
        headers = {"Origin": "https://jspec.com.cn"}
        ws = await self.client.ws_connect("/xtxapp", protocols=("cryptokit-kdets-protocol",), headers=headers)
        try:
            # 1. Send malformed JSON
            await ws.send_str("{invalid json payload")
            resp_err = await asyncio.wait_for(ws.receive_json(), timeout=2)
            self.assertEqual(resp_err.get("error", {}).get("code"), -32700)
            self.assertEqual(resp_err.get("error", {}).get("message"), "Parse error")

            # 2. Send non-object JSON
            await ws.send_str("[1, 2, 3]")
            resp_nonobj = await asyncio.wait_for(ws.receive_json(), timeout=2)
            self.assertEqual(resp_nonobj.get("error", {}).get("code"), -32600)
            self.assertIn("request must be a JSON object", resp_nonobj.get("error", {}).get("message", ""))

            # 3. Send invalid method
            await ws.send_json({"call_cmd_id": "c_1", "xtx_func_name": "   "})
            resp_bad_meth = await asyncio.wait_for(ws.receive_json(), timeout=2)
            self.assertEqual(resp_bad_meth.get("error", {}).get("code"), -32600)
            self.assertIn("method must be a nonempty string", resp_bad_meth.get("error", {}).get("message", ""))

            # 4. Send invalid params
            await ws.send_json({"call_cmd_id": "c_2", "xtx_func_name": "SOF_GetVersion", "param": "not-a-list"})
            resp_bad_param = await asyncio.wait_for(ws.receive_json(), timeout=2)
            self.assertEqual(resp_bad_param.get("error", {}).get("code"), -32600)
            self.assertIn("params must be a dict or list", resp_bad_param.get("error", {}).get("message", ""))

            # 5. Socket is still fully functional: send valid request
            await ws.send_json({
                "call_cmd_id": "c_3",
                "xtx_func_name": "SOF_GetVersion",
                "param": [],
            })
            resp_valid = await asyncio.wait_for(ws.receive_json(), timeout=2)
            self.assertEqual(resp_valid.get("call_cmd_id"), "c_3")
            self.assertTrue(resp_valid.get("retVal"))
        finally:
            await ws.close()

    async def test_session_lifecycle_and_scope_repros(self):
        """Compact tests for the four concrete auth/lifecycle repros and caller scope revocation."""
        class TestGM:
            def __init__(self):
                self.pin_calls = 0
                self.cert_der = b"fake-cert-der"

            def verify_pin(self, pin: str):
                self.pin_calls += 1
                if pin == "fake-good":
                    return True, 10
                if pin == "raise-err":
                    raise RuntimeError("device communication error")
                return False, 5

            def ecc_sign(self, digest: bytes) -> bytes:
                return b"\x55" * 64

        test_gm = TestGM()
        test_dev = FakeDeviceManager(test_gm)

        with patch("bjca_service.api_handlers.get_device_manager", return_value=test_dev):
            handler = APIHandler()
        digest_patcher = patch.object(handler, "_sm2_message_digest", return_value=b"\x01" * 32)
        digest_patcher.start()
        self.addCleanup(digest_patcher.stop)

        # -------------------------------------------------------------
        # Repro 1: A login yields ta; B calls SOF_LoginEx with wrong PIN and token=ta.
        # B's wrong PIN must NOT revoke A!
        # -------------------------------------------------------------
        res_a = await handler.handle_request(
            {"jsonrpc": "2.0", "method": "SOF_LoginEx", "params": ["certA", "fake-good", 0], "id": 1},
            connection_id="A",
        )
        self.assertTrue(res_a["result"]["retVal"])
        ta = res_a["result"]["token"]
        self.assertTrue(ta)

        # B calls SOF_LoginEx with wrong PIN and top-level token=ta
        res_b = await handler.handle_request(
            {"jsonrpc": "2.0", "method": "SOF_LoginEx", "params": ["certB", "wrong-pin", 0], "token": ta, "id": 2},
            connection_id="B",
        )
        self.assertFalse(res_b["result"]["retVal"])
        # A's session ta must still exist and be valid
        self.assertIn(ta, handler._sessions)
        res_a_sign = await handler.handle_request(
            {"jsonrpc": "2.0", "method": "SOF_SignData", "params": ["certA", "data", 0, ""], "token": ta, "id": 3},
            connection_id="A",
        )
        self.assertTrue(res_a_sign["result"]["retVal"])

        # -------------------------------------------------------------
        # Repro 2: HTTP login yields th; WS B SOF_Logout token=th must NOT delete HTTP session.
        # EXACT scope equality required.
        # -------------------------------------------------------------
        res_h = await handler.handle_request(
            {"jsonrpc": "2.0", "method": "SOF_LoginEx", "params": ["certH", "fake-good", 0], "id": 4},
            connection_id="",
        )
        self.assertTrue(res_h["result"]["retVal"])
        th = res_h["result"]["token"]
        self.assertTrue(th)

        # WS B attempts to logout with token=th
        res_b_logout = await handler.handle_request(
            {"jsonrpc": "2.0", "method": "SOF_Logout", "params": [], "token": th, "id": 5},
            connection_id="B",
        )
        self.assertTrue(res_b_logout["result"]["retVal"])
        # th must NOT be deleted because scope ('') != B
        self.assertIn(th, handler._sessions)

        # HTTP own logout with th DOES revoke th
        res_h_logout = await handler.handle_request(
            {"jsonrpc": "2.0", "method": "SOF_Logout", "params": [], "token": th, "id": 6},
            connection_id="",
        )
        self.assertTrue(res_h_logout["result"]["retVal"])
        self.assertNotIn(th, handler._sessions)
        # But A is untouched
        self.assertIn(ta, handler._sessions)

        # -------------------------------------------------------------
        # Repro 3: A login then A SOF_LoginEx empty PIN returns false and revokes own caller
        # -------------------------------------------------------------
        res_a_empty = await handler.handle_request(
            {"jsonrpc": "2.0", "method": "SOF_LoginEx", "params": ["certA", "", 0], "id": 7},
            connection_id="A",
        )
        self.assertFalse(res_a_empty["result"]["retVal"])
        # A's old session is revoked
        self.assertNotIn(ta, handler._sessions)
        res_a_islogin = await handler.handle_request(
            {"jsonrpc": "2.0", "method": "SOF_IsLogin", "params": [], "id": 8},
            connection_id="A",
        )
        self.assertFalse(res_a_islogin["result"]["retVal"])

        # -------------------------------------------------------------
        # Repro 4: With _MAX_SESSIONS=1 and A already logged in, A re-login replaces itself;
        # Unrelated new B at capacity fails without touching A, before any PIN call!
        # -------------------------------------------------------------
        handler._clear_all_sessions()
        with patch("bjca_service.api_handlers._MAX_SESSIONS", 1):
            # A logs in -> capacity reached (1/1)
            res_a_cap = await handler.handle_request(
                {"jsonrpc": "2.0", "method": "SOF_LoginEx", "params": ["certA", "fake-good", 0], "id": 9},
                connection_id="A",
            )
            self.assertTrue(res_a_cap["result"]["retVal"])
            ta_cap = res_a_cap["result"]["token"]
            self.assertIn(ta_cap, handler._sessions)

            # Unrelated new B at capacity must fail without touching A and without calling verify_pin
            pin_calls_before = test_gm.pin_calls
            res_b_cap = await handler.handle_request(
                {"jsonrpc": "2.0", "method": "SOF_LoginEx", "params": ["certB", "fake-good", 0], "id": 10},
                connection_id="B",
            )
            self.assertFalse(res_b_cap["result"]["retVal"])
            self.assertEqual(test_gm.pin_calls, pin_calls_before)
            self.assertIn(ta_cap, handler._sessions)

            # A re-login should replace itself and succeed at max capacity
            res_a_relogin = await handler.handle_request(
                {"jsonrpc": "2.0", "method": "SOF_LoginEx", "params": ["certA", "fake-good", 0], "id": 11},
                connection_id="A",
            )
            self.assertTrue(res_a_relogin["result"]["retVal"])
            ta_new = res_a_relogin["result"]["token"]
            self.assertNotEqual(ta_cap, ta_new)
            self.assertNotIn(ta_cap, handler._sessions)
            self.assertIn(ta_new, handler._sessions)
            self.assertEqual(len(handler._sessions), 1)

            # HTTP relogin with its token replaces itself at capacity
            handler._clear_all_sessions()
            res_h_init = await handler.handle_request(
                {"jsonrpc": "2.0", "method": "SOF_LoginEx", "params": ["certH", "fake-good", 0], "id": 12},
                connection_id="",
            )
            self.assertTrue(res_h_init["result"]["retVal"])
            th_init = res_h_init["result"]["token"]
            self.assertEqual(len(handler._sessions), 1)

            # HTTP relogin with token replaces itself
            res_h_relogin = await handler.handle_request(
                {"jsonrpc": "2.0", "method": "SOF_LoginEx", "params": ["certH", "fake-good", 0], "token": th_init, "id": 13},
                connection_id="",
            )
            self.assertTrue(res_h_relogin["result"]["retVal"])
            th_new = res_h_relogin["result"]["token"]
            self.assertNotEqual(th_init, th_new)
            self.assertNotIn(th_init, handler._sessions)
            self.assertIn(th_new, handler._sessions)
            self.assertEqual(len(handler._sessions), 1)

        # -------------------------------------------------------------
        # Additional coverage: verify_pin exception and failed signing only revoke caller
        # -------------------------------------------------------------
        # Re-login A
        res_a_exp = await handler.handle_request(
            {"jsonrpc": "2.0", "method": "SOF_LoginEx", "params": ["certA", "fake-good", 0], "id": 14},
            connection_id="A",
        )
        ta_exp = res_a_exp["result"]["token"]
        self.assertIn(ta_exp, handler._sessions)

        # B encounters verify_pin exception -> does not touch A
        res_b_err = await handler.handle_request(
            {"jsonrpc": "2.0", "method": "SOF_LoginEx", "params": ["certB", "raise-err", 0], "token": ta_exp, "id": 15},
            connection_id="B",
        )
        self.assertFalse(res_b_err["result"]["retVal"])
        self.assertIn(ta_exp, handler._sessions)

        # Failed signing on B with inline wrong PIN does NOT revoke A
        res_b_sign_fail = await handler.handle_request(
            {"jsonrpc": "2.0", "method": "SOF_SignData", "params": ["certB", "data", 0, "wrong-pin"], "token": ta_exp, "id": 16},
            connection_id="B",
        )
        self.assertEqual(res_b_sign_fail["result"]["retVal"], "")
        self.assertIn(ta_exp, handler._sessions)

        # Failed signing on A with inline wrong PIN revokes A
        res_a_sign_fail = await handler.handle_request(
            {"jsonrpc": "2.0", "method": "SOF_SignData", "params": ["certA", "data", 0, "wrong-pin"], "token": ta_exp, "id": 17},
            connection_id="A",
        )
        self.assertEqual(res_a_sign_fail["result"]["retVal"], "")
        self.assertNotIn(ta_exp, handler._sessions)

    async def test_inline_pin_verify_exception_and_device_init_error(self):
        """Verify inline verify_pin exceptions revoke only caller session, and init errors are handled safely."""
        class MockGM:
            def __init__(self):
                self.fail_pin = False
                self.raise_pin = False
                self.raise_crypto = False
                self.cert_der = _generate_test_ec_certificate()

            def verify_pin(self, pin: str):
                if self.raise_pin:
                    raise RuntimeError("hardware bus read error")
                if self.fail_pin:
                    return False, 3
                return True, 10

            def ecc_sign(self, digest: bytes) -> bytes:
                if self.raise_crypto:
                    raise ValueError("unrelated ecc failure")
                return b"\x30" * 64

        mock_gm = MockGM()
        mock_dev = FakeDeviceManager(mock_gm)

        with patch("bjca_service.api_handlers.get_device_manager", return_value=mock_dev):
            handler = APIHandler()
        digest_patcher = patch.object(handler, "_sm2_message_digest", return_value=b"\x01" * 32)
        digest_patcher.start()
        self.addCleanup(digest_patcher.stop)

        # 1. SubTest for SOF_SignData and SOF_SignMessage when inline verify_pin raises
        for method, sign_params in [
            ("SOF_SignData", lambda data, pin: ["cert", data, 0, pin]),
            ("SOF_SignMessage", lambda data, pin: [0, "cert", data, pin]),
        ]:
            with self.subTest(method=method):
                # Login A and B
                res_a = await handler.handle_request(
                    {"jsonrpc": "2.0", "method": "SOF_LoginEx", "params": ["certA", "123456", 0], "id": 1},
                    connection_id="conn-A",
                )
                self.assertTrue(res_a["result"]["retVal"])
                token_a = res_a["result"]["token"]

                res_b = await handler.handle_request(
                    {"jsonrpc": "2.0", "method": "SOF_LoginEx", "params": ["certB", "123456", 0], "id": 2},
                    connection_id="conn-B",
                )
                self.assertTrue(res_b["result"]["retVal"])
                token_b = res_b["result"]["token"]

                # A invokes sign with inline PIN, verify_pin raises RuntimeError
                mock_gm.raise_pin = True
                res_a_sign = await handler.handle_request(
                    {"jsonrpc": "2.0", "method": method, "params": sign_params("hello", "any-pin"), "token": token_a, "id": 3},
                    connection_id="conn-A",
                )
                self.assertEqual(res_a_sign["result"]["retVal"], "")
                mock_gm.raise_pin = False

                # A has lost authentication
                self.assertNotIn(token_a, handler._sessions)
                # B token remains valid and B signing succeeds
                self.assertIn(token_b, handler._sessions)
                res_b_sign = await handler.handle_request(
                    {"jsonrpc": "2.0", "method": method, "params": sign_params("hello", ""), "token": token_b, "id": 4},
                    connection_id="conn-B",
                )
                self.assertTrue(res_b_sign["result"]["retVal"])

                # 2. Ensure crypto/backend error after successful PIN does NOT revoke session
                mock_gm.raise_crypto = True
                res_b_crypto_err = await handler.handle_request(
                    {"jsonrpc": "2.0", "method": method, "params": sign_params("hello", "123456"), "token": token_b, "id": 5},
                    connection_id="conn-B",
                )
                self.assertEqual(res_b_crypto_err["result"]["retVal"], "")
                # B token must NOT be revoked by downstream ecc_sign/CMS failure!
                self.assertIn(token_b, handler._sessions)
                mock_gm.raise_crypto = False

                handler._clear_all_sessions()

        # 3. Test sof_login when init_device raises
        # Pre-login A on conn-A
        res_a_pre = await handler.handle_request(
            {"jsonrpc": "2.0", "method": "SOF_LoginEx", "params": ["certA", "123456", 0], "id": 10},
            connection_id="conn-A",
        )
        token_a_pre = res_a_pre["result"]["token"]
        self.assertIn(token_a_pre, handler._sessions)

        mock_dev.gm3000 = None
        with patch.object(mock_dev, "init_device", side_effect=RuntimeError("init failed")):
            # B attempts login while init_device fails
            res_b_init_fail = await handler.handle_request(
                {"jsonrpc": "2.0", "method": "SOF_LoginEx", "params": ["certB", "123456", 0], "id": 11},
                connection_id="conn-B",
            )
            self.assertFalse(res_b_init_fail["result"]["retVal"])
            # B's failure does not revoke A
            self.assertIn(token_a_pre, handler._sessions)

            # If A attempts login and init_device fails, A is revoked
            res_a_init_fail = await handler.handle_request(
                {"jsonrpc": "2.0", "method": "SOF_LoginEx", "params": ["certA", "123456", 0], "id": 12},
                connection_id="conn-A",
            )
            self.assertFalse(res_a_init_fail["result"]["retVal"])
            self.assertNotIn(token_a_pre, handler._sessions)
        mock_dev.gm3000 = mock_gm


if __name__ == "__main__":
    unittest.main()
