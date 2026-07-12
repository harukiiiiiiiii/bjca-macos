"""
Smoke tests for the BJCA macOS certificate service.

Run with:
    python3 -m pytest tests/ -v
Or:
    python3 tests/test_service.py
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_config_loads():
    """Verify configuration can be loaded."""
    from bjca_service.config import ServiceConfig
    config = ServiceConfig()
    assert config.listen_port == 21061
    assert config.listen_host == "127.0.0.1"
    assert config.log_level == "trace"


def test_config_defaults():
    """Verify all config defaults are sensible."""
    from bjca_service.config import ServiceConfig
    config = ServiceConfig()
    assert config.install_online_update is True
    assert "update.bjca.org.cn" in config.update_server_url_1
    assert len(config.driver_types) > 0
    assert config.bjca_root == "/Library/BJCA"


def test_crypto_sm3_hash():
    """Verify SM3 hash works (or falls back to SHA-256)."""
    from bjca_service.crypto_ops import SM3Hash
    data = b"Hello BJCA!"
    digest = SM3Hash.hash(data)
    assert len(digest) == 32  # 256-bit output


def test_crypto_base64():
    """Verify Base64 encode/decode round-trip."""
    from bjca_service.crypto_ops import Base64Util
    original = b"Test data for Base64 round-trip verification"
    encoded = Base64Util.encode(original)
    decoded = Base64Util.decode(encoded)
    assert decoded == original


def test_crypto_sm2_keygen():
    """Verify SM2 key pair generation."""
    from bjca_service.crypto_ops import SM2Engine
    try:
        kp = SM2Engine.generate_key_pair()
        assert len(kp.public_key) > 0
        assert len(kp.private_key) > 0
        assert kp.algorithm == "SM2"
    except RuntimeError as e:
        if "gmssl" in str(e):
            print("(Skipping — gmssl not installed)")
        else:
            raise


def test_cert_parse():
    """Verify certificate parsing with a self-signed test cert."""
    from bjca_service.cert_manager import CertificateManager
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding
    import datetime

    # Create a self-signed test certificate
    key = rsa.generate_private_key(65537, 2048, default_backend())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Cert")])

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(12345)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(Encoding.DER)

    mgr = CertificateManager()
    info = mgr.parse_certificate(cert_der)

    assert info.version > 0
    assert '12345' in info.serial_number or '3039' in info.serial_number
    assert 'Test Cert' in info.subject
    assert info.public_key_algorithm == 'RSA'
    assert info.public_key_size == 2048


def test_api_handler_method_map():
    """Verify all API methods have handlers."""
    from bjca_service.api_handlers import APIHandler
    handler = APIHandler()
    methods = list(APIHandler._METHOD_MAP.keys())
    assert len(methods) > 20
    assert "sign" in methods
    assert "list_certificates" in methods
    assert "health" in methods


def test_api_handler_health():
    """Verify the health endpoint."""
    import asyncio
    from bjca_service.api_handlers import APIHandler

    async def run():
        handler = APIHandler()
        result = await handler.health()
        assert result["status"] == "ok"
        assert "version" in result

    asyncio.run(run())


def test_api_handler_list_devices():
    """Verify device listing endpoint."""
    import asyncio
    from bjca_service.api_handlers import APIHandler

    async def run():
        handler = APIHandler()
        result = await handler.list_devices()
        assert "count" in result
        assert "devices" in result
        assert isinstance(result["count"], int)

    asyncio.run(run())


def test_list_certificates_initializes_gm3000_before_listing():
    """Certificate listing must initialize a cold GM3000 session."""
    import asyncio
    from types import SimpleNamespace
    from bjca_service.api_handlers import APIHandler

    class FakeCert:
        def to_dict(self):
            return {"subject": "CN=Test"}

    async def run():
        handler = APIHandler()
        handler._current_cert_info = lambda: FakeCert()
        handler._dev = SimpleNamespace(gm3000=None, gm3000_cert=None)
        handler._pkcs11 = SimpleNamespace(is_available=False, _session=None)
        result = await handler.list_certificates()
        assert result == {"count": 1, "certificates": [{"subject": "CN=Test"}]}

    asyncio.run(run())


def test_jsonrpc_dispatcher():
    """Verify JSON-RPC request dispatching."""
    import asyncio
    from bjca_service.api_handlers import APIHandler

    async def run():
        handler = APIHandler()

        # Valid request
        response = await handler.handle_request({
            "jsonrpc": "2.0",
            "method": "health",
            "params": {},
            "id": 1,
        })
        assert response["id"] == 1
        assert "result" in response
        assert response["result"]["status"] == "ok"

        # Unknown method
        response = await handler.handle_request({
            "jsonrpc": "2.0",
            "method": "nonexistent_method",
            "params": {},
            "id": 2,
        })
        assert response["id"] == 2
        assert "error" in response
        assert response["error"]["code"] == -32601

    asyncio.run(run())


def test_sof_sm2_signature_der_encoding():
    """Verify raw GM3000 r||s signatures are DER encoded for CMS."""
    from asn1crypto import core
    from bjca_service.api_handlers import APIHandler

    raw = b"\x01" * 32 + b"\x02" * 32
    der = APIHandler._sm2_signature_der(raw)
    values = core.SequenceOf.load(der, spec=core.Integer)
    assert values[0].native == int.from_bytes(raw[:32], "big")
    assert values[1].native == int.from_bytes(raw[32:], "big")


def test_sof_sm2_cms_signed_data_structure():
    """Verify SOF_SignMessage CMS output is structurally valid."""
    import datetime
    from asn1crypto import cms
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from bjca_service.api_handlers import APIHandler

    key = rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CMS Test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(123456)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )

    content = b"1698768740355349"
    der = APIHandler._build_sm2_cms_signed_data(
        content=content,
        signer_cert_der=cert.public_bytes(Encoding.DER),
        signature_der=APIHandler._sm2_signature_der(b"\x01" * 64),
        detached=False,
    )

    parsed = cms.ContentInfo.load(der)
    signed_data = parsed["content"]
    signer_info = signed_data["signer_infos"][0]
    assert parsed["content_type"].native == "signed_data"
    assert signed_data["encap_content_info"]["content"].native == content
    assert signer_info["digest_algorithm"]["algorithm"].dotted == "1.2.156.10197.1.401"
    assert signer_info["signature_algorithm"]["algorithm"].dotted == "1.2.156.10197.1.501"


def test_websocket_log_summary_does_not_include_payload():
    """Verify WebSocket logs never include request/response payload values."""
    import logging
    from bjca_service import server

    records = []

    class Handler(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = Handler()
    old_level = server.logger.level
    server.logger.setLevel(logging.INFO)
    server.logger.addHandler(handler)
    try:
        server._log_ws("WS RECV", "SOF_LoginEx", "i_1")
        server._log_ws("WS SEND", "SOF_LoginEx", "i_1", True)
    finally:
        server.logger.removeHandler(handler)
        server.logger.setLevel(old_level)

    text = "\n".join(records)
    assert "SOF_LoginEx" in text
    assert "secret" not in text
    assert "cert" not in text
    assert "token" not in text


def test_origin_allowed():
    """Verify WebSocket Origin allowlist is exact."""
    from bjca_service.server import _origin_allowed

    assert _origin_allowed("https://www.jspec.com.cn")
    assert _origin_allowed("https://jspec.com.cn")
    assert _origin_allowed("https://foo.sgcc.com.cn")
    assert _origin_allowed("https://a.b.sgcc.com.cn")
    assert not _origin_allowed("")
    assert not _origin_allowed("null")
    assert not _origin_allowed("http://www.jspec.com.cn")
    assert not _origin_allowed("https://evil.example")
    assert not _origin_allowed("https://sgcc.com.cn.evil.example")


def test_websocket_supports_trading_center_protocol():
    """The Jiangsu client requires its WebSocket subprotocol to be echoed."""
    from bjca_service.server import WEBSOCKET_PROTOCOLS

    assert "cryptokit-kdets-protocol" in WEBSOCKET_PROTOCOLS


def test_sof_login_does_not_cache_plain_pin():
    """Verify successful SOF login stores state, not the plaintext PIN."""
    import asyncio
    from bjca_service.api_handlers import APIHandler

    class FakeGM3000:
        def verify_pin(self, pin):
            return pin == "123456", 8

    class FakeDeviceManager:
        gm3000 = FakeGM3000()

    async def run():
        handler = APIHandler()
        handler._dev = FakeDeviceManager()
        result = await handler.sof_login(["cert-id", "123456", 0])
        assert result["retVal"] is True
        assert handler._logged_in is True
        assert not hasattr(handler, "_last_pin")

    asyncio.run(run())


def test_gm3000_verify_pin_accepts_skf_success_code():
    """Verify GM3000 VerifyPIN accepts SKF success payloads."""
    from bjca_service.longmai_gm3000 import GM3000HID

    class FakeGM3000(GM3000HID):
        def __init__(self):
            self.calls = 0

        def transceive(self, apdu):
            self.calls += 1
            if self.calls == 1:
                return b"12345678", 0x9000
            return b"\x09\x00\x00\x00\x00", 0x0000

    ok, retries = FakeGM3000().verify_pin("123456")
    assert ok is True
    assert retries == -1


def test_gm3000_verify_pin_reads_head_retry_status():
    """Verify GM3000 VerifyPIN reads 63Cx from response payload head."""
    from bjca_service.longmai_gm3000 import GM3000HID

    class FakeGM3000(GM3000HID):
        def __init__(self):
            self.calls = 0

        def transceive(self, apdu):
            self.calls += 1
            if self.calls == 1:
                return b"12345678", 0x9000
            return bytes.fromhex("63c3000000"), 0x0000

    ok, retries = FakeGM3000().verify_pin("123456")
    assert ok is False
    assert retries == 3


def test_gm3000_pin_key_uses_sha1_padded_pin():
    """Verify GM3000 PIN key matches the Linux/RK verified derivation."""
    import hashlib
    from bjca_service.longmai_gm3000 import GM3000HID

    expected = hashlib.sha1(b"123456" + b"\x00" * 10).digest()[:16]
    assert GM3000HID._lookup_pin_key("123456") == expected


def test_sof_sign_requires_session_token():
    """Verify SOF signing requires the login token, not just global login state."""
    from bjca_service.api_handlers import APIHandler, _REQUEST_TOKEN

    class FakeGM3000:
        def ecc_sign(self, digest):
            return b"\x01" * 64

    class FakeDeviceManager:
        gm3000 = FakeGM3000()
        gm3000_cert = b"cert"

    handler = APIHandler()
    handler._dev = FakeDeviceManager()
    handler._logged_in = True
    handler._session_token = "token-1"
    handler._sm2_message_digest = lambda data, cert: b"\x02" * 32

    assert handler._sign_sof_text("data") == ""
    ctx = _REQUEST_TOKEN.set("token-1")
    try:
        assert handler._sign_sof_text("data")
    finally:
        _REQUEST_TOKEN.reset(ctx)


def test_device_presence_snapshot_helper():
    """Verify monitor presence checks do not call full device probing."""
    from bjca_service.server import _read_device_presence

    class FakeDeviceManager:
        def get_presence_info(self):
            return {"present": True, "name": "Longmai-GM3000"}

        def list_devices(self):
            raise AssertionError("list_devices should not be used for polling")

    class FakeHandler:
        _dev = FakeDeviceManager()

    present, name = _read_device_presence(FakeHandler())
    assert present is True
    assert name == "Longmai-GM3000"


def test_device_presence_uses_physical_gm3000_state_when_ready():
    """Verify polling does not treat a stale GM3000 session as inserted."""
    from bjca_service.device_manager import DeviceManager

    closed = []

    class FakeGM3000:
        def close(self):
            closed.append(True)

    class FakeLongmaiDetect:
        def list_devices(self):
            return []

    class FakeSmartCard:
        def list_readers(self):
            return []

    mgr = DeviceManager.__new__(DeviceManager)
    mgr._gm3000 = FakeGM3000()
    mgr._gm3000_ready = True
    mgr._gm3000_info = object()
    mgr._gm3000_pin = "cached"
    mgr._gm3000_cert = b"cert"
    mgr._longmai_detect = FakeLongmaiDetect()
    mgr._sc = FakeSmartCard()

    info = mgr.get_presence_info()
    assert info["present"] is False
    assert mgr._gm3000_ready is False
    assert mgr._gm3000 is None
    assert mgr._gm3000_info is None
    assert mgr._gm3000_pin is None
    assert mgr._gm3000_cert is None
    assert closed == [True]


def test_smartcard_no_devices():
    """Verify smart card manager handles no-device case gracefully."""
    from bjca_service.smartcard import SmartCardManager, HAS_PYSCARD

    if not HAS_PYSCARD:
        print("(Skipping — pyscard not installed)")
        return

    try:
        mgr = SmartCardManager()
        readers = mgr.list_readers()
        assert isinstance(readers, list)
    except RuntimeError:
        print("(Skipping — PC/SC not available)")


def test_pkcs11_bridge_discovery():
    """Verify PKCS#11 module discovery."""
    from bjca_service.pkcs11_bridge import find_pkcs11_module
    path = find_pkcs11_module()
    if path:
        print(f"PKCS#11 module found: {path}")
        assert os.path.exists(path)
    else:
        print("(No PKCS#11 module found — hardware tokens not available)")


def test_server_app_creation():
    """Verify the aiohttp application can be created."""
    from bjca_service.server import create_app

    try:
        import aiohttp
        app = create_app()
        assert app is not None
        routes = list(app.router.routes())
        assert len(routes) >= 4
    except ImportError:
        print("(Skipping — aiohttp not installed)")


if __name__ == "__main__":
    try:
        import pytest
        pytest.main([__file__, "-v", "--tb=short"])
    except ImportError:
        tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
        passed = failed = skipped = 0
        for t in tests:
            name = t.__name__
            try:
                t()
                passed += 1
                print(f"  PASS  {name}")
            except Exception as e:
                failed += 1
                print(f"  FAIL  {name}: {e}")
        print(f"\n{passed} passed, {failed} failed, total {passed + failed}")
