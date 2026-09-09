"""
Regression tests for HTTP and file boundaries.

Tests:
  - Allowed origin validation (strict HTTPS jspec/sgcc, extension HTTP, rejection of evil/null/malformed)
  - Preflight and actual response CORS headers
  - Safe public-file resolution (/data/{filename}) with symlink escape, percent encoding, traversal prevention
  - Strict JSON-RPC HTTP boundary (/api, /api/{method}) MIME, JSON format, method, params checks
  - WebSocket origin boundary (rejects chrome-extension, accepts allowlisted HTTPS)
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from aiohttp.test_utils import AioHTTPTestCase

from bjca_service.config import ServiceConfig, get_config, set_config
from bjca_service.security import origin_allowed, resolve_public_file, PublicFileError
from bjca_service.server import create_app, _origin_allowed


class TestSecurityHelpers(unittest.TestCase):
    def test_origin_allowed_strict_https(self):
        # Valid HTTPS domains
        self.assertTrue(origin_allowed("https://jspec.com.cn"))
        self.assertTrue(origin_allowed("https://www.jspec.com.cn"))
        self.assertTrue(origin_allowed("https://ebp.sgcc.com.cn"))
        self.assertTrue(origin_allowed("https://sub.portal.sgcc.com.cn"))

        # server._origin_allowed alias
        self.assertTrue(_origin_allowed("https://jspec.com.cn"))
        self.assertTrue(_origin_allowed("https://ebp.sgcc.com.cn"))
        self.assertFalse(_origin_allowed("chrome-extension://" + "a" * 32))

        # Rejections
        self.assertFalse(origin_allowed(""))
        self.assertFalse(origin_allowed("null"))
        self.assertFalse(origin_allowed("http://jspec.com.cn"))
        self.assertFalse(origin_allowed("https://evil-jspec.com.cn"))
        self.assertFalse(origin_allowed("https://jspec.com.cn.evil.com"))
        self.assertFalse(origin_allowed("https://sgcc.com.cn"))  # suffix requires leading dot .sgcc.com.cn
        self.assertFalse(origin_allowed("https://evil-sgcc.com.cn"))
        self.assertFalse(origin_allowed("https://user:pass@jspec.com.cn"))
        self.assertFalse(origin_allowed("https://jspec.com.cn:8443"))
        self.assertFalse(origin_allowed("https://jspec.com.cn/"))
        self.assertFalse(origin_allowed("https://jspec.com.cn/path"))
        self.assertFalse(origin_allowed("https://jspec.com.cn?query=1"))
        self.assertFalse(origin_allowed("https://jspec.com.cn#frag"))
        self.assertFalse(origin_allowed(" https://jspec.com.cn "))

    def test_origin_allowed_extension(self):
        valid_ext = "chrome-extension://" + "abcdefghijklmnop" * 2
        invalid_ext_chars = "chrome-extension://" + "abcdefghijklmnoq" * 2
        short_ext = "chrome-extension://abcdef"

        self.assertTrue(origin_allowed(valid_ext, allow_extension=True))
        self.assertFalse(origin_allowed(valid_ext, allow_extension=False))
        self.assertFalse(origin_allowed(invalid_ext_chars, allow_extension=True))
        self.assertFalse(origin_allowed(short_ext, allow_extension=True))

    def test_resolve_public_file_boundaries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = Path(tmpdir) / "safe_dir"
            base_dir.mkdir()
            safe_file = base_dir / "client_setup.ini"
            safe_file.write_text("safe=true")

            secret_dir = Path(tmpdir) / "secret"
            secret_dir.mkdir()
            secret_file = secret_dir / "secret.key"
            secret_file.write_text("private_key_data")

            # Symlink inside safe_dir pointing to secret_file outside safe_dir
            escaped_symlink = base_dir / "escaped_link.ini"
            escaped_symlink.symlink_to(secret_file)

            # Legitimate symlink inside safe_dir pointing to target inside safe_dir
            safe_target = base_dir / "actual_config.ini"
            safe_target.write_text("safe_target=true")
            safe_symlink = base_dir / "safe_link.ini"
            safe_symlink.symlink_to(safe_target)

            files = {
                "client_setup.ini": safe_file,
                "escaped_link.ini": escaped_symlink,
                "safe_link.ini": safe_symlink,
            }

            # Safe resolution
            resolved = resolve_public_file("client_setup.ini", files)
            self.assertEqual(resolved, safe_file.resolve())

            resolved_safe_link = resolve_public_file("safe_link.ini", files)
            self.assertEqual(resolved_safe_link, safe_target.resolve())

            # Escaped symlink
            with self.assertRaises(PublicFileError):
                resolve_public_file("escaped_link.ini", files)

            # Traversal / encoding attacks
            for bad_name in [
                "../client_setup.ini",
                "..%2fclient_setup.ini",
                "%2e%2e%2fclient_setup.ini",
                "client_setup.ini%00",
                "client_setup.ini/sub",
                "client_setup.ini\\sub",
                "/etc/passwd",
                "secret.key",
                "",
            ]:
                with self.assertRaises(PublicFileError):
                    resolve_public_file(bad_name, files)


class TestHttpBoundaries(AioHTTPTestCase):
    def setUp(self):
        self._orig_config = get_config()
        self.tmpdir = tempfile.mkdtemp()
        self.safe_dir = Path(self.tmpdir) / "config"
        self.safe_dir.mkdir()
        self.ini_file = self.safe_dir / "client_setup.ini"
        self.ini_file.write_text("[general]\nversion=1.0\n")

        self.secret_dir = Path(self.tmpdir) / "private"
        self.secret_dir.mkdir()
        self.secret_file = self.secret_dir / "private.key"
        self.secret_file.write_text("SECRET")

        self.escaped_symlink = self.safe_dir / "escape.ini"
        self.escaped_symlink.symlink_to(self.secret_file)

        self.test_config = ServiceConfig(
            public_files={
                "client_setup.ini": str(self.ini_file),
                "escape.ini": str(self.escaped_symlink),
            }
        )
        super().setUp()

    def tearDown(self):
        super().tearDown()
        set_config(self._orig_config)
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    async def get_application(self):
        # Fake device and handler so real devices are never initialized
        async def fake_health():
            return {"status": "ok"}

        async def fake_handle_request(req):
            return {
                "jsonrpc": "2.0",
                "result": {"handled_method": req.get("method"), "params": req.get("params")},
                "id": req.get("id", 1),
            }

        fake_handler = MagicMock()
        fake_handler.health.side_effect = fake_health
        fake_handler.handle_request.side_effect = fake_handle_request
        fake_handler._dev.get_presence_info.return_value = {"present": False, "name": "FakeToken"}
        self.fake_handler = fake_handler

        with patch("bjca_service.server.get_handler", return_value=fake_handler), \
             patch("bjca_service.server._monitor_device_presence", return_value=None):
            return create_app(self.test_config)

    async def test_origin_middleware_rejection(self):
        # Evil Origin rejected with 403 on text and JSON
        self.fake_handler.handle_request.reset_mock()
        resp = await self.client.get("/health", headers={"Origin": "https://evil.com"})
        self.assertEqual(resp.status, 403)

        resp2 = await self.client.post("/api", headers={"Origin": "https://evil.com"}, json={"method": "ping"})
        self.assertEqual(resp2.status, 403)

        # Evil Origin with text/plain to /api and /api/close_device: handle_request never called
        resp_evil_plain1 = await self.client.post(
            "/api",
            headers={"Origin": "https://evil.com", "Content-Type": "text/plain"},
            data="evil text",
        )
        self.assertEqual(resp_evil_plain1.status, 403)

        resp_evil_plain2 = await self.client.post(
            "/api/close_device",
            headers={"Origin": "https://evil.com", "Content-Type": "text/plain"},
            data="evil text",
        )
        self.assertEqual(resp_evil_plain2.status, 403)
        self.fake_handler.handle_request.assert_not_called()

        # Malformed / null Origin rejected with 403
        resp3 = await self.client.get("/health", headers={"Origin": "null"})
        self.assertEqual(resp3.status, 403)

        # Missing Origin works (CLI requests)
        resp4 = await self.client.get("/health")
        self.assertEqual(resp4.status, 200)

        # Disallowed Origin preflight (OPTIONS) rejected with 403
        resp_options = await self.client.options(
            "/api",
            headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        self.assertEqual(resp_options.status, 403)

    async def test_cors_preflight_and_actual_headers(self):
        trusted_origins = [
            "https://jspec.com.cn",
            "https://www.jspec.com.cn",
            "https://ebp.sgcc.com.cn",
            "chrome-extension://" + "a" * 32,
        ]
        for orig in trusted_origins:
            # Preflight
            preflight = await self.client.options(
                "/api",
                headers={
                    "Origin": orig,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type",
                },
            )
            self.assertEqual(preflight.status, 200)
            self.assertEqual(preflight.headers.get("Access-Control-Allow-Origin"), orig)

            # Actual POST
            actual = await self.client.post(
                "/api",
                headers={"Origin": orig, "Content-Type": "application/json"},
                json={"method": "TestMethod", "params": {}},
            )
            self.assertEqual(actual.status, 200)
            self.assertEqual(actual.headers.get("Access-Control-Allow-Origin"), orig)

    async def test_api_strict_boundaries(self):
        # Wrong Content-Type
        resp = await self.client.post(
            "/api",
            data="not json",
            headers={"Content-Type": "text/plain"},
        )
        self.assertEqual(resp.status, 415)

        # Non-object JSON
        resp2 = await self.client.post(
            "/api",
            data="[1, 2, 3]",
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(resp2.status, 400)
        json_body = await resp2.json()
        self.assertIn("request body must be a JSON object", json_body["error"]["message"])

        # Empty/whitespace method
        resp3 = await self.client.post(
            "/api",
            json={"method": "   "},
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(resp3.status, 400)
        json_body3 = await resp3.json()
        self.assertIn("method must be a nonempty string", json_body3["error"]["message"])

        # Bad params type (number instead of dict or list)
        resp4 = await self.client.post(
            "/api",
            json={"method": "test", "params": 12345},
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(resp4.status, 400)
        json_body4 = await resp4.json()
        self.assertIn("params must be a dict or list", json_body4["error"]["message"])

        # Valid /api/{method} with charset in Content-Type
        resp5 = await self.client.post(
            "/api/SpecificMethod",
            data=b'{"params": {"a": 1}}',
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        self.assertEqual(resp5.status, 200)
        data = await resp5.json()
        self.assertEqual(data["result"]["handled_method"], "SpecificMethod")

    async def test_data_public_file_serving(self):
        # Safe config 200
        resp = await self.client.get("/data/client_setup.ini")
        self.assertEqual(resp.status, 200)
        text = await resp.text()
        self.assertIn("[general]", text)

        # Escaped symlink 404
        resp_sym = await self.client.get("/data/escape.ini")
        self.assertEqual(resp_sym.status, 404)

        # Arbitrary file / private file 404
        resp_priv = await self.client.get("/data/private.key")
        self.assertEqual(resp_priv.status, 404)

        # Encoded absolute path of existing temporary harmless sentinel and double-encoded path rejected
        import urllib.parse
        encoded_abs_path = urllib.parse.quote(str(self.ini_file), safe="")
        double_encoded_path = urllib.parse.quote(encoded_abs_path, safe="")

        # Encoded traversal attacks 404
        for path in [
            f"/data/{encoded_abs_path}",
            f"/data/{double_encoded_path}",
            "/data/..%2fclient_setup.ini",
            "/data/%2e%2e%2fclient_setup.ini",
            "/data/client_setup.ini%00",
            "/data/%2fetc%2fpasswd",
        ]:
            resp_bad = await self.client.get(path)
            self.assertEqual(resp_bad.status, 404)

    async def test_websocket_origin_boundary(self):
        # Disallowed origin WS rejected
        with self.assertRaises(Exception):
            await self.client.ws_connect("/xtxapp", headers={"Origin": "https://evil.com"})

        # Extension origin WS rejected (WS is HTTPS-only)
        ext_origin = "chrome-extension://" + "a" * 32
        with self.assertRaises(Exception):
            await self.client.ws_connect("/xtxapp", headers={"Origin": ext_origin})

        # Allowlisted HTTPS WS connects
        ws = await self.client.ws_connect("/xtxapp", headers={"Origin": "https://jspec.com.cn"})
        await ws.close()


class TestServiceRunnerExit(unittest.TestCase):
    def test_runner_exit_ast_execution(self):
        """Extract __main__ AST from test_service.py and test in subprocess with fake pytest / fallback."""
        import ast
        import subprocess
        import sys

        service_test_path = Path(__file__).parent / "test_service.py"
        source = service_test_path.read_text(encoding="utf-8")
        parsed = ast.parse(source)

        # Extract only the `if __name__ == '__main__':` block AST
        main_if = None
        for node in parsed.body:
            if isinstance(node, ast.If):
                # Check condition: __name__ == '__main__'
                if isinstance(node.test, ast.Compare):
                    left = node.test.left
                    if isinstance(left, ast.Name) and left.id == "__name__":
                        main_if = node
                        break

        self.assertIsNotNone(main_if, "Could not find __main__ block in test_service.py")
        assert isinstance(main_if, ast.If)
        mod = ast.Module(body=main_if.body, type_ignores=[])
        runner_code = ast.unparse(mod)

        # 1. Test runner with fake pytest returning 0
        script_pytest_0 = f"""
import sys, types
fake_pytest = types.ModuleType("pytest")
fake_pytest.main = lambda args: 0
sys.modules["pytest"] = fake_pytest
__file__ = "{service_test_path}"
print("SENTINEL_PYTEST_0_STARTED")
{runner_code}
"""
        proc = subprocess.run([sys.executable, "-c", script_pytest_0], capture_output=True, text=True)
        self.assertIn("SENTINEL_PYTEST_0_STARTED", proc.stdout)
        self.assertEqual(proc.returncode, 0)

        # 2. Test runner with fake pytest returning 1
        script_pytest_1 = f"""
import sys, types
fake_pytest = types.ModuleType("pytest")
fake_pytest.main = lambda args: 1
sys.modules["pytest"] = fake_pytest
__file__ = "{service_test_path}"
print("SENTINEL_PYTEST_1_STARTED")
{runner_code}
"""
        proc = subprocess.run([sys.executable, "-c", script_pytest_1], capture_output=True, text=True)
        self.assertIn("SENTINEL_PYTEST_1_STARTED", proc.stdout)
        self.assertEqual(proc.returncode, 1)

        # 3. Test fallback runner with no pytest and passing tests
        script_fallback_pass = f"""
import sys
# Ensure pytest is not importable
sys.modules["pytest"] = None
__file__ = "{service_test_path}"
def test_ok():
    pass
print("SENTINEL_FALLBACK_PASS_STARTED")
{runner_code}
"""
        proc = subprocess.run([sys.executable, "-c", script_fallback_pass], capture_output=True, text=True)
        self.assertIn("SENTINEL_FALLBACK_PASS_STARTED", proc.stdout)
        self.assertIn("PASS  test_ok", proc.stdout)
        self.assertEqual(proc.returncode, 0)

        # 4. Test fallback runner with failing test
        script_fallback_fail = f"""
import sys
sys.modules["pytest"] = None
__file__ = "{service_test_path}"
def test_fail():
    raise AssertionError("boom")
print("SENTINEL_FALLBACK_FAIL_STARTED")
{runner_code}
"""
        proc = subprocess.run([sys.executable, "-c", script_fallback_fail], capture_output=True, text=True)
        self.assertIn("SENTINEL_FALLBACK_FAIL_STARTED", proc.stdout)
        self.assertIn("FAIL  test_fail", proc.stdout)
        self.assertEqual(proc.returncode, 1)


if __name__ == "__main__":
    unittest.main()
