# BJCA macOS Security and Reliability Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复审查确认的 23 项安全、密码学、硬件、扩展和发布缺陷，使默认安装安全可用、兼容模式显式可控、测试结果可信。

**Architecture:** 默认模式由服务生成安装级令牌，浏览器扩展通过 Native Messaging 获取令牌并代理页面请求；旧网页直连只在 `--legacy-no-token` 下开放。密码学和硬件层采用失败关闭、能力检测和严格资源生命周期，安装层使用受控 Python runtime 与发布门槛。

**Tech Stack:** Python 3.9+、aiohttp、cryptography、asn1crypto、gmssl、python-pkcs11、pyscard、hidapi、Chrome Manifest V3、bash、launchd、unittest。

## Global Constraints

- 默认模式必须认证，兼容模式只能通过 `--legacy-no-token` 显式启用。
- 不得记录或长期缓存令牌、PIN、PFX 密码和私钥。
- 不得用 SHA-256/ECDSA 冒充 SM3/SM2，也不得把结构解析成功当作签名验证成功。
- 任何写入 Token 的接口只有在读回验证后才能返回成功。
- 每项生产代码变更前必须先运行对应失败测试并确认失败原因。
- 不重写与修复无关的模块，不删除用户已有工作。

---

### Task 1: 建立可信测试入口

**Files:**
- Create: `tests/function_runner.py`
- Create: `tests/test_runner_contract.py`
- Modify: `tests/test_service.py:468-484`

**Interfaces:**
- Produces: `run_test_functions(namespace: dict) -> tuple[int, int]`
- Produces: `main(namespace: dict) -> int`

- [ ] **Step 1: 写失败测试，要求失败测试返回非零且 skip 不计为 pass**

```python
# tests/function_runner.py（RED 阶段最小桩，仅用于让行为断言失败）
def run_test_functions(namespace):
    return 0, 0


# tests/test_runner_contract.py
import unittest

from tests.function_runner import run_test_functions


class RunnerContractTests(unittest.TestCase):
    def test_failure_is_counted(self):
        def test_failure():
            raise AssertionError("boom")

        passed, failed = run_test_functions({"test_failure": test_failure})
        self.assertEqual((passed, failed), (0, 1))

    def test_success_is_counted(self):
        def test_success():
            return None

        passed, failed = run_test_functions({"test_success": test_success})
        self.assertEqual((passed, failed), (1, 0))
```

- [ ] **Step 2: 运行测试并确认 RED**

Run: `python3 -m unittest tests.test_runner_contract -v`

Expected: `test_failure_is_counted` FAIL with expected `(0, 1)` but got `(0, 0)`.

- [ ] **Step 3: 实现通用函数测试运行器**

```python
# tests/function_runner.py
from __future__ import annotations

from typing import Callable, Mapping


def run_test_functions(namespace: Mapping[str, object]) -> tuple[int, int]:
    tests = [value for name, value in sorted(namespace.items())
             if name.startswith("test_") and callable(value)]
    passed = failed = 0
    for test in tests:
        try:
            test()
        except Exception as exc:
            failed += 1
            print(f"  FAIL  {test.__name__}: {exc}")
        else:
            passed += 1
            print(f"  PASS  {test.__name__}")
    return passed, failed
```

Update `tests/test_service.py` main block to call `run_test_functions(globals())` and `raise SystemExit(1 if failed else 0)`. When pytest is available, use `raise SystemExit(pytest.main(...))`.

- [ ] **Step 4: 验证 GREEN 与基线**

Run: `python3 -m unittest tests.test_runner_contract -v`

Expected: 2 tests pass.

Run: `python3 tests/test_service.py`

Expected: existing suite reports zero failures and exits 0.

- [ ] **Step 5: 提交**

```bash
git add tests/function_runner.py tests/test_runner_contract.py tests/test_service.py
git commit -m "test: make service test failures authoritative"
```

### Task 2: 封堵任意文件读取并建立固定公开文件映射

**Files:**
- Create: `tests/test_server_security.py`
- Create: `bjca_service/security.py`
- Modify: `bjca_service/server.py:114-191`
- Modify: `bjca_service/config.py:19-63`

**Interfaces:**
- Produces: `resolve_public_file(name: str, files: Mapping[str, Path]) -> Path`
- Produces: `ServiceConfig.public_files: Dict[str, str]`

- [ ] **Step 1: 写路径逃逸失败测试**

```python
# tests/test_server_security.py
import asyncio
import tempfile
import unittest
from pathlib import Path

from aiohttp import WSServerHandshakeError
from aiohttp.test_utils import TestClient, TestServer

from bjca_service.config import ServiceConfig
from bjca_service.server import create_app


class PublicFileTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        public = root / "client_setup.ini"
        public.write_text("ok", encoding="utf-8")
        config = ServiceConfig()
        config.public_files = {"client_setup.ini": str(public)}
        self.client = TestClient(TestServer(create_app(config)))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        self.tempdir.cleanup()

    async def test_rejects_encoded_absolute_path(self):
        response = await self.client.get("/data/%2Fetc%2Fhosts")
        self.assertEqual(response.status, 404)

    async def test_rejects_tls_private_key_name(self):
        response = await self.client.get("/data/server.key")
        self.assertEqual(response.status, 404)

    async def test_serves_only_explicit_mapping(self):
        response = await self.client.get("/data/client_setup.ini")
        self.assertEqual(response.status, 200)
        self.assertEqual(await response.text(), "ok")
```

- [ ] **Step 2: 运行测试并确认 RED**

Run: `python3 -m unittest tests.test_server_security.PublicFileTests -v`

Expected: encoded absolute path or private-key request returns 200, and explicit temporary mapping is ignored.

- [ ] **Step 3: 实现固定映射解析器并替换静态路由**

```python
# bjca_service/security.py
from pathlib import Path
from typing import Mapping
from urllib.parse import unquote


class PublicFileError(ValueError):
    pass


def resolve_public_file(name: str, files: Mapping[str, Path]) -> Path:
    decoded = unquote(name)
    if decoded != name or decoded not in files or Path(decoded).name != decoded:
        raise PublicFileError("public file is not allowed")
    path = Path(files[decoded]).resolve(strict=True)
    if not path.is_file():
        raise PublicFileError("public file is not a regular file")
    return path
```

`ServerHandlers.static_file()` must build the mapping from `ServiceConfig.public_files`, call `resolve_public_file()`, and return 404 for `PublicFileError`. Remove the three-directory search loop completely.

- [ ] **Step 4: 验证 GREEN 与编码路径集成行为**

Run: `python3 -m unittest tests.test_server_security.PublicFileTests -v`

Expected: all tests pass.

Run an aiohttp test server and request `/data/%2Fetc%2Fhosts` and `/data/server.key`.

Expected: both return 404; `client_setup.ini` returns 200 only when explicitly mapped.

- [ ] **Step 5: 提交**

```bash
git add bjca_service/security.py bjca_service/server.py bjca_service/config.py tests/test_server_security.py
git commit -m "fix: confine public file serving"
```

### Task 3: 默认令牌认证、Origin 和请求资源限制

**Files:**
- Modify: `bjca_service/security.py`
- Modify: `bjca_service/config.py`
- Modify: `bjca_service/server.py`
- Modify: `bjca_service/api_handlers.py`
- Modify: `tests/test_server_security.py`

**Interfaces:**
- Produces: `ensure_auth_token(path: Path) -> str`
- Produces: `authenticate_request(request, token: str, legacy: bool) -> None`
- Produces: `ServiceConfig.auth_token_path`, `auth_required`, `legacy_no_token`

- [ ] **Step 1: 写令牌权限、认证与跨站失败测试**

```python
from bjca_service import security


class AuthTests(unittest.IsolatedAsyncioTestCase):
    def test_token_file_is_private_and_stable(self):
        ensure_auth_token = getattr(security, "ensure_auth_token", None)
        self.assertIsNotNone(ensure_auth_token)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "auth" / "token"
            first = ensure_auth_token(path)
            second = ensure_auth_token(path)
            self.assertEqual(first, second)
            self.assertGreaterEqual(len(first), 43)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    async def test_missing_token_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            token_path = Path(tmp) / "token"
            token_path.write_text("secret", encoding="ascii")
            config = ServiceConfig()
            config.auth_required = True
            config.auth_token_path = str(token_path)
            client = TestClient(TestServer(create_app(config)))
            await client.start_server()
            try:
                response = await client.post(
                    "/api",
                    json={"jsonrpc": "2.0", "method": "health", "params": {}, "id": 1},
                )
                self.assertEqual(response.status, 401)
            finally:
                await client.close()

    async def test_evil_origin_text_plain_never_dispatches(self):
        with tempfile.TemporaryDirectory() as tmp:
            token_path = Path(tmp) / "token"
            token_path.write_text("secret", encoding="ascii")
            config = ServiceConfig()
            config.auth_required = True
            config.auth_token_path = str(token_path)
            client = TestClient(TestServer(create_app(config)))
            await client.start_server()
            try:
                response = await client.post(
                    "/api",
                    data='{"jsonrpc":"2.0","method":"close_device","params":{},"id":1}',
                    headers={
                        "Authorization": "Bearer secret",
                        "Content-Type": "text/plain",
                        "Origin": "https://evil.example",
                    },
                )
                self.assertIn(response.status, (403, 415))
            finally:
                await client.close()
```

- [ ] **Step 2: 运行测试并确认 RED**

Run: `python3 -m unittest tests.test_server_security.AuthTests -v`

Expected: FAIL because authentication helpers are absent.

- [ ] **Step 3: 实现安全令牌与 aiohttp middleware**

Use exclusive `os.open(..., os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)`, `secrets.token_urlsafe(32)`, `secrets.compare_digest`, exact Origin validation, and `web.Application(client_max_size=2 * 1024 * 1024)`. Apply middleware to every route except reduced `/health`. Reject browser Origins outside the allowlist even when the token is valid.

`ServerHandlers.api()` must reject non-JSON content type before `request.json()`, require a JSON object, and never dispatch rejected requests.

`sof_gen_random()` must parse an integer in `[1, 4096]`; strict Base64 helpers must use `base64.b64decode(value, validate=True)`.

- [ ] **Step 4: 验证 GREEN 与真实请求**

Run: `python3 -m unittest tests.test_server_security.AuthTests -v`

Expected: all tests pass.

Run aiohttp integration requests for missing token, evil Origin with text/plain, valid token with allowed Origin, and `SOF_GenRandom` above 4096.

Expected: 401, 403/415, 200, and JSON-RPC `-32602` respectively; rejected requests never call the API handler.

- [ ] **Step 5: 提交**

```bash
git add bjca_service/security.py bjca_service/config.py bjca_service/server.py bjca_service/api_handlers.py tests/test_server_security.py
git commit -m "feat: require authenticated local API access"
```

### Task 4: WebSocket 认证、兼容模式和错误响应

**Files:**
- Modify: `bjca_service/server.py:198-301`
- Modify: `bjca_service/config.py`
- Modify: `tests/test_server_security.py`

**Interfaces:**
- Consumes: installation token from Task 3
- Produces: `--legacy-no-token`
- Produces: authenticated WebSocket subprotocol `bjca.v1`

- [ ] **Step 1: 写 WebSocket 认证和解析错误测试**

```python
class WebSocketPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        token_path = Path(self.tempdir.name) / "token"
        token_path.write_text("secret", encoding="ascii")
        self.config = ServiceConfig()
        self.config.auth_required = True
        self.config.auth_token_path = str(token_path)
        self.config.legacy_no_token = False
        self.client = TestClient(TestServer(create_app(self.config)))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        self.tempdir.cleanup()

    @staticmethod
    def token_protocol():
        return "bjca.token.secret"

    async def test_invalid_json_receives_parse_error(self):
        ws = await self.client.ws_connect(
            "/xtxapp",
            headers={"Origin": "https://jspec.com.cn"},
            protocols=(self.token_protocol(),),
        )
        await ws.send_str("not-json")
        message = await asyncio.wait_for(ws.receive_json(), timeout=1)
        self.assertEqual(message["error"]["code"], -32700)

    async def test_missing_token_is_rejected_by_default(self):
        with self.assertRaises(WSServerHandshakeError) as ctx:
            await self.client.ws_connect(
                "/xtxapp", headers={"Origin": "https://jspec.com.cn"}
            )
        self.assertEqual(ctx.exception.status, 401)
```

- [ ] **Step 2: 运行测试并确认 RED**

Run: `python3 -m unittest tests.test_server_security.WebSocketPolicyTests -v`

Expected: missing token currently connects and invalid JSON times out.

- [ ] **Step 3: 实现子协议认证和显式兼容模式**

Parse a `bjca.token.<base64url>` offered subprotocol, compare the token without logging it, and prepare the socket with response protocol `bjca.v1`. When `legacy_no_token` is true, accept only existing allowed HTTPS Origins and log one startup warning. Replace the duplicate `except json.JSONDecodeError` with one branch that sends JSON-RPC `-32700`.

- [ ] **Step 4: 验证 GREEN**

Run: `python3 -m unittest tests.test_server_security.WebSocketPolicyTests -v`

Expected: authenticated socket works, missing token is rejected, invalid JSON receives exactly one error response, legacy mode accepts only allowlisted Origins.

- [ ] **Step 5: 提交**

```bash
git add bjca_service/server.py bjca_service/config.py tests/test_server_security.py
git commit -m "fix: authenticate websocket connections"
```

### Task 5: 修复 SM3、SM2、SM4 与严格 Base64

**Files:**
- Create: `tests/test_crypto_correctness.py`
- Modify: `bjca_service/crypto_ops.py:77-218`

**Interfaces:**
- Produces: `secure_random_scalar() -> int`
- Produces: correct `SM2Engine.sign/verify/encrypt/decrypt`
- Produces: fail-closed `SM3Hash`

- [ ] **Step 1: 写密码学闭环和失败关闭测试**

```python
# tests/test_crypto_correctness.py
import unittest
from unittest.mock import patch

from bjca_service.crypto_ops import Base64Util, SM2Engine, SM3Hash, SM4Cipher


class CryptoCorrectnessTests(unittest.TestCase):
    def test_sm2_sign_verify_round_trip(self):
        pair = SM2Engine.generate_key_pair()
        engine = SM2Engine(pair.private_key.hex(), pair.public_key.hex())
        signature = engine.sign(b"message")
        self.assertTrue(engine.verify(b"message", signature))
        self.assertFalse(engine.verify(b"tampered", signature))

    def test_sm2_encrypt_decrypt_round_trip(self):
        pair = SM2Engine.generate_key_pair()
        engine = SM2Engine(pair.private_key.hex(), pair.public_key.hex())
        self.assertEqual(engine.decrypt(engine.encrypt(b"secret")), b"secret")

    def test_sm3_fails_when_dependency_is_missing(self):
        with patch("bjca_service.crypto_ops.HAS_GMSSL", False):
            with self.assertRaises(RuntimeError):
                SM3Hash.hash(b"message")

    def test_base64_is_strict(self):
        with self.assertRaises(ValueError):
            Base64Util.decode("@@not-base64@@")
```

- [ ] **Step 2: 运行测试并确认 RED**

Run: `python3 -m unittest tests.test_crypto_correctness.CryptoCorrectnessTests -v`

Expected: sign/verify is false, encrypt raises AttributeError, SM3 falls back, and invalid Base64 is accepted.

- [ ] **Step 3: 实现安全随机标量和正确 gmssl 调用**

Generate private scalars and per-signature nonce with `secrets.randbelow`. Instantiate `CryptSM2` with both matching keys, use `sign_with_sm3(..., random_hex_str=nonce)` and `verify_with_sm3`. Pass bytes directly to `encrypt()` and `decrypt()`. Remove SHA-256 SM3 fallback. Remove manual SM4 padding because gmssl already pads, validate 16-byte key and IV, and validate Base64 with `validate=True`.

- [ ] **Step 4: 验证 GREEN 与原有测试**

Run: `python3 -m unittest tests.test_crypto_correctness.CryptoCorrectnessTests -v`

Expected: all tests pass.

Run: `python3 tests/test_service.py`

Expected: existing crypto smoke tests pass without fallback warnings.

- [ ] **Step 5: 提交**

```bash
git add bjca_service/crypto_ops.py tests/test_crypto_correctness.py
git commit -m "fix: make SM cryptography fail closed and interoperable"
```

### Task 6: 生成真实 SM2 CSR 并统一 GM3000 摘要

**Files:**
- Modify: `bjca_service/crypto_ops.py:297-333`
- Modify: `bjca_service/api_handlers.py:278-327,484-510,1017-1047`
- Modify: `tests/test_crypto_correctness.py`

**Interfaces:**
- Produces: `PKCS10Handler.generate_csr(...) -> bytes` using SM2 OIDs
- Reuses: `_sm2_message_digest()` for all GM3000 SM3withSM2 signing

- [ ] **Step 1: 写 CSR OID、公钥一致性与签名测试**

```python
def test_sm2_csr_has_matching_key_and_sm2_oids(self):
    from asn1crypto import core, csr
    pair = SM2Engine.generate_key_pair()
    der = PKCS10Handler.generate_csr("BJCA User", pair, "SM2")
    request = csr.CertificationRequest.load(der)
    algorithm = request["certification_request_info"]["subject_pk_info"]["algorithm"]
    self.assertEqual(algorithm["parameters"].chosen.dotted, "1.2.156.10197.1.301")
    self.assertEqual(request["signature_algorithm"]["algorithm"].dotted,
                     "1.2.156.10197.1.501")
    encoded_point = request["certification_request_info"]["subject_pk_info"]["public_key"].native
    self.assertEqual(encoded_point.lstrip(b"\x04"), pair.public_key)
    values = core.SequenceOf.load(request["signature"].native, spec=core.Integer)
    raw_signature = (
        int(values[0].native).to_bytes(32, "big")
        + int(values[1].native).to_bytes(32, "big")
    )
    verifier = SM2Engine(public_key_hex=pair.public_key.hex())
    self.assertTrue(verifier.verify(
        request["certification_request_info"].dump(), raw_signature
    ))
```

Add a fake GM3000 test asserting `sign()` receives `SM3(ZA || M)`, not `SM3(M)`.

- [ ] **Step 2: 运行测试并确认 RED**

Run: `python3 -m unittest tests.test_crypto_correctness -v`

Expected: CSR reports P-256/ECDSA-SHA256 and the key does not match; generic GM signing receives the wrong digest.

- [ ] **Step 3: 用 asn1crypto 构建并签署 SM2 CSR**

Build `CertificationRequestInfo` with SM2 curve OID, sign its DER using the matching SM2 key and secure nonce, DER-encode `(r, s)`, and assemble `CertificationRequest` with SM3withSM2 OID. In `APIHandler.sign()`, call `_sm2_message_digest(data, gm3000_cert)` before `ecc_sign()`.

- [ ] **Step 4: 验证 GREEN**

Run: `python3 -m unittest tests.test_crypto_correctness -v`

Expected: CSR self-verifies, keys match, and both GM signing paths use the same ZA digest.

- [ ] **Step 5: 提交**

```bash
git add bjca_service/crypto_ops.py bjca_service/api_handlers.py tests/test_crypto_correctness.py
git commit -m "fix: generate genuine SM2 certificate requests"
```

### Task 7: 实现真实 CMS 验证与硬件 CMS 签名

**Files:**
- Create: `tests/test_cms_validation.py`
- Create: `tests/crypto_fixtures.py`
- Modify: `bjca_service/crypto_ops.py:254-295`
- Modify: `bjca_service/api_handlers.py:358-387,981-1120`

**Interfaces:**
- Produces: `PKCS7Handler.verify_signed_data(pkcs7_der, detached_data=None, trusted_certs=None)`
- Produces: hardware-backed `APIHandler.sign_pkcs7()`

- [ ] **Step 1: 写伪签名、篡改内容与有效 CMS 测试**

```python
# tests/crypto_fixtures.py
from datetime import datetime, timedelta

from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID


def build_valid_rsa_cms(data: bytes) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CMS Test Root")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.utcnow() - timedelta(minutes=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    signed = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(data)
        .add_signer(cert, key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [])
    )
    return signed, cert.public_bytes(serialization.Encoding.DER)


def replace_encapsulated_content(value: bytes, content: bytes) -> bytes:
    parsed = cms.ContentInfo.load(value)
    parsed["content"]["encap_content_info"]["content"] = content
    return parsed.dump()


def replace_signature(value: bytes, signature: bytes) -> bytes:
    parsed = cms.ContentInfo.load(value)
    parsed["content"]["signer_infos"][0]["signature"] = signature
    return parsed.dump()


# tests/test_cms_validation.py
import unittest

from bjca_service.crypto_ops import PKCS7Handler
from tests.crypto_fixtures import (
    build_valid_rsa_cms,
    replace_encapsulated_content,
    replace_signature,
)


class CMSValidationTests(unittest.TestCase):
    def test_rejects_structurally_valid_bogus_signature(self):
        cms_der, root_der = build_valid_rsa_cms(b"message")
        bogus = replace_signature(cms_der, b"not-a-real-signature")
        valid, details = PKCS7Handler.verify_signed_data(bogus, trusted_certs=[root_der])
        self.assertFalse(valid)
        self.assertEqual(details["signature_valid"], False)

    def test_rejects_tampered_content(self):
        cms_der, root_der = build_valid_rsa_cms(b"original")
        tampered = replace_encapsulated_content(cms_der, b"tampered")
        self.assertFalse(PKCS7Handler.verify_signed_data(tampered, trusted_certs=[root_der])[0])

    def test_accepts_valid_trusted_cms(self):
        cms_der, root_der = build_valid_rsa_cms(b"message")
        self.assertTrue(PKCS7Handler.verify_signed_data(cms_der, trusted_certs=[root_der])[0])
```

- [ ] **Step 2: 运行测试并确认 RED**

Run: `python3 -m unittest tests.test_cms_validation -v`

Expected: bogus and tampered CMS are currently accepted or cannot be verified meaningfully.

- [ ] **Step 3: 实现摘要、签名和信任链三层验证**

Parse CMS with asn1crypto, verify `messageDigest`, select RSA/ECDSA/SM2 by OID, verify the signature against signed attributes or content, then validate the signer certificate against provided trust roots. Return separate `digest_valid`, `signature_valid`, and `chain_valid` fields; overall validity is their conjunction.

Replace `sign_pkcs7()` empty-key call with GM3000/PKCS#11 hardware signing and existing CMS builder. Return unsupported when no hardware-backed signer is available.

- [ ] **Step 4: 验证 GREEN**

Run: `python3 -m unittest tests.test_cms_validation -v`

Expected: valid trusted CMS passes; altered content, bogus signature, unknown root, and expired signer fail.

- [ ] **Step 5: 提交**

```bash
git add bjca_service/crypto_ops.py bjca_service/api_handlers.py tests/crypto_fixtures.py tests/test_cms_validation.py
git commit -m "fix: cryptographically verify CMS signatures"
```

### Task 8: 修复证书时区、信任链与普通验签

**Files:**
- Create: `tests/test_certificate_validation.py`
- Modify: `bjca_service/cert_manager.py:286-354`
- Modify: `bjca_service/api_handlers.py:415-440`

**Interfaces:**
- Produces: `validate_certificate(..., trusted_certs=None) -> dict`
- Produces: algorithm-aware `verify_signature(...)`

- [ ] **Step 1: 写有效期、未知根和 SM2/EC/RSA 验签测试**

Create a test root and leaf certificate. Assert trusted current leaf is valid, unknown root is invalid, expired leaf is invalid, and no aware/naive exception appears. Add RSA and ECDSA signature round trips plus an SM2 raw `r||s` fixture.

- [ ] **Step 2: 运行测试并确认 RED**

Run: `python3 -m unittest tests.test_certificate_validation -v`

Expected: current validation returns timezone error or marks unknown roots valid; SM2 output cannot verify.

- [ ] **Step 3: 实现 UTC 与链验证**

Use `datetime.now(timezone.utc)`, pyOpenSSL `X509Store`/`X509StoreContext` for the configured trust roots, and explicit `revocation_status: not_checked`. Select RSA/ECDSA/SM2 verification from the certificate and requested algorithm, converting raw SM2 `r||s` when required.

- [ ] **Step 4: 验证 GREEN**

Run: `python3 -m unittest tests.test_certificate_validation -v`

Expected: all trust, expiry, and signature cases pass.

- [ ] **Step 5: 提交**

```bash
git add bjca_service/cert_manager.py bjca_service/api_handlers.py tests/test_certificate_validation.py
git commit -m "fix: validate certificate time trust and signatures"
```

### Task 9: 对齐 python-pkcs11 API 并禁止虚假导入成功

**Files:**
- Create: `tests/test_pkcs11_bridge_contract.py`
- Modify: `bjca_service/pkcs11_bridge.py`
- Modify: `bjca_service/cert_manager.py:174-258`
- Modify: `bjca_service/device_manager.py:210-226`

**Interfaces:**
- Produces: API-compatible `PKCS11Bridge`
- Produces: capability-checked `import_certificate`, `import_pfx`, `set_pin`

- [ ] **Step 1: 写符合 python-pkcs11 0.9.x 形状的 fake token 测试**

The fake objects expose `Attribute` mapping access, `slot_description`, `manufacturer_id`, `flags`, `token.open(user_pin=...)`, `session.get_objects()`, `session.create_object()`, and `session.set_pin()`. They deliberately do not expose `.label`, `.id`, `.value`, `session.login()`, or `MechanismType`.

Assert slot listing, authenticated session open, certificate listing, exact mechanism selection, failed session propagation, object read-back after import, and unsupported import failure.

- [ ] **Step 2: 运行测试并确认 RED**

Run: `python3 -m unittest tests.test_pkcs11_bridge_contract -v`

Expected: missing attributes/imports fail and `DeviceManager.init_device()` incorrectly reports success.

- [ ] **Step 3: 重写 PKCS#11 属性、会话和机制访问**

Use top-level `pkcs11.Attribute`, `ObjectClass`, `KeyType`, and `Mechanism`; use attribute dictionaries keyed by `Attribute.CLASS`. Authenticate through `token.open(user_pin=pin)`. Query token mechanisms before signing and reject unavailable SM3/SM2 instead of mapping it to SHA-256. Propagate false `open_session()` results.

Implement certificate object creation with read-back. Implement PFX import only for supported extractable key types and writable sessions; otherwise return a stable unsupported error with zero counts.

- [ ] **Step 4: 验证 GREEN**

Run: `python3 -m unittest tests.test_pkcs11_bridge_contract -v`

Expected: all fake contract tests pass and no nonexistent python-pkcs11 symbols are imported.

- [ ] **Step 5: 提交**

```bash
git add bjca_service/pkcs11_bridge.py bjca_service/cert_manager.py bjca_service/device_manager.py tests/test_pkcs11_bridge_contract.py
git commit -m "fix: align token access with python-pkcs11"
```

### Task 10: 修复 PC/SC、GM3000 PID、传输边界和 PIN 生命周期

**Files:**
- Create: `tests/test_device_transport.py`
- Modify: `bjca_service/smartcard.py`
- Modify: `bjca_service/longmai_hid.py`
- Modify: `bjca_service/longmai_gm3000.py`
- Modify: `bjca_service/device_manager.py`

**Interfaces:**
- Produces: connected PC/SC connections
- Produces: path-based GM3000 open for all declared PIDs
- Produces: PIN-free `DeviceManager` state

- [ ] **Step 1: 写连接、PID、多包和清理测试**

Use fake readers to assert `createConnection()` is followed by `connect()` and ATR becomes bytes. Use fake hid enumeration for each PID in `LONGMAI_GM3000_PRODUCT_IDS`, assert `open_path()` receives the enumerated path, assert every report is exactly 65 bytes for APDUs above 103 bytes, assert caller timeout reaches reads, and assert failed PIN/init closes the handle and leaves no `_gm3000_pin` attribute/value.

- [ ] **Step 2: 运行测试并确认 RED**

Run: `python3 -m unittest tests.test_device_transport -v`

Expected: PC/SC is unconnected, three PIDs cannot open, long APDU produces oversized report, timeout is ignored, and PIN remains cached.

- [ ] **Step 3: 实现真实连接、path 打开、通用分包和统一清理**

Call `connection.connect()`, convert ATR with `bytes()`, open the selected HID path, loop over continuation chunks of 63 bytes, verify write lengths and response sequence, pass `timeout_ms` to each read, and extract status words only from protocol-defined positions. Wrap probes and initialization in `try/finally`; remove plaintext PIN state.

- [ ] **Step 4: 验证 GREEN**

Run: `python3 -m unittest tests.test_device_transport -v`

Expected: all fake transport tests pass.

Run: `python3 tests/test_service.py`

Expected: existing GM3000 PIN and presence tests pass after updating fixtures to assert no cached PIN.

- [ ] **Step 5: 提交**

```bash
git add bjca_service/smartcard.py bjca_service/longmai_hid.py bjca_service/longmai_gm3000.py bjca_service/device_manager.py tests/test_device_transport.py tests/test_service.py
git commit -m "fix: harden smartcard and GM3000 transport"
```

### Task 11: 将硬件 I/O 移出事件循环并串行化

**Files:**
- Create: `tests/test_async_device_access.py`
- Modify: `bjca_service/api_handlers.py`
- Modify: `bjca_service/server.py`

**Interfaces:**
- Produces: `APIHandler._run_device(callable, *args)`
- Produces: one `asyncio.Lock` per handler/device manager

- [ ] **Step 1: 写事件循环活性和串行测试**

Use a fake blocking device call guarded by threading events. Assert an unrelated coroutine still advances while the call runs, and two signing calls never overlap their fake hardware critical sections.

- [ ] **Step 2: 运行测试并确认 RED**

Run: `python3 -m unittest tests.test_async_device_access -v`

Expected: event loop is blocked or fake calls overlap after moving to threads without a lock.

- [ ] **Step 3: 实现工作线程和设备锁**

Add `self._device_lock = asyncio.Lock()` and run all PC/SC, PKCS#11 and HID calls under the lock with `await asyncio.to_thread(...)` (or `loop.run_in_executor` on Python 3.9). Move notification subprocess work to a thread as well.

- [ ] **Step 4: 验证 GREEN**

Run: `python3 -m unittest tests.test_async_device_access -v`

Expected: ticker advances and hardware critical sections are serialized.

- [ ] **Step 5: 提交**

```bash
git add bjca_service/api_handlers.py bjca_service/server.py tests/test_async_device_access.py
git commit -m "fix: isolate blocking token operations"
```

### Task 12: 重建 Chrome 主世界桥、隔离桥和 Native Messaging Host

**Files:**
- Create: `extensions/chrome/page_bridge.js`
- Create: `extensions/chrome/content_bridge.js`
- Modify: `extensions/chrome/background.js`
- Modify: `extensions/chrome/manifest.json`
- Delete: `extensions/chrome/inject.js`
- Create: `native_host/bjca_native_host.py`
- Create: `native_host/com.bjca.certservice.json.in`
- Create: `tests/test_extension_contract.py`

**Interfaces:**
- Page message: `{source:"bjca-page", id, method, params}`
- Response message: `{source:"bjca-extension", id, result|error}`
- Native command: `{command:"get_auth_token"}`

- [ ] **Step 1: 写 manifest 资源、消息协议和 native host 测试**

Assert every manifest script/icon exists, MAIN world script contains no `chrome.` access, isolated bridge has a fixed method allowlist and validates `event.source === window`, recursive `navigator.plugins` override is absent, and native host rejects every command except `get_auth_token` and never accepts a path parameter.

- [ ] **Step 2: 运行测试并确认 RED**

Run: `python3 -m unittest tests.test_extension_contract -v`

Expected: missing icons, missing MAIN world, absent bridge and recursive getter fail.

- [ ] **Step 3: 实现三层消息桥和最小 Native Host**

`page_bridge.js` exposes Promise-based APIs and a narrowly matched WebSocket proxy via `window.postMessage`. `content_bridge.js` validates source, method and parameter size then calls runtime. `background.js` validates sender URL, retrieves the token using `chrome.runtime.connectNative`, adds the Bearer header, and does not return the token. Remove unused permissions and missing icon entries until real assets are present.

The Python native host implements Chrome's 4-byte little-endian framing, reads the fixed token path, and only answers the fixed command.

- [ ] **Step 4: 验证 GREEN 和 JavaScript 语法**

Run: `python3 -m unittest tests.test_extension_contract -v`

Run: `node --check extensions/chrome/page_bridge.js`

Run: `node --check extensions/chrome/content_bridge.js`

Run: `node --check extensions/chrome/background.js`

Expected: all pass and manifest has no missing resources.

- [ ] **Step 5: 提交**

```bash
git add extensions/chrome native_host tests/test_extension_contract.py
git commit -m "feat: add authenticated browser extension bridge"
```

### Task 13: 修复配置编码、字段对称性和统一版本

**Files:**
- Create: `tests/test_configuration_contract.py`
- Modify: `bjca_service/config.py`
- Modify: `bjca_service/__init__.py`
- Modify: `bjca_service/server.py`
- Modify: `config/client_setup.ini`
- Modify: `extensions/chrome/manifest.json`
- Modify: `packaging/build_dmg.sh`

**Interfaces:**
- Produces: UTF-8-SIG/UTF-8/GB18030 config loading
- Produces: CLI-over-config precedence
- Produces: one authoritative version

- [ ] **Step 1: 写仓库配置读取和 round-trip 测试**

Load the real `config/client_setup.ini`, assert no decode error, assert `[server]` and `[pkcs11]` values are parsed, save to a temporary file, reload, and compare every persisted field. Add a CLI merge test proving omitted flags keep config values and explicit flags override them. Assert package, server and extension versions equal `bjca_service.__version__` during release checks.

- [ ] **Step 2: 运行测试并确认 RED**

Run: `python3 -m unittest tests.test_configuration_contract -v`

Expected: UnicodeDecodeError, missing server/pkcs11 fields, CLI overwrite, and version mismatch.

- [ ] **Step 3: 实现编码回退、完整字段解析和版本同步**

Read bytes once and decode in the fixed order UTF-8-SIG, UTF-8, GB18030. Parse/save server, auth, public files and PKCS#11 module paths symmetrically. Set argparse defaults to `None` where precedence matters, then merge explicit values into loaded config. Make build checks read `bjca_service.__version__`; update the released version consistently.

- [ ] **Step 4: 验证 GREEN**

Run: `python3 -m unittest tests.test_configuration_contract -v`

Expected: all cases pass.

- [ ] **Step 5: 提交**

```bash
git add bjca_service/config.py bjca_service/__init__.py bjca_service/server.py config/client_setup.ini extensions/chrome/manifest.json packaging/build_dmg.sh tests/test_configuration_contract.py
git commit -m "fix: make configuration and version authoritative"
```

### Task 14: 修复源码安装、运行时、目标用户和权限

**Files:**
- Create: `requirements.lock`
- Modify: `requirements.txt`
- Modify: `install.sh`
- Modify: `packaging/build_dmg.sh`
- Modify: `packaging/copy_vendor.py`
- Modify: `launchd/com.bjca.certservice.plist`
- Create: `tests/test_installation_contract.py`

**Interfaces:**
- Source install: dedicated venv and consistent interpreter
- DMG build: explicit `PYTHON_RUNTIME` and target architecture
- Installer: console user LaunchAgent, root-owned global payload

- [ ] **Step 1: 写安装脚本静态与产物契约测试**

Assert install uses `"$PYTHON" -m venv`, venv `python -m pip`, the lock file, hidapi and asn1crypto; assert no wrapper hardcodes `/Library/BJCA` when `INSTALL_DIR` is configurable. Assert postinstall resolves `/dev/console` when running as root, global payload BOM is root:wheel, launcher uses bundled runtime, build fails without `PYTHON_RUNTIME`, and architecture mismatch is rejected.

- [ ] **Step 2: 运行测试并确认 RED**

Run: `python3 -m unittest tests.test_installation_contract -v`

Expected: missing hidapi, root target user, hardcoded path, user-owned BOM, target `command -v python3`, and silent failures are reported.

- [ ] **Step 3: 实现确定性安装**

Create the venv with the selected Python, install exact locked dependencies, use one interpolated install root, and make health failure fatal. In DMG builds, copy an explicit controlled runtime rather than user-site packages, validate its architecture and ABI, install system payload root:wheel, resolve the console user, and propagate launchctl failures.

The initial reviewed lock set is:

```text
aiohappyeyeballs==2.6.1
aiohttp==3.13.5
aiohttp-cors==0.8.1
aiosignal==1.4.0
asn1crypto==1.5.1
async-timeout==5.0.1
attrs==26.1.0
cffi==2.0.0
cryptography==49.0.0
frozenlist==1.8.0
gmssl==3.2.2
hidapi==0.15.0
idna==3.18
multidict==6.7.1
propcache==0.4.1
pycparser==2.23
pycryptodomex==3.23.0
pyOpenSSL==26.3.0
pyscard==2.3.1
python-pkcs11==0.9.4
typing_extensions==4.15.0
yarl==1.22.0
```

`requirements.txt` lists direct runtime dependencies with the same exact versions; `requirements.lock` contains the complete set above. CryptoTokenKit PyObjC packages move to a separately documented optional extra because the native GM3000 path and core service do not require them.

`copy_vendor.py` becomes a validation/copy helper only for the controlled runtime and treats every missing core package as fatal.

- [ ] **Step 4: 验证 GREEN 和 shell 语法**

Run: `python3 -m unittest tests.test_installation_contract -v`

Run: `bash -n install.sh packaging/build_dmg.sh`

Expected: all tests and syntax checks pass.

- [ ] **Step 5: 提交**

```bash
git add requirements.txt requirements.lock install.sh packaging/build_dmg.sh packaging/copy_vendor.py launchd/com.bjca.certservice.plist tests/test_installation_contract.py
git commit -m "fix: make macOS installation deterministic"
```

### Task 15: 发布签名、公证门槛与安装说明

**Files:**
- Modify: `packaging/build_dmg.sh`
- Modify: `README.md`
- Modify: `tests/test_installation_contract.py`

**Interfaces:**
- Produces: `RELEASE=1` hard gate for signing, notarization, stapling and verification
- Produces: clearly labeled development artifacts

- [ ] **Step 1: 写发布模式失败门槛测试**

Assert release mode requires `DEVELOPER_ID_INSTALLER`, `DEVELOPER_ID_APPLICATION`, `NOTARY_PROFILE`, runs `productsign`, `notarytool submit --wait`, `stapler`, `pkgutil --check-signature`, and `spctl`. Assert development artifact names contain `-development` and instructions state they are unsigned.

- [ ] **Step 2: 运行测试并确认 RED**

Run: `python3 -m unittest tests.test_installation_contract.ReleaseContractTests -v`

Expected: current unsigned package flow fails the contract.

- [ ] **Step 3: 实现开发/发布双构建路径**

In release mode, fail before packaging when credentials are absent, sign executable content and pkg, notarize/staple pkg and DMG, and verify after the final repack. In development mode, skip external signing but visibly label artifacts and README output.

- [ ] **Step 4: 验证 GREEN**

Run: `python3 -m unittest tests.test_installation_contract.ReleaseContractTests -v`

Expected: static release contract passes. If credentials are available, a release smoke build passes signature and Gatekeeper verification; otherwise the command exits nonzero before producing a release artifact.

- [ ] **Step 5: 提交**

```bash
git add packaging/build_dmg.sh README.md tests/test_installation_contract.py
git commit -m "build: enforce signed notarized releases"
```

### Task 16: 全量集成、威胁复测和验收审计

**Files:**
- Create: `tests/test_full_security_integration.py`
- Modify: `README.md`
- Modify: any preceding file only when a failing acceptance test identifies a root cause

**Interfaces:**
- Consumes: all prior tasks
- Produces: evidence for every design acceptance criterion

- [ ] **Step 1: 写端到端安全集成测试**

Start an ephemeral authenticated service and cover: valid extension-style HTTP request, missing/wrong token, evil Origin with text/plain JSON, encoded absolute path, TLS key filename, authenticated WebSocket, unauthenticated WebSocket, invalid JSON response, oversized random request, valid CMS, forged CMS, real UTF-8 config load, and clean shutdown with no PIN/token in logs.

- [ ] **Step 2: 运行集成测试并确认剩余 RED**

Run: `python3 -m unittest tests.test_full_security_integration -v`

Expected: any remaining integration gap fails with a specific assertion; fix only the root cause associated with that assertion.

- [ ] **Step 3: 运行完整验证矩阵**

Run: `python3 -m unittest discover -s tests -p 'test_*.py' -v`

Run: `python3 tests/test_service.py`

Run: `env PYTHONPYCACHEPREFIX=/tmp/bjca-pyc python3 -m compileall -q bjca_service native_host packaging/copy_vendor.py`

Run: `bash -n install.sh packaging/build_dmg.sh`

Run: `node --check extensions/chrome/page_bridge.js`

Run: `node --check extensions/chrome/content_bridge.js`

Run: `node --check extensions/chrome/background.js`

Run: `python3 -m json.tool extensions/chrome/manifest.json`

Run: `plutil -lint launchd/com.bjca.certservice.plist`

Expected: every command exits 0, no unexpected warnings, no false pass/skip accounting.

- [ ] **Step 4: 逐项验收 23 项发现**

Create a local checklist mapping each finding to its test name or build command. Re-run the original reproductions for arbitrary file read, evil-Origin text/plain POST, bogus CMS acceptance, SM2 round trip, config decode, missing extension resources, package ownership, Python ABI and package signature gate.

Expected: every original reproduction now demonstrates rejection or correct behavior.

- [ ] **Step 5: 更新使用文档并提交**

Document secure mode, token lifecycle, extension installation, Native Messaging, explicit legacy mode, supported GM3000 devices, development versus release builds, and exact verification commands.

```bash
git add README.md tests/test_full_security_integration.py
git commit -m "test: verify complete security remediation"
```

## Plan Self-Review Checklist

- [x] Every design acceptance criterion maps to a task and a verification command.
- [x] No task reports success for an unsupported hardware operation.
- [x] All algorithm labels match the actual primitives used.
- [x] Secure mode remains the default in server, extension, installer and docs.
- [x] Compatibility mode is explicit and still validates Origin and input limits.
- [x] Release artifacts cannot be produced silently without required signing evidence.
