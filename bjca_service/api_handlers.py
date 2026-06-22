"""
JSON-RPC API handlers for the local certificate service.

Supported endpoints:

  HTTP:
    GET  /health           → Health check (mod_health.c)
    GET  /A/certs          → Certificate list
    GET  /A/cert.pem       → Certificate export
    POST /api/<method>     → JSON-RPC call

  WebSocket:
    wss://127.0.0.1:21061/xtxapp → Bidirectional JSON messaging

Each request has the format:
  {
    "jsonrpc": "2.0",
    "method":  "<method_name>",
    "params":  { ... },
    "id":      1
  }

Response:
  {
    "jsonrpc": "2.0",
    "result":  { ... },
    "id":      1
  }
"""

import base64
import contextvars
from datetime import datetime
import json
import logging
import secrets
from typing import Any, Callable, Dict, Optional

from .config import ServiceConfig, get_config
from .device_manager import DeviceManager, get_device_manager
from .cert_manager import CertificateManager, get_cert_manager
from .crypto_ops import (
    SM2Engine,
    SM3Hash,
    Algorithm,
    Base64Util,
    PKCS7Handler,
    hash_data,
)
from .pkcs11_bridge import PKCS11Bridge, get_bridge

logger = logging.getLogger(__name__)
_REQUEST_TOKEN = contextvars.ContextVar("request_token", default="")


class APIError(Exception):
    """API-level error with code and message."""
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


class APIHandler:
    """
    Dispatches JSON-RPC requests to the appropriate handler methods.

    The methods here correspond to the browser-facing certificate control API.
    """

    def __init__(self):
        self._dev = get_device_manager()
        self._cert = get_cert_manager()
        self._pkcs11 = get_bridge()
        self._logged_in: bool = False
        self._session_token: str = ""
        self._last_cert_id: str = ""
        self._last_pin_retries: int = -1

    # ------------------------------------------------------------------
    # Request dispatcher
    # ------------------------------------------------------------------

    async def handle_request(self, request_data: dict) -> dict:
        """
        Handle a JSON-RPC request and return the response.

        Parses the method name and dispatches to the appropriate handler.
        """
        method = request_data.get("method", "")
        params = request_data.get("params", {})
        req_id = request_data.get("id", 0)
        request_token = request_data.get("token", "")
        if not request_token and isinstance(params, dict):
            request_token = params.get("token", "")
        token_context = _REQUEST_TOKEN.set(str(request_token or ""))

        try:
            handler = self._get_handler(method)
            if handler is None:
                return self._error(req_id, -32601, f"Method not found: {method}")

            result = await handler(params)
            return {
                "jsonrpc": "2.0",
                "result": result,
                "id": req_id,
            }

        except APIError as e:
            return self._error(req_id, e.code, e.message)
        except Exception as e:
            logger.exception(f"API handler error in {method}: {e}")
            return self._error(req_id, -32603, str(e))
        finally:
            _REQUEST_TOKEN.reset(token_context)

    # ------------------------------------------------------------------
    # Health Check (mirrors mod_health.c → /health)
    # ------------------------------------------------------------------

    async def health(self, params: dict = None) -> dict:
        """Health check endpoint."""
        config = get_config()
        return {
            "status": "ok",
            "version": "1.0.0",
            "service": "BJCA Certificate Environment (macOS)",
            "timestamp": __import__("time").strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                __import__("time").gmtime(),
            ),
            "devices_connected": self._dev.get_device_count(),
            "pkcs11_available": self._pkcs11.is_available,
        }

    # ------------------------------------------------------------------
    # Device Management (mirrors XTXAppCOM device functions)
    # ------------------------------------------------------------------

    async def list_devices(self, params: dict = None) -> dict:
        """List all connected USB Key devices (mirrors GetDeviceCountEx)."""
        devices = self._dev.list_devices()
        return {
            "count": len(devices),
            "devices": devices,
        }

    async def get_device_info(self, params: dict) -> dict:
        """Get info about a specific device (mirrors GetDeviceInfo)."""
        index = params.get("index", 0)
        return self._dev.get_device_info(index)

    async def init_device(self, params: dict) -> dict:
        """Initialize a device connection (mirrors InitDevice)."""
        index = params.get("index", 0)
        pin = params.get("pin")
        success = self._dev.init_device(index, pin)
        return {"initialized": success}

    async def close_device(self, params: dict = None) -> dict:
        """Close device connection."""
        self._dev.close_device()
        return {"closed": True}

    # ------------------------------------------------------------------
    # Container Management
    # ------------------------------------------------------------------

    async def list_containers(self, params: dict = None) -> dict:
        """List key containers on the current device."""
        containers = self._dev.list_containers()
        return {
            "count": len(containers),
            "containers": [c.__dict__ for c in containers],
        }

    async def get_container_count(self, params: dict = None) -> dict:
        """Get the number of containers (mirrors GetContainerCount)."""
        index = (params or {}).get("index", 0)
        count = self._dev.get_container_count(index)
        return {"count": count}

    # ------------------------------------------------------------------
    # Certificate Management (mirrors /A/certs, /A/cert.pem)
    # ------------------------------------------------------------------

    async def list_certificates(self, params: dict = None) -> dict:
        """
        List all certificates on the device (mirrors /A/certs endpoint).
        Uses the native GM3000 driver when available.
        """
        cert_list = []
        gm = self._dev.gm3000
        if gm is not None and self._dev.gm3000_cert:
            cert_list.append(self._cert.parse_certificate(
                self._dev.gm3000_cert).to_dict())
        elif self._pkcs11.is_available and self._pkcs11._session:
            certs = self._pkcs11.list_certificates()
            cert_list = [c.to_dict() for c in certs]
        return {"count": len(cert_list), "certificates": cert_list}

    async def get_certificate(self, params: dict) -> dict:
        """Get certificate details and PEM export (mirrors /A/cert.pem)."""
        # GM3000 native path
        if self._dev.gm3000 is not None and self._dev.gm3000_cert:
            info = self._cert.parse_certificate(self._dev.gm3000_cert)
            return {"certificate": info.to_dict()}
        cert_id = params.get("cert_id", "")
        pem = self._cert.export_certificate(cert_id, format="pem")
        if pem:
            info = self._cert.parse_certificate(pem.encode("ascii"))
            return {"certificate": info.to_dict()}
        return {"error": "Certificate not found"}

    async def parse_certificate(self, params: dict) -> dict:
        """Parse a certificate from provided base64 or PEM data."""
        cert_b64 = params.get("cert_data", "") or params.get("certificate", "")
        if not cert_b64:
            raise APIError(-32602, "cert_data parameter required")

        try:
            cert_data = Base64Util.decode(cert_b64)
        except Exception:
            cert_data = cert_b64.encode("ascii")

        info = self._cert.parse_certificate(cert_data)
        return {"certificate": info.to_dict()}

    async def validate_certificate(self, params: dict) -> dict:
        """Validate a certificate."""
        cert_b64 = params.get("cert_data", "")
        if not cert_b64:
            raise APIError(-32602, "cert_data parameter required")

        try:
            cert_data = Base64Util.decode(cert_b64)
        except Exception:
            cert_data = cert_b64.encode("ascii")

        return self._cert.validate_certificate(cert_data)

    async def import_certificate(self, params: dict) -> dict:
        """
        Import a certificate to the USB Key (mirrors ImportSignCert/ImportEncCert).

        Params:
            cert_data: Base64 or PEM certificate
            cert_type: 'sign' or 'enc'
        """
        cert_b64 = params.get("cert_data", "")
        cert_type = params.get("cert_type", "sign")

        try:
            cert_data = Base64Util.decode(cert_b64)
        except Exception:
            cert_data = cert_b64.encode("ascii")

        return self._cert.import_certificate(cert_data, cert_type)

    async def import_pfx(self, params: dict) -> dict:
        """Import a PKCS#12 (.pfx) bundle (mirrors ImportPfxToDevice)."""
        pfx_b64 = params.get("pfx_data", "")
        password = params.get("password", "")
        token_pin = params.get("pin")

        try:
            pfx_data = Base64Util.decode(pfx_b64)
        except Exception:
            raise APIError(-32602, "Invalid base64 pfx_data")

        return self._cert.import_pfx(pfx_data, password, token_pin)

    # ------------------------------------------------------------------
    # Signing Operations (mirrors AnySign_SignData/SignPkcs7Data)
    # ------------------------------------------------------------------

    async def sign(self, params: dict) -> dict:
        """
        Sign data using the USB Key.

        Params:
            data: Base64-encoded data to sign
            algorithm: Signing algorithm (SM3withSM2, SHA256withRSA, etc.)
            container: Container index (optional)
            pin: Token PIN (optional)
        """
        data_b64 = params.get("data", "")
        algorithm = params.get("algorithm", Algorithm.SM3WITHSM2)
        pin = params.get("pin")

        try:
            data = Base64Util.decode(data_b64)
        except Exception:
            raise APIError(-32602, "Invalid base64 data")

        # ---- Longmai GM3000 native signing (primary path) ----
        gm = self._dev.gm3000
        if gm is None:
            # Auto-initialise: try opening GM3000 directly
            try:
                self._dev.init_device(0, pin)
                gm = self._dev.gm3000
            except Exception:
                pass
        if gm is not None:
            if not pin:
                raise APIError(-32001, "PIN is required for GM3000 signing")
            # Compute SM3 hash of data (the GM3000 expects a 32-byte digest)
            digest = SM3Hash.hash(data)
            if len(digest) != 32:
                raise APIError(-32000, "SM3 hash must be 32 bytes")
            try:
                ok, retries = gm.verify_pin(pin)
                if not ok:
                    raise APIError(-32002, f"PIN incorrect ({retries} retries left)")
                signature = gm.ecc_sign(digest)
                return {
                    "signature": Base64Util.encode(signature),
                    "algorithm": "SM3withSM2",
                    "signer": "GM3000-hardware",
                    "format": "raw",
                    "key_type": "SM2",
                }
            except Exception as e:
                logger.warning("GM3000 signing failed: %s", e)
                raise APIError(-32000, f"GM3000 signing error: {e}") from e

        # ---- PKCS#11 hardware signing (secondary path) ----
        if self._pkcs11.is_available:
            try:
                if pin:
                    self._pkcs11.login(pin)
                signature = self._pkcs11.sign(data, algorithm)
                return {
                    "signature": Base64Util.encode(signature),
                    "algorithm": algorithm,
                    "signer": "hardware",
                    "format": "raw",
                }
            except Exception as e:
                logger.warning(f"Hardware signing failed: {e}")

        if params.get("allow_software_fallback") is True:
            sig_bytes = self._software_sign(data, algorithm)
            return {
                "signature": Base64Util.encode(sig_bytes),
                "algorithm": algorithm,
                "signer": "software-test-only",
                "format": "raw",
            }

        raise APIError(
            -32000,
            "Hardware signing is not available. Insert a supported USB Key.",
        )

    async def sign_pkcs7(self, params: dict) -> dict:
        """
        Create a PKCS#7 signed-data structure (mirrors AnySign_SignPkcs7Data).

        Returns base64-encoded PKCS#7 DER.
        """
        data_b64 = params.get("data", "")
        cert_id = params.get("cert_id", "")
        pin = params.get("pin")

        try:
            data = Base64Util.decode(data_b64)
        except Exception:
            raise APIError(-32602, "Invalid base64 data")

        # Get signer certificate from token
        cert_der = self._pkcs11.get_certificate_der(cert_id)
        if not cert_der:
            raise APIError(-32000, "Signer certificate not found on token")

        # Create PKCS#7
        pkcs7_der = PKCS7Handler.create_signed_data(
            data, cert_der, b"",  # key is on token, handled by PKCS#11
        )

        return {
            "pkcs7": Base64Util.encode(pkcs7_der),
            "format": "p7s",
            "cert_id": cert_id,
        }

    async def sign_hash(self, params: dict) -> dict:
        """
        Sign a pre-computed hash (mirrors AnySign_SignHashData).
        """
        hash_b64 = params.get("hash", "")
        algorithm = params.get("algorithm", Algorithm.SM3WITHSM2)

        try:
            hash_bytes = Base64Util.decode(hash_b64)
        except Exception:
            raise APIError(-32602, "Invalid base64 hash")

        if self._pkcs11.is_available:
            signature = self._pkcs11.sign(hash_bytes, algorithm)
        else:
            raise APIError(-32000, "Signing requires PKCS#11 hardware")

        return {
            "signature": Base64Util.encode(signature),
            "algorithm": algorithm,
        }

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    async def verify(self, params: dict) -> dict:
        """Verify a signature (mirrors AnySign_VerifyTimeStamp)."""
        data_b64 = params.get("data", "")
        signature_b64 = params.get("signature", "")
        cert_b64 = params.get("cert_data", "")

        try:
            data = Base64Util.decode(data_b64)
            signature = Base64Util.decode(signature_b64)
            cert_data = Base64Util.decode(cert_b64)
        except Exception:
            raise APIError(-32602, "Invalid base64 parameter")

        valid = self._cert.verify_signature(data, signature, cert_data)
        return {"valid": valid}

    async def verify_pkcs7(self, params: dict) -> dict:
        """Verify a PKCS#7 signature."""
        pkcs7_b64 = params.get("pkcs7", "")
        try:
            pkcs7_der = Base64Util.decode(pkcs7_b64)
        except Exception:
            raise APIError(-32602, "Invalid base64 pkcs7 data")

        valid, details = PKCS7Handler.verify_signed_data(pkcs7_der)
        return {"valid": valid, "details": details}

    # ------------------------------------------------------------------
    # Hash (mirrors SM3/SHA usages)
    # ------------------------------------------------------------------

    async def hash(self, params: dict) -> dict:
        """Hash data with the specified algorithm."""
        data_b64 = params.get("data", "")
        algorithm = params.get("algorithm", Algorithm.SHA256)

        try:
            data = Base64Util.decode(data_b64)
        except Exception:
            raise APIError(-32602, "Invalid base64 data")

        digest = hash_data(data, algorithm)
        return {
            "hash": digest.hex(),
            "hash_base64": Base64Util.encode(digest),
            "algorithm": algorithm,
            "size": len(digest),
        }

    async def sm3_hash(self, params: dict) -> dict:
        """Compute SM3 hash (Chinese national standard)."""
        data_b64 = params.get("data", "")
        try:
            data = Base64Util.decode(data_b64)
        except Exception:
            raise APIError(-32602, "Invalid base64 data")

        digest = SM3Hash.hash(data)
        return {
            "hash": digest.hex(),
            "hash_base64": Base64Util.encode(digest),
            "algorithm": "SM3",
            "size": len(digest),
        }

    # ------------------------------------------------------------------
    # Certificate Request (PKCS#10 / CSR)
    # ------------------------------------------------------------------

    async def generate_csr(self, params: dict) -> dict:
        """
        Generate a PKCS#10 CSR for a new certificate (mirrors ExportPKCS10).

        Params:
            subject_cn: Common Name for the certificate
            algorithm: Key algorithm (SM2 or RSA)
        """
        from .crypto_ops import PKCS10Handler, SM2Engine, KeyPair

        subject_cn = params.get("subject_cn", "BJCA User")
        algorithm = params.get("algorithm", Algorithm.SM2)

        if algorithm == Algorithm.SM2:
            kp = SM2Engine.generate_key_pair()
        else:
            raise APIError(-32602, f"Unsupported algorithm: {algorithm}")

        csr_der = PKCS10Handler.generate_csr(subject_cn, kp, algorithm)
        return {
            "csr": Base64Util.encode(csr_der),
            "format": "p10",
            "algorithm": algorithm,
            "public_key": Base64Util.encode(kp.public_key),
            "private_key": Base64Util.encode(kp.private_key),
            "warning": "Store the private_key securely!",
        }

    # ------------------------------------------------------------------
    # PIN Management
    # ------------------------------------------------------------------

    async def change_pin(self, params: dict) -> dict:
        """
        Change the device PIN (mirrors ChangeAdminPass in XTXAppCOM).

        Params:
            old_pin: Current PIN
            new_pin: New PIN
        """
        old_pin = params.get("old_pin", "")
        new_pin = params.get("new_pin", "")

        if not new_pin or len(new_pin) < 6:
            raise APIError(-32602, "PIN must be at least 6 characters")

        # This would need PKCS#11 C_SetPIN or APDU-based PIN change
        # For now, return guidance
        return {
            "success": False,
            "message": "PIN change requires hardware-level support. "
                       "Use the device manufacturer's tool or macOS Keychain.",
        }

    # ------------------------------------------------------------------
    # Electronic Seal Operations
    # ------------------------------------------------------------------

    async def list_seals(self, params: dict = None) -> dict:
        """List electronic seals on the device (mirrors EnumESeal)."""
        seals = self._dev.enum_eseal()
        return {
            "count": len(seals),
            "seals": [
                {
                    "seal_id": s.seal_id,
                    "seal_name": s.seal_name,
                }
                for s in seals
            ],
        }

    async def get_seal_image(self, params: dict) -> dict:
        """Get a seal image from the device (mirrors GetPicture)."""
        seal_id = params.get("seal_id", "")
        image = self._dev.get_picture(seal_id)

        if image:
            return {
                "image": Base64Util.encode(image),
                "size": len(image),
            }
        return {"error": "Seal image not found"}

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    async def get_config(self, params: dict = None) -> dict:
        """Get the current service configuration."""
        config = get_config()
        return {
            "listen_host": config.listen_host,
            "listen_port": config.listen_port,
            "update_server": config.update_server_url_1,
            "help_address": config.help_address,
            "driver_types": config.driver_types,
            "use_css": config.use_css,
            "bjca_root": config.bjca_root,
        }

    # ------------------------------------------------------------------
    # Base64 Utility (mirrors Base64EncodeFile)
    # ------------------------------------------------------------------

    async def base64_encode(self, params: dict) -> dict:
        """Base64 encode data."""
        data_b64 = params.get("data", "")
        try:
            data = data_b64.encode("ascii")
        except Exception:
            data = data_b64
        return {"encoded": Base64Util.encode(data) if isinstance(data, bytes)
                else Base64Util.encode(data.encode())}

    # ------------------------------------------------------------------
    # SOF Layer (mirrors BJCA SOF_* functions)
    # ------------------------------------------------------------------

    async def sof_get_user_list(self, params: dict = None) -> dict:
        """SOF_GetUserList — return certificate list in BJCA xtxasyn format."""
        cert_info = self._current_cert_info()
        if cert_info is None or not self._dev.gm3000_cert:
            return {"retVal": "", "userlist": []}

        cert_id = self._cert_id(cert_info)
        cert_b64 = self._cert_b64()
        # xtxasyn.js parses "certName||certID&&&" from retVal. The trailing
        # slash is accepted by supported pages and mirrors BJCA soft/hard split.
        ret_val = f"{cert_info.subject}||{cert_id}&&&/"
        self._last_cert_id = cert_id
        return {
            "retVal": ret_val,
            "retValue": ret_val,
            "userlist": [{
                "certDN": cert_info.subject,
                "certSN": cert_info.serial_number,
                "userName": cert_info.subject,
                "certNotAfter": cert_info.not_after,
                "certNotBefore": cert_info.not_before,
                "containerName": "personalCert00",
                "keyType": "SM2",
                "certData": cert_b64,
                "signAlg": "SM3withSM2",
            }],
        }

    async def sof_export_user_cert(self, params: dict = None) -> dict:
        """SOF_ExportUserCert — export the current signing certificate."""
        if self._current_cert_info() is None:
            return {"retVal": ""}
        return {"retVal": self._cert_b64(), "retValue": self._cert_b64()}

    async def sof_get_cert_info(self, params: dict = None) -> dict:
        """SOF_GetCertInfo — return common certificate fields used by xtxasyn."""
        cert_text = self._param(params, 0, "Cert", "")
        info_type = int(self._param(params, 1, "type", -1) or -1)

        cert_info = None
        if cert_text:
            try:
                cert_info = self._cert.parse_certificate(Base64Util.decode(cert_text))
            except Exception:
                pass
        cert_info = cert_info or self._current_cert_info()
        if cert_info is None:
            return {"retVal": ""}

        values = {
            2: cert_info.serial_number,
            11: self._sof_time(cert_info.not_before),
            12: self._sof_time(cert_info.not_after),
        }
        ret_val = values.get(info_type, cert_info.subject)
        return {"retVal": ret_val, "retValue": ret_val}

    async def sof_login(self, params: dict = None) -> dict:
        """SOF_Login/SOF_LoginEx — verify token PIN and cache login state."""
        cert_id = str(self._param(params, 0, "CertID", "") or "")
        pin = str(self._param(params, 1, "PassWd", "") or "")
        gm = self._dev.gm3000
        if gm is None:
            self._dev.init_device(0)
            gm = self._dev.gm3000
        if gm is None or not pin:
            self._last_pin_retries = -1
            return {"retVal": False, "retValue": False}
        try:
            ok, retries = gm.verify_pin(pin)
        except Exception as e:
            logger.warning("SOF_Login PIN verification failed: %s", e)
            ok, retries = False, -1
        self._last_pin_retries = retries
        if ok:
            self._logged_in = True
            self._session_token = secrets.token_hex(16)
            self._last_cert_id = cert_id or self._last_cert_id
            return {
                "retVal": True,
                "retValue": True,
                "token": self._session_token,
            }
        self._logged_in = False
        self._session_token = ""
        return {"retVal": False, "retValue": False}

    async def sof_logout(self, params: dict = None) -> dict:
        """SOF_Logout — clear cached login state."""
        self._logged_in = False
        self._session_token = ""
        return {"retVal": True, "retValue": True}

    async def sof_is_login(self, params: dict = None) -> dict:
        """SOF_IsLogin — report whether a PIN was verified in this session."""
        return {"retVal": self._logged_in, "retValue": self._logged_in}

    async def sof_get_pin_retry_count(self, params: dict = None) -> dict:
        """SOF_GetPinRetryCount — return the last known retry count."""
        ret_val = self._last_pin_retries if self._last_pin_retries >= 0 else 9
        return {"retVal": ret_val, "retValue": ret_val}

    async def sof_sign_data(self, params: dict = None) -> dict:
        """SOF_SignData/SignedData — sign text and return raw SM2 signature."""
        data = self._param(params, 1, "InData", "")
        pin = str(self._param(params, 3, "PassWd", "") or "")
        ret_val = self._sign_sof_text(str(data or ""), pin)
        return {"retVal": ret_val, "retValue": ret_val}

    async def sof_sign_message(self, params: dict = None) -> dict:
        """SOF_SignMessage — return PKCS#7/CMS signed message data."""
        data = self._param(params, 2, "InData", "")
        try:
            flag = int(self._param(params, 0, "dwFlag", 0) or 0)
        except (TypeError, ValueError):
            flag = 0
        pin = str(self._param(params, 3, "PassWd", "") or "")
        ret_val = self._sign_sof_message(str(data or ""), detached=bool(flag), pin=pin)
        return {"retVal": ret_val, "retValue": ret_val}

    async def sof_gen_random(self, params: dict = None) -> dict:
        """SOF_GenRandom — generate random hex text."""
        length = int(self._param(params, 0, "RandomLen", 16) or 16)
        ret_val = secrets.token_hex(max(1, length))
        return {"retVal": ret_val, "retValue": ret_val}

    async def sof_base64_encode(self, params: dict = None) -> dict:
        """SOF_Base64Encode — encode text as Base64."""
        data = str(self._param(params, 0, "sIndata", "") or "")
        ret_val = base64.b64encode(data.encode("utf-8")).decode("ascii")
        return {"retVal": ret_val, "retValue": ret_val}

    async def sof_base64_decode(self, params: dict = None) -> dict:
        """SOF_Base64Decode — decode Base64 text."""
        data = str(self._param(params, 0, "sIndata", "") or "")
        try:
            ret_val = base64.b64decode(data).decode("utf-8")
        except Exception:
            ret_val = ""
        return {"retVal": ret_val, "retValue": ret_val}

    async def sof_get_all_device_sn(self, params: dict = None) -> dict:
        """GetAllDeviceSN — return comma-terminated SN list as XTXAppCOM does."""
        sn = self._device_sn()
        ret_val = f"{sn}," if sn else ""
        return {"retVal": ret_val, "retValue": ret_val}

    async def sof_get_device_count(self, params: dict = None) -> dict:
        """GetDeviceCount/GetDeviceCountEx."""
        ret_val = self._dev.get_device_count()
        return {"retVal": ret_val, "retValue": ret_val}

    async def sof_get_device_sn_by_index(self, params: dict = None) -> dict:
        """GetDeviceSNByIndex."""
        ret_val = self._device_sn() if int(self._param(params, 0, "iIndex", 0) or 0) == 0 else ""
        return {"retVal": ret_val, "retValue": ret_val}

    async def sof_get_device_info(self, params: dict = None) -> dict:
        """GetDeviceInfo — type 7 is device kind; supported pages expect HARD."""
        info_type = int(self._param(params, 1, "iType", 0) or 0)
        if info_type == 7:
            ret_val = "HARD" if self._device_sn() else ""
        else:
            ret_val = self._device_sn()
        return {"retVal": ret_val, "retValue": ret_val}

    async def sof_set_env_sn(self, params: dict = None) -> dict:
        """SetENVSN — select container/environment; GM3000 has one active container."""
        return {"retVal": True, "retValue": True}

    async def sof_is_device_exist(self, params: dict = None) -> dict:
        """IsDeviceExist."""
        ret_val = bool(self._device_sn())
        return {"retVal": ret_val, "retValue": ret_val}

    async def sof_get_container_count(self, params: dict = None) -> dict:
        """GetContainerCount."""
        ret_val = 1 if self._device_sn() else 0
        return {"retVal": ret_val, "retValue": ret_val}

    async def sof_get_version(self, params: dict = None) -> dict:
        """SOF_GetVersion/SOF_GetProductVersion."""
        return {"retVal": "BJCA-macOS-1.0.0", "retValue": "BJCA-macOS-1.0.0"}

    async def sof_get_last_error(self, params: dict = None) -> dict:
        """SOF_GetLastError/SOF_GetLastErrMsg."""
        return {"retVal": 0, "retValue": 0}

    # ------------------------------------------------------------------
    # Method dispatch
    # ------------------------------------------------------------------

    _METHOD_MAP: Dict[str, str] = {
        # Device
        "list_devices": "list_devices",
        "get_device_info": "get_device_info",
        "init_device": "init_device",
        "close_device": "close_device",
        # Container
        "list_containers": "list_containers",
        "get_container_count": "get_container_count",
        # Certificate
        "list_certificates": "list_certificates",
        "get_certificate": "get_certificate",
        "parse_certificate": "parse_certificate",
        "validate_certificate": "validate_certificate",
        "import_certificate": "import_certificate",
        "import_pfx": "import_pfx",
        "generate_csr": "generate_csr",
        # Sign
        "sign": "sign",
        "sign_pkcs7": "sign_pkcs7",
        "sign_hash": "sign_hash",
        # Verify
        "verify": "verify",
        "verify_pkcs7": "verify_pkcs7",
        # Hash
        "hash": "hash",
        "sm3_hash": "sm3_hash",
        # PIN
        "change_pin": "change_pin",
        # Seal
        "list_seals": "list_seals",
        "get_seal_image": "get_seal_image",
        # Config
        "get_config": "get_config",
        # Health
        "health": "health",
        # Utility
        "base64_encode": "base64_encode",
        # SOF layer
        "SOF_GetUserList": "sof_get_user_list",
        "GetUserList": "sof_get_user_list",
        "SOF_ExportUserCert": "sof_export_user_cert",
        "GetSignCert": "sof_export_user_cert",
        "SOF_GetCertInfo": "sof_get_cert_info",
        "GetCertBasicinfo": "sof_get_cert_info",
        "SOF_Login": "sof_login",
        "SOF_LoginEx": "sof_login",
        "VerifyUserPIN": "sof_login",
        "SOF_Logout": "sof_logout",
        "SOF_IsLogin": "sof_is_login",
        "SOF_GetPinRetryCount": "sof_get_pin_retry_count",
        "GetUserPINRetryCount": "sof_get_pin_retry_count",
        "SOF_SignMessage": "sof_sign_message",
        "SOF_SignData": "sof_sign_data",
        "SignedData": "sof_sign_data",
        "SOF_GenRandom": "sof_gen_random",
        "GenerateRandom": "sof_gen_random",
        "SOF_Base64Encode": "sof_base64_encode",
        "SOF_Base64Decode": "sof_base64_decode",
        "GetAllDeviceSN": "sof_get_all_device_sn",
        "GetDeviceCount": "sof_get_device_count",
        "GetDeviceCountEx": "sof_get_device_count",
        "GetDeviceSNByIndex": "sof_get_device_sn_by_index",
        "GetDeviceInfo": "sof_get_device_info",
        "SetENVSN": "sof_set_env_sn",
        "IsDeviceExist": "sof_is_device_exist",
        "GetContainerCount": "sof_get_container_count",
        "SOF_GetVersion": "sof_get_version",
        "SOF_GetProductVersion": "sof_get_version",
        "SOF_GetLastError": "sof_get_last_error",
        "SOF_GetLastErrMsg": "sof_get_last_error",
    }

    def _get_handler(self, method: str):
        """Get the async handler method for a given API method name."""
        method_name = self._METHOD_MAP.get(method)
        if method_name is None:
            return None
        return getattr(self, method_name, None)

    def _software_sign(self, data: bytes, algorithm: str) -> bytes:
        """Software-based signing fallback (uses gmssl)."""
        if "SM2" in algorithm or "SM3" in algorithm:
            # SM2 software sign
            from .crypto_ops import SM2Engine
            eng = SM2Engine()
            kp = SM2Engine.generate_key_pair()
            eng = SM2Engine(
                private_key_hex=kp.private_key.hex(),
                public_key_hex=kp.public_key.hex(),
            )
            return eng.sign(data)

        # For RSA, use cryptography library
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.backends import default_backend

        key = rsa.generate_private_key(65537, 2048, default_backend())
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    @staticmethod
    def _param(params: Any, index: int, name: str, default: Any = None) -> Any:
        """Read xtxasyn list params or JSON-RPC dict params."""
        if isinstance(params, (list, tuple)):
            return params[index] if index < len(params) else default
        if isinstance(params, dict):
            if name in params:
                return params[name]
            legacy = f"param_{index + 1}"
            if legacy in params:
                return params[legacy]
        return default

    def _current_cert_info(self):
        """Initialise GM3000 if needed and return parsed signing certificate."""
        gm = self._dev.gm3000
        if gm is None:
            ok = self._dev.init_device(0)
            if not ok:
                try:
                    ok = self._dev._init_gm3000(None)
                except Exception as e:
                    logger.debug("Direct GM3000 initialisation failed: %s", e)
                    ok = False
            gm = self._dev.gm3000
        if gm is None or not self._dev.gm3000_cert:
            return None
        return self._cert.parse_certificate(self._dev.gm3000_cert)

    def _cert_id(self, cert_info) -> str:
        return cert_info.serial_number if cert_info else self._last_cert_id

    def _cert_b64(self) -> str:
        return base64.b64encode(self._dev.gm3000_cert or b"").decode("ascii")

    def _device_sn(self) -> str:
        devices = self._dev.list_devices()
        for device in devices:
            sn = device.get("device_sn") or device.get("serial_number")
            if sn:
                return sn
        return ""

    def _token_valid(self) -> bool:
        token = _REQUEST_TOKEN.get()
        return bool(
            self._logged_in
            and self._session_token
            and token
            and secrets.compare_digest(token, self._session_token)
        )

    @staticmethod
    def _sof_time(value: str) -> str:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt.strftime("%Y%m%d%H%M%S")
        except Exception:
            return ""

    def _sign_sof_text(self, text: str, pin: str = "") -> str:
        if not self._token_valid():
            logger.warning("SOF signing requested before successful login")
            return ""
        gm = self._dev.gm3000
        if gm is None and pin:
            self._dev.init_device(0, pin)
            gm = self._dev.gm3000
        if gm is None:
            return ""
        try:
            if pin:
                ok, retries = gm.verify_pin(pin)
                self._last_pin_retries = retries
                if not ok:
                    self._logged_in = False
                    return ""
            data = text.encode("utf-8")
            digest = self._sm2_message_digest(data, self._dev.gm3000_cert)
            signature = gm.ecc_sign(digest)
            return Base64Util.encode(signature)
        except Exception as e:
            logger.warning("SOF signing failed: %s", e)
            return ""

    def _sign_sof_message(self, text: str, detached: bool = False, pin: str = "") -> str:
        """Create a BJCA-compatible PKCS#7/CMS SignedData value."""
        if not self._token_valid():
            logger.warning("SOF signing requested before successful login")
            return ""
        gm = self._dev.gm3000
        if gm is None and pin:
            self._dev.init_device(0, pin)
            gm = self._dev.gm3000
        if gm is None or not self._dev.gm3000_cert:
            return ""

        try:
            if pin:
                ok, retries = gm.verify_pin(pin)
                self._last_pin_retries = retries
                if not ok:
                    self._logged_in = False
                    return ""

            content = text.encode("utf-8")
            digest = self._sm2_message_digest(content, self._dev.gm3000_cert)
            raw_signature = gm.ecc_sign(digest)
            signature = self._sm2_signature_der(raw_signature)
            cms_der = self._build_sm2_cms_signed_data(
                content=content,
                signer_cert_der=self._dev.gm3000_cert,
                signature_der=signature,
                detached=detached,
            )
            return Base64Util.encode(cms_der)
        except Exception as e:
            logger.warning("SOF PKCS#7 signing failed: %s", e)
            return ""

    @staticmethod
    def _sm2_message_digest(
        content: bytes,
        signer_cert_der: Optional[bytes],
        user_id: bytes = b"1234567812345678",
    ) -> bytes:
        """
        Compute the SM2 signing digest e = SM3(ZA || M).

        GM3000's SKF_ECCSignData APDU signs a 32-byte digest. For certificate
        verification, SM2 requires the ZA prefix derived from the signer public
        key and the default user ID.
        """
        if not signer_cert_der:
            return SM3Hash.hash(content)

        try:
            px, py = APIHandler._sm2_public_key_xy(signer_cert_der)
            entl = (len(user_id) * 8).to_bytes(2, "big")
            ecc = {
                "a": bytes.fromhex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"),
                "b": bytes.fromhex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"),
                "gx": bytes.fromhex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"),
                "gy": bytes.fromhex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"),
            }
            za = SM3Hash.hash(
                entl + user_id + ecc["a"] + ecc["b"] + ecc["gx"] + ecc["gy"] + px + py
            )
            return SM3Hash.hash(za + content)
        except Exception as e:
            logger.warning("SM2 ZA digest failed, falling back to SM3(data): %s", e)
            return SM3Hash.hash(content)

    @staticmethod
    def _sm2_public_key_xy(cert_der: bytes) -> tuple[bytes, bytes]:
        """Extract the uncompressed SM2 public key coordinates from a cert."""
        from asn1crypto import x509

        cert = x509.Certificate.load(cert_der)
        spki = cert["tbs_certificate"]["subject_public_key_info"]
        public_key = bytes(spki["public_key"].contents)
        if public_key and public_key[0] == 0x00:
            public_key = public_key[1:]
        if len(public_key) == 65 and public_key[0] == 0x04:
            public_key = public_key[1:]
        if len(public_key) != 64:
            raise ValueError(f"Unexpected SM2 public key length: {len(public_key)}")
        return public_key[:32], public_key[32:]

    @staticmethod
    def _sm2_signature_der(raw_signature: bytes) -> bytes:
        """Convert GM3000 64-byte r||s signature to ASN.1 ECDSA-Sig-Value."""
        if len(raw_signature) != 64:
            return raw_signature

        from asn1crypto import core

        r = int.from_bytes(raw_signature[:32], "big")
        s = int.from_bytes(raw_signature[32:], "big")
        return core.SequenceOf(spec=core.Integer, value=[r, s]).dump()

    @staticmethod
    def _build_sm2_cms_signed_data(
        content: bytes,
        signer_cert_der: bytes,
        signature_der: bytes,
        detached: bool = False,
    ) -> bytes:
        """Build a minimal CMS SignedData object for SM3withSM2."""
        from asn1crypto import algos, cms, x509

        cert = x509.Certificate.load(signer_cert_der)
        digest_algorithm = algos.DigestAlgorithm({
            "algorithm": "1.2.156.10197.1.401",  # SM3
        })
        signature_algorithm = algos.SignedDigestAlgorithm({
            "algorithm": "1.2.156.10197.1.501",  # SM3withSM2
        })

        encap_content_info = {"content_type": "data"}
        if not detached:
            encap_content_info["content"] = content

        signed_data = cms.SignedData({
            "version": "v1",
            "digest_algorithms": [digest_algorithm],
            "encap_content_info": encap_content_info,
            "certificates": [cert],
            "signer_infos": [{
                "version": "v1",
                "sid": {
                    "issuer_and_serial_number": {
                        "issuer": cert.issuer,
                        "serial_number": cert.serial_number,
                    },
                },
                "digest_algorithm": digest_algorithm,
                "signature_algorithm": signature_algorithm,
                "signature": signature_der,
            }],
        })
        return cms.ContentInfo({
            "content_type": "signed_data",
            "content": signed_data,
        }).dump()

    @staticmethod
    def _error(req_id: Any, code: int, message: str) -> dict:
        """Create a JSON-RPC error response."""
        return {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": req_id,
        }


# ---------------------------------------------------------------------------
# Global API handler instance
# ---------------------------------------------------------------------------

_handler: Optional[APIHandler] = None


def get_handler() -> APIHandler:
    global _handler
    if _handler is None:
        _handler = APIHandler()
    return _handler
