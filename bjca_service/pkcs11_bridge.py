"""
PKCS#11 bridge for hardware-token access.

On macOS, this interfaces with:
  1. python-pkcs11 for hardware token access via PKCS#11
  2. macOS CryptoTokenKit framework (via PyObjC) for native smart card integration
  3. Fallback to pyscard raw APDU commands

PKCS#11 libraries for common USB Keys on macOS:
  - Feitian ePass:  libeTPKCS11.dylib
  - WatchData:      libwdpkcs11.dylib
  - OpenSC (generic): /usr/local/lib/opensc-pkcs11.so
  - BJCA bundle:    /Library/BJCA/lib/libbjcapkcs11.dylib
"""

import ctypes
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Try python-pkcs11 first (preferred), fall back to ctypes
# ---------------------------------------------------------------------------
try:
    import pkcs11 as _pkcs11_lib
    HAS_PKCS11 = True
except ImportError:
    _pkcs11_lib = None
    HAS_PKCS11 = False
    logger.warning(
        "python-pkcs11 not installed. PKCS#11 functions limited. "
        "Install with: pip install python-pkcs11"
    )

# macOS CryptoTokenKit bridge (native, no separate driver needed)
try:
    import Cocoa
    from CryptoTokenKit import (
        TKSmartCardSlotManager,
        TKSmartCard,
        TKSmartCardSlotState,
    )
    HAS_CTK = True
except ImportError:
    HAS_CTK = False
    logger.debug("CryptoTokenKit (PyObjC) not available")


# ---------------------------------------------------------------------------
# PKCS#11 library discovery
# ---------------------------------------------------------------------------

KNOWN_PKCS11_MODULES = [
    # BJCA bundled
    "/Library/BJCA/lib/libbjcapkcs11.dylib",
    "/Library/BJCA/lib/libeTPKCS11.dylib",
    # Feitian ePass
    "/usr/local/lib/libeTPKCS11.dylib",
    "/opt/homebrew/lib/libeTPKCS11.dylib",
    "/Applications/Feitian/ePassManager.app/Contents/MacOS/libeTPKCS11.dylib",
    # WatchData
    "/usr/local/lib/libwdpkcs11.dylib",
    # OpenSC (generic PKCS#11 provider for CCID/PIV/OpenPGP/supported tokens)
    "/opt/homebrew/lib/opensc-pkcs11.so",
    "/opt/homebrew/lib/pkcs11/opensc-pkcs11.so",
    "/usr/local/lib/opensc-pkcs11.so",
    "/Library/OpenSC/lib/opensc-pkcs11.so",
    # SmartcardServices
    "/usr/local/lib/pkcs11-tokend.so",
    # Default system search paths
    "libeTPKCS11.dylib",
    "libopensc-pkcs11.so",
]


def find_pkcs11_module() -> Optional[str]:
    """Auto-discover an available PKCS#11 module for the connected USB Key."""
    for path in KNOWN_PKCS11_MODULES:
        if os.path.isfile(path):
            logger.info(f"Found PKCS#11 module: {path}")
            return path
        if not path.startswith("/"):
            # Search in standard library paths
            for prefix in ["/usr/local/lib", "/opt/homebrew/lib", "/usr/lib"]:
                full = os.path.join(prefix, path)
                if os.path.isfile(full):
                    return full
    return None


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SlotInfo:
    """Information about a PKCS#11 slot."""
    slot_id: int
    label: str = ""
    manufacturer: str = ""
    token_present: bool = False
    token_label: str = ""
    token_serial: str = ""
    hardware_version: str = ""
    firmware_version: str = ""

    def to_dict(self) -> dict:
        return {
            "slot_id": self.slot_id,
            "slot_label": self.label,
            "manufacturer": self.manufacturer,
            "token_present": self.token_present,
            "token_label": self.token_label,
            "token_serial": self.token_serial,
            "hardware_version": self.hardware_version,
            "firmware_version": self.firmware_version,
        }


@dataclass
class CertificateInfo:
    """Information about a certificate found on a PKCS#11 token."""
    label: str
    cert_id: str = ""
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    key_type: str = ""       # RSA, EC, etc.
    key_size: int = 0
    has_private_key: bool = False
    is_encryption_cert: bool = False
    is_signature_cert: bool = False

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "cert_id": self.cert_id,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "key_type": self.key_type,
            "key_size": self.key_size,
            "has_private_key": self.has_private_key,
            "is_encryption_cert": self.is_encryption_cert,
            "is_signature_cert": self.is_signature_cert,
        }


# ---------------------------------------------------------------------------
# PKCS#11 bridge class
# ---------------------------------------------------------------------------

class PKCS11Error(Exception):
    """Error from PKCS#11 operations."""
    pass


class PKCS11Bridge:
    """
    Provides PKCS#11 access to hardware tokens.

    Provides token slot, certificate, and signing access through PKCS#11.
    """

    def __init__(self, module_path: Optional[str] = None):
        self._module_path = module_path or find_pkcs11_module()
        self._token = None
        self._session = None
        self._lib = None

        if self._module_path and HAS_PKCS11:
            try:
                self._lib = _pkcs11_lib.lib(self._module_path)
                logger.info(f"Loaded PKCS#11: {self._module_path}")
            except Exception as e:
                logger.warning(f"Failed to load PKCS#11 module: {e}")
                self._lib = None
        elif not HAS_PKCS11:
            logger.debug("python-pkcs11 not installed — PKCS#11 unavailable")
        elif not self._module_path:
            logger.debug("No PKCS#11 module found — PKCS#11 unavailable")

    @property
    def is_available(self) -> bool:
        return self._lib is not None

    # ---- Slot / Token Management ----

    def get_slots(self, token_present: bool = True) -> List[SlotInfo]:
        """Get all available PKCS#11 slots (mirrors slot enumeration in NSS)."""
        if not self._lib:
            return []

        slots = []
        try:
            for slot in self._lib.get_slots(token_present=token_present):
                info = SlotInfo(
                    slot_id=slot.slot_id,
                    label=slot.label or "",
                    manufacturer=slot.manufacturer or "",
                    token_present=slot.token_present,
                )
                if slot.token_present:
                    token = slot.get_token()
                    info.token_label = token.label or ""
                    info.token_serial = token.serial.hex() if token.serial else ""
                    info.hardware_version = (
                        f"{token.hardware_version[0]}.{token.hardware_version[1]}"
                    )
                    info.firmware_version = (
                        f"{token.firmware_version[0]}.{token.firmware_version[1]}"
                    )
                slots.append(info)
        except Exception as e:
            logger.error(f"Failed to enumerate slots: {e}")

        return slots

    def get_slot_count(self) -> int:
        """Get the number of available slots with tokens."""
        return len(self.get_slots(token_present=True))

    # ---- Session Management ----

    def open_session(self, slot_id: int = 0, pin: Optional[str] = None) -> bool:
        """
        Open a PKCS#11 session to a token.

        Returns True if session opened successfully.
        """
        if not self._lib:
            raise PKCS11Error("No PKCS#11 module loaded")

        try:
            slots = self._lib.get_slots(token_present=True)
            if slot_id >= len(slots):
                raise PKCS11Error(
                    f"Slot {slot_id} not available "
                    f"({len(slots)} slot(s) with tokens)"
                )

            token = slots[slot_id].get_token()
            self._session = token.open(
                rw=True if pin else False,
                user_pin=pin
            )
            logger.info(f"Opened session on slot {slot_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to open session: {e}")
            self._session = None
            return False

    def close_session(self) -> None:
        """Close the current session."""
        if self._session:
            try:
                self._session.close()
            except Exception:
                pass
            self._session = None

    def login(self, pin: str) -> bool:
        """Log in to the token with PIN (mirrors PIN verification)."""
        if not self._session:
            raise PKCS11Error("No active session")
        try:
            self._session.login(pin)
            return True
        except Exception as e:
            logger.error(f"Login failed: {e}")
            return False

    def logout(self) -> None:
        """Log out from the token."""
        if self._session:
            try:
                self._session.logout()
            except Exception:
                pass

    # ---- Certificate Operations ----

    def list_certificates(self) -> List[CertificateInfo]:
        """
        List all certificates on the token (mirrors certificate enumeration).

        This corresponds to the certificate listing endpoint.
        """
        if not self._session:
            raise PKCS11Error("No active session")

        certs = []
        try:
            from pkcs11.constants import ObjectClass, CertificateType

            for obj in self._session.get_objects({
                ObjectClass: ObjectClass.CERTIFICATE,
            }):
                cert_info = CertificateInfo(
                    label=obj.label or "",
                    cert_id=obj.id.hex() if obj.id else "",
                )

                # Extract certificate fields
                try:
                    cert_type = obj.certificate_type
                    if cert_type == CertificateType.X_509:
                        der = obj.value  # DER-encoded X.509 cert
                        cert_info = self._parse_x509_der(cert_info, der)
                except Exception:
                    pass

                # Check for corresponding private key
                try:
                    key_id = obj.id
                    if key_id:
                        keys = list(self._session.get_objects({
                            ObjectClass: ObjectClass.PRIVATE_KEY,
                            _pkcs11_lib.Attribute('ID'): key_id,
                        }))
                        cert_info.has_private_key = len(keys) > 0
                except Exception:
                    pass

                certs.append(cert_info)

        except Exception as e:
            logger.error(f"Failed to list certificates: {e}")

        return certs

    def get_certificate_der(self, cert_id: str) -> Optional[bytes]:
        """Export a certificate as DER bytes."""
        if not self._session:
            raise PKCS11Error("No active session")

        try:
            from pkcs11.constants import ObjectClass
            cid = bytes.fromhex(cert_id) if cert_id else None
            for obj in self._session.get_objects({
                ObjectClass: ObjectClass.CERTIFICATE,
            }):
                if obj.id == cid or not cid:
                    return obj.value
        except Exception as e:
            logger.error(f"Failed to get certificate: {e}")
        return None

    # ---- Private Key Operations ----

    def sign(self, data: bytes, mechanism: str = "SM3withSM2",
             key_label: Optional[str] = None) -> bytes:
        """
        Sign data using a private key on the token.

        Args:
            data: The data to sign (or hash, depending on mechanism)
            mechanism: Signing mechanism (SM3withSM2, SHA256withRSA, etc.)
            key_label: Specific key label to use (uses first available if None)

        Returns:
            The signature bytes.
        """
        if not self._session:
            raise PKCS11Error("No active session")

        try:
            from pkcs11.constants import ObjectClass, Mechanism

            # Find signing key
            priv_key = self._find_private_key(key_label)
            if not priv_key:
                raise PKCS11Error("No signing key found on token")

            # Map mechanism string to PKCS#11 mechanism
            mech = self._map_mechanism(mechanism)

            # Sign
            signature = priv_key.sign(data, mechanism=mech)
            return signature

        except Exception as e:
            raise PKCS11Error(f"Signing failed: {e}") from e

    # ---- Internal Helpers ----

    def _find_private_key(self, label: Optional[str] = None):
        """Find a private key object on the token."""
        from pkcs11.constants import ObjectClass, KeyType

        search = {ObjectClass: ObjectClass.PRIVATE_KEY}
        if label:
            search[_pkcs11_lib.Attribute('LABEL')] = label

        keys = list(self._session.get_objects(search))
        if not keys:
            return None

        # Prefer EC keys (SM2) over RSA
        for key in keys:
            try:
                if key.key_type == KeyType.EC:
                    return key
            except Exception:
                pass

        return keys[0]

    @staticmethod
    def _map_mechanism(name: str):
        """Map algorithm name to PKCS#11 Mechanism."""
        from pkcs11 import Mechanism
        from pkcs11.constants import MechanismType as MT

        MECH_MAP = {
            "SM3withSM2":      MT.ECDSA_SHA256,  # Closest PKCS#11 match
            "SHA1withSM2":     MT.ECDSA_SHA1,
            "SHA256withSM2":   MT.ECDSA_SHA256,
            "SM2":             MT.ECDSA,
            "SHA1withRSA":     MT.SHA1_RSA_PKCS,
            "SHA256withRSA":   MT.SHA256_RSA_PKCS,
            "RSA_PKCS1":       MT.RSA_PKCS,
            "SHA1":            MT.SHA_1,
            "SHA256":          MT.SHA256,
            "SM3":             MT.SHA256,         # Closest PKCS#11 match for SM3
        }
        mt = MECH_MAP.get(name, MT.ECDSA_SHA256)
        return Mechanism(mt)

    @staticmethod
    def _parse_x509_der(info: CertificateInfo, der: bytes) -> CertificateInfo:
        """Parse X.509 DER certificate to extract metadata."""
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization

            cert = x509.load_der_x509_certificate(der)
            info.subject = ", ".join(
                f"{a.oid._name}={a.value}" for a in cert.subject
            )[:200]
            info.issuer = ", ".join(
                f"{a.oid._name}={a.value}" for a in cert.issuer
            )[:200]
            info.serial_number = format(cert.serial_number, 'X')
            info.not_before = cert.not_valid_before.isoformat()
            info.not_after = cert.not_valid_after.isoformat()

            # Key info
            pub_key = cert.public_key()
            from cryptography.hazmat.primitives.asymmetric import ec, rsa
            if isinstance(pub_key, ec.EllipticCurvePublicKey):
                info.key_type = f"EC-{pub_key.curve.name}"
                info.key_size = pub_key.key_size
            elif isinstance(pub_key, rsa.RSAPublicKey):
                info.key_type = "RSA"
                info.key_size = pub_key.key_size

            # Certificate purpose
            try:
                eku = cert.extensions.get_extension_for_class(
                    x509.ExtendedKeyUsage
                )
                info.is_signature_cert = (
                    x509.oid.ExtendedKeyUsageOID.CODE_SIGNING
                    in eku.value
                )
                info.is_encryption_cert = (
                    x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION
                    in eku.value
                )
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"X.509 parse error: {e}")

        return info


# ---------------------------------------------------------------------------
# Global bridge instance
# ---------------------------------------------------------------------------

_bridge: Optional[PKCS11Bridge] = None


def get_bridge(module_path: Optional[str] = None) -> PKCS11Bridge:
    """Get or create the global PKCS11Bridge instance."""
    global _bridge
    if _bridge is None or module_path:
        _bridge = PKCS11Bridge(module_path)
    return _bridge
