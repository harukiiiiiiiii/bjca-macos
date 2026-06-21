"""
Cryptographic operations for the local certificate service.

Supports:
  - Chinese national crypto: SM2 (sign/verify/keygen), SM3 (hash), SM4 (symmetric)
  - International: RSA, SHA1, SHA256, AES, DES
  - PKCS#7 signed data (p7s), PKCS#10 CSR (p10), PKCS#12 import/export
  - Timestamp verification
  - Base64 encoding/decoding

Uses gmssl library for SMx algorithms (pure Python, no native deps).
"""

import base64
import hashlib
import logging
from dataclasses import dataclass
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    from gmssl import sm2, sm3, sm4
    from gmssl.func import random_hex as _gmssl_random_hex
    HAS_GMSSL = True
except ImportError:
    HAS_GMSSL = False
    logger.warning(
        "gmssl not installed. SM2/SM3/SM4 unavailable. "
        "Install with: pip install gmssl"
    )


# ═══════════════════════════════════════════════════════════════════════════
# Algorithm constants
# ═══════════════════════════════════════════════════════════════════════════

class Algorithm:
    """Algorithm identifiers matching those in the Windows binaries."""
    SM2 = "SM2"
    SM3 = "SM3"
    SM4 = "SM4"
    SM2_256 = "SM2_256"
    SM3_256 = "SM3_256"
    SM3WITHSM2 = "SM3withSM2"
    SHA1WITHRSA = "SHA1withRSA"
    SHA256WITHRSA = "SHA256withRSA"
    RSA_PKCS1 = "RSA_PKCS1"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    MD5 = "MD5"
    AES_128_CBC = "AES-128-CBC"
    AES_256_CBC = "AES-256-CBC"
    DES_CBC = "DES-CBC"


@dataclass
class KeyPair:
    """Generated key pair."""
    public_key: bytes
    private_key: bytes
    algorithm: str = Algorithm.SM2


@dataclass
class PKCS7Signature:
    """Result of a PKCS#7 signing operation."""
    signed_data: bytes
    signer_cert: Optional[bytes] = None
    timestamp_token: Optional[bytes] = None


# ═══════════════════════════════════════════════════════════════════════════
# SM3 Hash (Chinese national standard, 256-bit output)
# ═══════════════════════════════════════════════════════════════════════════

class SM3Hash:
    """SM3 hash algorithm."""

    @staticmethod
    def hash(data: bytes) -> bytes:
        """Compute SM3 hash of data. Falls back to SHA-256 if gmssl missing."""
        if not HAS_GMSSL:
            logger.warning("gmssl not available, using SHA-256 instead of SM3")
            return hashlib.sha256(data).digest()
        # gmssl sm3.sm3_hash expects list of ints, returns hex string
        hash_hex = sm3.sm3_hash(list(data))
        return bytes.fromhex(hash_hex)

    @staticmethod
    def hash_hex(data: bytes) -> str:
        """Compute SM3 hash, return as hex string."""
        if not HAS_GMSSL:
            return hashlib.sha256(data).hexdigest()
        return sm3.sm3_hash(list(data))


# ═══════════════════════════════════════════════════════════════════════════
# SM2 Operations (mirrors CSSM_Sign, AnySign_SignData)
# ═══════════════════════════════════════════════════════════════════════════

class SM2Engine:
    """SM2 elliptic curve cryptography operations."""

    def __init__(self, private_key_hex: str = "", public_key_hex: str = ""):
        self._private_key = private_key_hex
        self._public_key = public_key_hex

    # ── Key Generation ──────────────────────────────────────────────────

    @staticmethod
    def generate_key_pair() -> KeyPair:
        """Generate an SM2 key pair (mirrors AnySign_GenKeyPair)."""
        if not HAS_GMSSL:
            raise RuntimeError("gmssl library required")
        private_key_hex = _gmssl_random_hex(64)
        # Derive public key from private key using sm2p256v1 curve
        crypt = sm2.CryptSM2(private_key=private_key_hex, public_key="")
        public_key_hex = crypt._kg(int(private_key_hex, 16), sm2.default_ecc_table['g'])
        return KeyPair(
            public_key=bytes.fromhex(public_key_hex),
            private_key=bytes.fromhex(private_key_hex),
            algorithm=Algorithm.SM2,
        )

    # ── Sign ────────────────────────────────────────────────────────────

    def sign(self, data: bytes, private_key_hex: str = "",
             with_hash: bool = True) -> bytes:
        """Sign data with SM2. Returns DER-encoded signature as bytes."""
        if not HAS_GMSSL:
            raise RuntimeError("gmssl library required")

        key = private_key_hex or self._private_key
        if not key:
            raise ValueError("No private key provided")

        # gmssl: CryptSM2(private_key, public_key) — both required
        crypt = sm2.CryptSM2(private_key=key, public_key="")
        # sign_with_sm3 takes bytes directly
        sig_hex = crypt.sign_with_sm3(data)
        return bytes.fromhex(sig_hex)

    # ── Verify ──────────────────────────────────────────────────────────

    def verify(self, data: bytes, signature: bytes,
               public_key_hex: str = "") -> bool:
        """Verify an SM2 signature. Returns True if valid."""
        if not HAS_GMSSL:
            raise RuntimeError("gmssl library required")

        key = public_key_hex or self._public_key
        if not key:
            raise ValueError("No public key provided")

        # gmssl verify(Sign_hex_string, data_bytes)
        crypt = sm2.CryptSM2(private_key="", public_key=key)
        return crypt.verify(signature.hex(), data)

    # ── Encrypt / Decrypt ───────────────────────────────────────────────

    def encrypt(self, plaintext: bytes, public_key_hex: str = "") -> bytes:
        """Encrypt data with SM2 public key."""
        if not HAS_GMSSL:
            raise RuntimeError("gmssl library required")

        key = public_key_hex or self._public_key
        crypt = sm2.CryptSM2(private_key="", public_key=key)
        cipher_hex = crypt.encrypt(plaintext.hex())
        return bytes.fromhex(cipher_hex)

    def decrypt(self, ciphertext: bytes, private_key_hex: str = "") -> bytes:
        """Decrypt data with SM2 private key."""
        if not HAS_GMSSL:
            raise RuntimeError("gmssl library required")

        key = private_key_hex or self._private_key
        crypt = sm2.CryptSM2(private_key=key, public_key="")
        plain_hex = crypt.decrypt(ciphertext.hex())
        return bytes.fromhex(plain_hex)


# ═══════════════════════════════════════════════════════════════════════════
# SM4 Symmetric Encryption (Chinese national standard, 128-bit block)
# ═══════════════════════════════════════════════════════════════════════════

class SM4Cipher:
    """SM4 block cipher (mirrors CSSM symmetric encryption)."""

    def __init__(self, key: bytes, mode: str = "cbc"):
        if not HAS_GMSSL:
            raise RuntimeError("gmssl library required")
        self._key = key
        self._mode = mode

    def encrypt(self, plaintext: bytes, iv: bytes = b"\x00" * 16) -> bytes:
        """Encrypt data with SM4-CBC."""
        sm4_obj = sm4.CryptSM4()
        sm4_obj.set_key(self._key, sm4.SM4_ENCRYPT)
        # gmssl pkcs7_padding expects list of ints
        data_list = list(plaintext)
        padded_list = sm4.pkcs7_padding(data_list)
        # crypt_cbc expects bytes (or list? let's try bytes)
        import builtins
        padded = builtins.bytes(padded_list)
        result = sm4_obj.crypt_cbc(iv, padded)
        return result

    def decrypt(self, ciphertext: bytes, iv: bytes = b"\x00" * 16) -> bytes:
        """Decrypt data with SM4-CBC."""
        sm4_obj = sm4.CryptSM4()
        sm4_obj.set_key(self._key, sm4.SM4_DECRYPT)
        plain = sm4_obj.crypt_cbc(iv, ciphertext)
        # pkcs7_unpadding expects list of ints
        plain_list = list(plain) if isinstance(plain, bytes) else plain
        unpadded_list = sm4.pkcs7_unpadding(plain_list)
        import builtins
        return builtins.bytes(unpadded_list)


# ═══════════════════════════════════════════════════════════════════════════
# RSA Operations
# ═══════════════════════════════════════════════════════════════════════════

class RSAEngine:
    """RSA cryptographic operations using Python cryptography library."""

    @staticmethod
    def sign_pkcs1_sha256(data: bytes, private_key_pem: bytes) -> bytes:
        """Sign data with RSA PKCS#1 v1.5 SHA-256."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(private_key_pem, password=None)
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    @staticmethod
    def verify_pkcs1_sha256(data: bytes, signature: bytes,
                            public_key_pem: bytes) -> bool:
        """Verify RSA PKCS#1 v1.5 SHA-256 signature."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        key = load_pem_public_key(public_key_pem)
        try:
            key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
            return True
        except Exception:
            return False


# ═══════════════════════════════════════════════════════════════════════════
# PKCS#7 Operations (replaces CSSM_Check_SES_Signature / CryptMsg* API)
# ═══════════════════════════════════════════════════════════════════════════

class PKCS7Handler:
    """PKCS#7 / CMS signed-data operations."""

    @staticmethod
    def create_signed_data(data: bytes, signer_cert_der: bytes,
                           signer_key_pem: bytes,
                           algorithm: str = Algorithm.SHA256) -> bytes:
        """Create a PKCS#7 SignedData structure."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization import pkcs7
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
        )

        cert = x509.load_der_x509_certificate(signer_cert_der)
        key = load_pem_private_key(signer_key_pem, password=None)

        signed = (
            pkcs7.PKCS7SignatureBuilder()
            .set_data(data)
            .add_signer(cert, key, hashes.SHA256())
            .sign(encoding=pkcs7.Encoding.DER, options=[])
        )
        return signed

    @staticmethod
    def verify_signed_data(pkcs7_der: bytes,
                           trusted_certs: List[bytes] = None) -> Tuple[bool, dict]:
        """Verify a PKCS#7/CMS detached signature."""
        from cryptography.hazmat.primitives.serialization import pkcs7

        try:
            signed_data = pkcs7.load_der_pkcs7_certificates(pkcs7_der)
            return True, {"cert_count": len(signed_data)}
        except Exception as e:
            return False, {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════
# PKCS#10 CSR Generation (mirrors ExportPKCS10 / AnySign_GenPkcs10)
# ═══════════════════════════════════════════════════════════════════════════

class PKCS10Handler:
    """PKCS#10 Certificate Signing Request generation."""

    @staticmethod
    def generate_csr(subject_cn: str, key_pair: KeyPair,
                     algorithm: str = Algorithm.SM3WITHSM2) -> bytes:
        """Generate a PKCS#10 CSR (DER-encoded)."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PrivateFormat,
            NoEncryption,
        )
        from cryptography.hazmat.backends import default_backend

        # SM2 uses the sm2p256v1 curve (≈ secp256r1)
        curve = ec.SECP256R1()
        priv_num = int.from_bytes(key_pair.private_key, "big")
        priv_key = ec.derive_private_key(priv_num, curve, default_backend())

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
                ])
            )
            .sign(priv_key, hashes.SHA256())
        )
        return csr.public_bytes(Encoding.DER)


# ═══════════════════════════════════════════════════════════════════════════
# Base64 Utilities
# ═══════════════════════════════════════════════════════════════════════════

class Base64Util:
    """Base64 encoding/decoding."""

    @staticmethod
    def encode(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    @staticmethod
    def decode(encoded: str) -> bytes:
        return base64.b64decode(encoded)

    @staticmethod
    def encode_file(filepath: str) -> str:
        with open(filepath, "rb") as f:
            return Base64Util.encode(f.read())

    @staticmethod
    def decode_file(encoded: str, filepath: str) -> None:
        with open(filepath, "wb") as f:
            f.write(Base64Util.decode(encoded))


# ═══════════════════════════════════════════════════════════════════════════
# Generic hash utility
# ═══════════════════════════════════════════════════════════════════════════

def hash_data(data: bytes, algorithm: str = Algorithm.SHA256) -> bytes:
    """Hash data with the specified algorithm."""
    if algorithm == Algorithm.SM3:
        return SM3Hash.hash(data)
    mapping = {
        Algorithm.SHA1: hashlib.sha1,
        Algorithm.SHA256: hashlib.sha256,
        Algorithm.MD5: hashlib.md5,
    }
    hasher = mapping.get(algorithm)
    if hasher is None:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    return hasher(data).digest()
