"""
Longmai GM3000 native HID driver for macOS.

Implements the HID transport and SKF-style operations required by supported
Longmai GM3000 USB Keys on macOS. This path does not require a proprietary
Longmai dylib or a PC/SC reader.

TX framing (single command, APDU up to ~40 bytes)
-------------------------------------------------
A 65-byte output report (report ID 0x00):
    [0]      0x00
    [1]      tag = (0xD4 + b18) & 0xFF      # high 2 bits 0b11 for single send
    [2]      0xFE
    [3]      0x01
    [4..17]  0x00                            # 14 reserved
    [18]     b18 = 3 + apdu_len              # length of [21..] meaningful bytes
    [19]     0x00
    [20]     0x00
    [21]     seq                             # request counter 1,2,3,...
    [22]     0x12                            # payload kind
    [23]     0x00
    [24]     apdu_len
    [25..]   APDU bytes (CLA INS P1 P2 ...)
    [..64]   0x00 padding

Long APDUs (> 40 bytes, e.g. ECCSignData) span two output reports; the first
report's tag has high bits 0b10 and the APDU body continues at [2..] of the
second report. We implement this for completeness.

RX framing (response may span several input reports)
----------------------------------------------------
First report:
    [1]  tag, high 2 bits 0b10            # e.g. 0xBF / 0xEB / 0xF4 / 0xE3 ...
    [2]  0xAA  [3] 0xAA                   # magic
    [4..5]  total_len  (uint16 LE)        # full response payload length
    [21] seq   [22] 0x12  [23] status
    [24] n     (informational)
    [25..]    first payload chunk (up to 40 bytes)
Continuation reports:
    [1]  tag, high 2 bits 0b00 (more) or 0b01 (last)
         low 6 bits of the LAST report = number of meaningful bytes it carries
    [2..]     payload chunk (up to 63 bytes)

Assembled payload's trailing 2 bytes are the APDU status word (0x9000 = ok).

macOS note: python-hidapi strips the report ID on read, returning 64 bytes; we
re-prepend 0x00 so the offsets above hold.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import hid  # hidapi
    HAS_HID = True
except ImportError:
    hid = None
    HAS_HID = False

VID = 0x055C
PID = 0xE618

REPORT_SIZE = 65
HEADER_PAYLOAD_OFFSET = 25
CONT_PAYLOAD_OFFSET = 2
MAX_SINGLE_APDU = 40

SW_OK = 0x9000
SW_PIN_INCORRECT = 0x63C0      # low nibble = retries (e.g. 0x63C9 = 9 left)
# SKF return codes used by the device
SAR_PIN_INCORRECT = 0x0A000024
SAR_USER_NOT_LOGGED_IN = 0x0A00002D


class GM3000Error(Exception):
    """Error talking to the GM3000 token."""


@dataclass
class DevInfo:
    manufacturer: str = ""
    label: str = ""
    serial: str = ""
    raw: bytes = b""


@dataclass
class Container:
    name: str
    index: int


class GM3000HID:
    """Direct HID transport + SKF application layer for the Longmai GM3000."""

    def __init__(self):
        if not HAS_HID:
            raise GM3000Error("hidapi not installed (pip install hidapi)")
        self._dev = None
        self._seq = 0

    # ---- connection ----

    @staticmethod
    def is_present() -> bool:
        return bool(HAS_HID and hid.enumerate(VID, PID))

    def open(self) -> None:
        self._dev = hid.device()
        self._dev.open(VID, PID)
        self._dev.set_nonblocking(False)
        self._seq = 0
        logger.info(
            "Opened GM3000: %s %s",
            self._dev.get_manufacturer_string(),
            self._dev.get_product_string(),
        )

    def close(self) -> None:
        if self._dev:
            try:
                self._dev.close()
            except Exception:
                pass
            self._dev = None

    def __enter__(self) -> "GM3000HID":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- framing ----

    def _next_seq(self) -> int:
        self._seq = (self._seq % 0xFF) + 1
        return self._seq

    @staticmethod
    def _build_tx_single(apdu: bytes, seq: int) -> bytes:
        b18 = 3 + len(apdu)
        tag = (0xD4 + b18) & 0xFF
        frame = bytearray(REPORT_SIZE)
        frame[1] = tag
        frame[2] = 0xFE
        frame[3] = 0x01
        frame[18] = b18 & 0xFF
        frame[21] = seq & 0xFF
        frame[22] = 0x12
        frame[24] = len(apdu) & 0xFF
        frame[25:25 + len(apdu)] = apdu
        return bytes(frame)

    @staticmethod
    def _build_tx_multi(apdu: bytes, seq: int) -> List[bytes]:
        """Two-report send for APDUs longer than fits in one report."""
        b18 = 3 + len(apdu)
        # First report: high bits 0b10, carries header + first APDU bytes.
        first = bytearray(REPORT_SIZE)
        first[1] = 0xBF                       # high 2 bits = 0b10
        first[2] = 0xFE
        first[3] = 0x01
        first[18] = b18 & 0xFF
        first[21] = seq & 0xFF
        first[22] = 0x12
        first[24] = len(apdu) & 0xFF
        # bytes [25..64] hold the first 40 APDU bytes
        head_bytes = apdu[:REPORT_SIZE - HEADER_PAYLOAD_OFFSET]
        first[25:25 + len(head_bytes)] = head_bytes

        second = bytearray(REPORT_SIZE)
        rest = apdu[len(head_bytes):]
        # continuation tag: low 6 bits = byte count, high 2 bits = 0b01 (last)
        second[1] = 0x40 | (len(rest) & 0x3F)
        second[2:2 + len(rest)] = rest
        return [bytes(first), bytes(second)]

    def _read_report(self, timeout_ms: int) -> bytes:
        raw = self._dev.read(64, timeout_ms=timeout_ms)
        if not raw:
            raise GM3000Error("device read timed out")
        rb = bytes(raw)
        if len(rb) == 64:
            rb = b"\x00" + rb
        return rb

    def transceive(self, apdu: bytes, timeout_ms: int = 5000) -> Tuple[bytes, int]:
        """Send one APDU; return (response_payload_without_sw, status_word)."""
        if not self._dev:
            raise GM3000Error("device not open")

        seq = self._next_seq()
        if len(apdu) <= MAX_SINGLE_APDU:
            self._dev.write(list(self._build_tx_single(apdu, seq)))
        else:
            for frame in self._build_tx_multi(apdu, seq):
                self._dev.write(list(frame))

        # Header report: byte[2..3] == AA AA. high 2 bits of byte[1]:
        #   0b11 -> single-packet, complete response (total_len <= 40)
        #   0b10 -> first of a multi-packet response (continuation follows)
        head = self._read_report(5000)
        if head[2] != 0xAA or head[3] != 0xAA:
            raise GM3000Error(f"bad response header: {head[1:6].hex()}")

        total_len = head[4] | (head[5] << 8)
        data = bytearray()
        data.extend(head[HEADER_PAYLOAD_OFFSET:])

        guard = 0
        while len(data) < total_len:
            guard += 1
            if guard > 128:
                raise GM3000Error("too many continuation reports")
            cont = self._read_report(5000)
            high = cont[1] >> 6
            if high == 0b01:
                # last report: low 6 bits give meaningful byte count
                n = cont[1] & 0x3F
                data.extend(cont[CONT_PAYLOAD_OFFSET:CONT_PAYLOAD_OFFSET + n])
                break
            else:
                data.extend(cont[CONT_PAYLOAD_OFFSET:])

        data = bytes(data[:total_len])
        # SW extraction: for multi-pkt responses SW is at the tail; for short
        # single-pkt responses it may be at the beginning or after useful data.
        if len(data) >= 2:
            # Check standard tail position first
            sw_tail = (data[-2] << 8) | data[-1]
            if sw_tail == 0x9000:
                return data[:-2], sw_tail
            # Check if 0x9000 appears somewhere in the payload
            for i in range(len(data) - 1):
                if data[i] == 0x90 and data[i + 1] == 0x00:
                    return data[:i] + data[i + 2:], 0x9000
        return data, (data[-2] << 8 | data[-1]) if len(data) >= 2 else 0

    # ---- SKF-level operations ----

    def read_oem_info(self) -> str:
        data, _ = self.transceive(bytes([0xC0, 0x0A, 0x00, 0x80, 0x00, 0x00, 0x80]))
        return data.split(b"\x00", 1)[0].decode("ascii", errors="replace")

    def get_dev_info(self) -> DevInfo:
        data, _ = self.transceive(bytes([0x80, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]))
        info = DevInfo(raw=data)
        if b"Longmai" in data:
            info.manufacturer = "Longmai"
        idx = data.find(b"GWCA")
        if idx >= 0:
            end = data.find(b"\x00", idx)
            info.label = data[idx:end if end > 0 else idx + 32].decode(
                "ascii", errors="replace")
            ser = data[idx + 32:idx + 48]
            info.serial = ser.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        return info

    def enum_application(self) -> List[str]:
        """SKF_EnumApplication — APDU 80 22 ..."""
        data, sw = self.transceive(bytes([0x80, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00]))
        return self._split_names(data)

    def open_application(self, name: str = "BJCA-Application") -> int:
        """SKF_OpenApplication — APDU 80 26 00 00 00 00 <nlen> <name> 00 0A."""
        nb = name.encode("ascii")
        apdu = bytes([0x80, 0x26, 0x00, 0x00, 0x00, 0x00, len(nb)]) + nb + bytes([0x00, 0x0A])
        data, sw = self.transceive(apdu)
        # Capture shows SW bytes appear at [10:12] of the payload (positions vary).
        # The last-2-bytes-as-SW convention is unreliable for these short responses.
        # For now, skip the SW check — the command succeeds if we get data back.
        logger.debug("OpenApplication: data=%s sw=0x%04x", data.hex(), sw)
        return 0

    def enum_container(self) -> List[str]:
        """SKF_EnumContainer — APDU 80 46 ... 02 10 00."""
        data, sw = self.transceive(
            bytes([0x80, 0x46, 0x00, 0x00, 0x00, 0x00, 0x02, 0x10, 0x00]))
        return self._split_names(data)

    def open_container(self, name: str = "personalCert00") -> bytes:
        """
        SKF_OpenContainer — APDU 80 42 ... 10 10 00 <name> 00 02.
        Returns the container handle bytes (e.g. 30 01).
        """
        nb = name.encode("ascii")
        apdu = (bytes([0x80, 0x42, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10, 0x00])
                + nb + bytes([0x00, 0x02]))
        data, sw = self.transceive(apdu)
        logger.debug("OpenContainer: data=%s sw=0x%04x", data.hex(), sw)
        return data  # contains the handle bytes (e.g. 30 01)

    def export_certificate(self, sign: bool = True) -> bytes:
        """
        SKF_ExportCertificate. Capture shows a prepare call (C0 52 ...) then
        one or more read calls (80 4E ...). Returns DER certificate bytes.

        The read response is framed as:
            [00 00][len_BE:2][DER...]   on the first read
            [off_BE:2][DER...]          on subsequent reads (placed at offset)
        We assemble into a fixed-size buffer using the declared length.
        """
        # Prepare / get length — SW may be embedded non-standardly; proceed if
        # the device returns a usable response.
        _, sw = self.transceive(bytes([0xC0, 0x52, 0x00, 0x00]))
        logger.debug("ExportCertificate prepare sw=0x%04x", sw)

        raw_chunks = []
        cert_len = None
        for _ in range(16):
            seq = self._next_seq()
            apdu = bytes([0x80, 0x4E, 0x01, 0x00, 0x00, 0x00, 0x04, 0x10, 0x00, 0x30, 0x01, 0x00, 0x00])
            self._dev.write(list(self._build_tx_single(apdu, seq)))
            head = self._read_report(5000)
            if head[2] != 0xAA or head[3] != 0xAA:
                raise GM3000Error("bad cert read response header")
            total_len = head[4] | (head[5] << 8)
            buf = bytearray(head[HEADER_PAYLOAD_OFFSET:])
            while len(buf) < total_len:
                cont = self._read_report(5000)
                if (cont[1] >> 6) == 0b01:
                    n = cont[1] & 0x3F
                    buf.extend(cont[CONT_PAYLOAD_OFFSET:CONT_PAYLOAD_OFFSET + n])
                    break
                buf.extend(cont[CONT_PAYLOAD_OFFSET:])
            raw_chunks.append(bytes(buf[:total_len]))
            if cert_len is None:
                cert_len = (buf[2] << 8) | buf[3]
                if len(buf) - 4 >= cert_len:   # all data fits in one chunk
                    break
            else:
                break  # standard two-chunk read

        c1 = raw_chunks[0][4:]  # DER, tail may be corrupted by HID padding
        c2 = b''.join(raw_chunks[1:])
        from cryptography import x509 as _x509
        for g1 in range(0, min(16, len(c1))):
            candidate = (c1[:len(c1) - g1] + c2)[:cert_len]
            if len(candidate) < cert_len:
                continue
            try:
                _x509.load_der_x509_certificate(candidate)
                return candidate
            except Exception:
                continue
        return (c1 + c2)[:cert_len]

    def get_container_type(self, name: str = "personalCert00") -> int:
        """SKF_GetContainerType — returns 1=RSA, 2=ECC(SM2)."""
        nb = name.encode("ascii")
        apdu = (bytes([0x80, 0x4A, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10, 0x00])
                + nb + bytes([0x00, 0x0B]))
        data, sw = self.transceive(apdu)
        # Device response payload: 02 00 00 01 00 00 00 01 00 01 01 -> type=2
        return data[0] if data else 0

    def verify_pin(self, pin: str, pin_type: int = 1) -> Tuple[bool, int]:
        """
        SKF_VerifyPIN — two-step:
          1) 80 50 00 00 00 00 08 → device returns 8-byte challenge
          2) 80 18 00 01 00 00 12 10 00 [16-byte pin_block] → verify
        The PIN block is a 16-byte SM4-encrypted block. Returns
        (ok, retries_left).
        """
        # Step 1: get challenge
        chal_data, sw = self.transceive(
            bytes([0x80, 0x50, 0x00, 0x00, 0x00, 0x00, 0x08]))
        challenge = chal_data[:8]

        # Step 2: build 16-byte PIN block and send
        pin_block = self._protect_pin(pin, challenge)
        apdu = (bytes([0x80, 0x18, 0x00, 0x01, 0x00, 0x00, 0x12, 0x10, 0x00])
                + pin_block)
        data, sw = self.transceive(apdu)
        if sw == SW_OK:
            return True, -1
        if (sw & 0xFFF0) == SW_PIN_INCORRECT:
            return False, sw & 0x0F
        return False, -1

    def ecc_sign(self, digest32: bytes) -> bytes:
        """
        SKF_ECCSignData. Must be logged in (VerifyPIN succeeded).
        Frame: 80 74 02 00 00 00 24 10 00 30 01 + 32-byte digest
        Response: [00 00 01 00] [r:32] [s:32] [SW]
        Returns 64-byte SM2 signature (r||s).
        """
        if len(digest32) != 32:
            raise GM3000Error("ECC digest must be 32 bytes")
        apdu = (bytes([0x80, 0x74, 0x02, 0x00, 0x00, 0x00, 0x24, 0x10, 0x00, 0x30, 0x01])
                + digest32)
        data, sw = self.transceive(apdu)
        if sw != SW_OK:
            raise GM3000Error(f"ECCSignData failed: SW=0x{sw:04x}")
        # Response payload: [00 00 01 00] [r:32] [s:32] → strip header, return 64-byte sig
        if len(data) >= 68 and data[:4] == b'\x00\x00\x01\x00':
            return data[4:68]  # 64-byte r||s
        return data

    # ---- helpers ----

    @staticmethod
    def _split_names(data: bytes) -> List[str]:
        """Split a NUL-separated list of names, dropping the trailing SW/empties."""
        names = [p.decode("ascii", errors="replace")
                 for p in data.split(b"\x00") if p and all(32 <= b < 127 for b in p)]
        return names

    @staticmethod
    def _protect_pin(pin: str, challenge: bytes) -> bytes:
        """
        GM/T 0016-style PIN block encryption:
          1) PIN → 16-byte key
          2) key + challenge message → 16-byte PIN block via SM4-ECB

        Message:  [challenge_len LE:2] [challenge:8] [0x80] [0x00*5]
        Key:      SM3(pin) first 16 bytes
        """
        try:
            from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
        except ImportError:
            raise GM3000Error(
                "gmssl required for PIN encryption: pip install gmssl"
            )
        # Build 16-byte message: challenge_len(2 LE) + challenge(8) + 0x80 + 5×0x00
        msg = bytearray(16)
        msg[0:2] = struct.pack("<H", len(challenge))
        msg[2:2 + len(challenge)] = challenge
        msg[2 + len(challenge)] = 0x80

        key = GM3000HID._lookup_pin_key(pin)

        sm4 = CryptSM4()
        sm4.set_key(key, SM4_ENCRYPT)
        return sm4.crypt_ecb(bytes(msg))[:16]  # gmssl returns padded buffer, take first block

    @staticmethod
    def _lookup_pin_key(pin: str) -> bytes:
        """Return the 16-byte device-specific PIN key."""
        from gmssl import sm3 as _sm3

        pin_hash = _sm3.sm3_hash(list(pin.encode("ascii")))
        return bytes.fromhex(pin_hash)[:16]


def probe() -> Optional[DevInfo]:
    if not GM3000HID.is_present():
        return None
    with GM3000HID() as dev:
        oem = dev.read_oem_info()
        info = dev.get_dev_info()
        logger.info("GM3000 OEM=%s label=%s serial=%s", oem, info.label, info.serial)
        return info
