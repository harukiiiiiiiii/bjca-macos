"""
Smart card communication layer.

Uses pyscard (Python PC/SC wrapper) on macOS.
macOS has a built-in CCID driver (AppleUSBCardReader), so most CCID-compliant
USB Keys are recognized automatically without additional drivers.

Uses pyscard to access standard PC/SC readers on macOS.
"""

import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from enum import IntEnum

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Try to import pyscard — it may not be installed yet
# ---------------------------------------------------------------------------
try:
    from smartcard.System import readers as sc_readers
    from smartcard.scard import (
        SCARD_PROTOCOL_T0,
        SCARD_PROTOCOL_T1,
        SCARD_SHARE_SHARED,
        SCARD_SHARE_EXCLUSIVE,
        SCARD_STATE_EMPTY,
        SCARD_STATE_PRESENT,
        SCARD_STATE_MUTE,
    )
    from smartcard.Exceptions import CardConnectionException, NoCardException
    HAS_PYSCARD = True
except ImportError:
    HAS_PYSCARD = False
    logger.warning(
        "pyscard not installed. Smart card functions unavailable. "
        "Install with: pip install pyscard"
    )


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class DeviceType(IntEnum):
    """USB Key device types matching the Windows driver configuration."""
    UNKNOWN = 0
    EPASS2000 = 1       # Feitian ePass2000 / Haitai GX series
    EPASS3000 = 2       # Feitian ePass3000 (GM3000)
    USK218 = 3          # WatchData USK218
    TENDYRON = 4        # Tendyron SmartCA series
    HAIKEY = 5          # Haitai CSP device
    OTG_HID_CSP = 6     # OTG HID CSP device


@dataclass
class DeviceInfo:
    """Information about a connected USB Key device."""
    reader_name: str           # PC/SC reader name
    device_sn: str = ""        # Device serial number
    device_type: DeviceType = DeviceType.UNKNOWN
    container_count: int = 0   # Number of key containers
    is_present: bool = False   # Is the card inserted?
    atr: bytes = b""           # Answer To Reset (card identification)

    def to_dict(self) -> dict:
        return {
            "reader_name": self.reader_name,
            "device_sn": self.device_sn,
            "device_type": self.device_type.name,
            "device_type_id": int(self.device_type),
            "container_count": self.container_count,
            "is_present": self.is_present,
            "atr_hex": self.atr.hex() if self.atr else "",
        }


# ---------------------------------------------------------------------------
# PC/SC wrapper
# ---------------------------------------------------------------------------

class SmartCardError(Exception):
    """Base error for smart card operations."""
    pass


class DeviceNotFoundError(SmartCardError):
    """No device found."""
    pass


class CardCommunicationError(SmartCardError):
    """Failed to communicate with the card."""
    pass


class SmartCardManager:
    """
    Manages smart card readers and card communication.

    Equivalent to the standard PC/SC calls:
      - SCardEstablishContext → __init__
      - SCardListReaders      → list_readers()
      - SCardConnect          → connect()
      - SCardTransmit         → transmit()
      - SCardGetStatusChange  → wait_for_card()
      - SCardReleaseContext   → close()
    """

    def __init__(self):
        self._connection = None
        self._current_reader: Optional[str] = None
        if not HAS_PYSCARD:
            logger.warning(
                "pyscard not installed. Smart card functions unavailable. "
                "Install: pip install pyscard"
            )

    # ---- Reader / Device Management ----

    def list_readers(self) -> List[str]:
        """List all PC/SC smart card readers (mirrors SCardListReadersA)."""
        if not HAS_PYSCARD:
            return []
        try:
            readers = sc_readers()
            return [str(r) for r in readers]
        except Exception as e:
            logger.error(f"Failed to list readers: {e}")
            return []

    def get_device_count(self) -> int:
        """Get the number of connected USB Key devices (mirrors GetDeviceCount)."""
        return len(self.list_readers())

    def get_all_device_sn(self) -> List[str]:
        """Get serial numbers of all connected devices (mirrors GetAllDeviceSN)."""
        sn_list = []
        for reader_name in self.list_readers():
            try:
                conn = self._connect_reader(reader_name)
                # Try to read device serial number via standard APDU
                sn = self._read_device_sn(conn)
                sn_list.append(sn)
                conn.disconnect()
            except Exception as e:
                logger.warning(f"Could not read SN from {reader_name}: {e}")
                sn_list.append("")
        return sn_list

    def get_device_info(self, index: int = 0) -> DeviceInfo:
        """Get detailed information about a device (mirrors GetDeviceInfo)."""
        readers = self.list_readers()
        if index < 0 or index >= len(readers):
            raise DeviceNotFoundError(f"No device at index {index}")

        reader_name = readers[index]
        info = DeviceInfo(reader_name=reader_name)

        try:
            conn = self._connect_reader(reader_name)
            info.atr = conn.getATR() if hasattr(conn, 'getATR') else b""
            info.is_present = True
            info.device_sn = self._read_device_sn(conn)
            info.device_type = self._detect_device_type(info.atr)
            conn.disconnect()
        except NoCardException:
            info.is_present = False
        except Exception as e:
            logger.warning(f"Could not get device info for {reader_name}: {e}")

        return info

    # ---- Card Connection ----

    def connect(self, reader_index: int = 0) -> None:
        """
        Connect to a USB Key device (mirrors SCardConnect + InitDevice).

        After this call, transmit() can be used to send APDUs.
        """
        readers = self.list_readers()
        if reader_index < 0 or reader_index >= len(readers):
            raise DeviceNotFoundError(
                f"No device at index {reader_index} "
                f"(found {len(readers)} reader(s))"
            )

        self._current_reader = readers[reader_index]
        self._connection = self._connect_reader(self._current_reader)
        logger.info(f"Connected to {self._current_reader}")

    def disconnect(self) -> None:
        """Disconnect from the current device (mirrors SCardDisconnect)."""
        if self._connection:
            try:
                self._connection.disconnect()
            except Exception:
                pass
            self._connection = None
            self._current_reader = None

    def is_connected(self) -> bool:
        """Check if connected to a device."""
        return self._connection is not None

    # ---- APDU Transmission ----

    def transmit(self, apdu: bytes) -> Tuple[int, bytes]:
        """
        Send an APDU command to the card (mirrors SCardTransmit).

        Returns (sw1_sw2, response_data).
        For standard ISO 7816, SW=0x9000 means success.
        """
        if not self._connection:
            raise CardCommunicationError("Not connected to any device")

        try:
            response, sw1, sw2 = self._connection.transmit(
                list(apdu)
            )
            sw = (sw1 << 8) | sw2
            return sw, bytes(response)
        except Exception as e:
            raise CardCommunicationError(f"APDU transmit failed: {e}") from e

    # ---- Device Detection ----

    def detect_device_type(self, reader_index: int = 0) -> DeviceType:
        """Detect the type of USB Key connected (mirrors IsDeviceExist logic)."""
        info = self.get_device_info(reader_index)
        return info.device_type

    # ---- Wait for Card Events ----

    def wait_for_card(self, timeout_ms: int = 10000) -> bool:
        """
        Wait for a card to be inserted (mirrors SCardGetStatusChange).

        Returns True if a card was inserted within the timeout period.
        """
        if not HAS_PYSCARD:
            return False

        start = time.monotonic()
        while (time.monotonic() - start) * 1000 < timeout_ms:
            readers = self.list_readers()
            for reader_name in readers:
                try:
                    conn = self._connect_reader(reader_name)
                    conn.disconnect()
                    return True
                except NoCardException:
                    continue
                except Exception:
                    continue
            time.sleep(0.5)
        return False

    # ---- Internal Helpers ----

    @staticmethod
    def _connect_reader(reader_name: str):
        """Internal: connect to a specific reader."""
        from smartcard.System import readers as sc_readers
        readers = sc_readers()
        for r in readers:
            if str(r) == reader_name:
                return r.createConnection()
        raise DeviceNotFoundError(f"Reader not found: {reader_name}")

    @staticmethod
    def _read_device_sn(connection) -> str:
        """
        Try to read the device serial number via standard APDU commands.
        Different USB Key models use different methods.
        """
        # Try common serial number read commands
        sn_apdus = [
            # ISO 7816-4: GET DATA for card serial
            bytes([0x80, 0xCA, 0x9F, 0x7F, 0x00]),
            # Feitian serial number
            bytes([0x80, 0x14, 0x00, 0x00, 0x08]),
            # Generic GET DATA
            bytes([0x00, 0xCA, 0x01, 0x88, 0x00]),
            # WatchData serial
            bytes([0x80, 0xB0, 0x00, 0x00, 0x10]),
        ]

        for apdu in sn_apdus:
            try:
                response, sw1, sw2 = connection.transmit(list(apdu))
                if sw1 == 0x90 and sw2 == 0x00:
                    return bytes(response).hex().upper()
            except Exception:
                continue

        return ""

    @staticmethod
    def _detect_device_type(atr: bytes) -> DeviceType:
        """
        Detect device type from ATR (Answer To Reset) bytes.

        This is a heuristic — different manufacturers use different ATR patterns.
        """
        if not atr:
            return DeviceType.UNKNOWN

        atr_hex = atr.hex().upper()

        # Feitian ePass series
        if any(p in atr_hex for p in [
            "3B9F9580", "3BFA1300", "3B8D80",
            "3B9F958131", "3BDB9600",
        ]):
            # Differentiate between ePass2000 and ePass3000
            if len(atr) > 15:
                return DeviceType.EPASS3000
            return DeviceType.EPASS2000

        # WatchData USK218
        if "3B7D96" in atr_hex or "3B9F95" in atr_hex:
            return DeviceType.USK218

        # Tendyron
        if "3BFA" in atr_hex:
            return DeviceType.TENDYRON

        # Generic CCID — assume ePass2000 as default
        if len(atr) > 6:
            return DeviceType.EPASS2000

        return DeviceType.UNKNOWN


# ---------------------------------------------------------------------------
# Global manager instance
# ---------------------------------------------------------------------------

_manager: Optional[SmartCardManager] = None


def get_manager() -> SmartCardManager:
    """Get or create the global SmartCardManager instance."""
    global _manager
    if _manager is None:
        _manager = SmartCardManager()
    return _manager
