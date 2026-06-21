"""
Longmai GM3000 HID support.

Supported BJCA USB Keys in this family identify as:
  - USB Product: Longmai-GM3000
  - Vendor ID:  0x055c
  - Product ID: 0xe618
  - Interface:  HID, UsagePage 0xffa0, reports 64 bytes

This is not a CCID/PCSC smart card reader, so OpenSC's generic PKCS#11 module
will not expose it as a slot. This module provides safe discovery and open/read
metadata for compatible Longmai HID tokens.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import hid  # type: ignore
    HAS_HIDAPI = True
except ImportError:
    hid = None
    HAS_HIDAPI = False


LONGMAI_VENDOR_ID = 0x055C
LONGMAI_GM3000_PRODUCT_IDS = {
    0xE618: "Longmai-GM3000",
    0xDB08: "Longmai-GM3000",
    0xF603: "Longmai-GM3000",
    0x2205: "Longmai-GM3000",
}


@dataclass
class LongmaiHIDDeviceInfo:
    """Information about a Longmai GM3000 HID token."""

    path: bytes
    vendor_id: int
    product_id: int
    product_string: str = ""
    manufacturer_string: str = ""
    serial_number: str = ""
    usage_page: int = 0
    usage: int = 0
    interface_number: int = -1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transport": "hid",
            "vendor": "Longmai",
            "manufacturer": self.manufacturer_string or "Longmai Technologies",
            "product": self.product_string or LONGMAI_GM3000_PRODUCT_IDS.get(
                self.product_id, "Longmai-GM3000"
            ),
            "device_type": "LONGMAI_GM3000_HID",
            "device_type_id": 3000,
            "vid": f"0x{self.vendor_id:04x}",
            "pid": f"0x{self.product_id:04x}",
            "device_sn": self.serial_number,
            "serial_number": self.serial_number,
            "usage_page": f"0x{self.usage_page:04x}",
            "usage": f"0x{self.usage:04x}",
            "interface_number": self.interface_number,
            "is_present": True,
            "pkcs11_supported": False,
            "pcsc_supported": False,
            "note": "Longmai GM3000 is visible as HID; requires SKF-over-HID adapter, not OpenSC PKCS#11.",
        }


class LongmaiHIDManager:
    """Safe discovery/open wrapper for Longmai GM3000 HID tokens."""

    def list_devices(self) -> List[LongmaiHIDDeviceInfo]:
        if not HAS_HIDAPI:
            return []

        devices: List[LongmaiHIDDeviceInfo] = []
        for dev in hid.enumerate():
            vid = dev.get("vendor_id")
            pid = dev.get("product_id")
            product = dev.get("product_string") or ""
            manufacturer = dev.get("manufacturer_string") or ""

            is_longmai = vid == LONGMAI_VENDOR_ID and (
                pid in LONGMAI_GM3000_PRODUCT_IDS
                or "GM3000" in product.upper()
                or "LONGMAI" in manufacturer.upper()
            )
            if not is_longmai:
                continue

            path = dev.get("path") or b""
            if isinstance(path, str):
                path = path.encode()

            devices.append(LongmaiHIDDeviceInfo(
                path=path,
                vendor_id=int(vid or 0),
                product_id=int(pid or 0),
                product_string=product,
                manufacturer_string=manufacturer,
                serial_number=dev.get("serial_number") or "",
                usage_page=int(dev.get("usage_page") or 0),
                usage=int(dev.get("usage") or 0),
                interface_number=int(dev.get("interface_number") or -1),
            ))

        return devices

    def get_device_count(self) -> int:
        return len(self.list_devices())

    def open_first(self):
        """Open the first Longmai device without sending any command."""
        if not HAS_HIDAPI:
            raise RuntimeError("hidapi is not installed")
        devices = self.list_devices()
        if not devices:
            raise RuntimeError("No Longmai GM3000 HID device found")

        dev = hid.device()
        path = devices[0].path
        dev.open_path(path)
        return dev


_manager: Optional[LongmaiHIDManager] = None


def get_longmai_manager() -> LongmaiHIDManager:
    global _manager
    if _manager is None:
        _manager = LongmaiHIDManager()
    return _manager
