"""Device and container management with native Longmai GM3000 HID support."""

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .smartcard import (
    DeviceInfo,
    DeviceType,
    SmartCardManager,
    get_manager,
)
from .pkcs11_bridge import (
    SlotInfo,
    PKCS11Bridge,
    get_bridge,
)
from .longmai_gm3000 import GM3000HID
from .longmai_hid import get_longmai_manager

logger = logging.getLogger(__name__)


@dataclass
class ContainerInfo:
    """Key container information."""
    container_id: int
    container_name: str = ""
    has_certificate: bool = False
    has_key_pair: bool = False
    key_algorithm: str = ""


@dataclass
class ESealInfo:
    seal_id: str
    seal_name: str = ""
    image_data: Optional[bytes] = None
    image_format: str = "bmp"


class DeviceManager:
    """
    High-level device and container management.

    Composes SmartCardManager (PC/SC), PKCS11Bridge (PKCS#11), and the
    native Longmai GM3000 HID driver to provide the browser-facing device API.
    """

    def __init__(self):
        self._sc = get_manager()
        self._pkcs11 = get_bridge()
        self._longmai_detect = get_longmai_manager()

        # Active GM3000 session — created once init_device is called.
        self._gm3000: Optional[GM3000HID] = None
        self._gm3000_ready: bool = False
        self._gm3000_info: Optional[Any] = None
        self._gm3000_pin: Optional[str] = None
        self._gm3000_cert: Optional[bytes] = None  # cached signing certificate

    # ---- Device Enumeration ----

    def get_device_count(self) -> int:
        pcsc_count = self._sc.get_device_count()
        pkcs11_count = self._pkcs11.get_slot_count()
        longmai_count = self._longmai_detect.get_device_count()
        return max(pcsc_count, pkcs11_count) + longmai_count

    def get_presence_info(self) -> Dict[str, Any]:
        """
        Return a cheap UKey presence snapshot for notification polling.

        This intentionally avoids list_devices() because GM3000 list_devices()
        opens the HID token to read metadata. The monitor only needs edge
        detection, so HID/PCSC enumeration is enough and does not disturb an
        active signing session.
        """
        longmai_check_ok = True
        try:
            longmai_devices = self._longmai_detect.list_devices()
        except Exception as e:
            logger.debug("Longmai presence check failed: %s", e)
            longmai_check_ok = False
            longmai_devices = []

        if longmai_devices:
            dev = longmai_devices[0]
            name = dev.product_string or "Longmai-GM3000"
            return {
                "present": True,
                "name": name,
                "transport": "hid",
                "device_type": "LONGMAI_GM3000",
                "serial_number": dev.serial_number,
            }

        if longmai_check_ok and self._gm3000_ready:
            logger.info("GM3000 removed; resetting active HID session")
            self._reset_gm3000_session()

        try:
            readers = self._sc.list_readers()
        except Exception as e:
            logger.debug("PC/SC presence check failed: %s", e)
            readers = []

        if readers:
            return {
                "present": True,
                "name": readers[0],
                "transport": "pcsc",
                "device_type": "PCSC",
            }

        return {
            "present": False,
            "name": "UKey",
        }

    def _reset_gm3000_session(self) -> None:
        if self._gm3000:
            try:
                self._gm3000.close()
            except Exception:
                pass
        self._gm3000 = None
        self._gm3000_ready = False
        self._gm3000_info = None
        self._gm3000_pin = None
        self._gm3000_cert = None

    def list_devices(self) -> List[Dict[str, Any]]:
        devices: List[Dict[str, Any]] = []

        # PC/SC devices
        for i in range(self._sc.get_device_count()):
            info = self._sc.get_device_info(i)
            devices.append(info.to_dict())

        # PKCS#11 slots
        pkcs11_slots = self._pkcs11.get_slots(token_present=True)
        for slot in pkcs11_slots:
            matched = False
            for dev in devices:
                if slot.token_serial and slot.token_serial in dev.get("device_sn", ""):
                    dev["slot_id"] = slot.slot_id
                    dev["token_label"] = slot.token_label
                    dev["manufacturer"] = slot.manufacturer
                    matched = True
                    break
            if not matched:
                devices.append({
                    "slot_id": slot.slot_id,
                    "token_label": slot.token_label,
                    "manufacturer": slot.manufacturer,
                    "token_serial": slot.token_serial,
                    "device_type": "PKCS11",
                })

        # GM3000 (always first if present)
        # If we already have an active session, use cached info.
        if self._gm3000_ready:
            info = getattr(self, "_gm3000_info", None)
            manufacturer = getattr(info, "manufacturer", "") or "Longmai"
            label = getattr(info, "label", "") or "GM3000 UKey"
            serial = getattr(info, "serial", "") or ""
            devices.insert(0, {
                "transport": "hid",
                "device_type": "LONGMAI_GM3000",
                "device_type_id": 3000,
                "manufacturer": manufacturer,
                "token_label": label,
                "device_sn": serial,
                "serial_number": serial,
                "is_present": True,
                "session_active": True,
                "capabilities": ["SM2", "SM3", "cert_export", "sign"],
            })
        elif GM3000HID.is_present():
            try:
                probe = GM3000HID()
                probe.open()
                info = probe.get_dev_info()
                probe.close()
                devices.insert(0, {
                    "transport": "hid",
                    "device_type": "LONGMAI_GM3000",
                    "device_type_id": 3000,
                    "manufacturer": info.manufacturer or "Longmai",
                    "token_label": info.label,
                    "device_sn": info.serial,
                    "serial_number": info.serial,
                    "is_present": True,
                    "capabilities": ["SM2", "SM3", "cert_export", "sign"],
                })
            except Exception as e:
                logger.debug("GM3000 probe failed: %s", e)

        return devices

    def get_device_info(self, index: int = 0) -> Dict[str, Any]:
        devices = self.list_devices()
        if 0 <= index < len(devices):
            return devices[index]
        return {"error": f"No device at index {index}"}

    # ---- Device Initialization (mirrors InitDevice) ----

    def init_device(self, index: int = 0, pin: Optional[str] = None) -> bool:
        """
        Initialize a connection to a USB Key.
        For GM3000: opens the HID session, enumerates apps/containers,
        and opens the signing container ready for sign().
        """
        devices = self.list_devices()
        if 0 <= index < len(devices) and devices[index].get("device_type") == "LONGMAI_GM3000":
            return self._init_gm3000(pin)
        try:
            self._sc.connect(index)
            if self._pkcs11.is_available:
                self._pkcs11.open_session(index, pin)
            return True
        except Exception as e:
            logger.error("init_device(%d) failed: %s", index, e)
            return False

    def _init_gm3000(self, pin: Optional[str] = None) -> bool:
        """Full GM3000 SKF initialisation: open → app → container."""
        try:
            self._gm3000 = GM3000HID()
            self._gm3000.open()
            info = self._gm3000.get_dev_info()
            self._gm3000_info = info
            logger.info("GM3000 init: label=%s serial=%s", info.label, info.serial)

            self._gm3000.enum_application()
            self._gm3000.open_application("BJCA-Application")
            conts = self._gm3000.enum_container()
            logger.info("GM3000 containers: %s", conts)
            self._gm3000.open_container("personalCert00")

            # Cache the signing certificate
            self._gm3000_cert = self._gm3000.export_certificate(sign=True)

            self._gm3000_pin = pin
            if pin:
                ok, retries = self._gm3000.verify_pin(pin)
                if not ok:
                    logger.warning("GM3000 PIN verification failed")
                    return False
                logger.info("GM3000 PIN verified (retries left: %d)", retries)

            self._gm3000_ready = True
            return True
        except Exception as e:
            logger.error("GM3000 init failed: %s", e)
            self._gm3000_ready = False
            return False

    def close_device(self) -> None:
        self._reset_gm3000_session()
        self._pkcs11.close_session()
        self._sc.disconnect()

    @property
    def gm3000(self) -> Optional[GM3000HID]:
        return self._gm3000 if self._gm3000_ready else None

    @property
    def gm3000_cert(self) -> Optional[bytes]:
        return self._gm3000_cert

    # ---- Container Operations ----

    def get_container_count(self, device_index: int = 0) -> int:
        if self._gm3000_ready:
            return 2  # personalCert00 + unitCert00
        if not self._sc.is_connected():
            self.init_device(device_index)
        try:
            sw, response = self._sc.transmit(bytes([0x80, 0x52, 0x00, 0x00, 0x00]))
            if sw == 0x9000 and response:
                return response[0] if response else 0
        except Exception:
            pass
        if self._pkcs11.is_available:
            certs = self._pkcs11.list_certificates()
            return len(set(c.cert_id for c in certs if c.cert_id))
        return 0

    def list_containers(self) -> List[ContainerInfo]:
        if self._gm3000_ready:
            return [
                ContainerInfo(container_id=0, container_name="personalCert00",
                              has_certificate=True, has_key_pair=True, key_algorithm="SM2"),
                ContainerInfo(container_id=1, container_name="unitCert00",
                              has_certificate=True, has_key_pair=True, key_algorithm="SM2"),
            ]
        containers: List[ContainerInfo] = []
        certs = self._pkcs11.list_certificates() if self._pkcs11.is_available else []
        seen: set = set()
        for i, cert in enumerate(certs):
            cid = cert.cert_id or f"unknown_{i}"
            if cid in seen:
                continue
            seen.add(cid)
            containers.append(ContainerInfo(
                container_id=i, container_name=cert.label or f"Container_{i}",
                has_certificate=True, has_key_pair=cert.has_private_key,
                key_algorithm=cert.key_type,
            ))
        return containers

    # ---- Electronic Seal Operations ----

    def enum_eseal(self) -> List[ESealInfo]:
        seals: List[ESealInfo] = []
        certs = self._pkcs11.list_certificates() if self._pkcs11.is_available else []
        for cert in certs:
            if any(kw in (cert.label or "").upper()
                   for kw in ["SEAL", "ESEAL", "印章", "签章", "SIG"]):
                seals.append(ESealInfo(seal_id=cert.cert_id or cert.label,
                                       seal_name=cert.label or "Unknown Seal"))
        return seals

    def get_picture(self, seal_id: str = "") -> Optional[bytes]:
        if self._sc.is_connected():
            try:
                sw, response = self._sc.transmit(bytes([0x80, 0xCA, 0x9F, 0x7F, 0x00]))
                if sw == 0x9000:
                    return bytes(response)
            except Exception:
                pass
        return None


# ---------------------------------------------------------------------------
_device_manager: Optional[DeviceManager] = None


def get_device_manager() -> DeviceManager:
    global _device_manager
    if _device_manager is None:
        _device_manager = DeviceManager()
    return _device_manager
