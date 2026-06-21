#!/usr/bin/env python3
"""
Diagnose macOS smart-card / PKCS#11 support for BJCA USB Keys.

This checks four layers:
  1. USB/HID device visibility
  2. PC/SC reader visibility via system tools
  3. OpenSC PKCS#11 module loading
  4. Token slots/certificates visible through pkcs11-tool and python-pkcs11

Usage:
  python3 diagnose_pkcs11.py
  BJCA_PKCS11_MODULE=/path/to/vendor-pkcs11.dylib python3 diagnose_pkcs11.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


DEFAULT_MODULES = [
    "/opt/homebrew/lib/opensc-pkcs11.so",
    "/opt/homebrew/lib/pkcs11/opensc-pkcs11.so",
    "/usr/local/lib/opensc-pkcs11.so",
    "/Library/OpenSC/lib/opensc-pkcs11.so",
    "/Library/BJCA/lib/libbjcapkcs11.dylib",
    "/Library/BJCA/lib/libeTPKCS11.dylib",
    "/usr/local/lib/libeTPKCS11.dylib",
    "/opt/homebrew/lib/libeTPKCS11.dylib",
    "/usr/local/lib/libwdpkcs11.dylib",
]


def section(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def run(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    print("$ " + " ".join(cmd))
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        out = p.stdout.strip()
        if out:
            print(out)
        else:
            print("(no output)")
        return p.returncode, out
    except FileNotFoundError:
        print(f"not found: {cmd[0]}")
        return 127, ""
    except subprocess.TimeoutExpired:
        print("timed out")
        return 124, ""


def find_modules() -> list[str]:
    env_module = os.environ.get("BJCA_PKCS11_MODULE")
    candidates = [env_module] if env_module else []
    candidates.extend(DEFAULT_MODULES)
    seen = set()
    found = []
    for c in candidates:
        if not c or c in seen:
            continue
        seen.add(c)
        if Path(c).exists():
            found.append(c)
    return found


def main() -> int:
    section("1. Tool availability")
    for tool in ["system_profiler", "pcsctest", "opensc-tool", "pkcs11-tool"]:
        path = shutil.which(tool)
        print(f"{tool}: {path or 'not found'}")

    section("2. USB HID tokens")
    found_hid = []
    try:
        import hid  # type: ignore
        for dev in hid.enumerate():
            if dev.get("vendor_id") == 0x055C or "Longmai" in str(dev) or "GM3000" in str(dev):
                found_hid.append(dev)
                print("Longmai/GM3000 HID device:")
                for key in [
                    "vendor_id", "product_id", "serial_number",
                    "manufacturer_string", "product_string",
                    "usage_page", "usage", "interface_number",
                ]:
                    print(f"  {key}: {dev.get(key)}")
        if not found_hid:
            print("No Longmai/GM3000 HID token found via hidapi.")
    except Exception as e:
        print(f"hidapi check unavailable/error: {type(e).__name__}: {e}")

    section("3. USB CCID / SmartCard devices")
    run(["system_profiler", "SPSmartCardsDataType"], timeout=30)
    print("\nUSB CCID quick scan:")
    run(["bash", "-lc", "system_profiler SPUSBDataType | grep -Ei -A8 'ccid|smart|token|usb key|epass|watchdata|haitai|bjca|gm3000' || true"], timeout=30)

    section("4. PKCS#11 module candidates")
    modules = find_modules()
    if not modules:
        print("No PKCS#11 module found. Install OpenSC or provide BJCA_PKCS11_MODULE.")
        return 2
    for m in modules:
        print(m)

    module = modules[0]
    print(f"\nUsing module: {module}")

    section("5. pkcs11-tool module info")
    run(["pkcs11-tool", "--module", module, "-I"], timeout=30)

    section("6. pkcs11-tool slots")
    slot_rc, slot_out = run(["pkcs11-tool", "--module", module, "-L"], timeout=30)

    section("7. pkcs11-tool token objects, if a token slot exists")
    if "token present" in slot_out.lower() or "slot " in slot_out.lower() and "no slots" not in slot_out.lower():
        run(["pkcs11-tool", "--module", module, "-O"], timeout=30)
    else:
        print("No token slot visible. Insert the USB Key, then rerun this script.")

    section("8. python-pkcs11 load test")
    try:
        import pkcs11  # type: ignore

        lib = pkcs11.lib(module)
        all_slots = list(lib.get_slots(token_present=False))
        token_slots = list(lib.get_slots(token_present=True))
        print(f"python-pkcs11 loaded module: {module}")
        print(f"all slots: {len(all_slots)}")
        print(f"token slots: {len(token_slots)}")
        for i, slot in enumerate(token_slots):
            print(f"  token slot {i}: id={slot.slot_id}, label={slot.label!r}, manufacturer={slot.manufacturer!r}")
    except Exception as e:
        print(f"python-pkcs11 failed: {type(e).__name__}: {e}")
        return 3

    section("9. Result")
    if "No slots" in slot_out or not slot_out.strip():
        if found_hid:
            print("A Longmai/GM3000 HID token is visible and accessible, but it is not a PC/SC/OpenSC token.")
            print("This model needs a Longmai SKF-over-HID adapter or vendor macOS SKF/PKCS#11 driver.")
        else:
            print("OpenSC is installed and loadable, but no USB Key/token is visible yet.")
            print("If the key is already inserted, this model likely needs a vendor macOS driver")
            print("or a custom PC/SC/APDU/SKF implementation rather than generic OpenSC.")
        return 1

    print("A PKCS#11 module is loadable and at least one slot is visible.")
    print("Next step: list certificates and test signing with the real PIN.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
