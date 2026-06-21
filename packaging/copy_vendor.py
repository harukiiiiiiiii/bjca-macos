#!/usr/bin/env python3
"""Copy runtime Python dependencies into a portable vendor directory."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


SKIP_DIRS = {
    "__pycache__",
    ".pytest_cache",
    "SelfTest",
    "test",
    "tests",
}

SKIP_FILES = {
    ".DS_Store",
    "RECORD",
    "REQUESTED",
}


PACKAGES = [
    "aiohappyeyeballs",
    "aiohttp",
    "aiohttp_cors",
    "aiosignal",
    "asn1crypto",
    "attr",
    "attrs",
    "async_timeout",
    "cffi",
    "cryptography",
    "Cryptodome",
    "frozenlist",
    "gmssl",
    "hid.cpython-39-darwin.so",
    "idna",
    "multidict",
    "OpenSSL",
    "pkcs11",
    "propcache",
    "pycparser",
    "smartcard",
    "typing_extensions.py",
    "yarl",
    "_cffi_backend.cpython-39-darwin.so",
]

DIST_INFOS = [
    "aiohappyeyeballs-",
    "aiohttp-",
    "aiohttp_cors-",
    "aiosignal-",
    "asn1crypto-",
    "async_timeout-",
    "attrs-",
    "cffi-",
    "cryptography-",
    "frozenlist-",
    "gmssl-",
    "hidapi-",
    "idna-",
    "multidict-",
    "propcache-",
    "pycryptodomex-",
    "pycparser-",
    "pyopenssl-",
    "pyscard-",
    "python_pkcs11-",
    "typing_extensions-",
    "yarl-",
]


def copy_file_data(src: Path, dst: Path) -> None:
    """Copy file content and mode without preserving xattrs/resource forks."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst, follow_symlinks=False)
    shutil.copymode(src, dst, follow_symlinks=False)


def copy_tree_data(src: Path, dst: Path) -> None:
    """Recursively copy a directory without macOS metadata sidecars."""
    for root, dirnames, filenames in os.walk(src):
        dirnames[:] = [
            dirname for dirname in dirnames
            if dirname not in SKIP_DIRS and not dirname.startswith("._")
        ]
        root_path = Path(root)
        rel = root_path.relative_to(src)
        dst_root = dst / rel
        dst_root.mkdir(parents=True, exist_ok=True)
        shutil.copymode(root_path, dst_root, follow_symlinks=False)

        for dirname in dirnames:
            child = dst_root / dirname
            child.mkdir(exist_ok=True)

        for filename in filenames:
            if (
                filename in SKIP_FILES
                or filename.startswith("._")
                or filename.endswith((".pyc", ".pyo"))
            ):
                continue
            copy_file_data(root_path / filename, dst_root / filename)


def copy_path(src: Path, dst: Path) -> None:
    if not src.exists():
        print(f"warning: missing {src}", file=sys.stderr)
        return
    if src.is_dir():
        copy_tree_data(src, dst)
    else:
        copy_file_data(src, dst)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: copy_vendor.py <site-packages> <vendor-dir>", file=sys.stderr)
        return 2

    site_packages = Path(sys.argv[1])
    vendor = Path(sys.argv[2])
    vendor.mkdir(parents=True, exist_ok=True)

    for name in PACKAGES:
        copy_path(site_packages / name, vendor / name)

    for child in site_packages.iterdir():
        if not (child.name.endswith(".dist-info") or child.name.endswith(".egg-info")):
            continue
        if any(child.name.startswith(prefix) for prefix in DIST_INFOS):
            copy_path(child, vendor / child.name)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
