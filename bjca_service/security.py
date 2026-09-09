"""
Security helpers for BJCA macOS service.

Handles:
  - Allowed origin checking (HTTPS domain whitelist and Chromium extension ID)
  - Safe public-file resolution
"""

import os
import re
from pathlib import Path
from typing import Mapping, Union
from urllib.parse import unquote, urlsplit


ALLOWED_ORIGIN_HOSTS = frozenset({
    "jspec.com.cn",
    "www.jspec.com.cn",
})
ALLOWED_ORIGIN_SUFFIXES = (
    ".sgcc.com.cn",
)

# Chromium extension origin: chrome-extension://<32 a-p chars>
_EXTENSION_ORIGIN_PATTERN = re.compile(r"^chrome-extension://[a-p]{32}$")


class PublicFileError(ValueError):
    pass


def origin_allowed(origin: str, *, allow_extension: bool = False) -> bool:
    """
    Return whether origin is an exact allowlisted HTTPS origin or,
    when allow_extension is True, a valid Chromium extension origin.

    Rejects credentials, path, query, fragment, null, invalid ports.
    """
    if not origin or origin != origin.strip():
        return False

    if allow_extension and origin.startswith("chrome-extension://"):
        return bool(_EXTENSION_ORIGIN_PATTERN.fullmatch(origin))

    try:
        parsed = urlsplit(origin)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return False

    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.netloc.lower() != host
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        return False

    return host in ALLOWED_ORIGIN_HOSTS or any(
        len(host) > len(suffix) and host.endswith(suffix)
        for suffix in ALLOWED_ORIGIN_SUFFIXES
    )


def resolve_public_file(name: str, files: Mapping[str, Union[str, Path]]) -> Path:
    """
    Safely resolve a public file name against explicit whitelist.
    Rejects directory traversal, backslashes, percent-encoding, symlink escapes, etc.
    Resolved file must remain within the intended configured target's parent directory.
    """
    if not name or "\\" in name:
        raise PublicFileError("invalid public file name")

    decoded = unquote(name)
    if decoded != name or decoded not in files or Path(decoded).name != decoded:
        raise PublicFileError("public file is not allowed")

    configured_target = Path(files[decoded])
    # Base directory is the resolved parent of configured target
    try:
        base_dir = configured_target.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PublicFileError("public file parent does not exist") from exc

    try:
        resolved_path = configured_target.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PublicFileError("public file does not exist") from exc

    if not resolved_path.is_file():
        raise PublicFileError("public file is not a regular file")

    # Symlink escape check: resolved path must be inside base_dir
    try:
        resolved_path.relative_to(base_dir)
    except ValueError as exc:
        raise PublicFileError("public file escaped target directory") from exc

    return resolved_path
