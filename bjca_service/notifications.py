"""macOS user notifications for BJCA service events."""

from __future__ import annotations

import logging
import shutil
import subprocess

logger = logging.getLogger(__name__)


def notify(title: str, message: str) -> None:
    """Show a best-effort macOS notification."""
    if shutil.which("osascript") is None:
        logger.debug("osascript not found; notification skipped")
        return

    script = (
        f'display notification {_applescript_quote(message)} '
        f'with title {_applescript_quote(title)}'
    )
    try:
        subprocess.run(
            ["osascript", "-e", script],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        logger.info("Notification requested: %s - %s", title, message)
    except Exception as e:
        logger.debug("notification failed: %s", e)


def _applescript_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
