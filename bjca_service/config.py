"""
Configuration management for BJCA macOS service.

Mirrors the structure of client_setup.ini from the Windows version.
Handles:
  - Update server URLs
  - Driver/device configuration
  - Certificate paths
  - Tray/service settings (adapted for macOS)
"""

import os
import configparser
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class ServiceConfig:
    """Complete service configuration."""

    # --- Server settings ---
    listen_host: str = "127.0.0.1"
    listen_port: int = 21061
    websocket_path: str = "/xtxapp"
    api_prefix: str = "/api"

    # --- Update configuration (mirrors [update] section) ---
    install_online_update: bool = True
    update_server_url_1: str = "http://update.bjca.org.cn/service/update2"
    update_server_url_3: str = "http://update.bjca.org.cn/service/update2"

    # --- Driver/device type (mirrors [driver] section) ---
    driver_types: List[str] = field(
        default_factory=lambda: ["epass2000", "epass3000", "OTGHIDCSP"]
    )

    # --- CSS configuration ---
    use_css: bool = False
    css_config_path: str = "/Library/BJCA/data/aideinternet.ini"

    # --- Certificate paths ---
    bjca_root: str = "/Library/BJCA"
    log_path: str = ""  # auto-detect
    cert_data_path: str = "/Library/BJCA/data"
    pkcs11_module_paths: List[str] = field(default_factory=list)

    # --- Service configuration ---
    service_run_type: int = 1  # 1=system user, 2=current user
    threads_per_child: int = 300
    log_level: str = "trace"

    # --- WLAN/business configuration ---
    wlan_type: int = 2  # 1=enterprise, 2=gov
    update_address: str = (
        "https://userweb.bjca.org.cn/bossuserweb/onlineupdate.aspx"
    )
    help_address: str = "http://help.bjca.org.cn"

    # --- Certificate expiry ---
    cert_expiry_warning_days: int = 60
    tray_show_duration: int = 60

    @classmethod
    def from_file(cls, path: str) -> "ServiceConfig":
        """Load configuration from a Windows-style client_setup.ini."""
        config = cls()
        if not os.path.exists(path):
            return config

        parser = configparser.ConfigParser()
        parser.read(path, encoding="gb2312")

        # [update]
        if parser.has_section("update"):
            config.install_online_update = (
                parser.get("update", "Install", fallback="on").lower() == "on"
            )
            config.update_server_url_1 = parser.get(
                "update", "updateserverurl_1", fallback=config.update_server_url_1
            )
            config.update_server_url_3 = parser.get(
                "update", "updateserverurl_3", fallback=config.update_server_url_3
            )

        # [driver]
        if parser.has_section("driver"):
            types_str = parser.get("driver", "type", fallback="")
            config.driver_types = [t.strip() for t in types_str.split() if t.strip()]

        # [UseCSS]
        if parser.has_section("UseCSS"):
            config.use_css = parser.getint("UseCSS", "cssconfig", fallback=0) == 1
            config.css_config_path = parser.get(
                "UseCSS", "filename",
                fallback="/Library/BJCA/data/aideinternet.ini"
            )

        # [WLAN]
        if parser.has_section("WLAN"):
            config.wlan_type = parser.getint("WLAN", "wlanType", fallback=2)
            config.update_address = parser.get(
                "WLAN", "UpdateAdress", fallback=config.update_address
            )
            config.help_address = parser.get(
                "WLAN", "HelpAdress", fallback=config.help_address
            )

        # [daysofcertenddate]
        if parser.has_section("daysofcertenddate"):
            config.cert_expiry_warning_days = parser.getint(
                "daysofcertenddate", "thedays", fallback=60
            )

        return config

    def save(self, path: str) -> None:
        """Save configuration to a .ini file."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        parser = configparser.ConfigParser()

        parser.add_section("update")
        parser.set("update", "Install", "on" if self.install_online_update else "off")
        parser.set("update", "updateserverurl_1", self.update_server_url_1)
        parser.set("update", "updateserverurl_3", self.update_server_url_3)

        parser.add_section("server")
        parser.set("server", "listen_host", self.listen_host)
        parser.set("server", "listen_port", str(self.listen_port))
        parser.set("server", "log_level", self.log_level)

        with open(path, "w", encoding="utf-8") as f:
            parser.write(f)


# Global configuration instance
_default_config: Optional[ServiceConfig] = None


def get_config() -> ServiceConfig:
    """Get the global service configuration."""
    global _default_config
    if _default_config is None:
        # Try common config locations
        for path in [
            "./client_setup.ini",
            "/Library/BJCA/client_setup.ini",
            os.path.expanduser("~/.bjca/client_setup.ini"),
        ]:
            if os.path.exists(path):
                _default_config = ServiceConfig.from_file(path)
                break
        if _default_config is None:
            _default_config = ServiceConfig()
    return _default_config


def set_config(config: ServiceConfig) -> None:
    """Set the global service configuration."""
    global _default_config
    _default_config = config
