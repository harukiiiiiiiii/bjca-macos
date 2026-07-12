from pathlib import Path


def test_upgrade_installation_contract():
    build = Path("packaging/build_dmg.sh").read_text()

    assert 'PKG_ID="cn.com.jspec.bjca-macos"' in build
    assert 'VERSION="2.1.0"' in build
    assert "pkgutil --forget org.bjca-macos.ukey-service" in build
    assert "pkgutil --forget cn.com.jspec.bjca-macos" in build
    assert 'SHARED_EXTENSION="/Users/Shared/BJCA-Chrome-Extension"' in build
    assert 'rm -rf "$USER_HOME/.bjca"' not in build
    assert Path("docs/BJCA-UKey-Service-安装指南.md").exists()


if __name__ == "__main__":
    test_upgrade_installation_contract()
    print("upgrade installation contract: ok")
