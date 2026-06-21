#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
export COPYFILE_DISABLE=1
export COPY_EXTENDED_ATTRIBUTES_DISABLE=1
BUILD_DIR="$ROOT_DIR/build"
STAGE_DIR="$BUILD_DIR/stage"
PAYLOAD_DIR="$BUILD_DIR/payload"
SCRIPTS_DIR="$BUILD_DIR/scripts"
DIST_DIR="$ROOT_DIR/dist"
PKG_ID="org.bjca-macos.ukey-service"
PKG_NAME="BJCA-UKey-Service.pkg"
DMG_NAME="BJCA-UKey-Service.dmg"
VERSION="1.0.0"

SITE_PACKAGES="$(python3 - <<'PY'
import site
print(site.getusersitepackages())
PY
)"

echo "Building BJCA UKey DMG..."
rm -rf "$BUILD_DIR" "$DIST_DIR"
mkdir -p "$STAGE_DIR/bjca-macos" "$PAYLOAD_DIR/Library/Application Support/BJCA-UKey-Service" "$SCRIPTS_DIR" "$DIST_DIR"

echo "Copying service files..."
ditto --norsrc --noextattr "$ROOT_DIR/bjca_service" "$PAYLOAD_DIR/Library/Application Support/BJCA-UKey-Service/bjca_service"
mkdir -p "$PAYLOAD_DIR/Library/Application Support/BJCA-UKey-Service/config"
install -m 0644 "$ROOT_DIR/config/client_setup.ini" "$PAYLOAD_DIR/Library/Application Support/BJCA-UKey-Service/config/client_setup.ini"
install -m 0644 "$ROOT_DIR/requirements.txt" "$PAYLOAD_DIR/Library/Application Support/BJCA-UKey-Service/requirements.txt"
install -m 0644 "$ROOT_DIR/README.md" "$PAYLOAD_DIR/Library/Application Support/BJCA-UKey-Service/README.md"

echo "Copying Python vendor dependencies..."
VENDOR="$PAYLOAD_DIR/Library/Application Support/BJCA-UKey-Service/vendor"
mkdir -p "$VENDOR"
python3 "$ROOT_DIR/packaging/copy_vendor.py" "$SITE_PACKAGES" "$VENDOR"

cat > "$SCRIPTS_DIR/postinstall" <<'SCRIPT'
#!/bin/bash
set -euo pipefail

TARGET_USER="${USER:-}"
if [ "$TARGET_USER" = "root" ] && [ -n "${SUDO_USER:-}" ]; then
    TARGET_USER="$SUDO_USER"
fi
if [ -z "$TARGET_USER" ]; then
    TARGET_USER="$(stat -f %Su /dev/console)"
fi
USER_HOME="$(dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory | awk '{print $2}')"
USER_ID="$(id -u "$TARGET_USER")"

APP_SRC="/Library/Application Support/BJCA-UKey-Service"
RUN_DIR="$USER_HOME/.bjca/runtime"
LOG_DIR="$USER_HOME/.bjca/log"
PYCACHE_DIR="$USER_HOME/.bjca/pycache"
BIN_DIR="$RUN_DIR/bin"
LAUNCHER="$BIN_DIR/BJCA-UKey-Service"
LAUNCH_AGENTS="$USER_HOME/Library/LaunchAgents"
PLIST="$LAUNCH_AGENTS/com.bjca.certservice.plist"

mkdir -p "$RUN_DIR" "$LOG_DIR" "$PYCACHE_DIR" "$BIN_DIR" "$LAUNCH_AGENTS"
ditto --norsrc --noextattr "$APP_SRC/bjca_service" "$RUN_DIR/bjca_service"
ditto --norsrc --noextattr "$APP_SRC/config" "$RUN_DIR/config"
ditto --norsrc --noextattr "$APP_SRC/vendor" "$RUN_DIR/vendor"
install -m 0644 "$APP_SRC/requirements.txt" "$RUN_DIR/requirements.txt"
install -m 0644 "$APP_SRC/README.md" "$RUN_DIR/README.md"

cat > "$LAUNCHER" <<'LAUNCHER'
#!/bin/bash
set -euo pipefail

RUN_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$RUN_DIR"

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"
export PYTHONPATH="$RUN_DIR/vendor:$RUN_DIR"
export PYTHONPYCACHEPREFIX="${PYTHONPYCACHEPREFIX:-$HOME/.bjca/pycache}"

PYTHON_BIN="$(command -v python3)"
exec -a "BJCA UKey Service" "$PYTHON_BIN" -m bjca_service.server "$@"
LAUNCHER
chmod 755 "$LAUNCHER"

cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.bjca.certservice</string>
    <key>ProgramArguments</key>
    <array>
        <string>$LAUNCHER</string>
        <string>--host</string>
        <string>127.0.0.1</string>
        <string>--port</string>
        <string>21061</string>
        <string>--log-level</string>
        <string>info</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$RUN_DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/stderr.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
        <key>PYTHONPATH</key>
        <string>$RUN_DIR/vendor:$RUN_DIR</string>
        <key>PYTHONPYCACHEPREFIX</key>
        <string>$PYCACHE_DIR</string>
    </dict>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
</dict>
</plist>
PLIST

chown -R "$TARGET_USER":staff "$USER_HOME/.bjca" "$PLIST"
chmod 644 "$PLIST"

launchctl bootout "gui/$USER_ID" "$PLIST" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$USER_ID" "$PLIST" >/dev/null 2>&1 || true
launchctl kickstart -k "gui/$USER_ID/com.bjca.certservice" >/dev/null 2>&1 || true

exit 0
SCRIPT
chmod +x "$SCRIPTS_DIR/postinstall"

echo "Building pkg..."
find "$PAYLOAD_DIR" "$STAGE_DIR" -name '._*' -delete
xattr -cr "$PAYLOAD_DIR" "$STAGE_DIR" 2>/dev/null || true
pkgbuild \
  --root "$PAYLOAD_DIR" \
  --scripts "$SCRIPTS_DIR" \
  --filter '.*/\._[^/]*$' \
  --filter '.*/\.DS_Store$' \
  --filter '.*/__MACOSX(/.*)?$' \
  --identifier "$PKG_ID" \
  --version "$VERSION" \
  --install-location "/" \
  "$DIST_DIR/$PKG_NAME"

echo "Removing macOS metadata sidecars from pkg payload..."
CLEAN_PKG_DIR="$BUILD_DIR/pkg-expanded"
rm -rf "$CLEAN_PKG_DIR"
pkgutil --expand "$DIST_DIR/$PKG_NAME" "$CLEAN_PKG_DIR"
find "$CLEAN_PKG_DIR" -name '._*' -delete

PAYLOAD_COUNT="$(
  cd "$PAYLOAD_DIR"
  find . \( -name '._*' -o -name '.DS_Store' \) -prune -o -print | wc -l | tr -d ' '
)"
PAYLOAD_KB="$(du -sk "$PAYLOAD_DIR" | awk '{print $1}')"

(
  cd "$PAYLOAD_DIR"
  find . \( -name '._*' -o -name '.DS_Store' \) -prune -o -print \
    | LC_ALL=C sort \
    | COPYFILE_DISABLE=1 cpio -o --format odc \
    | gzip -c > "$CLEAN_PKG_DIR/Payload"
)
mkbom "$PAYLOAD_DIR" "$CLEAN_PKG_DIR/Bom"
perl -0pi -e "s#<payload numberOfFiles=\"[0-9]+\" installKBytes=\"[0-9]+\"/>#<payload numberOfFiles=\"$PAYLOAD_COUNT\" installKBytes=\"$PAYLOAD_KB\"/>#" "$CLEAN_PKG_DIR/PackageInfo"
pkgutil --flatten "$CLEAN_PKG_DIR" "$DIST_DIR/$PKG_NAME.clean"
mv "$DIST_DIR/$PKG_NAME.clean" "$DIST_DIR/$PKG_NAME"

echo "Building DMG..."
mkdir -p "$STAGE_DIR/dmg"
install -m 0644 "$DIST_DIR/$PKG_NAME" "$STAGE_DIR/dmg/$PKG_NAME"
cat > "$STAGE_DIR/dmg/README-安装说明.txt" <<'TXT'
BJCA UKey Service 安装说明

1. 双击 BJCA-UKey-Service.pkg 安装。
2. 安装完成后，本地服务会自动启动。
3. 服务地址：https://127.0.0.1:21061
4. 健康检查：https://127.0.0.1:21061/health
5. 插入或拔出已支持的 UKey 后，系统会弹出“UKey 已插入 / UKey 已拔出”通知。
6. macOS 后台项目中会显示为 BJCA UKey Service。

已验证：Longmai GM3000 / 兼容证书登录页面。
TXT

hdiutil create \
  -volname "BJCA UKey Service" \
  -srcfolder "$STAGE_DIR/dmg" \
  -ov \
  -format UDZO \
  "$DIST_DIR/$DMG_NAME"

echo "Done:"
echo "  $DIST_DIR/$PKG_NAME"
echo "  $DIST_DIR/$DMG_NAME"
