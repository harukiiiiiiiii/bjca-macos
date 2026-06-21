#!/bin/bash
# ============================================================================
# BJCA Certificate Environment — macOS Installation Script
# ============================================================================
# This script installs the macOS-native BJCA certificate environment,
# providing a native macOS local certificate service.
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

INSTALL_DIR="${INSTALL_DIR:-/Library/BJCA}"
SERVICE_NAME="com.bjca.certservice"
PLIST_PATH="$HOME/Library/LaunchAgents/${SERVICE_NAME}.plist"

echo "================================================"
echo " BJCA Certificate Environment — macOS Installer"
echo " v1.0.0"
echo "================================================"
echo ""

# -------------------------------------------------------------------
# 1. Check prerequisites
# -------------------------------------------------------------------
echo -e "${YELLOW}[1/7]${NC} Checking prerequisites..."

# macOS version
OS_VER=$(sw_vers -productVersion)
echo "  macOS version: $OS_VER"

# Python 3
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}Error: python3 not found. Please install Python 3.9+.${NC}"
    exit 1
fi
PYTHON=$(command -v python3)
echo "  Python: $($PYTHON --version)"

# pip
if ! command -v pip3 &>/dev/null; then
    echo -e "${RED}Error: pip3 not found.${NC}"
    exit 1
fi

# Homebrew (optional, for additional tools)
if command -v brew &>/dev/null; then
    echo "  Homebrew: found"
else
    echo "  Homebrew: not found (optional — for pcsc-tools, opensc)"
fi

echo -e "${GREEN}  OK${NC}"

# -------------------------------------------------------------------
# 2. Create installation directory
# -------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[2/7]${NC} Creating installation directories..."

mkdir -p "$INSTALL_DIR"/{bin,lib,data,log,BJCAlog,BJCAROOT/pawdconf,BJCAROOT/pawdocs}
echo "  Install directory: $INSTALL_DIR"

# -------------------------------------------------------------------
# 3. Install Python dependencies
# -------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[3/7]${NC} Installing Python dependencies..."

cd "$(dirname "$0")"

# Install required packages
pip3 install --quiet --upgrade pip 2>&1 | tail -1

echo "  Installing core packages..."
pip3 install --quiet \
    aiohttp \
    aiohttp-cors \
    gmssl \
    cryptography \
    pyOpenSSL \
    asn1crypto \
    2>&1 | tail -5

# Optional: smart card support
echo "  Installing smart card packages..."
pip3 install --quiet pyscard 2>/dev/null || {
    echo -e "  ${YELLOW}Warning: pyscard not available (PC/SC support disabled)${NC}"
}
pip3 install --quiet python-pkcs11 2>/dev/null || {
    echo -e "  ${YELLOW}Warning: python-pkcs11 not available (PKCS#11 support disabled)${NC}"
}

echo -e "${GREEN}  OK${NC}"

# -------------------------------------------------------------------
# 4. Install service files
# -------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[4/7]${NC} Installing service files..."

# Copy source
cp -r bjca_service "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"
cp config/client_setup.ini "$INSTALL_DIR/" 2>/dev/null || true

# Create executable wrapper
cat > "$INSTALL_DIR/bin/bjca-service" << 'WRAPPER'
#!/bin/bash
# BJCA Certificate Environment Service Launcher
INSTALL_DIR="/Library/BJCA"
cd "$INSTALL_DIR"
exec python3 -m bjca_service.server \
    --host "${BJCA_HOST:-127.0.0.1}" \
    --port "${BJCA_PORT:-21061}" \
    --config "${BJCA_CONFIG:-$INSTALL_DIR/client_setup.ini}" \
    "$@"
WRAPPER
chmod +x "$INSTALL_DIR/bin/bjca-service"

echo "  Service wrapper: $INSTALL_DIR/bin/bjca-service"

# -------------------------------------------------------------------
# 5. Set up launchd service
# -------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[5/7]${NC} Setting up launchd service..."

# Create LaunchAgent plist
cat > "$PLIST_PATH" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${SERVICE_NAME}</string>

    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/bin/bjca-service</string>
        <string>--host</string>
        <string>127.0.0.1</string>
        <string>--port</string>
        <string>21061</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>StandardOutPath</key>
    <string>${INSTALL_DIR}/log/stdout.log</string>

    <key>StandardErrorPath</key>
    <string>${INSTALL_DIR}/log/stderr.log</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>BJCA_ROOT</key>
        <string>${INSTALL_DIR}</string>
        <key>BJCA_HOST</key>
        <string>127.0.0.1</string>
        <key>BJCA_PORT</key>
        <string>21061</string>
    </dict>
</dict>
</plist>
PLIST

echo "  LaunchAgent: $PLIST_PATH"

# -------------------------------------------------------------------
# 6. Start the service
# -------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[6/7]${NC} Starting service..."

# Unload if already running
launchctl unload "$PLIST_PATH" 2>/dev/null || true

# Load and start
launchctl load "$PLIST_PATH" 2>/dev/null || {
    echo -e "  ${YELLOW}(launchd may require a user session — starting in background)${NC}"
    "$INSTALL_DIR/bin/bjca-service" &
    echo "  Started in background (PID $!)"
}

echo -e "${GREEN}  Service started${NC}"

# -------------------------------------------------------------------
# 7. Verify installation
# -------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[7/7]${NC} Verifying installation..."

sleep 2

# Check if service is responding
if curl -skf https://127.0.0.1:21061/health > /dev/null 2>&1; then
    echo -e "${GREEN}  ✅ Service is running and responding${NC}"
    HEALTH=$(curl -sk https://127.0.0.1:21061/health)
    echo "  Health response: $HEALTH"
else
    echo -e "  ${YELLOW}⚠️  Service not responding yet (may take a moment)${NC}"
    echo "  Check logs: $INSTALL_DIR/log/stderr.log"
fi

# -------------------------------------------------------------------
# Done
# -------------------------------------------------------------------
echo ""
echo "================================================"
echo -e "${GREEN} Installation Complete!${NC}"
echo ""
echo "  Service URL:     https://127.0.0.1:21061"
echo "  Health check:    https://127.0.0.1:21061/health"
echo "  WebSocket:       wss://127.0.0.1:21061/xtxapp"
echo "  API:             POST https://127.0.0.1:21061/api"
echo ""
echo "  Start service:   launchctl load $PLIST_PATH"
echo "  Stop service:    launchctl unload $PLIST_PATH"
echo "  View logs:       tail -f $INSTALL_DIR/log/stderr.log"
echo ""
echo "  Config file:     $INSTALL_DIR/client_setup.ini"
echo "  PKCS#11 modules: $INSTALL_DIR/lib/"
echo "  Trust certificates: $INSTALL_DIR/trust.pem"
echo ""
echo "  For USB Key support, install (optional):"
echo "    brew install pcsc-lite opensc pcsc-tools"
echo ""
echo "================================================"
