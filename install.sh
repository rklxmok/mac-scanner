#!/bin/bash
# MAC Vendor Scanner Installer
# Run once as root: sudo ./install.sh
# Configures a scoped passwordless-sudo rule for nmap so the app
# (and the CLI) can scan without prompting for a password afterwards.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root: sudo ./install.sh${NC}"
    exit 1
fi

ACTUAL_USER="${SUDO_USER:-$USER}"
if [ "$ACTUAL_USER" = "root" ]; then
    echo -e "${RED}Run with sudo from your normal user, not as root directly.${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/mac-scanner"

NMAP_BIN="$(command -v nmap || true)"
if [ -z "$NMAP_BIN" ]; then
    echo -e "${RED}nmap not found. Install it first: sudo pacman -S nmap (or apt install nmap)${NC}"
    exit 1
fi

echo -e "${GREEN}=== MAC Vendor Scanner Installer ===${NC}"
echo ""

echo -e "${YELLOW}[1/5] Installing application files...${NC}"
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/mac_scanner_gui.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/mac_scanner.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/icon.svg" "$INSTALL_DIR/"
chmod 755 "$INSTALL_DIR/mac_scanner_gui.py"

echo -e "${YELLOW}[2/5] Installing icon...${NC}"
install -Dm644 "$SCRIPT_DIR/icon.svg" /usr/share/icons/hicolor/scalable/apps/mac-scanner.svg

echo -e "${YELLOW}[3/5] Creating launcher...${NC}"
cat > "$INSTALL_DIR/mac-scanner" << LAUNCHER
#!/bin/bash
exec python3 "$INSTALL_DIR/mac_scanner_gui.py" "\$@"
LAUNCHER
chmod 755 "$INSTALL_DIR/mac-scanner"
ln -sf "$INSTALL_DIR/mac-scanner" /usr/local/bin/mac-scanner

echo -e "${YELLOW}[4/5] Configuring passwordless scans (sudoers)...${NC}"
# Allow the installing user to run ONLY 'nmap -sn <subnet>' without a
# password. No other root commands are granted.
SUDOERS_FILE="/etc/sudoers.d/mac-scanner"
SUDOERS_TMP="${SUDOERS_FILE}.tmp"
echo "# Allow $ACTUAL_USER to run nmap ping scans without a password (MAC Vendor Scanner)" > "$SUDOERS_TMP"
echo "$ACTUAL_USER ALL=(root) NOPASSWD: $NMAP_BIN -sn *" >> "$SUDOERS_TMP"
visudo -cf "$SUDOERS_TMP" > /dev/null
chmod 440 "$SUDOERS_TMP"
mv "$SUDOERS_TMP" "$SUDOERS_FILE"
echo "  Created $SUDOERS_FILE"

echo -e "${YELLOW}[5/5] Creating desktop entry...${NC}"
cat > /usr/share/applications/mac-scanner.desktop << DESKTOP
[Desktop Entry]
Name=MAC Vendor Scanner
Comment=Scan the local network for devices by vendor MAC prefix
Exec=$INSTALL_DIR/mac-scanner
Icon=mac-scanner
Type=Application
Categories=Network;Utility;
Terminal=false
StartupWMClass=mac-scanner
DESKTOP

echo ""
echo -e "${GREEN}=== Installation Complete ===${NC}"
echo ""
echo "  App installed to:  $INSTALL_DIR"
echo "  Launcher command:  mac-scanner"
echo "  App menu entry:    MAC Vendor Scanner"
echo ""
echo "Scans now run without a sudo password prompt for user '$ACTUAL_USER'."
