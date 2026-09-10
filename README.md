# MAC Vendor Scanner

A LAN scanner for devices matching a specific vendor MAC prefix — useful for finding all devices from a particular manufacturer (Fanvil, Axis, Shelly, Ubiquiti, etc.) on your network. Ships with both a GUI application and an interactive CLI.

## Features

- **GUI application** (`mac_scanner_gui.py`, PyQt6) — installable to your app menu
- **Interactive CLI** (`mac_scanner.py`) — same features in the terminal
- Auto-detects network interfaces and subnets
- Accepts MAC prefix in any format (`0c38ab`, `0C:38:AB`, `0c-38-ab`)
- Shows IP, MAC, hostname, and vendor for each match
- Works with `ip addr` or `ifconfig` (auto-fallback)
- **No sudo prompt at scan time** — the installer creates a scoped sudoers rule allowing only `nmap -sn`

## Requirements

- Linux with `nmap` (`sudo pacman -S nmap` / `sudo apt install nmap`)
- GUI: Python 3 with PyQt6
- CLI: Python 3.6+ (standard library only)
- `sudo` access **once**, to run the installer

## Install (GUI app + passwordless scans)

Run the installer once with sudo:

```bash
cd mac-scanner
sudo ./install.sh
```

The installer:

1. Copies the app to `/opt/mac-scanner`
2. Installs the icon and an applications-menu entry ("MAC Vendor Scanner")
3. Creates `/etc/sudoers.d/mac-scanner` allowing **only** `nmap -sn <subnet>` to run without a password — no other root access is granted

After that, launch **MAC Vendor Scanner** from your app menu (or run `mac-scanner` in a terminal) and scan without any password prompt.

## Usage

### GUI

Launch from the app menu, pick an interface, enter a vendor prefix, click **Scan**. Press Enter in the prefix field to scan, or click the button again to cancel.

### CLI

```bash
python3 mac_scanner.py
```

(The CLI still prompts for your sudo password; the GUI does not.)

## Uninstall

```bash
sudo rm -rf /opt/mac-scanner
sudo rm /usr/local/bin/mac-scanner
sudo rm /usr/share/applications/mac-scanner.desktop
sudo rm /usr/share/icons/hicolor/scalable/apps/mac-scanner.svg
sudo rm /etc/sudoers.d/mac-scanner
```

```
╔══════════════════════════════════════╗
║       MAC Vendor Scanner v1.0        ║
╚══════════════════════════════════════╝

Detected interfaces:

  [1] ens18            10.10.2.50         (10.10.2.0/24)
  [2] ens19            172.16.1.1         (172.16.1.0/24)

Select interface [1-2]: 1

  → Scanning ens18 (10.10.2.0/24)

Enter vendor MAC prefix (e.g. 0c38ab, 0C:38:AB, 0c-38-ab): 0c383e
  → Filtering by: 0C:38:3E

Scanning 10.10.2.0/24 for devices with MAC starting 0C:38:3E ...

Found 3 device(s):

  IP                 MAC                  Hostname                  Vendor
  ────────────────── ──────────────────── ───────────────────────── ────────────────────
  10.10.2.138        0C:38:3E:2F:**:**   —                         Fanvil Technology
  10.10.2.121        0C:38:3E:1B:**:**   —                         Fanvil Technology
  10.10.2.139        0C:38:3E:44:**:**   —                         Fanvil Technology
```

## Common Vendor Prefixes

| Vendor | Prefix |
|--------|--------|
| Fanvil | `0C:38:3E` |
| Axis | `B8:A4:4F`, `AC:CC:8E` |
| Shelly | `34:94:54`, `98:CD:AC`, `C8:2B:96` |
| Ubiquiti | `FC:EC:DA`, `78:8A:20` |
| Hikvision | `C0:56:E3`, `44:19:B6` |
| Dahua | `3C:EF:8C`, `A0:BD:1D` |
| Yealink | `80:5E:C0` |

## License

MIT
