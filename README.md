# MAC Vendor Scanner

A simple interactive CLI tool that scans your local network for devices matching a specific vendor MAC prefix. Useful for finding all devices from a particular manufacturer (Fanvil, Axis, Shelly, Ubiquiti, etc.) on your LAN.

## Features

- Auto-detects network interfaces and subnets
- Accepts MAC prefix in any format (`0c38ab`, `0C:38:AB`, `0c-38-ab`)
- Shows IP, MAC, hostname, and vendor for each match
- Works with `ifconfig` or `ip addr` (auto-fallback)
- Clean interactive CLI with subnet selection

## Requirements

- Python 3.6+
- `nmap` installed (`sudo apt install nmap` or `sudo pacman -S nmap`)
- `sudo` access (nmap needs root for MAC address discovery)

No Python packages required — uses only the standard library.

## Usage

```bash
python3 mac_scanner.py
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
  10.10.2.138        0C:38:3E:2F:AA:5E   —                         Fanvil Technology
  10.10.2.121        0C:38:3E:1B:22:F0   —                         Fanvil Technology
  10.10.2.139        0C:38:3E:44:B1:03   —                         Fanvil Technology
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
