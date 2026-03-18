#!/usr/bin/env python3
"""
MAC Vendor Scanner
Scans a local subnet for devices matching a specific vendor MAC prefix.
Uses nmap under the hood with a clean interactive CLI.
"""

import subprocess
import re
import sys
import getpass
import ipaddress


def get_interfaces():
    """Parse ifconfig output to get interface names and IPv4 addresses."""
    try:
        result = subprocess.run(["ifconfig"], capture_output=True, text=True, check=True)
    except FileNotFoundError:
        # Fall back to ip addr on systems without ifconfig
        try:
            result = subprocess.run(["ip", "-4", "addr", "show"], capture_output=True, text=True, check=True)
            return _parse_ip_addr(result.stdout)
        except FileNotFoundError:
            print("Error: Neither 'ifconfig' nor 'ip' found.")
            sys.exit(1)

    return _parse_ifconfig(result.stdout)


def _parse_ifconfig(output):
    """Parse ifconfig output into a list of (interface, ip, netmask) tuples."""
    interfaces = []
    current_iface = None

    for line in output.splitlines():
        # Interface line (not indented)
        iface_match = re.match(r'^(\S+?):\s', line)
        if iface_match:
            current_iface = iface_match.group(1)

        # IPv4 address line
        ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
        mask_match = re.search(r'netmask\s+(\S+)', line)
        if ip_match and current_iface:
            ip = ip_match.group(1)
            netmask = mask_match.group(1) if mask_match else "255.255.255.0"
            if ip != "127.0.0.1":
                interfaces.append((current_iface, ip, netmask))

    return interfaces


def _parse_ip_addr(output):
    """Parse 'ip addr' output as fallback."""
    interfaces = []
    current_iface = None

    for line in output.splitlines():
        iface_match = re.match(r'^\d+:\s+(\S+?):', line)
        if iface_match:
            current_iface = iface_match.group(1)

        ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
        if ip_match and current_iface:
            ip = ip_match.group(1)
            cidr = ip_match.group(2)
            if ip != "127.0.0.1":
                # Convert CIDR to netmask for consistency
                netmask = str(ipaddress.IPv4Network(f"0.0.0.0/{cidr}").netmask)
                interfaces.append((current_iface, ip, netmask))

    return interfaces


def netmask_to_cidr(netmask):
    """Convert dotted netmask or hex netmask to CIDR prefix length."""
    if netmask.startswith("0x"):
        # Hex netmask (e.g., 0xffffff00)
        mask_int = int(netmask, 16)
    else:
        # Dotted decimal
        try:
            parts = netmask.split(".")
            mask_int = 0
            for part in parts:
                mask_int = (mask_int << 8) | int(part)
        except (ValueError, IndexError):
            return 24  # Default fallback

    return bin(mask_int).count("1")


def normalize_mac_prefix(raw):
    """
    Accept a vendor MAC prefix in any format and normalize to uppercase colon-separated.
    Accepts: 0c38ab, 0C:38:AB, 0c-38-ab, 0C38AB, 0c:38, etc.
    Returns: '0C:38:AB' or '0C:38' etc.
    """
    # Strip everything that isn't a hex character
    clean = re.sub(r'[^0-9a-fA-F]', '', raw)

    if len(clean) < 4 or len(clean) > 6 or len(clean) % 2 != 0:
        return None

    # Insert colons every 2 chars and uppercase
    pairs = [clean[i:i+2].upper() for i in range(0, len(clean), 2)]
    return ":".join(pairs)


def calc_subnet(ip, netmask):
    """Calculate the network address in CIDR notation."""
    cidr = netmask_to_cidr(netmask)
    network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
    return str(network)


def run_scan(subnet, mac_prefix, sudo_pass):
    """Run nmap scan and filter results by MAC prefix."""
    cmd = f"sudo -S nmap -sn {subnet}"

    proc = subprocess.Popen(
        cmd,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    stdout, stderr = proc.communicate(input=sudo_pass + "\n")

    if proc.returncode != 0:
        # Filter out the password prompt from stderr
        err_lines = [l for l in stderr.splitlines() if "password" not in l.lower()]
        if err_lines:
            print(f"\n[!] nmap error:\n{''.join(err_lines)}")
        return []

    # Parse: pair each IP with its MAC, filter by prefix
    results = []
    current_ip = None
    current_host = None

    for line in stdout.splitlines():
        report_match = re.search(r'Nmap scan report for\s+(?:(\S+)\s+\()?(\d+\.\d+\.\d+\.\d+)', line)
        if report_match:
            current_host = report_match.group(1)  # hostname or None
            current_ip = report_match.group(2)
            continue

        # Bare IP (no hostname)
        bare_match = re.search(r'Nmap scan report for\s+(\d+\.\d+\.\d+\.\d+)', line)
        if bare_match and not current_ip:
            current_ip = bare_match.group(1)
            current_host = None

        mac_match = re.search(r'MAC Address:\s+([0-9A-F:]+)\s*\(?(.*?)\)?$', line, re.IGNORECASE)
        if mac_match and current_ip:
            mac = mac_match.group(1).upper()
            vendor = mac_match.group(2).rstrip(")")
            if mac.startswith(mac_prefix):
                results.append({
                    "ip": current_ip,
                    "hostname": current_host,
                    "mac": mac,
                    "vendor": vendor,
                })
            current_ip = None
            current_host = None

    return results


def main():
    print("╔══════════════════════════════════════╗")
    print("║       MAC Vendor Scanner v1.0        ║")
    print("╚══════════════════════════════════════╝")
    print()

    # --- Step 1: Discover interfaces ---
    interfaces = get_interfaces()

    if not interfaces:
        print("[!] No active network interfaces found.")
        sys.exit(1)

    print("Detected interfaces:\n")
    for i, (iface, ip, mask) in enumerate(interfaces, 1):
        subnet = calc_subnet(ip, mask)
        print(f"  [{i}] {iface:<16} {ip:<18} ({subnet})")

    print()

    # --- Step 2: Select interface ---
    while True:
        choice = input(f"Select interface [1-{len(interfaces)}]: ").strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(interfaces):
                break
        except ValueError:
            pass
        print("  Invalid selection, try again.")

    iface, ip, mask = interfaces[idx]
    subnet = calc_subnet(ip, mask)
    print(f"\n  → Scanning {iface} ({subnet})\n")

    # --- Step 3: MAC prefix input ---
    while True:
        raw_prefix = input("Enter vendor MAC prefix (e.g. 0c38ab, 0C:38:AB, 0c-38-ab): ").strip()
        mac_prefix = normalize_mac_prefix(raw_prefix)
        if mac_prefix:
            break
        print("  Invalid prefix. Enter 4-6 hex characters (the first 2-3 octets).")

    print(f"  → Filtering by: {mac_prefix}")
    print()

    # --- Step 4: sudo password ---
    sudo_pass = getpass.getpass("[sudo] password: ")

    # --- Step 5: Scan ---
    print(f"\nScanning {subnet} for devices with MAC starting {mac_prefix} ...")
    print("This may take a moment.\n")

    results = run_scan(subnet, mac_prefix, sudo_pass)

    # --- Step 6: Results ---
    if not results:
        print(f"No devices found with MAC prefix {mac_prefix}")
        return

    print(f"Found {len(results)} device(s):\n")
    print(f"  {'IP':<18} {'MAC':<20} {'Hostname':<25} {'Vendor'}")
    print(f"  {'─'*18} {'─'*20} {'─'*25} {'─'*20}")

    for dev in results:
        hostname = dev["hostname"] or "—"
        print(f"  {dev['ip']:<18} {dev['mac']:<20} {hostname:<25} {dev['vendor']}")

    print()


if __name__ == "__main__":
    main()
