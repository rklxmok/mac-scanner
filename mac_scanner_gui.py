#!/usr/bin/env python3
"""
MAC Vendor Scanner - GUI edition.

Scans a local subnet for devices matching a vendor MAC prefix.
Runs nmap via the passwordless sudo rule created by install.sh,
so no sudo password prompt is needed at scan time.
"""

import os
import re
import shutil
import subprocess
import sys
import ipaddress

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QGridLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


# ---------------------------------------------------------------- interfaces

def get_interfaces():
    """Return a list of (iface, ip, netmask) tuples for IPv4 interfaces."""
    if shutil.which("ip"):
        out = subprocess.run(
            ["ip", "-4", "addr", "show"],
            capture_output=True, text=True, check=True,
        ).stdout
        return _parse_ip_addr(out)
    if shutil.which("ifconfig"):
        out = subprocess.run(
            ["ifconfig"],
            capture_output=True, text=True, check=True,
        ).stdout
        return _parse_ifconfig(out)
    return []


def _parse_ip_addr(output):
    interfaces = []
    current = None
    for line in output.splitlines():
        m = re.match(r"^\d+:\s+(\S+?):", line)
        if m:
            current = m.group(1)
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if m and current:
            ip, cidr = m.group(1), m.group(2)
            if ip != "127.0.0.1":
                netmask = str(ipaddress.IPv4Network(f"0.0.0.0/{cidr}").netmask)
                interfaces.append((current, ip, netmask))
    return interfaces


def _parse_ifconfig(output):
    interfaces = []
    current = None
    for line in output.splitlines():
        m = re.match(r"^(\S+?):\s", line)
        if m:
            current = m.group(1)
        ip_m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", line)
        mask_m = re.search(r"netmask\s+(\S+)", line)
        if ip_m and current:
            ip = ip_m.group(1)
            netmask = mask_m.group(1) if mask_m else "255.255.255.0"
            if ip != "127.0.0.1":
                interfaces.append((current, ip, netmask))
    return interfaces


def netmask_to_cidr(netmask):
    """Convert dotted or hex netmask to CIDR prefix length."""
    if netmask.startswith("0x"):
        mask_int = int(netmask, 16)
    else:
        try:
            mask_int = 0
            for part in netmask.split("."):
                mask_int = (mask_int << 8) | int(part)
        except (ValueError, IndexError):
            return 24
    return bin(mask_int).count("1")


def calc_subnet(ip, netmask):
    cidr = netmask_to_cidr(netmask)
    return str(ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False))


def normalize_mac_prefix(raw):
    """Normalize a vendor MAC prefix to '0C:38:3E' form. None if invalid."""
    clean = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(clean) < 4 or len(clean) > 6 or len(clean) % 2 != 0:
        return None
    pairs = [clean[i:i + 2].upper() for i in range(0, len(clean), 2)]
    return ":".join(pairs)


# ---------------------------------------------------------------- nmap

def parse_nmap_results(stdout, prefix):
    """Pair each IP with its MAC and filter by prefix."""
    results = []
    current_ip = None
    current_host = None

    for line in stdout.splitlines():
        report = re.search(
            r"Nmap scan report for\s+(?:(\S+)\s+\()?(\d+\.\d+\.\d+\.\d+)", line
        )
        if report:
            current_host = report.group(1)
            current_ip = report.group(2)
            continue

        mac = re.search(
            r"MAC Address:\s+([0-9A-F:]+)\s*(?:\((.*?)\))?",
            line, re.IGNORECASE,
        )
        if mac and current_ip:
            addr = mac.group(1).upper()
            if addr.startswith(prefix):
                results.append({
                    "ip": current_ip,
                    "hostname": current_host,
                    "mac": addr,
                    "vendor": mac.group(2) or "Unknown",
                })
            current_ip = None
            current_host = None

    return results


class ScanThread(QThread):
    results_ready = pyqtSignal(list)
    scan_failed = pyqtSignal(str)

    def __init__(self, nmap_bin, subnet, prefix):
        super().__init__()
        self.nmap_bin = nmap_bin
        self.subnet = subnet
        self.prefix = prefix
        self._proc = None
        self._cancelled = False

    def run(self):
        try:
            self._proc = subprocess.Popen(
                ["sudo", "-n", self.nmap_bin, "-sn", self.subnet],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = self._proc.communicate()
        except FileNotFoundError:
            self.scan_failed.emit("nmap binary not found. Install it with: sudo pacman -S nmap")
            return

        if self._cancelled:
            return

        if self._proc.returncode != 0:
            err = (stderr or "").strip()
            if "a password is required" in err.lower():
                msg = (
                    "Passwordless scanning is not configured for this user.\n"
                    "Re-run the installer:  sudo ./install.sh"
                )
            else:
                msg = err or f"nmap exited with code {self._proc.returncode}"
            self.scan_failed.emit(msg)
            return

        self.results_ready.emit(parse_nmap_results(stdout, self.prefix))

    def cancel(self):
        self._cancelled = True
        if self._proc:
            self._proc.kill()


# ---------------------------------------------------------------- GUI

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MAC Vendor Scanner")
        self.resize(780, 520)

        icon_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "icon.svg"
        )
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.nmap_bin = shutil.which("nmap") or "/usr/bin/nmap"
        self.interfaces = []
        self.scan_thread = None

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(16, 16, 16, 12)
        layout.setSpacing(10)

        header = QLabel("Scan your LAN for devices by vendor MAC prefix")
        header.setStyleSheet("font-size: 15pt; font-weight: 600;")
        layout.addWidget(header)

        form = QGridLayout()
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(10)

        form.addWidget(QLabel("Interface:"), 0, 0)
        self.combo_iface = QComboBox()
        self.combo_iface.setMinimumWidth(320)
        form.addWidget(self.combo_iface, 0, 1)
        self.btn_refresh = QPushButton("Refresh")
        self.btn_refresh.clicked.connect(self.refresh_interfaces)
        form.addWidget(self.btn_refresh, 0, 2)

        form.addWidget(QLabel("Vendor MAC prefix:"), 1, 0)
        self.edit_prefix = QLineEdit()
        self.edit_prefix.setPlaceholderText("e.g. 0c38ab, 0C:38:AB, 0c-38-ab")
        self.edit_prefix.returnPressed.connect(self.start_scan)
        form.addWidget(self.edit_prefix, 1, 1)
        self.btn_scan = QPushButton("Scan")
        self.btn_scan.setDefault(True)
        self.btn_scan.clicked.connect(self.on_scan_button)
        form.addWidget(self.btn_scan, 1, 2)

        layout.addLayout(form)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(
            ["IP Address", "MAC Address", "Hostname", "Vendor"]
        )
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setCursor(Qt.CursorShape.PointingHandCursor)
        self.table.setToolTip("Click any field to copy it")
        self.table.cellClicked.connect(self.on_cell_clicked)
        layout.addWidget(self.table, 1)

        hint = QLabel("Tip: click any field in the results to copy it")
        hint.setStyleSheet("color: #8a8f98; font-size: 9pt;")
        hint.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(hint)

        self.statusBar().showMessage("Ready")

        self.setCentralWidget(central)
        self.refresh_interfaces()

        if not shutil.which("nmap"):
            QMessageBox.warning(
                self,
                "nmap missing",
                "nmap was not found on this system.\nInstall it with: sudo pacman -S nmap",
            )

    # --- helpers ---

    def refresh_interfaces(self):
        self.combo_iface.clear()
        try:
            self.interfaces = get_interfaces()
        except subprocess.SubprocessError:
            self.interfaces = []

        if not self.interfaces:
            self.combo_iface.addItem("(no interfaces found)")
            self.btn_scan.setEnabled(False)
            self.statusBar().showMessage("No network interfaces detected")
            return

        for iface, ip, mask in self.interfaces:
            subnet = calc_subnet(ip, mask)
            self.combo_iface.addItem(f"{iface}   {ip}   ({subnet})")

        self.btn_scan.setEnabled(True)
        self.statusBar().showMessage("Ready")

    def current_subnet(self):
        idx = self.combo_iface.currentIndex()
        if 0 <= idx < len(self.interfaces):
            iface, ip, mask = self.interfaces[idx]
            return calc_subnet(ip, mask)
        return None

    # --- scanning ---

    def on_scan_button(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.cancel_scan()
        else:
            self.start_scan()

    def start_scan(self):
        prefix = normalize_mac_prefix(self.edit_prefix.text().strip())
        if not prefix:
            QMessageBox.warning(
                self,
                "Invalid prefix",
                "Enter a vendor MAC prefix of 4-6 hex characters\n"
                "(the first 2-3 octets), e.g. 0c38ab",
            )
            self.edit_prefix.setFocus()
            return

        subnet = self.current_subnet()
        if not subnet:
            QMessageBox.warning(
                self, "No interface", "Select a network interface to scan."
            )
            return

        self.table.setRowCount(0)
        self.btn_scan.setText("Cancel")
        self.statusBar().showMessage(
            f"Scanning {subnet} for MAC prefix {prefix} — this may take a moment…"
        )

        self.scan_thread = ScanThread(self.nmap_bin, subnet, prefix)
        self.scan_thread.results_ready.connect(self.on_results)
        self.scan_thread.scan_failed.connect(self.on_error)
        self.scan_thread.finished.connect(self.on_scan_finished)
        self.scan_thread.start()

    def cancel_scan(self):
        if self.scan_thread:
            self.scan_thread.cancel()
        self.statusBar().showMessage("Scan cancelled")

    def on_scan_finished(self):
        self.btn_scan.setText("Scan")

    def on_results(self, results):
        self.table.setRowCount(len(results))
        for row, dev in enumerate(results):
            values = [
                dev["ip"],
                dev["mac"],
                dev["hostname"] or "—",
                dev["vendor"],
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                if col == 1:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(row, col, item)

        if results:
            self.statusBar().showMessage(
                f"Found {len(results)} device(s) — done"
            )
        else:
            self.statusBar().showMessage("No matching devices found")

    def on_cell_clicked(self, row, col):
        """Copy a results field to the clipboard on click."""
        item = self.table.item(row, col)
        if not item:
            return
        text = item.text()
        if not text or text == "\u2014":  # skip empty / placeholder cells
            return
        QApplication.clipboard().setText(text)
        self.statusBar().showMessage(f"Copied: {text}", 2000)

    def on_error(self, message):
        self.statusBar().showMessage("Scan failed")
        QMessageBox.critical(self, "Scan failed", message)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("MAC Vendor Scanner")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
