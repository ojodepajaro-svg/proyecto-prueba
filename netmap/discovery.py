"""Descubrimiento de equipos: nmap si está, si no ping + tabla ARP + sondeo TCP."""

from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import os
import platform
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from .config import norm_mac

IS_WINDOWS = platform.system() == "Windows"
MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}")

# Puertos que más ayudan a adivinar qué es cada equipo.
COMMON_PORTS = [
    22, 23, 53, 80, 139, 443, 445, 515, 548, 554, 631, 1400, 1883, 3389,
    5000, 5353, 7000, 8000, 8008, 8009, 8080, 8443, 8554, 9100, 32400, 49152, 62078,
]


def run(cmd: list[str] | str, timeout: float = 60, shell: bool = False) -> str:
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, shell=shell,
            errors="replace",
        )
        return out.stdout + out.stderr
    except (OSError, subprocess.TimeoutExpired):
        return ""


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


# ── Información de este equipo ───────────────────────────────────────────

def local_ip() -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def default_gateway() -> str | None:
    if IS_WINDOWS:
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", run(["route", "print", "-4"]))
        return m.group(1) if m else None
    out = run(["ip", "route", "show", "default"])
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
    if m:
        return m.group(1)
    out = run(["netstat", "-rn"])  # macOS / BSD
    m = re.search(r"^(?:default|0\.0\.0\.0)\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
    return m.group(1) if m else None


def local_interface(ip: str | None) -> dict:
    """Nombre, MAC y tipo (cable/wifi) de la interfaz que tiene `ip`."""
    info: dict = {"name": None, "mac": None, "connection": None}
    if not ip:
        return info
    if platform.system() == "Linux":
        out = run(["ip", "-o", "-4", "addr", "show"])
        m = re.search(rf"^\d+:\s+(\S+)\s+inet {re.escape(ip)}/", out, re.M)
        if m:
            name = m.group(1)
            info["name"] = name
            try:
                info["mac"] = norm_mac(Path(f"/sys/class/net/{name}/address").read_text())
            except OSError:
                pass
            wireless = Path(f"/sys/class/net/{name}/wireless").exists() or name.startswith("wl")
            info["connection"] = "wifi" if wireless else "cable"
    elif platform.system() == "Darwin":
        out = run(["ifconfig"])
        for block in re.split(r"\n(?=\S)", out):
            if f"inet {ip} " in block:
                info["name"] = block.split(":")[0]
                m = re.search(r"ether (\S+)", block)
                info["mac"] = norm_mac(m.group(1)) if m else None
        hw = run(["networksetup", "-listallhardwareports"])
        m = re.search(r"Hardware Port: (.+)\nDevice: " + re.escape(info["name"] or "-"), hw)
        if m:
            info["connection"] = "wifi" if "Wi-Fi" in m.group(1) or "AirPort" in m.group(1) else "cable"
    elif IS_WINDOWS:
        out = run(["ipconfig", "/all"])
        for block in re.split(r"\r?\n(?=\S)", out):
            if ip in block:
                info["name"] = block.splitlines()[0].strip(" :")
                m = MAC_RE.search(block)
                info["mac"] = norm_mac(m.group(0)) if m else None
                low = block.lower()
                info["connection"] = "wifi" if ("wireless" in low or "wi-fi" in low or "inalámbric" in low) else "cable"
    return info


# ── Barrido ──────────────────────────────────────────────────────────────

def _ping(ip: str) -> bool:
    cmd = ["ping", "-n", "1", "-w", "800", ip] if IS_WINDOWS else ["ping", "-c", "1", "-W", "1", ip]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=3)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def ping_sweep(nets: list[ipaddress.IPv4Network]) -> set[str]:
    hosts = [str(h) for net in nets for h in net.hosts()]
    alive: set[str] = set()
    with cf.ThreadPoolExecutor(max_workers=96) as pool:
        for ip, ok in zip(hosts, pool.map(_ping, hosts)):
            if ok:
                alive.add(ip)
    return alive


def arp_table() -> dict[str, str]:
    """IP -> MAC según la tabla de vecinos del sistema operativo."""
    table: dict[str, str] = {}
    out = run(["ip", "neigh"]) if platform.system() == "Linux" else ""
    if out:
        for line in out.splitlines():
            parts = line.split()
            if "lladdr" in parts and "FAILED" not in parts and "INCOMPLETE" not in parts:
                table[parts[0]] = norm_mac(parts[parts.index("lladdr") + 1])
    else:
        for line in run(["arp", "-a"]).splitlines():
            ipm = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            macm = MAC_RE.search(line)
            if ipm and macm:
                mac = norm_mac(macm.group(0))
                if mac and mac != "ff:ff:ff:ff:ff:ff" and not mac.startswith("01:00:5e"):
                    table[ipm.group(1)] = mac
    return {ip: mac for ip, mac in table.items() if mac}


def _probe(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=0.6):
            return True
    except OSError:
        return False


def tcp_probe(ips: list[str], ports: list[int] = COMMON_PORTS) -> dict[str, list[int]]:
    jobs = [(ip, p) for ip in ips for p in ports]
    result: dict[str, list[int]] = {ip: [] for ip in ips}
    with cf.ThreadPoolExecutor(max_workers=128) as pool:
        for (ip, port), ok in zip(jobs, pool.map(lambda j: _probe(*j), jobs)):
            if ok:
                result[ip].append(port)
    return result


def reverse_dns(ips: list[str]) -> dict[str, str]:
    def lookup(ip: str) -> str | None:
        try:
            return socket.gethostbyaddr(ip)[0]
        except OSError:
            return None

    with cf.ThreadPoolExecutor(max_workers=32) as pool:
        return {ip: name for ip, name in zip(ips, pool.map(lookup, ips)) if name and name != ip}


# ── nmap ─────────────────────────────────────────────────────────────────

def has_nmap() -> bool:
    return shutil.which("nmap") is not None


def nmap_scan(nets: list[ipaddress.IPv4Network], ports: bool) -> dict[str, dict]:
    """Devuelve ip -> {mac, vendor, hostname, ports, os}."""
    args = ["nmap", "-oX", "-", "-T4", "--host-timeout", "90s"]
    if ports:
        args += ["-F", "--open"]
        if is_root():
            args += ["-O", "--osscan-limit"]
    else:
        args += ["-sn"]
    args += [str(n) for n in nets]
    xml = run(args, timeout=1800)
    hosts: dict[str, dict] = {}
    try:
        root = ET.fromstring(xml[xml.find("<?xml"):] if "<?xml" in xml else xml)
    except ET.ParseError:
        return hosts
    for h in root.iter("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue
        entry: dict = {"ports": [], "services": {}}
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                entry["ip"] = a.get("addr")
            elif a.get("addrtype") == "mac":
                entry["mac"] = norm_mac(a.get("addr"))
                if a.get("vendor"):
                    entry["vendor"] = a.get("vendor")
        hn = h.find("hostnames/hostname")
        if hn is not None:
            entry["hostname"] = hn.get("name")
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is not None and st.get("state") == "open":
                num = int(p.get("portid"))
                entry["ports"].append(num)
                svc = p.find("service")
                if svc is not None and svc.get("name"):
                    entry["services"][str(num)] = svc.get("name")
        osm = h.find("os/osmatch")
        if osm is not None:
            entry["os"] = osm.get("name")
        if "ip" in entry:
            hosts[entry["ip"]] = entry
    return hosts


# ── Fabricantes (OUI) ────────────────────────────────────────────────────

_OUI: dict[str, str] | None = None
OUI_CACHE = Path(__file__).resolve().parent.parent / "data" / "oui.txt"
NMAP_PREFIXES = [
    Path("/usr/share/nmap/nmap-mac-prefixes"),
    Path("/usr/local/share/nmap/nmap-mac-prefixes"),
    Path("/opt/homebrew/share/nmap/nmap-mac-prefixes"),
    Path(r"C:\Program Files (x86)\Nmap\nmap-mac-prefixes"),
    Path(r"C:\Program Files\Nmap\nmap-mac-prefixes"),
]


def _load_oui() -> dict[str, str]:
    global _OUI
    if _OUI is not None:
        return _OUI
    _OUI = {}
    for path in [OUI_CACHE, *NMAP_PREFIXES]:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2 and len(parts[0]) == 6:
                _OUI.setdefault(parts[0].upper(), parts[1].strip())
    return _OUI


def vendor_for(mac: str | None) -> str | None:
    if not mac:
        return None
    return _load_oui().get(mac.replace(":", "")[:6].upper())


def is_randomized_mac(mac: str | None) -> bool:
    """MAC privada/aleatoria (bit 'localmente administrada'): típico de celulares por wifi."""
    if not mac:
        return False
    return bool(int(mac[:2], 16) & 0x02)


def update_oui() -> int:
    """Descarga la lista oficial de fabricantes de la IEEE a data/oui.txt."""
    import csv
    import io
    import urllib.request

    url = "https://standards-oui.ieee.org/oui/oui.csv"
    with urllib.request.urlopen(url, timeout=60) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    lines = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 3 and len(row[1]) == 6:
            lines.append(f"{row[1].upper()} {row[2].strip()}")
    OUI_CACHE.parent.mkdir(parents=True, exist_ok=True)
    OUI_CACHE.write_text("\n".join(lines), encoding="utf-8")
    global _OUI
    _OUI = None
    return len(lines)
