"""Datos de ejemplo para ver el dashboard sin escanear nada."""

from __future__ import annotations

import ipaddress
import random
import time

from .config import Config, Infra, Site

NET = "192.168.1.0/24"


def demo_config() -> Config:
    net = ipaddress.ip_network(NET)
    return Config(
        sites=[Site("casa", "Casa", [net]), Site("fondito", "Fondito", [net])],
        infra=[
            Infra(id="router-casa", name="Router principal", kind="router", site="casa", ip="192.168.1.1",
                  wifi_clients_command="demo"),
            Infra(id="switch-living", name="Switch del living", kind="switch", site="casa", parent="router-casa",
                  ip="192.168.1.2", snmp_community="public"),
            Infra(id="switch-escritorio", name="Switch del escritorio", kind="switch", site="casa", parent="switch-living"),
            Infra(id="ap-fondito", name="AP del fondito", kind="ap", site="fondito", parent="switch-living",
                  ip="192.168.1.3", wifi_clients_command="demo"),
        ],
        devices={},
        scan_interval_minutes=0,
    )


# ip, mac, hostname, vendor, ports, conexión (de router/switch), padre, puerto
HOSTS = [
    (1, "c0:06:c3:11:22:01", "router.lan", "TP-Link", [53, 80, 443], None, None, None),
    (2, "c0:06:c3:11:22:02", None, "TP-Link", [80], None, None, None),
    (3, "18:e8:29:aa:00:03", None, "Ubiquiti", [22, 443], None, None, None),
    (10, "3c:7c:3f:10:20:30", "desktop-gamer", "ASUSTek", [135, 139, 445, 3389], "cable", "switch-living", "1"),
    (11, "00:11:32:aa:bb:cc", "diskstation", "Synology", [22, 80, 139, 445, 5000], "cable", "switch-living", "2"),
    (12, "a8:23:fe:01:02:03", "lgwebostv", "LG Electronics", [3000, 8008, 8009], "cable", "switch-living", "3"),
    (13, "28:c6:3f:44:55:66", "ps5", "Sony Interactive", [], "cable", "switch-living", "4"),
    (14, "b8:27:eb:12:34:56", "raspberrypi", "Raspberry Pi Foundation", [22, 80, 53], "cable", "switch-living", "5"),
    (20, "00:1e:0b:77:88:99", "hp-laserjet", "Hewlett Packard", [80, 443, 631, 9100], None, "switch-living", "6"),
    (21, "f4:4d:30:aa:bb:01", "notebook-trabajo", "Elitegroup", [135, 445], None, "switch-living", "6"),
    (30, "da:a1:19:5e:22:10", "iPhone-de-Ana", None, [62078], "wifi", "router-casa", None),
    (31, "62:3f:aa:91:0c:44", None, None, [], "wifi", "router-casa", None),
    (32, "f0:18:98:22:33:44", "MacBook-Air", "Apple", [22, 5000, 7000], "wifi", "router-casa", None),
    (33, "24:0a:c4:aa:10:01", "esp-luz-cocina", "Espressif", [80], "wifi", "router-casa", None),
    (34, "24:0a:c4:aa:10:02", "esp-enchufe-heladera", "Espressif", [80], "wifi", "router-casa", None),
    (35, "fc:a1:83:55:66:77", "echo-dot", "Amazon Technologies", [], "wifi", "router-casa", None),
    (36, "48:e1:e9:01:22:33", "chromecast", "Google", [8008, 8009], "wifi", "router-casa", None),
    (37, "9c:8e:cd:11:22:33", None, "Amcrest", [80, 554], None, None, None),
    (50, "c8:3a:35:00:50:01", "camara-patio", "Hikvision", [80, 554, 8000], "cable", "switch-living", "8"),
    (51, "ae:44:21:9f:10:02", "Galaxy-A54", None, [], "wifi", "ap-fondito", None),
    (52, "34:ce:00:12:34:56", "smart-tv-fondito", "Xiaomi", [8008, 8009], "wifi", "ap-fondito", None),
    (53, "5c:cf:7f:aa:bb:cc", "shelly-bomba-pileta", "Espressif", [80], "wifi", "ap-fondito", None),
    (54, "d8:0f:99:11:22:33", "lenovo-tab", "Lenovo", [], "wifi", "ap-fondito", None),
]


def fake_scan() -> dict:
    now = time.time()
    hosts, found = [], {}
    rnd = random.Random(int(now // 60))
    for last, mac, host, vendor, ports, conn, parent, port in HOSTS:
        if last in (31, 54) and rnd.random() < 0.4:
            continue  # algunos celulares van y vienen
        hosts.append({
            "ip": f"192.168.1.{last}", "mac": mac, "hostname": host, "vendor": vendor,
            "ports": ports, "is_gateway": last == 1,
            "randomized_mac": bool(int(mac[:2], 16) & 2),
        })
        if parent:
            found[mac] = {"parent": parent, "source": "datos de ejemplo"}
            if conn:
                found[mac]["connection"] = conn
            if port:
                found[mac]["port"] = port
    found["f4:4d:30:aa:bb:01"]["port_shared"] = 2
    found["00:1e:0b:77:88:99"]["port_shared"] = 2
    hosts.append({"ip": "192.168.1.40", "mac": "3c:22:fb:9a:00:01", "hostname": "este-equipo",
                  "vendor": "Apple", "ports": [], "is_self": True, "self_connection": "wifi"})
    return {
        "scanner": "demo", "scanner_ip": "192.168.1.40", "gateway": "192.168.1.1",
        "sites": ["casa", "fondito"], "method": "demo", "root": True,
        "started_at": now - 20, "finished_at": now, "hosts": hosts,
        "infra_found": found, "notes": [],
    }


def seed_history(history_file) -> None:
    """Simula que la red se viene escaneando hace un mes, con algún equipo nuevo y uno desconectado."""
    import json

    now = time.time()
    hist = {}
    for last, mac, host, vendor, ports, *_ in HOSTS:
        first = now - (3600 * 2 if last == 37 else 30 * 86400)
        hist[mac] = {"ip": f"192.168.1.{last}", "mac": mac, "hostname": host, "vendor": vendor,
                     "ports": ports, "first_seen": first, "last_seen": now - 600}
    hist["3c:22:fb:9a:00:01"] = {"ip": "192.168.1.40", "first_seen": now - 30 * 86400, "last_seen": now}
    hist["9e:31:0a:c2:77:01"] = {"ip": "192.168.1.60", "mac": "9e:31:0a:c2:77:01", "hostname": "notebook-visita",
                                 "first_seen": now - 9 * 86400, "last_seen": now - 3 * 86400}
    history_file.parent.mkdir(parents=True, exist_ok=True)
    history_file.write_text(json.dumps(hist, indent=2))
