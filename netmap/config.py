"""Carga de config.toml."""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Site:
    id: str
    name: str
    subnets: list[ipaddress.IPv4Network]


@dataclass
class Infra:
    id: str
    name: str
    kind: str = "switch"
    site: str | None = None
    parent: str | None = None
    link: str = "cable"
    ip: str | None = None
    mac: str | None = None
    snmp_community: str | None = None
    uplink_ports: list[str] = field(default_factory=list)
    wifi_clients_command: str | None = None


@dataclass
class Config:
    sites: list[Site]
    infra: list[Infra]
    devices: dict[str, dict]
    scan_interval_minutes: int = 15
    port_scan: bool = True
    use_nmap: bool = True

    def site_for_ip(self, ip: str) -> str | None:
        addr = ipaddress.ip_address(ip)
        for site in self.sites:
            if any(addr in net for net in site.subnets):
                return site.id
        return None

    def all_subnets(self, only_site: str | None = None) -> list[ipaddress.IPv4Network]:
        nets: list[ipaddress.IPv4Network] = []
        for site in self.sites:
            if only_site and site.id != only_site:
                continue
            for net in site.subnets:
                if net not in nets:
                    nets.append(net)
        return nets


def norm_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    hexchars = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    if len(hexchars) != 12:
        return None
    return ":".join(hexchars[i : i + 2] for i in range(0, 12, 2))


def load(path: Path) -> Config:
    raw = tomllib.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    general = raw.get("general", {})

    sites = [
        Site(
            id=s["id"],
            name=s.get("name", s["id"]),
            subnets=[ipaddress.ip_network(n, strict=False) for n in s.get("subnets", [])],
        )
        for s in raw.get("sites", [])
    ]

    infra = []
    for i in raw.get("infra", []):
        known = {k: v for k, v in i.items() if k in Infra.__dataclass_fields__}
        item = Infra(**known)
        item.mac = norm_mac(item.mac)
        item.uplink_ports = [str(p) for p in item.uplink_ports]
        infra.append(item)

    devices = {}
    for d in raw.get("devices", []):
        mac = norm_mac(d.get("mac"))
        key = mac or d.get("ip")
        if key:
            devices[key] = {k: v for k, v in d.items() if k not in ("mac", "ip")}

    return Config(
        sites=sites,
        infra=infra,
        devices=devices,
        scan_interval_minutes=int(general.get("scan_interval_minutes", 15)),
        port_scan=bool(general.get("port_scan", True)),
        use_nmap=bool(general.get("use_nmap", True)),
    )
