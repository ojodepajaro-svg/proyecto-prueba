"""Consulta a routers, switches y APs: qué MAC está en qué puerto o en el wifi."""

from __future__ import annotations

import shutil
from collections import defaultdict

from .config import Infra, norm_mac
from .discovery import MAC_RE, run

OID_BASEPORT_IFINDEX = ".1.3.6.1.2.1.17.1.4.1.2"
OID_DOT1D_FDB_PORT = ".1.3.6.1.2.1.17.4.3.1.2"
OID_DOT1Q_FDB_PORT = ".1.3.6.1.2.1.17.7.1.2.2.1.2"
OID_IFNAME = ".1.3.6.1.2.1.31.1.1.1.1"


def _walk(host: str, community: str, oid: str) -> list[tuple[list[int], str]]:
    out = run(["snmpwalk", "-v2c", "-c", community, "-On", "-Oq", "-t", "2", host, oid], timeout=60)
    rows = []
    for line in out.splitlines():
        if not line.startswith(oid + "."):
            continue
        oid_part, _, value = line.partition(" ")
        suffix = [int(x) for x in oid_part[len(oid) + 1 :].split(".") if x.isdigit()]
        rows.append((suffix, value.strip().strip('"')))
    return rows


def snmp_fdb(item: Infra) -> tuple[dict[str, str], str | None]:
    """MAC -> nombre de puerto de un switch administrable. Devuelve (tabla, error)."""
    if not shutil.which("snmpwalk"):
        return {}, "falta el comando snmpwalk (instalá net-snmp / snmp)"
    community = item.snmp_community or "public"
    bridge_to_if = {s[0]: v for s, v in _walk(item.ip, community, OID_BASEPORT_IFINDEX) if s}
    if_names = {str(s[0]): v for s, v in _walk(item.ip, community, OID_IFNAME) if s}

    port_of: dict[str, str] = {}
    for oid, offset in ((OID_DOT1Q_FDB_PORT, 1), (OID_DOT1D_FDB_PORT, 0)):
        for suffix, value in _walk(item.ip, community, oid):
            mac_octets = suffix[offset : offset + 6]
            if len(mac_octets) != 6 or not value.isdigit():
                continue
            mac = ":".join(f"{o:02x}" for o in mac_octets)
            bport = int(value)
            ifindex = bridge_to_if.get(bport, str(bport))
            port_of.setdefault(mac, if_names.get(str(ifindex), str(bport)))
        if port_of:
            break
    if not port_of and not bridge_to_if:
        return {}, "no respondió por SNMP (¿comunidad correcta? ¿SNMP activado?)"

    # Los puertos de subida (hacia otro switch/router) ven muchas MAC: se ignoran.
    uplinks = set(item.uplink_ports)
    if not uplinks:
        counts: dict[str, int] = defaultdict(int)
        for p in port_of.values():
            counts[p] += 1
        uplinks = {p for p, c in counts.items() if c >= 8}
    return {m: p for m, p in port_of.items() if p not in uplinks}, None


def wifi_clients(item: Infra) -> tuple[set[str], str | None]:
    out = run(item.wifi_clients_command, timeout=60, shell=True)
    macs = {norm_mac(m.group(0)) for m in MAC_RE.finditer(out)}
    macs.discard(None)
    if not macs and out.strip():
        return set(), "el comando no devolvió ninguna MAC: " + out.strip()[:200]
    return macs, None


def query_all(infra: list[Infra]) -> tuple[dict[str, dict], list[dict]]:
    """Devuelve mac -> {connection, parent, port, source} y una lista de avisos."""
    found: dict[str, dict] = {}
    notes: list[dict] = []

    # Primero el wifi: es la información más firme.
    for item in infra:
        if not item.wifi_clients_command:
            continue
        macs, err = wifi_clients(item)
        if err:
            notes.append({"infra": item.id, "message": err})
        for mac in macs:
            found[mac] = {"connection": "wifi", "parent": item.id, "source": f"wifi de {item.name}"}

    # Después los switches: si una MAC está en un puerto de acceso, es cable
    # (salvo que ya la hayamos visto en un AP, en cuyo caso ese puerto es del AP).
    candidates: dict[str, list[tuple[Infra, str, int]]] = defaultdict(list)
    for item in infra:
        if not (item.snmp_community and item.ip):
            continue
        table, err = snmp_fdb(item)
        if err:
            notes.append({"infra": item.id, "message": err})
        per_port: dict[str, int] = defaultdict(int)
        for port in table.values():
            per_port[port] += 1
        for mac, port in table.items():
            candidates[mac].append((item, port, per_port[port]))

    for mac, options in candidates.items():
        if mac in found:
            continue
        # El puerto con menos MAC aprendidas es el más cercano al equipo.
        item, port, shared = min(options, key=lambda o: o[2])
        entry = {"parent": item.id, "port": port, "source": f"SNMP de {item.name}"}
        if shared == 1:
            entry["connection"] = "cable"
        else:
            # Varias MAC en el mismo puerto: detrás hay un switch o AP sin administrar,
            # así que no sabemos si este equipo va por cable o por wifi.
            entry["port_shared"] = shared
        found[mac] = entry
    return found, notes
