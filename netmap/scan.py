"""Orquesta un escaneo y arma el estado que muestra el dashboard."""

from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from pathlib import Path

from . import classify, discovery, infra as infra_mod
from .config import Config, Infra, Site

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
SCANS_DIR = DATA_DIR / "scans"
HISTORY_FILE = DATA_DIR / "history.json"
OVERRIDES_FILE = DATA_DIR / "overrides.json"
NEW_DEVICE_SECONDS = 24 * 3600

_lock = threading.Lock()


def set_data_dir(path: Path) -> None:
    global DATA_DIR, SCANS_DIR, HISTORY_FILE, OVERRIDES_FILE
    DATA_DIR = path
    SCANS_DIR = path / "scans"
    HISTORY_FILE = path / "history.json"
    OVERRIDES_FILE = path / "overrides.json"


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def device_key(d: dict) -> str:
    return d.get("mac") or f"ip:{d['ip']}"


def ensure_sites(cfg: Config) -> None:
    """Sin sitios configurados, usa la red /24 de este equipo como 'Casa'."""
    if cfg.sites:
        return
    ip = discovery.local_ip()
    if ip:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        cfg.sites.append(Site(id="casa", name="Casa", subnets=[net]))


# ── Escaneo ──────────────────────────────────────────────────────────────

def run_scan(cfg: Config, only_site: str | None = None, log=print) -> dict:
    """Escanea las subredes de los sitios y devuelve los resultados crudos."""
    ensure_sites(cfg)
    nets = cfg.all_subnets(only_site)
    started = time.time()
    me_ip = discovery.local_ip()
    gateway = discovery.default_gateway()
    use_nmap = cfg.use_nmap and discovery.has_nmap()
    notes: list[dict] = []
    log(f"Escaneando {', '.join(map(str, nets))} con {'nmap' if use_nmap else 'ping + ARP'}...")

    hosts: dict[str, dict] = {}
    if use_nmap:
        hosts = discovery.nmap_scan(nets, ports=cfg.port_scan)
        if not discovery.is_root():
            notes.append({"message": "nmap corre sin permisos de administrador: corré con sudo para detectar más equipos, fabricantes y sistema operativo."})
    if not use_nmap or not discovery.is_root():
        for ip in discovery.ping_sweep(nets):
            hosts.setdefault(ip, {"ip": ip})
    if not discovery.has_nmap():
        notes.append({"message": "nmap no está instalado: el escaneo funciona igual, pero con nmap se identifican mejor los equipos."})

    # La tabla ARP agrega equipos que no responden al ping (muchos celulares) y sus MAC.
    for ip, mac in discovery.arp_table().items():
        if any(ipaddress.ip_address(ip) in n for n in nets):
            hosts.setdefault(ip, {"ip": ip})
            if not hosts[ip].get("mac"):
                hosts[ip]["mac"] = mac

    if me_ip and any(ipaddress.ip_address(me_ip) in n for n in nets):
        iface = discovery.local_interface(me_ip)
        me = hosts.setdefault(me_ip, {"ip": me_ip})
        me.update({"is_self": True, "hostname": me.get("hostname") or socket.gethostname()})
        me["mac"] = me.get("mac") or iface["mac"]
        if iface["connection"]:
            me["self_connection"] = iface["connection"]

    ips = sorted(hosts, key=lambda i: ipaddress.ip_address(i))
    log(f"{len(ips)} equipos responden. Buscando nombres y servicios...")
    for ip, name in discovery.reverse_dns([i for i in ips if not hosts[i].get("hostname")]).items():
        hosts[ip]["hostname"] = name
    if cfg.port_scan and not use_nmap:
        for ip, ports in discovery.tcp_probe(ips).items():
            hosts[ip]["ports"] = ports

    for ip in ips:
        h = hosts[ip]
        h.setdefault("ports", [])
        h["vendor"] = h.get("vendor") or discovery.vendor_for(h.get("mac"))
        h["is_gateway"] = ip == gateway
        h["randomized_mac"] = discovery.is_randomized_mac(h.get("mac"))

    infra_found, infra_notes = infra_mod.query_all([i for i in cfg.infra])
    notes += infra_notes

    log(f"Listo en {time.time() - started:.0f}s.")
    return {
        "scanner": socket.gethostname(),
        "scanner_ip": me_ip,
        "gateway": gateway,
        "sites": [only_site] if only_site else [s.id for s in cfg.sites],
        "method": "nmap" if use_nmap else "ping+arp",
        "root": discovery.is_root(),
        "started_at": started,
        "finished_at": time.time(),
        "hosts": [hosts[i] for i in ips],
        "infra_found": infra_found,
        "notes": notes,
    }


def save_scan(result: dict) -> None:
    """Guarda el escaneo y actualiza el historial de equipos vistos."""
    with _lock:
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in result.get("scanner", "local"))
        _write_json(SCANS_DIR / f"{safe}.json", result)
        history = _read_json(HISTORY_FILE, {})
        now = result.get("finished_at", time.time())
        for h in result["hosts"]:
            key = device_key(h)
            rec = history.get(key, {"first_seen": now})
            rec.update({k: v for k, v in h.items() if v not in (None, [], {})})
            rec["last_seen"] = now
            history[key] = rec
        _write_json(HISTORY_FILE, history)


def load_overrides() -> dict:
    return _read_json(OVERRIDES_FILE, {})


def save_override(key: str, changes: dict) -> None:
    allowed = {"name", "type", "connection", "parent", "port", "site", "notes"}
    with _lock:
        data = load_overrides()
        rec = data.get(key, {})
        for k, v in changes.items():
            if k not in allowed:
                continue
            if v in (None, ""):
                rec.pop(k, None)
            else:
                rec[k] = str(v)
        if rec:
            data[key] = rec
        else:
            data.pop(key, None)
        _write_json(OVERRIDES_FILE, data)


def forget_device(key: str) -> None:
    with _lock:
        history = _read_json(HISTORY_FILE, {})
        history.pop(key, None)
        _write_json(HISTORY_FILE, history)


# ── Estado para el dashboard ─────────────────────────────────────────────

def build_state(cfg: Config) -> dict:
    ensure_sites(cfg)
    scans = [_read_json(p, None) for p in sorted(SCANS_DIR.glob("*.json"))]
    scans = [s for s in scans if s]
    history = _read_json(HISTORY_FILE, {})
    overrides = load_overrides()
    now = time.time()

    online: dict[str, dict] = {}
    infra_found: dict[str, dict] = {}
    gateways: dict[str, str] = {}
    notes: list[dict] = []
    for s in scans:
        for h in s["hosts"]:
            online[device_key(h)] = h
        infra_found.update(s.get("infra_found", {}))
        if s.get("gateway"):
            for site_id in s.get("sites", []):
                gateways.setdefault(site_id, s["gateway"])
        notes += [{**n, "scanner": s["scanner"]} for n in s.get("notes", [])]

    # Infraestructura: la del config, más un router automático por sitio si falta.
    infra: list[Infra] = list(cfg.infra)
    for site in cfg.sites:
        gw = gateways.get(site.id)
        has_root = any(i.site == site.id and not i.parent for i in infra)
        if gw and not any(i.ip == gw for i in infra) and not has_root:
            infra.append(Infra(id=f"router-{site.id}", name=f"Router ({site.name})", kind="router", site=site.id, ip=gw))
    by_id = {i.id: i for i in infra}

    def root_for(site_id: str | None) -> str | None:
        same = [i for i in infra if i.site == site_id]
        for pool in (same, infra):
            for i in pool:
                if i.kind == "router" and not i.parent:
                    return i.id
            if pool:
                return pool[0].id
        return None

    def site_of_infra(i: Infra) -> str | None:
        seen = set()
        while i and i.id not in seen:
            if i.site:
                return i.site
            seen.add(i.id)
            i = by_id.get(i.parent)
        return None

    baseline = min((h.get("first_seen", now) for h in history.values()), default=now)
    devices = []
    infra_status: dict[str, dict] = {}
    for key in set(history) | set(online):
        d = {**history.get(key, {}), **online.get(key, {})}
        if "ip" not in d:
            continue
        d["key"] = key
        d["online"] = key in online
        d["first_seen"] = history.get(key, {}).get("first_seen", now)
        d["last_seen"] = history.get(key, {}).get("last_seen", now)
        # "Nuevo" = apareció en las últimas 24 h, pero no en el primer escaneo de todos.
        d["is_new"] = now - d["first_seen"] < NEW_DEVICE_SECONDS and d["first_seen"] - baseline > 600

        # ¿Es uno de los routers/switches/APs?
        match = next((i for i in infra if (i.mac and i.mac == d.get("mac")) or (i.ip and i.ip == d["ip"])), None)
        if match:
            infra_status[match.id] = {"online": d["online"], "ip": d["ip"], "mac": d.get("mac"), "vendor": d.get("vendor")}
            continue

        manual = {**cfg.devices.get(key, {}), **cfg.devices.get(d["ip"], {}), **overrides.get(key, {})}
        found = infra_found.get(d.get("mac") or "", {})

        d["type"] = manual.get("type") or classify.guess_type(d)
        d["name"] = manual.get("name") or d.get("hostname") or ""
        d["notes"] = manual.get("notes", "")
        d["parent"] = manual.get("parent") or found.get("parent")
        d["port"] = manual.get("port") or found.get("port")

        if manual.get("connection"):
            d["connection"], d["connection_source"], d["confirmed"] = manual["connection"], "marcado a mano", True
        elif found.get("connection"):
            d["connection"], d["connection_source"], d["confirmed"] = found["connection"], found["source"], True
        elif d.get("self_connection"):
            d["connection"], d["connection_source"], d["confirmed"] = d["self_connection"], "interfaz de este equipo", True
        else:
            conn, why = classify.guess_connection(d)
            d["connection"], d["connection_source"], d["confirmed"] = conn, why, False
            if found.get("port_shared"):
                d["connection_source"] = (
                    f"en el puerto {found['port']} hay {found['port_shared']} equipos: "
                    "detrás hay un switch o AP sin administrar" + (f"; {why}" if why else "")
                )

        parent = by_id.get(d["parent"]) if d["parent"] else None
        d["site"] = manual.get("site") or (site_of_infra(parent) if parent else None) or cfg.site_for_ip(d["ip"])
        if not parent:
            d["parent"] = root_for(d["site"])
            d["parent_guessed"] = True
        devices.append(d)

    devices.sort(key=lambda x: (not x["online"], ipaddress.ip_address(x["ip"])))
    last = max((s.get("finished_at", 0) for s in scans), default=None)
    return {
        "generated_at": now,
        "last_scan": last,
        "scanners": [
            {k: s.get(k) for k in ("scanner", "scanner_ip", "method", "root", "finished_at", "sites")}
            for s in scans
        ],
        "notes": notes,
        "sites": [{"id": s.id, "name": s.name, "subnets": [str(n) for n in s.subnets]} for s in cfg.sites],
        "infra": [
            {
                "id": i.id, "name": i.name, "kind": i.kind, "site": site_of_infra(i),
                "parent": i.parent, "link": i.link, "ip": i.ip or infra_status.get(i.id, {}).get("ip"),
                "mac": i.mac or infra_status.get(i.id, {}).get("mac"),
                "vendor": infra_status.get(i.id, {}).get("vendor"),
                "online": infra_status.get(i.id, {}).get("online"),
                "managed": bool(i.snmp_community or i.wifi_clients_command),
            }
            for i in infra
        ],
        "devices": devices,
    }
