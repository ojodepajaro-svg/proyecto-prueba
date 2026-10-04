"""Uso:
    python -m netmap                 abre el dashboard y escanea (lee config.toml)
    python -m netmap scan            escanea una vez y muestra el resultado en la terminal
    python -m netmap demo            dashboard con datos de ejemplo (no escanea nada)
    python -m netmap update-oui      descarga la lista de fabricantes (para ver la marca de cada equipo)
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

from . import config as config_mod
from . import scan, server

ROOT = Path(__file__).resolve().parent.parent
TYPE_ES = {
    "router": "router", "network": "equipo de red", "computer": "computadora", "phone": "celular",
    "tablet": "tablet", "tv": "TV / streaming", "printer": "impresora", "camera": "cámara",
    "console": "consola", "speaker": "parlante", "nas": "NAS / servidor", "iot": "domótica",
    "raspberry": "Raspberry Pi", "unknown": "?",
}


def load_config(path: str | None) -> config_mod.Config:
    p = Path(path) if path else ROOT / "config.toml"
    if not p.exists():
        print(f"(No encontré {p.name}: uso la red de este equipo. Copiá config.example.toml a config.toml para personalizar.)")
    return config_mod.load(p)


def print_table(state: dict) -> None:
    names = {i["id"]: i["name"] for i in state["infra"]}
    print(f"\n{'IP':<16}{'Nombre':<26}{'Tipo':<16}{'Conexión':<12}{'Conectado a':<28}{'Fabricante'}")
    print("─" * 120)
    for d in state["devices"]:
        if not d["online"]:
            continue
        conn = d.get("connection") or "?"
        if conn != "?" and not d.get("confirmed"):
            conn += " (est.)"
        where = names.get(d.get("parent"), d.get("parent") or "")
        if d.get("port"):
            where += f" puerto {d['port']}"
        print(f"{d['ip']:<16}{(d.get('name') or '')[:25]:<26}{TYPE_ES.get(d['type'], d['type']):<16}"
              f"{conn:<12}{where[:27]:<28}{(d.get('vendor') or '')[:30]}")
    for n in state["notes"]:
        print(f"\n⚠ {n.get('infra', '')} {n['message']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="netmap", description="Mapa de la red de casa.")
    ap.add_argument("--config", help="ruta a config.toml")
    sub = ap.add_subparsers(dest="cmd")

    s = sub.add_parser("serve", help="dashboard web (por defecto)")
    s.add_argument("--host", default="127.0.0.1", help="usá 0.0.0.0 para verlo desde el celular")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--token", help="clave para recibir escaneos de otra PC (ver 'scan --upload')")
    s.add_argument("--no-scan", action="store_true", help="no escanear al arrancar")

    sc = sub.add_parser("scan", help="escanear una vez")
    sc.add_argument("--site", help="escanear solo este sitio (p.ej. fondito)")
    sc.add_argument("--json", action="store_true", help="imprimir el resultado crudo en JSON")
    sc.add_argument("--upload", metavar="URL", help="mandar el resultado a un dashboard, p.ej. http://192.168.1.10:8765")
    sc.add_argument("--token", help="clave del dashboard que recibe")

    d = sub.add_parser("demo", help="dashboard con datos de ejemplo")
    d.add_argument("--host", default="127.0.0.1")
    d.add_argument("--port", type=int, default=8765)

    sub.add_parser("update-oui", help="descargar la lista de fabricantes")

    args = ap.parse_args(argv)
    cmd = args.cmd or "serve"

    if cmd == "update-oui":
        print(f"Descargados {scan.discovery.update_oui()} fabricantes.")
        return 0

    if cmd == "demo":
        from . import demo
        scan.set_data_dir(ROOT / "data-demo")
        for f in scan.SCANS_DIR.glob("*.json"):
            f.unlink()
        demo.seed_history(scan.HISTORY_FILE)
        scan.save_scan(demo.fake_scan())
        server.serve(demo.demo_config(), args.host, args.port, demo=True, scan_on_start=False)
        return 0

    cfg = load_config(args.config)

    if cmd == "scan":
        result = scan.run_scan(cfg, only_site=args.site, log=lambda m: print(m, file=sys.stderr))
        if args.upload:
            req = urllib.request.Request(
                args.upload.rstrip("/") + "/api/upload",
                data=json.dumps(result).encode(),
                headers={"Content-Type": "application/json", "X-Token": args.token or ""},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                print(f"Enviado a {args.upload}: {resp.status}", file=sys.stderr)
            return 0
        scan.save_scan(result)
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print_table(scan.build_state(cfg))
        return 0

    if args.host not in ("127.0.0.1", "localhost"):
        print("Ojo: el dashboard no tiene contraseña; cualquiera en tu red puede verlo y editar nombres.")
    server.serve(cfg, args.host, args.port, token=args.token, scan_on_start=not args.no_scan)
    return 0


if __name__ == "__main__":
    sys.exit(main())
