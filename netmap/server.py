"""Servidor web del dashboard (solo biblioteca estándar)."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from . import scan
from .config import Config

STATIC = Path(__file__).resolve().parent / "static"
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}


class Scanner:
    """Corre escaneos en segundo plano, de a uno por vez."""

    def __init__(self, cfg: Config, demo: bool = False):
        self.cfg = cfg
        self.demo = demo
        self.running = False
        self.log: list[str] = []
        self.error: str | None = None
        self._lock = threading.Lock()

    def start(self) -> bool:
        with self._lock:
            if self.running:
                return False
            self.running = True
        threading.Thread(target=self._run, daemon=True).start()
        return True

    def _run(self) -> None:
        self.log, self.error = [], None
        try:
            if self.demo:
                from . import demo
                time.sleep(2)
                scan.save_scan(demo.fake_scan())
            else:
                scan.save_scan(scan.run_scan(self.cfg, log=self.log.append))
        except Exception as exc:  # noqa: BLE001 - se muestra en el dashboard
            self.error = f"{type(exc).__name__}: {exc}"
        finally:
            self.running = False

    def loop(self) -> None:
        minutes = self.cfg.scan_interval_minutes
        while minutes > 0:
            time.sleep(minutes * 60)
            self.start()


def make_handler(cfg: Config, scanner: Scanner, token: str | None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # silencio
            pass

        def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8") -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, data) -> None:
            self._send(code, json.dumps(data, ensure_ascii=False).encode())

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 20_000_000:
                raise ValueError("demasiado grande")
            return json.loads(self.rfile.read(length) or b"{}")

        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/api/state":
                state = scan.build_state(cfg)
                state["scanning"] = scanner.running
                state["scan_log"] = scanner.log[-5:]
                state["scan_error"] = scanner.error
                state["demo"] = scanner.demo
                return self._json(200, state)
            name = "index.html" if path in ("/", "") else path.lstrip("/")
            file = (STATIC / name).resolve()
            if STATIC not in file.parents or not file.is_file():
                return self._send(404, b"no encontrado", "text/plain")
            self._send(200, file.read_bytes(), TYPES.get(file.suffix, "application/octet-stream"))

        def do_POST(self):
            path = self.path.split("?")[0]
            try:
                if path == "/api/scan":
                    started = scanner.start()
                    return self._json(202, {"started": started})
                if path == "/api/upload":
                    if not token or self.headers.get("X-Token") != token:
                        return self._json(403, {"error": "token inválido (iniciá el servidor con --token)"})
                    data = self._body()
                    if not isinstance(data.get("hosts"), list):
                        return self._json(400, {"error": "formato inválido"})
                    scan.save_scan(data)
                    return self._json(200, {"ok": True})
                if path.startswith("/api/device/"):
                    key = unquote(path[len("/api/device/"):])
                    body = self._body()
                    if body.get("forget"):
                        scan.forget_device(key)
                    else:
                        scan.save_override(key, body)
                    return self._json(200, {"ok": True})
            except (ValueError, json.JSONDecodeError) as exc:
                return self._json(400, {"error": str(exc)})
            self._json(404, {"error": "no encontrado"})

    return Handler


def serve(cfg: Config, host: str, port: int, demo: bool = False, token: str | None = None, scan_on_start: bool = True) -> None:
    scanner = Scanner(cfg, demo=demo)
    if scan_on_start:
        scanner.start()
    threading.Thread(target=scanner.loop, daemon=True).start()
    httpd = ThreadingHTTPServer((host, port), make_handler(cfg, scanner, token))
    shown = "localhost" if host in ("127.0.0.1", "0.0.0.0") else host
    print(f"Dashboard en http://{shown}:{port}  (Ctrl+C para salir)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nChau.")
