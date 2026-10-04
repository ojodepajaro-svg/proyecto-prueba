"""Adivina qué es cada equipo y, si no hay datos firmes, cómo se conecta."""

from __future__ import annotations

from .discovery import is_randomized_mac

# (tipo, palabras en hostname/fabricante/SO/servicios)
TYPE_HINTS: list[tuple[str, tuple[str, ...]]] = [
    ("camera", ("hikvision", "dahua", "ezviz", "imou", "reolink", "camera", "cam-", "ipcam", "wyze", "tapo c")),
    ("printer", ("printer", "epson", "brother", "canon", "hewlett", "hp-", "laserjet", "deskjet", "officejet", "ipp", "jetdirect")),
    ("tv", ("tv", "bravia", "roku", "webos", "tizen", "chromecast", "firetv", "fire-tv", "shield", "vizio", "hisense", "tcl")),
    ("console", ("playstation", "ps4", "ps5", "xbox", "nintendo", "switch-")),
    ("speaker", ("sonos", "echo", "alexa", "homepod", "google-home", "nest-mini", "nest-audio")),
    ("phone", ("iphone", "android", "galaxy", "pixel", "redmi", "moto", "huawei-p", "oneplus", "xiaomi-", "-phone")),
    ("tablet", ("ipad", "tab-", "-tab", "galaxy-tab", "kindle", "fire-")),
    ("nas", ("synology", "qnap", "diskstation", "nas", "truenas", "unraid")),
    ("iot", ("espressif", "esp-", "esp32", "esp8266", "tuya", "shelly", "sonoff", "tasmota", "broadlink", "smartlife", "wiz", "yeelight", "philips lighting", "hue")),
    ("raspberry", ("raspberry", "raspberrypi")),
    ("network", ("tp-link", "tplink", "ubiquiti", "mikrotik", "netgear", "d-link", "linksys", "zyxel", "tenda", "mercusys", "openwrt", "unifi", "deco", "eero", "asus router")),
    ("computer", ("desktop-", "laptop", "macbook", "imac", "mac-mini", "thinkpad", "notebook", "-pc", "windows", "dell", "lenovo", "intel corporate", "msi", "acer")),
]

# Tipos que casi siempre van por wifi / por cable.
WIFI_TYPES = {"phone", "tablet", "iot", "speaker"}
CABLE_TYPES = {"nas", "printer"}


def guess_type(d: dict) -> str:
    ports = set(d.get("ports") or [])
    text = " ".join(
        str(x).lower()
        for x in (d.get("hostname"), d.get("vendor"), d.get("os"), *(d.get("services") or {}).values())
        if x
    )
    if d.get("is_gateway"):
        return "router"
    if d.get("is_self"):
        return "computer"
    if 62078 in ports:
        return "phone"  # servicio de sincronización de iPhone/iPad
    if ports & {9100, 515, 631} and not ports & {22, 445}:
        return "printer"
    if ports & {554, 8554} and not ports & {445, 22}:
        return "camera"
    if ports & {8008, 8009}:
        return "tv"
    if 1400 in ports:
        return "speaker"
    if 32400 in ports:
        return "nas"
    for kind, words in TYPE_HINTS:
        if any(w in text for w in words):
            return kind
    if 3389 in ports or (ports & {139, 445}):
        return "computer"
    if 53 in ports and ports & {80, 443}:
        return "network"
    if 22 in ports:
        return "computer"
    if is_randomized_mac(d.get("mac")):
        return "phone"
    return "unknown"


def guess_connection(d: dict) -> tuple[str | None, str | None]:
    """Estimación cuando no hay datos del router/switch. Devuelve (conexión, motivo)."""
    if is_randomized_mac(d.get("mac")):
        return "wifi", "MAC privada/aleatoria: la usan celulares y notebooks por wifi"
    kind = d.get("type")
    if kind in WIFI_TYPES:
        return "wifi", "por el tipo de equipo"
    if kind in CABLE_TYPES:
        return "cable", "por el tipo de equipo"
    return None, None
