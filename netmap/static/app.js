"use strict";

const TYPES = {
  router: ["📡", "Router"], network: ["🔀", "Equipo de red"], computer: ["💻", "Computadora"],
  phone: ["📱", "Celular"], tablet: ["📱", "Tablet"], tv: ["📺", "TV / streaming"],
  printer: ["🖨️", "Impresora"], camera: ["📷", "Cámara"], console: ["🎮", "Consola"],
  speaker: ["🔊", "Parlante"], nas: ["🗄️", "NAS / servidor"], iot: ["💡", "Domótica"],
  raspberry: ["🍓", "Raspberry Pi"], unknown: ["❔", "Desconocido"],
};
const INFRA_KINDS = { router: ["📡", "Router"], switch: ["🔀", "Switch"], ap: ["📶", "Access point"], repeater: ["📶", "Repetidor"] };
const SERVICES = {
  22: "SSH", 23: "Telnet", 53: "DNS", 80: "Web", 135: "Windows", 139: "Compartir archivos", 443: "Web segura",
  445: "Compartir archivos", 515: "Impresión", 548: "AFP", 554: "Video (RTSP)", 631: "Impresión",
  1400: "Sonos", 1883: "MQTT", 3000: "Web", 3389: "Escritorio remoto", 5000: "Web/AirPlay",
  7000: "AirPlay", 8000: "Web", 8008: "Chromecast", 8009: "Chromecast", 8080: "Web", 8443: "Web segura",
  8554: "Video (RTSP)", 9100: "Impresión", 32400: "Plex", 62078: "iPhone/iPad",
};

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

let state = null;
let site = localGet("site") || "";
let sort = { key: "ip", dir: "asc" };
let pollTimer = null;

function localGet(k) { try { return localStorage.getItem("netmap." + k); } catch { return null; } }
function localSet(k, v) { try { localStorage.setItem("netmap." + k, v); } catch { /* sin storage */ } }

// ── Datos ────────────────────────────────────────────────────────────────

async function load() {
  try {
    const r = await fetch("api/state");
    state = await r.json();
    render();
  } catch (e) {
    $("#lastScan").textContent = "No me puedo conectar con el escáner. ¿Está corriendo?";
  }
  clearTimeout(pollTimer);
  pollTimer = setTimeout(load, state && state.scanning ? 2000 : 30000);
}

async function startScan() {
  await fetch("api/scan", { method: "POST" });
  load();
}

function ipNum(ip) { return ip.split(".").reduce((a, b) => a * 256 + +b, 0); }
function infraById(id) { return state.infra.find((i) => i.id === id); }
function infraName(id) { const i = infraById(id); return i ? i.name : id || ""; }
function siteName(id) { const s = state.sites.find((x) => x.id === id); return s ? s.name : id || ""; }
function typeOf(d) { return TYPES[d.type] || TYPES.unknown; }
function label(d) { return d.name || d.hostname || d.vendor || d.ip; }

function ago(ts) {
  if (!ts) return "";
  const s = Date.now() / 1000 - ts;
  if (s < 90) return "recién";
  if (s < 3600) return `hace ${Math.round(s / 60)} min`;
  if (s < 86400) return `hace ${Math.round(s / 3600)} h`;
  const d = Math.round(s / 86400);
  return `hace ${d} día${d > 1 ? "s" : ""}`;
}
function dateStr(ts) { return ts ? new Date(ts * 1000).toLocaleString("es-AR", { dateStyle: "short", timeStyle: "short" }) : ""; }

function inSite(d) { return !site || d.site === site; }
function connKey(d) { return d.connection || "none"; }

// ── Render ───────────────────────────────────────────────────────────────

function render() {
  const scanning = state.scanning;
  $("#demoBadge").hidden = !state.demo;
  const btn = $("#scanBtn");
  btn.disabled = scanning;
  btn.querySelector(".spinner").hidden = !scanning;
  btn.querySelector(".label").textContent = scanning ? "Escaneando…" : "Escanear ahora";

  let sub = state.last_scan ? `Último escaneo ${ago(state.last_scan)} (${dateStr(state.last_scan)})` : "Todavía no hay escaneos";
  if (scanning && state.scan_log.length) sub = state.scan_log[state.scan_log.length - 1];
  $("#lastScan").textContent = sub;

  const notes = [...state.notes.map((n) => n.message)];
  if (state.scan_error) notes.unshift("Error en el escaneo: " + state.scan_error);
  $("#notes").innerHTML = notes.map((n) => `<div class="note">⚠️ ${esc(n)}</div>`).join("");

  renderTabs();
  renderTiles();
  renderTree();
  renderTable();
}

function renderTabs() {
  const opts = [{ id: "", name: "Todo" }, ...state.sites];
  $("#siteTabs").hidden = state.sites.length < 2;
  if (site && !state.sites.some((s) => s.id === site)) site = "";
  $("#siteTabs").innerHTML = opts
    .map((s) => `<button data-site="${esc(s.id)}" aria-pressed="${s.id === site}">${esc(s.name)}</button>`)
    .join("");
}

function renderTiles() {
  const devs = state.devices.filter(inSite);
  const on = devs.filter((d) => d.online);
  const est = (c) => on.filter((d) => d.connection === c && !d.confirmed).length;
  const tiles = [
    { k: "En línea", v: on.length, h: `${state.sites.length > 1 && !site ? "en todos los sitios" : siteName(site) || "en la red"}`, icon: `<span class="dot on"></span>`, f: { state: "online", conn: "" } },
    { k: "Por cable", v: on.filter((d) => d.connection === "cable").length, h: est("cable") ? `${est("cable")} estimados` : "confirmados", icon: `<span class="swatch" style="background:var(--cable)"></span>`, f: { state: "online", conn: "cable" } },
    { k: "Por wifi", v: on.filter((d) => d.connection === "wifi").length, h: est("wifi") ? `${est("wifi")} estimados` : "confirmados", icon: `<span class="swatch" style="background:var(--wifi)"></span>`, f: { state: "online", conn: "wifi" } },
    { k: "Sin saber", v: on.filter((d) => !d.connection).length, h: "cable o wifi", icon: `<span class="swatch" style="background:var(--unknown)"></span>`, f: { state: "online", conn: "none" } },
    { k: "Nuevos", v: devs.filter((d) => d.is_new).length, h: "últimas 24 h", icon: "🆕", f: { state: "new", conn: "" } },
    { k: "Desconectados", v: devs.filter((d) => !d.online).length, h: "vistos antes", icon: `<span class="dot off"></span>`, f: { state: "offline", conn: "" } },
  ];
  $("#tiles").innerHTML = tiles
    .map((t, i) => `<button class="tile" data-tile="${i}"><div class="k">${t.icon} ${esc(t.k)}</div><div class="v">${t.v}</div><div class="h">${esc(t.h)}</div></button>`)
    .join("");
  $("#tiles").onclick = (e) => {
    const b = e.target.closest("[data-tile]");
    if (!b) return;
    const f = tiles[+b.dataset.tile].f;
    $("#fState").value = f.state;
    $("#fConn").value = f.conn;
    renderTable();
    $("#table").scrollIntoView({ behavior: "smooth", block: "start" });
  };
}

function chip(d) {
  const [ic] = typeOf(d);
  const cls = [d.confirmed ? connKey(d) : "", d.online ? "" : "offline", d.is_new ? "is-new" : ""].join(" ");
  const port = d.port ? `<span class="port">puerto ${esc(d.port)}</span>` : "";
  const tags = (d.is_self ? `<span class="port">este equipo</span>` : "") + (d.is_new ? `<span class="port">nuevo</span>` : "");
  return `<button class="chip ${cls}" data-key="${esc(d.key)}" title="${esc(typeOf(d)[1])} · ${esc(d.ip)}${d.vendor ? " · " + esc(d.vendor) : ""}">
    <span>${ic}</span><span class="nm">${esc(label(d))}</span><span class="ip">.${esc(d.ip.split(".").pop())}</span>${port}${tags}</button>`;
}

const GROUPS = [
  { test: (d) => d.connection === "cable" && d.confirmed, label: "Por cable", line: "cable" },
  { test: (d) => d.connection === "wifi" && d.confirmed, label: "Por wifi", line: "wifi" },
  { test: (d) => d.connection === "cable" && !d.confirmed, label: "Cable (estimado)", line: "unknown" },
  { test: (d) => d.connection === "wifi" && !d.confirmed, label: "Wifi (estimado)", line: "unknown" },
  { test: (d) => !d.connection, label: "Sin saber si es cable o wifi", line: "unknown" },
];

function renderTree() {
  const devs = state.devices.filter((d) => d.online && inSite(d));
  const byParent = {};
  for (const d of devs) (byParent[d.parent] ||= []).push(d);

  const infra = state.infra;
  const visible = new Set();
  // Un equipo de red se muestra si es del sitio elegido o si algo del sitio cuelga de él.
  const mark = (id) => { for (let i = infraById(id); i && !visible.has(i.id); i = infraById(i.parent)) visible.add(i.id); };
  for (const i of infra) if (!site || i.site === site) mark(i.id);
  for (const d of devs) if (d.parent) mark(d.parent);

  const kids = (id) => infra.filter((i) => i.parent === id && visible.has(i.id));
  const roots = infra.filter((i) => visible.has(i.id) && (!i.parent || !infraById(i.parent) || !visible.has(i.parent)));

  const count = (id) => (byParent[id] || []).length + kids(id).reduce((a, k) => a + count(k.id), 0);

  const node = (i, isRoot) => {
    const [ic, kindName] = INFRA_KINDS[i.kind] || ["🔀", i.kind];
    const status = i.online === true ? `<span class="dot on" title="responde"></span>` : i.online === false ? `<span class="dot off" title="no responde"></span>` : "";
    const meta = [kindName, i.ip, i.vendor, site && i.site && i.site !== site ? siteName(i.site) : null].filter(Boolean).join(" · ");
    const children = kids(i.id).map((k) => node(k, false)).join("");
    const mine = byParent[i.id] || [];
    const groups = GROUPS.map((g) => {
      const items = mine.filter(g.test).sort((a, b) => (a.port || "").localeCompare(b.port || "", undefined, { numeric: true }) || ipNum(a.ip) - ipNum(b.ip));
      if (!items.length) return "";
      return `<li class="${g.line}"><div class="group-label" style="padding-left:0">${esc(g.label)} · ${items.length}</div><div class="chips" style="padding-left:0">${items.map(chip).join("")}</div></li>`;
    }).join("");
    const n = count(i.id);
    return `<li class="${isRoot ? "" : i.link === "wifi" ? "wifi" : "cable"}">
      <div class="node infra ${i.online === false ? "offline" : ""}">${status}<span class="ic">${ic}</span>
        <span>${esc(i.name)}<br><span class="meta">${esc(meta)}</span></span>
        <span class="meta">${n} equipo${n === 1 ? "" : "s"}</span></div>
      ${children || groups ? `<ul>${children}${groups}</ul>` : ""}</li>`;
  };

  let html = roots.map((r) => node(r, true)).join("");
  const orphans = devs.filter((d) => !d.parent || !infraById(d.parent));
  if (orphans.length) {
    html += `<li><div class="node infra"><span class="ic">❔</span><span>Sin ubicar</span></div><ul><li class="unknown"><div class="chips" style="padding-left:0">${orphans.map(chip).join("")}</div></li></ul></li>`;
  }
  const internet = `<div class="node infra" style="margin-bottom:6px"><span class="ic">🌐</span><span>Internet</span></div>`;
  $("#tree").innerHTML = html ? internet + `<ul>${html}</ul>` : `<p class="empty">Todavía no hay equipos. Tocá “Escanear ahora”.</p>`;
  $("#tree").onclick = (e) => { const c = e.target.closest("[data-key]"); if (c) openDevice(c.dataset.key); };
}

function connCell(d) {
  if (!d.connection) return `<span class="conn"><span class="swatch" style="background:var(--unknown)"></span>Sin saber</span>`;
  const name = d.connection === "cable" ? "Cable" : "Wifi";
  return `<span class="conn"><span class="swatch" style="background:var(--${d.connection})"></span>${name}${d.confirmed ? "" : " <small>(estimado)</small>"}</span>`;
}

function renderTable() {
  const q = $("#q").value.trim().toLowerCase();
  const fc = $("#fConn").value;
  const fs = $("#fState").value;
  let rows = state.devices.filter(inSite).filter((d) => {
    if (fs === "online" && !d.online) return false;
    if (fs === "offline" && d.online) return false;
    if (fs === "new" && !d.is_new) return false;
    if (fc && connKey(d) !== fc) return false;
    if (q) {
      const hay = [d.ip, d.name, d.hostname, d.mac, d.vendor, typeOf(d)[1], infraName(d.parent), d.os, d.notes].join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const val = (d) => {
    switch (sort.key) {
      case "ip": return ipNum(d.ip);
      case "name": return label(d).toLowerCase();
      case "type": return typeOf(d)[1];
      case "connection": return connKey(d);
      case "parent": return infraName(d.parent) + (d.port || "").padStart(4, "0");
      case "last_seen": return d.online ? Infinity : d.last_seen || 0;
      default: return (d[sort.key] || "").toString().toLowerCase();
    }
  };
  rows.sort((a, b) => { const x = val(a), y = val(b); return (x < y ? -1 : x > y ? 1 : 0) * (sort.dir === "asc" ? 1 : -1); });
  document.querySelectorAll("th[data-sort]").forEach((th) => { th.dataset.dir = th.dataset.sort === sort.key ? sort.dir : ""; });

  $("#table tbody").innerHTML = rows.map((d) => {
    const [ic, tname] = typeOf(d);
    const svcs = [...new Set((d.ports || []).map((p) => SERVICES[p] || `:${p}`))];
    const where = d.parent ? esc(infraName(d.parent)) + (d.port ? ` <span class="port">puerto ${esc(d.port)}</span>` : "") + (d.parent_guessed ? ` <small style="color:var(--muted)">(supuesto)</small>` : "") : "";
    const sub = d.name && d.hostname && d.name !== d.hostname ? `<div class="hn">${esc(d.hostname)}</div>` : "";
    return `<tr data-key="${esc(d.key)}" class="${d.online ? "" : "offline"}">
      <td class="mono">${esc(d.ip)}</td>
      <td class="nm-cell">${esc(label(d))} ${d.is_new ? `<span class="badge new">nuevo</span>` : ""}${d.is_self ? ` <span class="badge">este equipo</span>` : ""}${sub}</td>
      <td>${ic} ${esc(tname)}</td>
      <td>${connCell(d)}</td>
      <td>${where}</td>
      <td>${esc(d.vendor || (d.randomized_mac ? "MAC privada" : ""))}</td>
      <td class="mono">${esc(d.mac || "")}</td>
      <td><div class="svc">${svcs.map((s) => `<span>${esc(s)}</span>`).join("")}</div></td>
      <td>${d.online ? `<span class="conn"><span class="dot on"></span>En línea</span>` : `<span class="conn"><span class="dot off"></span>${esc(ago(d.last_seen))}</span>`}</td>
    </tr>`;
  }).join("");
  $("#emptyTable").hidden = rows.length > 0;
}

// ── Detalle / edición ────────────────────────────────────────────────────

let current = null;
let initialForm = {};
const FIELDS = ["name", "type", "connection", "parent", "port", "notes"];
function formValues() {
  const f = $("#dlgForm");
  return Object.fromEntries(FIELDS.map((k) => [k, f[k].value.trim()]));
}

function openDevice(key) {
  const d = state.devices.find((x) => x.key === key);
  if (!d) return;
  current = d;
  const [ic, tname] = typeOf(d);
  $("#dlgTitle").textContent = `${ic} ${label(d)}`;
  const ports = (d.ports || []).map((p) => `${p}${SERVICES[p] ? " (" + SERVICES[p] + ")" : ""}`).join(", ");
  const info = [
    ["Estado", d.online ? "En línea" : `Desconectado, visto ${ago(d.last_seen)}`],
    ["IP", d.ip],
    ["MAC", d.mac ? d.mac + (d.randomized_mac ? " (privada/aleatoria)" : "") : "—"],
    ["Fabricante", d.vendor || "—"],
    ["Nombre de red", d.hostname || "—"],
    ["Tipo", tname],
    ["Sistema", d.os],
    ["Conexión", (d.connection ? (d.connection === "cable" ? "Cable" : "Wifi") : "Sin saber") + (d.connection_source ? ` — ${d.connection_source}` : "")],
    ["Conectado a", infraName(d.parent) + (d.port ? `, puerto ${d.port}` : "") + (d.parent_guessed ? " (supuesto)" : "")],
    ["Sitio", siteName(d.site)],
    ["Puertos abiertos", ports || "—"],
    ["Visto por 1ª vez", dateStr(d.first_seen)],
  ].filter(([, v]) => v);
  $("#dlgInfo").innerHTML = info.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("");

  const f = $("#dlgForm");
  f.name.value = d.name || "";
  f.type.innerHTML = Object.entries(TYPES).map(([k, [i, n]]) => `<option value="${k}">${i} ${esc(n)}</option>`).join("");
  f.type.value = d.type;
  f.connection.value = d.connection_source === "marcado a mano" ? d.connection : "";
  f.parent.innerHTML = `<option value="">Automático</option>` + state.infra.map((i) => `<option value="${esc(i.id)}">${esc(i.name)}</option>`).join("");
  f.parent.value = d.parent_guessed ? "" : d.parent || "";
  f.port.value = d.port || "";
  f.notes.value = d.notes || "";
  initialForm = formValues();
  $("#forgetBtn").hidden = d.online;
  $("#dlg").showModal();
}

$("#dlg").addEventListener("close", async () => {
  if ($("#dlg").returnValue !== "save" || !current) return;
  // Solo se guarda lo que cambió, así lo detectado automáticamente sigue actualizándose.
  const now = formValues();
  const body = Object.fromEntries(FIELDS.filter((k) => now[k] !== initialForm[k]).map((k) => [k, now[k]]));
  if (!Object.keys(body).length) return;
  await fetch("api/device/" + encodeURIComponent(current.key), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  load();
});

$("#forgetBtn").addEventListener("click", async () => {
  if (!current || !confirm(`¿Olvidar ${label(current)}? Desaparece de la lista hasta que vuelva a conectarse.`)) return;
  await fetch("api/device/" + encodeURIComponent(current.key), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ forget: true }) });
  $("#dlg").close();
  load();
});

// ── Eventos ──────────────────────────────────────────────────────────────

$("#scanBtn").addEventListener("click", startScan);
$("#siteTabs").addEventListener("click", (e) => {
  const b = e.target.closest("[data-site]");
  if (!b) return;
  site = b.dataset.site;
  localSet("site", site);
  render();
});
["#q", "#fConn", "#fState"].forEach((s) => $(s).addEventListener("input", renderTable));
document.querySelectorAll("th[data-sort]").forEach((th) => th.addEventListener("click", () => {
  sort = { key: th.dataset.sort, dir: sort.key === th.dataset.sort && sort.dir === "asc" ? "desc" : "asc" };
  renderTable();
}));
$("#table tbody").addEventListener("click", (e) => { const r = e.target.closest("tr[data-key]"); if (r) openDevice(r.dataset.key); });

load();
