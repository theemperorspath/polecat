"use strict";

var TAB = null, TAB_URL = "", FINDINGS = [], FILTER = "all", SORT = "severity", SEARCH = "";
var IGN = { hosts: [], prefixes: [] };
var OPEN = {}; // idx -> expanded

function $(id) { return document.getElementById(id); }
function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]; }); }
function send(msg) { return new Promise(function (res) { try { chrome.runtime.sendMessage(msg, function (r) { res(r); }); } catch (e) { res(null); } }); }

/* ---------- init ---------- */
function init() {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    var t = tabs && tabs[0]; if (!t) return;
    TAB = t.id; TAB_URL = t.url || "";
    loadIgnore(function () { load(); renderMutes(); });
    refreshStatus();
  });
}
function load() { send({ type: "get_findings", tabId: TAB }).then(function (l) { FINDINGS = Array.isArray(l) ? l : []; render(); }); }

function refreshStatus() {
  send({ type: "get_status", tabId: TAB }).then(function (s) {
    var el = $("status"), live = $("live"), txt = $("live-txt");
    var httpOk = /^https?:/i.test(TAB_URL);
    if (s && s.alive) {
      el.className = "status ok"; el.innerHTML = "hook active on this page";
      live.className = "live on"; txt.textContent = "live";
    } else if (!httpOk) {
      el.className = "status warn"; el.innerHTML = "not an http(s) page, nothing to hook here";
      live.className = "live off"; txt.textContent = "idle";
    } else {
      el.className = "status warn"; el.innerHTML = "<b>hook not active.</b> reload this tab (temp add-ons skip already-open pages).";
      live.className = "live off"; txt.textContent = "off";
    }
  });
}

/* ---------- mutes ---------- */
function loadIgnore(cb) { chrome.storage.local.get(["ignore"], function (r) { IGN = (r && r.ignore) || { hosts: [], prefixes: [] }; if (cb) cb(); }); }
function isIgnoredLocal(f) {
  try {
    var u = new URL(f.fullUrl);
    if (IGN.hosts.indexOf(u.host) !== -1) return true;
    var hp = u.host + u.pathname;
    if (IGN.prefixes.some(function (p) { return hp.indexOf(p) === 0; })) return true;
  } catch (e) {} return false;
}
function muteHost(f) { try { var h = new URL(f.fullUrl).host; if (IGN.hosts.indexOf(h) === -1) IGN.hosts.push(h); saveIgnore(); } catch (e) {} }
function muteEndpoint(f) { try { var u = new URL(f.fullUrl); var hp = u.host + u.pathname; if (IGN.prefixes.indexOf(hp) === -1) IGN.prefixes.push(hp); saveIgnore(); } catch (e) {} }
function clearMutes() { IGN = { hosts: [], prefixes: [] }; saveIgnore(); }
function saveIgnore() { chrome.storage.local.set({ ignore: IGN }, function () { render(); renderMutes(); }); }
function renderMutes() {
  var n = (IGN.hosts.length || 0) + (IGN.prefixes.length || 0);
  var el = $("mutes"); if (el) el.innerHTML = n ? ("muted " + n + ' · <a href="#" id="unmute">clear</a>') : "";
  var u = $("unmute"); if (u) u.addEventListener("click", function (e) { e.preventDefault(); clearMutes(); });
}

/* ---------- counts + filter + sort ---------- */
function counts() {
  var vis = FINDINGS.filter(function (f) { return !isIgnoredLocal(f); });
  $("c-total").textContent = vis.length;
  $("c-high").textContent = vis.filter(function (f) { return f.severity === "high"; }).length;
  $("c-med").textContent = vis.filter(function (f) { return f.matches && f.matches.length > 0; }).length;
  $("c-low").textContent = vis.filter(function (f) { return (!f.matches || !f.matches.length) && f.heuristics && f.heuristics.length; }).length;
}
function passesFilter(f) {
  if (isIgnoredLocal(f)) return false;
  if (SEARCH) {
    var hay = (f.url + " " + (f.fullUrl || "") + " " + (f.matches || []).map(function (m) { return m.from; }).join(" ") + " " + f.method).toLowerCase();
    if (hay.indexOf(SEARCH) === -1) return false;
  }
  if (FILTER === "all") return true;
  if (FILTER === "cspt2csrf") return !!f.cspt2csrf || !!f.canaryHit;
  if (FILTER === "reflected") return f.matches && f.matches.length > 0;
  if (FILTER === "heuristic") return f.heuristics && f.heuristics.length > 0;
  return true;
}
var SEVRANK = { high: 0, medium: 1, low: 2, info: 3 };
function sortIdx(indices) {
  return indices.sort(function (a, b) {
    var fa = FINDINGS[a], fb = FINDINGS[b];
    if (SORT === "newest") return (fb.ts || 0) - (fa.ts || 0);
    if (SORT === "method") return (fa.method || "").localeCompare(fb.method || "") || (fb.ts || 0) - (fa.ts || 0);
    var r = (SEVRANK[fa.severity] || 9) - (SEVRANK[fb.severity] || 9);
    return r !== 0 ? r : (fb.ts || 0) - (fa.ts || 0);
  });
}

/* ---------- render ---------- */
function renderPath(f) {
  var html = esc(f.url);
  (f.matches || []).forEach(function (m) {
    if (!m.seg) return;
    var re = new RegExp("(" + m.seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")");
    html = html.replace(re, "<b>$1</b>");
  });
  return html;
}
function record(f, idx) {
  var tags = [];
  if (f.cspt2csrf) tags.push('<span class="tag-b csrf">CSPT2CSRF</span>');
  if (f.canaryHit) tags.push('<span class="tag-b canary">canary</span>');
  if (f.matches && f.matches.some(function (m) { return m.decoded; })) tags.push('<span class="tag-b enc">encoded</span>');
  if (f.detector === "resource") tags.push('<span class="tag-b res">' + esc(f.resourceType || "resource") + '</span>');
  (f.heuristics || []).forEach(function (h) { tags.push('<span class="tag-b">' + esc(h) + '</span>'); });

  var srcTxt = (f.matches || []).map(function (m) { return '<span class="k">' + esc(m.from) + '</span>' + (m.matchType === "contained" ? "~" : ""); }).join(" ") || "none";
  var canProbe = f.matches && f.matches.length > 0 && f.sameOrigin;
  var open = OPEN[idx];

  var actions =
    '<button class="btn" data-copy="' + idx + '">copy url</button>' +
    (canProbe ? '<button class="btn" data-payload="' + idx + '">copy payload</button>' : "") +
    (canProbe ? '<button class="btn" data-probe="' + idx + '">probe</button>' : "") +
    '<button class="btn mute" data-mute-ep="' + idx + '">mute path</button>' +
    '<button class="btn mute" data-mute-host="' + idx + '">mute host</button>';

  var detail =
    '<div class="detail ' + (open ? "open" : "") + '" id="d-' + idx + '">' +
      '<dl>' +
        '<dt>full url</dt><dd>' + esc(f.fullUrl || f.url) + '</dd>' +
        '<dt>route</dt><dd>' + esc(f.route || "") + '</dd>' +
        '<dt>detector</dt><dd>' + esc(f.detector || "page") + (f.resourceType ? " / " + esc(f.resourceType) : "") + '</dd>' +
        '<dt>matches</dt><dd>' + ((f.matches || []).map(function (m) { return esc(m.from) + " → seg[" + m.segIndex + "] " + esc(m.seg) + " (" + m.matchType + ")"; }).join("<br>") || "none") + '</dd>' +
        '<dt>time</dt><dd>' + new Date(f.ts || Date.now()).toLocaleTimeString() + '</dd>' +
      '</dl>' +
      '<div class="probe-out" id="probe-' + idx + '" style="display:none"></div>' +
    '</div>';

  return '' +
    '<div class="rec ' + esc(f.severity || "info") + '">' +
      '<div class="rec-head">' +
        '<span class="mth ' + (f.stateChanging ? "state" : "") + '">' + esc(f.method) + '</span>' +
        tags.join("") +
        '<button class="rec-exp" data-exp="' + idx + '">' + (open ? "−" : "+") + '</button>' +
      '</div>' +
      '<div class="rec-path">' + renderPath(f) + '</div>' +
      '<div class="rec-meta">' + srcTxt + '<span class="sep">·</span>' + (f.sameOrigin ? "same-origin" : "cross-origin") + '<span class="sep">·</span>' + (f.credentialed ? "credentialed" : "no creds") + '</div>' +
      '<div class="rec-actions">' + actions + '</div>' +
      detail +
    '</div>';
}

function render() {
  counts();
  var idxs = FINDINGS.map(function (f, i) { return i; }).filter(function (i) { return passesFilter(FINDINGS[i]); });
  sortIdx(idxs);
  var el = $("list");
  if (!idxs.length) {
    el.innerHTML = '<div class="empty"><div class="empty-mark">//</div>' + (FINDINGS.filter(function (f) { return !isIgnoredLocal(f); }).length ? "No records match this view." : "No records yet. Exercise the target and reflections land here.") + '</div>';
    syncChips(); return;
  }
  el.innerHTML = idxs.map(function (i) { return record(FINDINGS[i], i); }).join("");
  wire(el);
  syncChips();
}
function syncChips() {
  document.querySelectorAll(".chip").forEach(function (c) { c.classList.toggle("active", c.getAttribute("data-f") === FILTER); });
  document.querySelectorAll(".stat").forEach(function (c) { c.classList.toggle("active", c.getAttribute("data-f") === FILTER); });
}

function wire(el) {
  el.querySelectorAll("[data-exp]").forEach(function (b) { b.addEventListener("click", function () { var i = +b.getAttribute("data-exp"); OPEN[i] = !OPEN[i]; render(); }); });
  el.querySelectorAll("[data-copy]").forEach(function (b) { b.addEventListener("click", function () { var f = FINDINGS[+b.getAttribute("data-copy")]; copy(f.fullUrl || f.url); flash(b, "copied"); }); });
  el.querySelectorAll("[data-payload]").forEach(function (b) { b.addEventListener("click", function () { copy(payloadSkeleton(FINDINGS[+b.getAttribute("data-payload")])); flash(b, "copied"); }); });
  el.querySelectorAll("[data-probe]").forEach(function (b) { b.addEventListener("click", function () { probe(+b.getAttribute("data-probe"), b); }); });
  el.querySelectorAll("[data-mute-ep]").forEach(function (b) { b.addEventListener("click", function () { muteEndpoint(FINDINGS[+b.getAttribute("data-mute-ep")]); }); });
  el.querySelectorAll("[data-mute-host]").forEach(function (b) { b.addEventListener("click", function () { muteHost(FINDINGS[+b.getAttribute("data-mute-host")]); }); });
}
function flash(b, t) { var old = b.textContent; b.textContent = t; setTimeout(function () { b.textContent = old; }, 900); }

/* build a traversal starting point at the matched segment */
function payloadSkeleton(f) {
  try {
    var m = (f.matches || [])[0]; if (!m) return f.fullUrl || f.url;
    var u = new URL(f.fullUrl || (location.origin + f.url));
    var parts = u.pathname.split("/"), ne = -1, target = -1;
    for (var i = 0; i < parts.length; i++) { if (parts[i] !== "") { ne++; if (ne === m.segIndex) { target = i; break; } } }
    if (target === -1) return u.href;
    parts[target] = parts[target] + "/../../REPLACE_WITH_TARGET";
    u.pathname = parts.join("/");
    return u.pathname + u.search + "   (" + f.method + ", source=" + m.from + ")";
  } catch (e) { return f.fullUrl || f.url; }
}

function probe(idx, btn) {
  var f = FINDINGS[idx], m = f.matches && f.matches[0]; if (!m) return;
  OPEN[idx] = true; render();
  var out = $("probe-" + idx); if (!out) return;
  out.style.display = "block"; out.className = "probe-out"; out.textContent = "GET with ../ at segment " + m.segIndex + " …";
  send({ type: "probe", tabId: TAB, req: { url: f.url, segIndex: m.segIndex } }).then(function (r) {
    if (!r) { out.className = "probe-out no"; out.textContent = "no response (content script not on this page)"; return; }
    if (r.error) { out.className = "probe-out no"; out.textContent = "error: " + r.error; return; }
    var verdict = r.collapsed ? "TRAVERSED — Mechanism A confirmed" : "did not collapse to target";
    out.className = "probe-out " + (r.collapsed ? "ok" : "no");
    out.innerHTML = "requested: " + esc(r.requested) + "<br>resolved:  " + esc(r.resolvedPath) + "<br>status " + esc(r.status) + " · " + verdict;
  });
}

/* ---------- exports ---------- */
function copy(t) { try { navigator.clipboard.writeText(t); } catch (e) {} }
function visible() { return FINDINGS.filter(passesFilter); }
function download(name, mime, text) {
  var b = new Blob([text], { type: mime }), a = document.createElement("a");
  a.href = URL.createObjectURL(b); a.download = name; a.click();
}
function exportAs(kind) {
  var rows = visible();
  if (kind === "json") { download("cspt-findings.json", "application/json", JSON.stringify({ tab: TAB_URL, exportedAt: new Date().toISOString(), findings: rows }, null, 2)); return; }
  if (kind === "csv") {
    var head = "severity,method,path,from,sameOrigin,credentialed,cspt2csrf,fullUrl\n";
    var body = rows.map(function (f) {
      var from = (f.matches || []).map(function (m) { return m.from; }).join("|");
      return [f.severity, f.method, '"' + (f.url || "").replace(/"/g, '""') + '"', from, f.sameOrigin, f.credentialed, !!f.cspt2csrf, '"' + (f.fullUrl || "") + '"'].join(",");
    }).join("\n");
    download("cspt-findings.csv", "text/csv", head + body); return;
  }
  if (kind === "md") {
    var lines = ["# CSPT-Hunter findings", "", "Target: `" + TAB_URL + "`  ", "Generated: " + new Date().toISOString(), ""];
    rows.forEach(function (f, i) {
      lines.push("## " + (i + 1) + ". " + (f.severity || "info").toUpperCase() + " — " + f.method + " " + f.url);
      if (f.cspt2csrf) lines.push("- **CSPT2CSRF candidate** (credentialed state-changing sink)");
      lines.push("- Source: " + ((f.matches || []).map(function (m) { return "`" + m.from + "` → seg[" + m.segIndex + "] `" + m.seg + "` (" + m.matchType + ")"; }).join(", ") || "heuristic only"));
      if (f.heuristics && f.heuristics.length) lines.push("- Heuristics: " + f.heuristics.join(", "));
      lines.push("- " + (f.sameOrigin ? "same-origin" : "cross-origin") + ", " + (f.credentialed ? "credentialed" : "no creds"));
      lines.push("- URL: `" + (f.fullUrl || f.url) + "`");
      lines.push("");
    });
    download("cspt-findings.md", "text/markdown", lines.join("\n")); return;
  }
}

/* ---------- wiring ---------- */
document.addEventListener("DOMContentLoaded", function () {
  init();
  $("settings").addEventListener("click", function () { try { chrome.runtime.openOptionsPage(); } catch (e) {} });
  $("clear").addEventListener("click", function () { OPEN = {}; send({ type: "clear", tabId: TAB }).then(load); });
  $("search").addEventListener("input", function () { SEARCH = this.value.trim().toLowerCase(); render(); });
  $("sort").addEventListener("change", function () { SORT = this.value; render(); });
  $("export").addEventListener("change", function () { if (this.value) exportAs(this.value); this.value = ""; });
  document.querySelectorAll(".chip, .stat").forEach(function (c) {
    c.addEventListener("click", function () { FILTER = c.getAttribute("data-f"); render(); });
  });
});
