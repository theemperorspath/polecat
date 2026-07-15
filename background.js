// background.js — event page (Firefox MV3).
// Per-tab finding store, badge, resource-load (webRequest) CSPT detection, mute list,
// and settings. Findings mirror to storage.session and rehydrate on wake.

"use strict";

var DEFAULTS = {
  minLen: 3, matchMode: "both", sameOriginOnly: false, colocationGuard: true,
  dynamicOnly: false, detectFetchXHR: true, detectBeacon: true,
  detectEventSource: true, detectResource: true, badgeCount: "all",
  clearOnNav: true, canary: ""
};

var store = {};   // tabId -> { findings: [], sigs: {} }
var lastUrl = {}; // tabId -> current URL (with hash)
var alive = {};   // tabId -> true once the page hook checks in
var ignore = { hosts: [], prefixes: [] };
var SET = Object.assign({}, DEFAULTS);

function dec(s) { try { return decodeURIComponent(s); } catch (e) { return s; } }
function looksDynamic(seg) { return /\d/.test(seg) || seg.length >= 16 || /^[0-9a-f-]{12,}$/i.test(seg); }

function loadState() {
  try {
    chrome.storage.local.get(["ignore", "settings"], function (r) {
      if (r && r.ignore) ignore = r.ignore;
      if (r && r.settings) SET = Object.assign({}, DEFAULTS, r.settings);
    });
  } catch (e) {}
}
loadState();
try {
  chrome.storage.onChanged.addListener(function (ch, area) {
    if (area !== "local") return;
    if (ch.ignore) ignore = ch.ignore.newValue || { hosts: [], prefixes: [] };
    if (ch.settings) { SET = Object.assign({}, DEFAULTS, ch.settings.newValue); recountAll(); }
  });
} catch (e) {}

function ensure(tabId) { if (!store[tabId]) store[tabId] = { findings: [], sigs: {} }; return store[tabId]; }
function persist(tabId) { try { var o = {}; o["f_" + tabId] = (store[tabId] && store[tabId].findings) || []; chrome.storage.session.set(o); } catch (e) {} }

(function rehydrate() {
  try {
    if (!chrome.storage || !chrome.storage.session) return;
    chrome.storage.session.get(null, function (all) {
      if (!all) return;
      Object.keys(all).forEach(function (k) {
        if (k.indexOf("f_") !== 0) return;
        var tabId = k.slice(2), arr = all[k] || [], st = ensure(tabId);
        arr.forEach(function (f) { var sig = sigOf(f); if (!st.sigs[sig]) { st.sigs[sig] = true; st.findings.push(f); } });
        badge(tabId);
      });
    });
  } catch (e) {}
})();

function isIgnored(f) {
  try {
    var u = new URL(f.fullUrl);
    if (ignore.hosts && ignore.hosts.indexOf(u.host) !== -1) return true;
    var hp = u.host + u.pathname;
    if (ignore.prefixes && ignore.prefixes.some(function (p) { return hp.indexOf(p) === 0; })) return true;
  } catch (e) {}
  return false;
}

function sigOf(f) {
  var ms = f.matches ? f.matches.map(function (m) { return m.from + ":" + m.seg; }).join(",") : "";
  return [f.method, f.url, ms, (f.heuristics || []).join(","), f.canaryHit ? "canary" : ""].join(" | ");
}
function severity(f) {
  if (f.canaryHit) return "high";
  var reflected = f.matches && f.matches.length > 0;
  if (reflected && f.credentialed && f.stateChanging) return "high";
  if (reflected && f.sameOrigin) return "medium";
  if (f.heuristics && f.heuristics.length > 0) return "low";
  return "info";
}
function isCspt2csrf(f) { return !!(f.matches && f.matches.length > 0 && f.credentialed && f.stateChanging); }

function add(tabId, f) {
  if (tabId == null || tabId < 0) return;
  if (isIgnored(f)) return;
  var st = ensure(tabId), sig = sigOf(f);
  if (st.sigs[sig]) return;
  st.sigs[sig] = true;
  f.severity = severity(f);
  f.cspt2csrf = isCspt2csrf(f);
  st.findings.push(f);
  persist(tabId);
  badge(tabId);
}

function badgeCount(list) {
  return SET.badgeCount === "high" ? list.filter(function (x) { return x.severity === "high"; }).length : list.length;
}
function badge(tabId) {
  try {
    var list = (store[tabId] && store[tabId].findings) || [];
    var n = badgeCount(list);
    var high = list.some(function (x) { return x.severity === "high"; });
    chrome.action.setBadgeText({ tabId: Number(tabId), text: n ? String(n) : "" });
    chrome.action.setBadgeBackgroundColor({ tabId: Number(tabId), color: high ? "#ff2b3d" : "#5c626c" });
  } catch (e) {}
}
function recountAll() { Object.keys(store).forEach(function (t) { badge(t); }); }

// resource-load correlation
var SKIP_TYPES = { xmlhttprequest: 1, main_frame: 1 };
function surfaceOf(href) {
  var out = [];
  try {
    var u = new URL(href);
    u.pathname.split("/").filter(Boolean).forEach(function (s) { out.push({ v: s, from: "path" }); });
    var hash = u.hash.slice(1);
    if (hash) hash.split(/[\/?#&=]/).filter(Boolean).forEach(function (s) { out.push({ v: s, from: "hash" }); });
    u.searchParams.forEach(function (val, key) { out.push({ v: val, from: "query:" + key }); });
  } catch (e) {}
  return out;
}
function correlate(curHref, details) {
  try {
    var reqU = new URL(details.url);
    var minLen = Math.max(1, SET.minLen || 3);
    var raw = reqU.pathname.split("/").filter(Boolean);
    var decd = raw.map(dec);
    var sources = surfaceOf(curHref);
    var curOrigin = ""; try { curOrigin = new URL(curHref).origin; } catch (e) {}
    var sameOrigin = reqU.origin === curOrigin;
    if (SET.sameOriginOnly && !sameOrigin) return null;

    var pageSegs = []; try { pageSegs = new URL(curHref).pathname.split("/").filter(Boolean); } catch (e) {}
    var cpl = 0, _n = Math.min(pageSegs.length, raw.length);
    while (cpl < _n && pageSegs[cpl] === raw[cpl]) cpl++;

    var matches = [];
    sources.forEach(function (src) {
      if (!src.v || src.v.length < minLen) return;
      var vd = dec(src.v);
      var startIdx = (src.from === "path" && SET.colocationGuard) ? cpl : 0;
      for (var i = startIdx; i < raw.length; i++) {
        var dup = matches.some(function (m) { return m.from === src.from && m.seg === raw[i]; });
        if (dup) continue;
        var hit = null;
        if (raw[i] === src.v || decd[i] === vd) hit = "exact";
        else if (SET.matchMode !== "exact" && vd.length >= minLen && decd[i].indexOf(vd) !== -1) hit = "contained";
        if (!hit) continue;
        if (SET.dynamicOnly && src.from === "path" && !looksDynamic(raw[i])) continue;
        matches.push({ from: src.from, value: src.v, matchType: hit, segIndex: i, seg: raw[i], decoded: raw[i] !== decd[i] });
        break;
      }
    });

    var heur = [];
    if (raw.indexOf("null") !== -1 || raw.indexOf("undefined") !== -1) heur.push("null_or_undefined");
    if (/(\.\.%2f|\.\.%5c|%2e%2e|\.\.\/|\.\.\\)/i.test(reqU.pathname)) heur.push("preencoded_traversal");
    if (matches.length === 0 && heur.length === 0) return null;

    var authy = (details.requestHeaders || []).some(function (h) { var n = String(h.name).toLowerCase(); return n === "authorization" || n === "cookie"; });
    return {
      detector: "resource", resourceType: details.type, method: details.method || "GET",
      url: reqU.pathname + reqU.search, fullUrl: reqU.href, sameOrigin: sameOrigin,
      stateChanging: ["GET", "HEAD"].indexOf((details.method || "GET").toUpperCase()) === -1,
      credentialed: authy || sameOrigin, matches: matches, heuristics: heur, canaryHit: false,
      route: curHref, ts: Date.now()
    };
  } catch (e) { return null; }
}
try {
  chrome.webRequest.onBeforeSendHeaders.addListener(function (details) {
    try {
      if (!SET.detectResource) return;
      if (SKIP_TYPES[details.type]) return;
      var cur = lastUrl[details.tabId];
      if (!cur) return;
      var f = correlate(cur, details);
      if (f) add(details.tabId, f);
    } catch (e) {}
  }, { urls: ["<all_urls>"] }, ["requestHeaders"]);
} catch (e) {}

// messaging
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  var tabId = sender && sender.tab && sender.tab.id;
  if (!msg) return;
  if (msg.type === "finding") { add(tabId, msg.finding); return; }
  if (msg.type === "alive") { if (tabId != null) alive[tabId] = true; return; }
  if (msg.type === "route") { if (tabId != null) lastUrl[tabId] = msg.url; return; }
  if (msg.type === "get_findings") { sendResponse((store[msg.tabId] && store[msg.tabId].findings) || []); return; }
  if (msg.type === "get_status") { sendResponse({ alive: !!alive[msg.tabId], count: (store[msg.tabId] && store[msg.tabId].findings.length) || 0 }); return; }
  if (msg.type === "clear") { store[msg.tabId] = { findings: [], sigs: {} }; persist(msg.tabId); badge(msg.tabId); sendResponse(true); return; }
  if (msg.type === "probe") { chrome.tabs.sendMessage(msg.tabId, { type: "run_probe", req: msg.req }, function (r) { sendResponse(r); }); return true; }
});

// reset on navigation (respect clearOnNav), cleanup on close
chrome.tabs.onUpdated.addListener(function (tabId, info) {
  if (info && info.status === "loading" && info.url) {
    lastUrl[tabId] = info.url;
    alive[tabId] = false;
    if (SET.clearOnNav) { store[tabId] = { findings: [], sigs: {} }; persist(tabId); }
    badge(tabId);
  }
});
chrome.tabs.onRemoved.addListener(function (tabId) {
  delete store[tabId]; delete lastUrl[tabId]; delete alive[tabId];
  try { chrome.storage.session.remove("f_" + tabId); } catch (e) {}
});
