// injected.js — MAIN-world content script (Firefox 128+).
// Loaded by the browser (not a <script> tag) so page CSP cannot block it.
// Correlates the current URL (path/query/hash, including the #hash the wire never
// sees) against outgoing request paths. All behavior is driven by settings pushed
// from the content script. Wrapped so a bug here can never break the page.

(function () {
  "use strict";
  if (window.__POLECAT__) return;
  window.__POLECAT__ = true;

  var DEFAULTS = {
    minLen: 3, matchMode: "both", sameOriginOnly: false, colocationGuard: true,
    dynamicOnly: false, detectFetchXHR: true, detectBeacon: true,
    detectEventSource: true, detectResource: true, badgeCount: "all",
    clearOnNav: true, canary: ""
  };
  var SET = Object.assign({}, DEFAULTS);

  var PROBE_TAG = "POLECATPROBE";
  var origFetch = window.fetch;
  var OrigXHR = window.XMLHttpRequest;
  var origBeacon = navigator.sendBeacon ? navigator.sendBeacon.bind(navigator) : null;

  function post(type, payload) {
    try { window.postMessage({ source: "POLECAT", type: type, payload: payload }, "*"); } catch (e) {}
  }

  post("alive", { href: location.href });
  try { console.debug("[Polecat] hook installed on " + location.href); } catch (e) {}

  function dec(s) { try { return decodeURIComponent(s); } catch (e) { return s; } }

  function looksDynamic(seg) {
    return /\d/.test(seg) || seg.length >= 16 || /^[0-9a-f-]{12,}$/i.test(seg);
  }

  function currentSurface() {
    var out = [];
    try {
      var u = new URL(location.href);
      u.pathname.split("/").filter(Boolean).forEach(function (s) { out.push({ v: s, from: "path" }); });
      var hash = u.hash.slice(1);
      if (hash) hash.split(/[\/?#&=]/).filter(Boolean).forEach(function (s) { out.push({ v: s, from: "hash" }); });
      u.searchParams.forEach(function (val, key) { out.push({ v: val, from: "query:" + key }); });
    } catch (e) {}
    return out;
  }

  function hasAuthHeader(h) {
    try {
      if (!h) return false;
      if (typeof Headers !== "undefined" && h instanceof Headers) return h.has("authorization");
      if (Array.isArray(h)) return h.some(function (p) { return String(p[0]).toLowerCase() === "authorization"; });
      return Object.keys(h).some(function (k) { return k.toLowerCase() === "authorization"; });
    } catch (e) { return false; }
  }

  function analyze(rawUrl, method, credentialed, kind) {
    try {
      if (kind === "beacon" && !SET.detectBeacon) return;
      if (kind === "es" && !SET.detectEventSource) return;
      if ((kind === "fetch" || kind === "xhr") && !SET.detectFetchXHR) return;
      if (!rawUrl) return;
      var s = String(rawUrl);
      if (s.indexOf(PROBE_TAG) !== -1) return;

      var reqU;
      try { reqU = new URL(s, location.href); } catch (e) { return; }
      var sameOrigin = reqU.origin === location.origin;
      if (SET.sameOriginOnly && !sameOrigin) return;

      var minLen = Math.max(1, SET.minLen || 3);
      var rawSegs = reqU.pathname.split("/").filter(Boolean);
      var decSegs = rawSegs.map(dec);
      var sources = currentSurface();

      var pageSegs = [];
      try { pageSegs = new URL(location.href).pathname.split("/").filter(Boolean); } catch (e) {}
      var cpl = 0, _n = Math.min(pageSegs.length, rawSegs.length);
      while (cpl < _n && pageSegs[cpl] === rawSegs[cpl]) cpl++;

      var matches = [];
      sources.forEach(function (src) {
        var val = src.v;
        if (!val || val.length < minLen) return;
        var valDec = dec(val);
        var startIdx = (src.from === "path" && SET.colocationGuard) ? cpl : 0;
        for (var i = startIdx; i < rawSegs.length; i++) {
          var already = matches.some(function (m) { return m.from === src.from && m.seg === rawSegs[i]; });
          if (already) continue;
          var hit = null;
          if (rawSegs[i] === val || decSegs[i] === valDec) hit = "exact";
          else if (SET.matchMode !== "exact" && valDec.length >= minLen && decSegs[i].indexOf(valDec) !== -1) hit = "contained";
          if (!hit) continue;
          if (SET.dynamicOnly && src.from === "path" && !looksDynamic(rawSegs[i])) { continue; }
          matches.push({ from: src.from, value: val, matchType: hit, segIndex: i, seg: rawSegs[i], decoded: rawSegs[i] !== decSegs[i] });
          break;
        }
      });

      var heur = [];
      if (rawSegs.indexOf("null") !== -1 || rawSegs.indexOf("undefined") !== -1) heur.push("null_or_undefined");
      if (/(\.\.%2f|\.\.%5c|%2e%2e|\.\.\/|\.\.\\)/i.test(reqU.pathname)) heur.push("preencoded_traversal");

      var canaryHit = false;
      var canary = SET.canary;
      if (canary && canary.length >= 3) {
        for (var j = 0; j < rawSegs.length; j++) {
          if (rawSegs[j].indexOf(canary) !== -1 || decSegs[j].indexOf(canary) !== -1) { canaryHit = true; break; }
        }
      }

      if (matches.length === 0 && heur.length === 0 && !canaryHit) return;

      var m = (method || "GET").toUpperCase();
      post("finding", {
        detector: "page", method: m,
        url: reqU.pathname + reqU.search, fullUrl: reqU.href,
        sameOrigin: sameOrigin,
        stateChanging: ["GET", "HEAD"].indexOf(m) === -1,
        credentialed: !!credentialed,
        matches: matches, heuristics: heur, canaryHit: canaryHit,
        route: location.href, ts: Date.now()
      });
    } catch (e) {}
  }

  // fetch
  window.fetch = function (input, init) {
    try {
      var url, method, headers, creds;
      if (input && typeof input === "object" && "url" in input) {
        url = input.url; method = input.method || "GET"; headers = input.headers; creds = input.credentials;
      } else {
        url = input; method = (init && init.method) || "GET"; headers = init && init.headers; creds = init && init.credentials;
      }
      var reqU; try { reqU = new URL(String(url), location.href); } catch (e) { reqU = null; }
      var sameOrigin = reqU && reqU.origin === location.origin;
      var credentialed = hasAuthHeader(headers) || (creds !== "omit" && sameOrigin);
      analyze(url, method, credentialed, "fetch");
    } catch (e) {}
    return origFetch.apply(this, arguments);
  };

  // XHR
  function HookedXHR() {
    var xhr = new OrigXHR();
    var meta = { method: "GET", url: "", auth: false };
    var open = xhr.open;
    xhr.open = function (m, u) { meta.method = m || "GET"; meta.url = u || ""; return open.apply(xhr, arguments); };
    var setH = xhr.setRequestHeader;
    xhr.setRequestHeader = function (name, value) {
      try { if (String(name).toLowerCase() === "authorization") meta.auth = true; } catch (e) {}
      return setH.apply(xhr, arguments);
    };
    var send = xhr.send;
    xhr.send = function () {
      try {
        var reqU; try { reqU = new URL(String(meta.url), location.href); } catch (e) { reqU = null; }
        var sameOrigin = reqU && reqU.origin === location.origin;
        var credentialed = meta.auth || xhr.withCredentials || sameOrigin;
        analyze(meta.url, meta.method, credentialed, "xhr");
      } catch (e) {}
      return send.apply(xhr, arguments);
    };
    return xhr;
  }
  HookedXHR.prototype = OrigXHR.prototype;
  ["UNSENT", "OPENED", "HEADERS_RECEIVED", "LOADING", "DONE"].forEach(function (k) { try { HookedXHR[k] = OrigXHR[k]; } catch (e) {} });
  window.XMLHttpRequest = HookedXHR;

  // sendBeacon
  if (origBeacon) {
    navigator.sendBeacon = function (url) {
      try { analyze(url, "POST", true, "beacon"); } catch (e) {}
      return origBeacon.apply(navigator, arguments);
    };
  }

  // EventSource
  if (window.EventSource) {
    var OrigES = window.EventSource;
    function HookedES(url, cfg) {
      try { analyze(url, "GET", !!(cfg && cfg.withCredentials) || true, "es"); } catch (e) {}
      return new OrigES(url, cfg);
    }
    HookedES.prototype = OrigES.prototype;
    try { HookedES.CONNECTING = OrigES.CONNECTING; HookedES.OPEN = OrigES.OPEN; HookedES.CLOSED = OrigES.CLOSED; } catch (e) {}
    window.EventSource = HookedES;
  }

  // route freshness for the background resource-load correlation
  ["pushState", "replaceState"].forEach(function (m) {
    var orig = history[m];
    if (typeof orig !== "function") return;
    history[m] = function () {
      var r = orig.apply(this, arguments);
      try { window.postMessage({ source: "POLECAT_ROUTE" }, "*"); } catch (e) {}
      return r;
    };
  });

  // config + ping/pong + probe
  window.addEventListener("message", function (e) {
    if (e.source !== window || !e.data) return;
    var d = e.data;
    if (d.source === "POLECAT_CONFIG") { if (d.settings) SET = Object.assign({}, DEFAULTS, d.settings); return; }
    if (d.source === "POLECAT_PING") { post("alive", { href: location.href }); return; }
    if (d.source === "POLECAT_PROBE") {
      runProbe(d.req || {}).then(function (result) {
        try { window.postMessage({ source: "POLECAT_PROBE_RESULT", id: d.id, result: result }, "*"); } catch (x) {}
      });
    }
  });

  function runProbe(req) {
    return new Promise(function (resolve) {
      try {
        var u = new URL(req.url, location.href);
        var parts = u.pathname.split("/");
        var nonEmpty = -1, target = -1;
        for (var i = 0; i < parts.length; i++) {
          if (parts[i] !== "") { nonEmpty++; if (nonEmpty === req.segIndex) { target = i; break; } }
        }
        if (target === -1) return resolve({ error: "segment not found" });
        var tag = PROBE_TAG + Math.random().toString(36).slice(2, 8);
        parts[target] = parts[target] + "/../" + tag;
        u.pathname = parts.join("/");
        var testUrl = u.pathname + u.search;
        origFetch(testUrl, { method: "GET", credentials: "include", redirect: "follow" })
          .then(function (res) {
            var resolved = ""; try { resolved = new URL(res.url).pathname; } catch (x) { resolved = res.url; }
            resolve({ requested: testUrl, resolvedPath: resolved, status: res.status,
              collapsed: resolved.indexOf(tag) !== -1 && resolved.indexOf("/../") === -1, tag: tag });
          })
          .catch(function (err) { resolve({ error: String(err), requested: testUrl }); });
      } catch (err) { resolve({ error: String(err) }); }
    });
  }
})();
