// content.js — ISOLATED world. Bridges the MAIN-world page hook and the background.
// Pushes the full settings object (including the canary) into the page hook.

(function () {
  "use strict";

  var DEFAULTS = {
    minLen: 3, matchMode: "both", sameOriginOnly: false, colocationGuard: true,
    dynamicOnly: false, detectFetchXHR: true, detectBeacon: true,
    detectEventSource: true, detectResource: true, badgeCount: "all",
    clearOnNav: true, canary: ""
  };

  window.addEventListener("message", function (e) {
    if (e.source !== window || !e.data) return;
    var d = e.data;
    if (d.source === "CSPT_HUNTER" && d.type === "finding") {
      try { chrome.runtime.sendMessage({ type: "finding", finding: d.payload }); } catch (x) {}
    } else if (d.source === "CSPT_HUNTER" && d.type === "alive") {
      try { chrome.runtime.sendMessage({ type: "alive" }); } catch (x) {}
    } else if (d.source === "CSPT_HUNTER_ROUTE") {
      reportUrl();
    }
  });

  try { window.postMessage({ source: "CSPT_HUNTER_PING" }, "*"); } catch (e) {}

  function reportUrl() {
    try { chrome.runtime.sendMessage({ type: "route", url: location.href }); } catch (x) {}
  }
  reportUrl();
  window.addEventListener("hashchange", reportUrl);
  window.addEventListener("popstate", reportUrl);

  function pushSettings(s) {
    var merged = Object.assign({}, DEFAULTS, s || {});
    try { window.postMessage({ source: "CSPT_HUNTER_CONFIG", settings: merged }, "*"); } catch (x) {}
  }
  try {
    chrome.storage.local.get(["settings"], function (r) { pushSettings(r && r.settings); });
    chrome.storage.onChanged.addListener(function (ch, area) {
      if (area === "local" && ch.settings) pushSettings(ch.settings.newValue);
    });
  } catch (e) {}

  chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (msg && msg.type === "run_probe") {
      var id = "probe_" + Math.random().toString(36).slice(2);
      var handler = function (e) {
        if (e.source === window && e.data && e.data.source === "CSPT_HUNTER_PROBE_RESULT" && e.data.id === id) {
          window.removeEventListener("message", handler);
          sendResponse(e.data.result);
        }
      };
      window.addEventListener("message", handler);
      try { window.postMessage({ source: "CSPT_HUNTER_PROBE", id: id, req: msg.req }, "*"); } catch (x) {}
      return true;
    }
  });
})();
