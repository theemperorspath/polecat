"use strict";

var DEFAULTS = {
  minLen: 3, matchMode: "both", sameOriginOnly: false, colocationGuard: true,
  dynamicOnly: false, detectFetchXHR: true, detectBeacon: true,
  detectEventSource: true, detectResource: true, badgeCount: "all",
  clearOnNav: true, canary: ""
};

var BOOLS = ["sameOriginOnly", "colocationGuard", "dynamicOnly", "detectFetchXHR", "detectBeacon", "detectEventSource", "detectResource", "clearOnNav"];
var SELS = ["matchMode", "badgeCount"];
var SET = Object.assign({}, DEFAULTS);
var IGN = { hosts: [], prefixes: [] };

function $(id) { return document.getElementById(id); }

function apply() {
  $("minLen").value = SET.minLen;
  SELS.forEach(function (k) { $(k).value = SET[k]; });
  BOOLS.forEach(function (k) { $(k).checked = !!SET[k]; });
  $("canary").value = SET.canary || "";
}

function savedFlash() { var s = $("saved"); s.classList.add("show"); clearTimeout(savedFlash._t); savedFlash._t = setTimeout(function () { s.classList.remove("show"); }, 1100); }
function save() { chrome.storage.local.set({ settings: SET }, savedFlash); }

function bind() {
  $("minLen").addEventListener("change", function () { var v = parseInt(this.value, 10); SET.minLen = isNaN(v) ? 3 : Math.max(1, Math.min(12, v)); this.value = SET.minLen; save(); });
  SELS.forEach(function (k) { $(k).addEventListener("change", function () { SET[k] = this.value; save(); }); });
  BOOLS.forEach(function (k) { $(k).addEventListener("change", function () { SET[k] = this.checked; save(); }); });
  $("canary").addEventListener("change", function () { SET.canary = this.value.trim(); save(); });
  $("genCanary").addEventListener("click", function () { var t = "cspt" + Math.random().toString(36).slice(2, 8); $("canary").value = t; SET.canary = t; save(); });

  $("clearMutes").addEventListener("click", function () { IGN = { hosts: [], prefixes: [] }; chrome.storage.local.set({ ignore: IGN }, renderMutes); });
  $("reset").addEventListener("click", function () { if (!confirm("Reset all settings to defaults? Mutes are kept.")) return; SET = Object.assign({}, DEFAULTS); apply(); save(); });

  $("exportSettings").addEventListener("click", function () {
    var blob = new Blob([JSON.stringify({ settings: SET, ignore: IGN }, null, 2)], { type: "application/json" });
    var a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "polecat-config.json"; a.click();
  });
  $("importSettings").addEventListener("click", function () { $("importFile").click(); });
  $("importFile").addEventListener("change", function () {
    var file = this.files && this.files[0]; if (!file) return;
    var r = new FileReader();
    r.onload = function () {
      try {
        var obj = JSON.parse(r.result);
        if (obj.settings) { SET = Object.assign({}, DEFAULTS, obj.settings); apply(); chrome.storage.local.set({ settings: SET }); }
        if (obj.ignore) { IGN = obj.ignore; chrome.storage.local.set({ ignore: IGN }, renderMutes); }
        savedFlash();
      } catch (e) { alert("Could not parse that config file."); }
    };
    r.readAsText(file); this.value = "";
  });
}

function renderMutes() {
  var el = $("muteList");
  var items = [];
  (IGN.hosts || []).forEach(function (h, i) { items.push({ type: "host", val: h, i: i }); });
  (IGN.prefixes || []).forEach(function (p, i) { items.push({ type: "path", val: p, i: i }); });
  if (!items.length) { el.innerHTML = '<div class="mute-empty">Nothing muted. Mute noisy hosts or endpoints from a record in the popup.</div>'; return; }
  el.innerHTML = items.map(function (it) {
    return '<div class="mute-item"><span class="mtype">' + it.type + '</span><span class="mval">' + it.val.replace(/</g, "&lt;") + '</span><button class="rm" data-t="' + it.type + '" data-i="' + it.i + '">remove</button></div>';
  }).join("");
  el.querySelectorAll(".rm").forEach(function (b) {
    b.addEventListener("click", function () {
      var t = b.getAttribute("data-t"), i = +b.getAttribute("data-i");
      if (t === "host") IGN.hosts.splice(i, 1); else IGN.prefixes.splice(i, 1);
      chrome.storage.local.set({ ignore: IGN }, renderMutes);
    });
  });
}

document.addEventListener("DOMContentLoaded", function () {
  chrome.storage.local.get(["settings", "ignore"], function (r) {
    if (r && r.settings) SET = Object.assign({}, DEFAULTS, r.settings);
    IGN = (r && r.ignore) || { hosts: [], prefixes: [] };
    apply(); renderMutes(); bind();
  });
});
