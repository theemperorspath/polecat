<div align="center">

# CSPT Hunter

**A Client Side Path Traversal detector for Firefox.**

[![Firefox](https://img.shields.io/badge/Firefox-128%2B-FF7139?logo=firefoxbrowser&logoColor=white)](https://www.mozilla.org/firefox/)
[![Manifest](https://img.shields.io/badge/Manifest-v3-4a90e2)](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions)
[![Zypher](https://img.shields.io/badge/by-Zypher-000000)](https://zypher.sh)
[![Research](https://img.shields.io/badge/Read_the_research-→-6f42c1)](https://zypher.sh/research/cspt-hunter/)

</div>

---

## About

CSPT Hunter was originally built for **internal use** at [Zypher](https://zypher.sh), my offensive security firm, to speed up Client Side Path Traversal discovery during engagements. We used it long enough to trust it, then decided to publish it so the wider community can hunt CSPT the same way we do.

You browse a target normally. When a value from the current URL (a path segment, query value, or `#hash` segment) shows up inside the **path** of an outgoing request, CSPT Hunter surfaces it as a record and increments the toolbar badge. That route to path echo is the CSPT injection point. Credentialed, state-changing sinks are flagged as **CSPT2CSRF** candidates, the class where the app's auto-attached token rides whatever path you bend.

> 📖 **Full technical write up:** [zypher.sh/research/cspt-hunter](https://zypher.sh/research/cspt-hunter/)

---

## Install

Temporary install (for testing):

1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add on**
3. Select `manifest.json`

Requires Firefox 128+ (the page hook is a `world: "MAIN"` content script). Temporary add ons unload on restart; for a persistent install, sign via AMO with `web-ext sign`.

## Verify it works

```bash
cd cspt-hunter/test
python3 -m http.server 8000
```

Open `http://localhost:8000/positive.html?id=inv_88371&doc=report2024`. The header should show **live**, the status bar **hook active**, and records for `query:id`, `query:doc`, and a `hash` match. Click the POST button to see a **CSPT2CSRF** record. If that works, the tool is healthy and a silent target simply has no reflection.

---

## Features

| Capability | What it does |
|---|---|
| **Route to path correlation** | Hooks `fetch`, `XMLHttpRequest`, `sendBeacon`, and `EventSource` in the page world so it sees the `#hash` the wire never carries. |
| **Resource load detection** | Watches `img` / `script` / `link` / `iframe` / websocket via `webRequest` for the CSS injection CSPT class the fetch hook can't see. |
| **CSPT2CSRF flagging** | Ranks credentialed, state changing sinks as high severity. |
| **Co location guard** | Suppresses the "page fetching its own directory" false positive by ignoring reflections inside the shared page/request path prefix. |
| **Canary mode** | Seed a token where your input persists; a hit means it reached a request path. |
| **Safe GET probe** | Re fires the request with `/../` at the matched segment (GET only) and reports whether the path collapsed, confirming Mechanism A. |
| **Copy payload** | Emits a traversal starting point injected at the matched segment. |
| **Search, filter, sort** | Live text filter, filter by CSPT2CSRF / reflected / heuristic, sort by severity / newest / method. |
| **Expandable records** | Full URL, route, matched segments with indices, detector, and time. |
| **Mute list** | Mute a noisy host or endpoint from any record; managed in settings. |
| **Exports** | JSON, Markdown report, or CSV of the current view. |

## Settings

Open via the gear button, or `about:addons` → CSPT Hunter → Preferences.

- **Detection.** Minimum segment length, exact vs contained matching, co location guard, dynamic values only, same origin only.
- **Detectors.** Toggle fetch/XHR, sendBeacon, EventSource, and resource loads independently.
- **Behavior.** Whether the badge counts all records or high only; whether records clear on navigation.
- **Canary.** Set or generate the token.
- **Muted.** View and remove muted hosts and endpoints.
- **Data.** Export/import config, reset to defaults.

## Severity

- **high.** Reflected value in a credentialed, state changing request (CSPT2CSRF), or any canary hit.
- **reflected (medium).** Same origin reflection into a request path.
- **heuristic (low).** `null` / `undefined` segment or pre encoded traversal, no confirmed reflection.

Credentialed is inferred from: `fetch` with `credentials !== 'omit'` same origin, an `Authorization` header, `xhr.withCredentials`, or a `Cookie` / `Authorization` header seen by `webRequest`. Cookies are invisible to JS, so same origin is treated as credentialed.

## Troubleshooting

**Detecting nothing?**

- **Reload the target tab.** Temporary add ons don't inject into already open tabs; the header shows **off** when this is the case.
- **Check the status bar / live pill.** Live means the hook is installed. If it stays off on an http(s) page after a reload, open `about:debugging` → this Firefox → CSPT Hunter → Inspect for errors.
- **Confirm the page reflects.** In the console, `window.__CSPT_HUNTER__` returns `true` if the hook is live. Then watch the Network tab; if no request path contains a current URL segment, there's nothing to flag.
- **Short IDs.** Raise or lower the minimum segment length in settings.

## Notes

- `<all_urls>` + `webRequest` are broad by necessity for a tool that watches every request. Run it against authorized targets only.
- Records are per page load unless "clear on navigation" is off. Export before navigating away.
- The co location guard and dynamic only mode trade a little recall for precision. If you suspect a real finding hidden inside a page's own path prefix, disable the guard for that pass.

---

<div align="center">

**CSPT Hunter is a [Zypher](https://zypher.sh) tool.** Authorized testing only.

[Website](https://zypher.sh) · [Research](https://zypher.sh/research/cspt-hunter/)

</div>
