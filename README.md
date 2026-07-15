<div align="center">

<br>

# 🦡 Polecat

### Client Side Path Traversal detector for Firefox

*Watch every request. Catch every reflection. Ship every CSPT2CSRF.*

<br>

[![Firefox](https://img.shields.io/badge/firefox-128%2B-FF7139?style=flat-square&logo=firefoxbrowser&logoColor=white)](https://www.mozilla.org/firefox/)
[![Manifest](https://img.shields.io/badge/manifest-v3-4a90e2?style=flat-square)](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions)
[![Zypher](https://img.shields.io/badge/by-zypher.sh-ff2b3d?style=flat-square)](https://zypher.sh)
[![Research](https://img.shields.io/badge/read_the_research-→-6f42c1?style=flat-square)](https://zypher.sh/research/cspt-hunter/)

<br>

</div>

## Origin

Polecat started as an internal tool at [**Zypher**](https://zypher.sh), my offensive security firm, to speed up **Client Side Path Traversal** hunting during engagements. I used it long enough on live targets to trust its output, and figured the wider community would get more mileage out of it than a private tool ever would.

So here it is.

> **Full technical write up:** [zypher.sh/research/cspt-hunter](https://zypher.sh/research/cspt-hunter/)

<br>

## What it does

You browse a target normally. When a value from the current URL (a path segment, a query value, or a `#hash` segment) shows up inside the **path** of an outgoing request, Polecat surfaces it as a record and increments the toolbar badge.

That route-to-path echo is the CSPT injection point. Credentialed, state-changing sinks get flagged as **CSPT2CSRF** candidates: the class where the app's auto-attached token rides whatever path you bend.

```
   current URL  ──►  https://target/user/1234/dashboard
                              │
                              │  reflected
                              ▼
   outgoing req ──►  POST  /api/user/1234/roles     ← CSPT2CSRF
                              ▲
                              └── same-origin, credentialed, state-changing
```

<br>

## Install

```bash
git clone https://github.com/theemperorspath/polecat
```

**Temporary load (for testing):**

1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. Select `manifest.json`

Requires **Firefox 128+** (the page hook is a `world: "MAIN"` content script). Temporary add-ons unload on restart; for a persistent install, sign via AMO with `web-ext sign`.

<br>

## Verify

```bash
cd polecat/test
python3 -m http.server 8000
```

Open `http://localhost:8000/positive.html?id=inv_88371&doc=report2024`.

The header should show **live**, the status bar **hook active**, and records for `query:id`, `query:doc`, and a `hash` match. Click the POST button to see a **CSPT2CSRF** record.

If that works, the tool is healthy and a silent target simply has no reflection.

<br>

## Features

<table>
<tr>
<td width="30%"><b>Route-to-path correlation</b></td>
<td>Hooks <code>fetch</code>, <code>XMLHttpRequest</code>, <code>sendBeacon</code>, and <code>EventSource</code> in the page world so it sees the <code>#hash</code> the wire never carries.</td>
</tr>
<tr>
<td><b>Resource-load detection</b></td>
<td>Watches <code>img</code> / <code>script</code> / <code>link</code> / <code>iframe</code> / websocket via <code>webRequest</code>, for the CSS-injection CSPT class the fetch hook can't see.</td>
</tr>
<tr>
<td><b>CSPT2CSRF flagging</b></td>
<td>Ranks credentialed, state-changing sinks as high severity.</td>
</tr>
<tr>
<td><b>Co-location guard</b></td>
<td>Suppresses the "page fetching its own directory" false positive by ignoring reflections inside the shared page/request path prefix.</td>
</tr>
<tr>
<td><b>Canary mode</b></td>
<td>Seed a token where your input persists. A hit means it reached a request path.</td>
</tr>
<tr>
<td><b>Safe GET probe</b></td>
<td>Re-fires with <code>/../</code> at the matched segment (GET only) and reports whether the path collapsed, confirming Mechanism A.</td>
</tr>
<tr>
<td><b>Copy payload</b></td>
<td>Emits a traversal starting point injected at the matched segment.</td>
</tr>
<tr>
<td><b>Search, filter, sort</b></td>
<td>Live text filter, filter by CSPT2CSRF / reflected / heuristic, sort by severity / newest / method.</td>
</tr>
<tr>
<td><b>Expandable records</b></td>
<td>Full URL, route, matched segments with indices, detector, and time.</td>
</tr>
<tr>
<td><b>Mute list</b></td>
<td>Mute a noisy host or endpoint from any record. Managed in settings.</td>
</tr>
<tr>
<td><b>Exports</b></td>
<td>JSON, Markdown report, or CSV of the current view.</td>
</tr>
</table>

<br>

## Settings

Open via the gear button, or `about:addons` → Polecat → Preferences.

<details>
<summary><b>Detection</b></summary>

- Minimum segment length
- Exact vs contained matching
- Co-location guard
- Dynamic values only (only flag identifier-looking path segments)
- Same-origin only
</details>

<details>
<summary><b>Detectors</b></summary>

- fetch / XHR
- sendBeacon
- EventSource
- Resource loads
</details>

<details>
<summary><b>Behavior</b></summary>

- Badge counts all records or high only
- Whether records clear on navigation
</details>

<details>
<summary><b>Canary</b></summary>

- Set or generate a token to seed where input persists
</details>

<details>
<summary><b>Muted</b></summary>

- View and remove muted hosts and endpoints
</details>

<details>
<summary><b>Data</b></summary>

- Export/import config, reset to defaults
</details>

<br>

## Severity

| Level | Trigger |
|:---:|---|
| 🔴 **high** | Reflected value in a credentialed, state-changing request (CSPT2CSRF), or any canary hit. |
| 🟡 **reflected** | Same-origin reflection into a request path. |
| ⚪ **heuristic** | `null` / `undefined` segment or pre-encoded traversal, no confirmed reflection. |

Credentialed is inferred from: `fetch` with `credentials !== 'omit'` same-origin, an `Authorization` header, `xhr.withCredentials`, or a `Cookie` / `Authorization` header seen by `webRequest`. Cookies are invisible to JS, so same-origin is treated as credentialed.

<br>

## Troubleshooting

**"Polecat isn't detecting anything."**

- **Reload the target tab.** Temporary add-ons don't inject into already-open tabs. The header shows **off** when this is the case.
- **Check the live pill.** Live means the hook is installed. If it stays off on an http(s) page after a reload, open `about:debugging` → this Firefox → Polecat → Inspect for errors.
- **Confirm the page reflects.** In the console, `window.__POLECAT__` returns `true` if the hook is live. Then watch the Network tab. If no request path contains a current URL segment, there's nothing to flag.
- **Short IDs?** Raise or lower the minimum segment length in settings.

<br>

## Notes

- `<all_urls>` + `webRequest` are broad by necessity for a tool that watches every request. Run it against authorized targets only.
- Records are per page load unless "clear on navigation" is off. Export before navigating away.
- The co-location guard and dynamic-only mode trade a little recall for precision. If you suspect a real finding hidden inside a page's own path prefix, disable the guard for that pass.

<br>

---

<div align="center">

**Polecat is a [Zypher](https://zypher.sh) tool.** Authorized testing only.

[Website](https://zypher.sh) · [Research](https://zypher.sh/research/cspt-hunter/) · [Report an issue](https://github.com/theemperorspath/polecat/issues)

<sub>Built by hunters, for hunters.</sub>

</div>
