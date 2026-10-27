# Opening the WAIO dashboard on iPad Pro

**Status:** the layout works at iPad Pro sizes (`docs/IPAD_PRO_TEST_REPORT.md`).
The access route below uses only what already runs on the Mac (host 800). It
has **not yet been tried from a physical iPad**. That last step is listed at
the end.

**The new layout is not live yet.** The running server serves files from the
live checkout `/Users/masa/WAIO` (56d46c0, behind master). Until this PR is
merged and that checkout is updated (`~/waio-ops/DEPLOY_PLAN.md`), the iPad
gets the old layout over the same route. The route itself works either way.

## What is running today (checked 2026-10-28)
- `com.waio.dashboard-server` runs `dashboard/serve_dashboard.py` from
  `/Users/masa/WAIO`. It binds **127.0.0.1:8000 only**. It answers 200 on
  loopback and does not answer on the LAN IP (192.168.1.80:8000).
- Its plist sets only `WAIO_DASHBOARD_BIND`, so there is **no dashboard
  password**. Only processes on the Mac itself can reach it.
- Remote Login (sshd) is on and reachable at 192.168.1.80:22. No
  `AllowTcpForwarding` or `DisableForwarding` override is set, so OpenSSH's
  default (forwarding allowed) applies.
- There is no VPN on the Mac: no Tailscale, WireGuard, ZeroTier or system VPN
  profile.

## Recommended route: SSH port forward (home network)
The dashboard stays on 127.0.0.1. The iPad reaches it through an SSH
connection. That connection is encrypted and authenticated with your SSH
key. No service, firewall rule or bind address on the Mac changes.

1. **iPad: SSH client with port forwarding.** Termius (already used for this
   Mac) or Blink. Use the **key-based login** you already have for
   `masa@192.168.1.80`.
2. **Add a local port forward** to that host:
   | Field | Value |
   |---|---|
   | Local port (on the iPad) | `8000` |
   | Bind address (on the iPad) | `127.0.0.1` |
   | Destination host (as seen from the Mac) | `127.0.0.1` |
   | Destination port | `8000` |

   This is the same as `ssh -N -L 127.0.0.1:8000:127.0.0.1:8000 masa@192.168.1.80`.
3. **Start the forward**, then open **`http://localhost:8000/`** in Safari.
   The Earth/weather page is `http://localhost:8000/earth_weather.html`.
4. **Keep the forward alive.** iPadOS suspends background apps, which closes
   the forward after a while. Use Split View with Termius and Safari side by
   side, or Termius's background keep-alive option.

   **When the forward drops,** the page keeps the last live data and shows
   a red "Connection to the dashboard server lost" notice. The source label
   and refresh status stop saying "live" or "refreshed". It never falls back
   to the embedded sample once it has shown live data, so a lost connection
   can't look like a healthy NORMAL. Restart the forward, then tap
   **Refresh now**. With auto-refresh on, returning to the Safari tab
   refreshes at once.
5. **Stop:** disconnect the forward in Termius.

**Why this route:**
- Nothing new listens on the LAN.
- No password crosses the network in clear text.
- It works with the live configuration as it is.

The connection reaches the dashboard from 127.0.0.1, which the default
configuration allows. With the LAN mode below, use the Mac's LAN IP as the
destination instead, because that mode's allowlist leaves loopback out on
purpose.

## Alternative: LAN mode (needs your approval, not enabled)
`serve_dashboard.py` already has an authenticated LAN mode (PR #169). It
fails closed: a non-loopback bind refuses to start without **both**:
- `WAIO_DASHBOARD_AUTH_FILE`: a 0600 PBKDF2 credential file made by
  `dashboard/set_dashboard_auth.py`
- `WAIO_DASHBOARD_ALLOWED_CLIENTS`: private CIDRs only, e.g.
  `192.168.1.0/24`

Safari then asks for the user name and password.

| | SSH forward | LAN mode |
|---|---|---|
| Changes to the Mac | none | plist environment change and a restart (approval) |
| Encryption | SSH | **none**: Basic auth over plain HTTP is readable on the LAN |
| Login | SSH key | password; 5 failures → 30 s lockout per client IP |

Enabling LAN mode is a change to a live service. The prepared plan is the
"Dashboard #169 deploy plan" note: worktree at `~/waio-dashboard-deploy`, and
the credential file at `~/.config/waio/dashboard-auth`, created by the
operator. It was not done here.

## Away from home
**Not supported today.** Do **not** forward port 8000 or 22 on the router.

`com.waio.cloudflared-tunnel` must **not** be used with the default
configuration. It would put the **unauthenticated** loopback dashboard on the
internet. That job is loaded and crash-looping (15,332 runs since login,
last exit 1). cloudflared is not installed, so nothing is exposed. It was left
untouched here.

Remote access needs an approved VPN (for example Tailscale on the Mac and the
iPad, followed by the SSH route above over the VPN address). That is an
operator decision and an install.

## Security notes
- **Exposure check on 800 (2026-10-28, read-only):**
  - The dashboard listens only on 127.0.0.1:8000, and the plist binds
    127.0.0.1.
  - No tunnel, ngrok, Tailscale or autossh process is running.
  - The cloudflared plists exist, but the binary does not.
  - No `RemoteForward` in `~/.ssh/config`. sshd has no `GatewayPorts`
    override, so the default "no" applies.
  - The **macOS application firewall is off**. That doesn't expose the
    loopback-only dashboard, but it means nothing but the server's own
    client allowlist would stand in front of LAN mode.
- **What is protected:** every allowlisted route, not only the page. The
  pages and all seven `logs/*.json` files are covered.
  - Default configuration: only loopback clients, so it is reachable only
    through SSH.
  - LAN mode: 401 without credentials, 403 outside the client allowlist,
    `Cache-Control: no-store` on every response. Checked for every route
    by `tests/serve_dashboard_test.sh` A15.
- **SND@HOME:** `snd-status-latest.json` (a LAN device list) is still never
  served. The SND panel shows embedded sample data. Takomachi is unchanged:
  `takomachi-status-latest.json`, refreshed manually.
- **Sessions:** there are none. No cookie or token is issued (A15 checks
  this).
  - SSH route: access ends when the forward closes.
  - LAN mode: Safari keeps the Basic credentials until Safari is quit.
    There is no server-side expiry or logout.
- Never put the dashboard password or SSH key in screenshots, notes or chat.

## Manual verification still needed (on the iPad)
1. With the forward from step 2 running, `http://localhost:8000/` loads.
   The source label shows live data, not "sample".
2. Rotate portrait ↔ landscape. Nothing is cut off, and there's no sideways
   page scrolling. In Split View and Slide Over, only the Response Timeline
   strip scrolls sideways inside its own card.
3. Tap "Refresh now" and the auto-refresh checkbox.
4. On the Earth page, tap anywhere on a chart. The nearest point's or
   earthquake's tooltip appears, and a tap elsewhere hides it.
5. Background Termius for a few minutes, then return to Safari and tap
   Refresh now.
   - If the forward died: the red connection notice appears and the last
     live data stays.
   - Restart the forward and refresh: the notice clears.
   - Note whether the forward survived; that decides whether Split View is
     required.
