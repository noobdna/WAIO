# iPad Pro dashboard: implementation and test report (2026-10-28)

Branch `feat/ipad-dashboard`, based on master `92f3490`. Every result below
was run on host 800 (macOS 13, x86_64). Nothing here was run on a physical
iPad; the device checks still needed are at the end.

## How layout was measured
`tests/ipad_viewport_check.swift` opens each page in **WebKit** (`WKWebView`),
the engine Safari uses on iPad. It uses an iPad Safari user agent and these
viewports:

| Name | CSS px |
|---|---|
| iPad Pro 11" portrait / landscape | 834×1194 / 1194×834 |
| iPad Pro 13" portrait / landscape | 1024×1366 / 1366×1024 |
| Split View ½ | 678×1024 |
| Slide Over | 375×1024 |
| Desktop (regression) | 1440×900 |

The page is served by the real `serve_dashboard.py` on a loopback test port.
The logs directory is **empty**, so the pages render their embedded sample
data and no live state is read.

For each viewport the check records:
- horizontal page overflow
- elements past the right edge (outside scroll containers)
- visible text under 12px
- touch targets under 44×44

It also saves a full-page screenshot.

**Limits of this method:**
- macOS WebKit is the same engine as iPad Safari, but not the same browser
  shell. Safe-area insets, Safari's toolbars and on-screen keyboard
  behaviour are not modelled.
- macOS shows classic scroll bars, so `innerWidth` is 15px narrower than
  on iPad. That makes the overflow check slightly stricter, not looser.

## Baseline (master, before any change)
| Page | Problem | Measured |
|---|---|---|
| index.html | Panel notes split into narrow side-by-side columns: the `.row` flex container separated text and `<code>`. Seen in System Overview, Decision Engine, Takomachi | Visible in the 834px screenshot; not caught by the overflow metric |
| index.html | Text under 12px | 268 elements (10–11px) at every size |
| index.html | Touch targets under 44px | 3 of 3: "Refresh now" 100×29, toggle label 160×18, checkbox 12×12 |
| index.html | Slide Over | Page 502px wide at 375px: horizontal scroll |
| index.html | Response Timeline | "t_containment" and "t_decision" labels overlap (also on desktop) |
| earth_weather.html | Text under 12px | 36 elements (tick labels 10px, headers/badges 11px) |
| earth_weather.html | Touch targets | The variable select is 93×18; the lag slider is 129×17 |
| earth_weather.html | Chart tooltips | `mousemove`/`mouseleave` only. On a tap, iOS sends no reliable `mouseleave`, so a tooltip sticks |
| earth_weather.html | Slide Over | Page 395px wide at 375px |

No overflow was found at full-screen iPad sizes. The existing viewport meta
tag and the `auto-fit` grid already worked.

## Changes
Only `dashboard/index.html` and `dashboard/earth_weather.html` changed. The
changes are CSS plus one small JS helper. There is no rebuild and there are
no new dependencies.

- `.panel-note` replaces the 6 note `<div class="row" style=…>`s.
- `.row` wraps; `.row > .value` and `code` break long strings.
- Text minimum is 12px; `-webkit-text-size-adjust: 100%`.
- 44px controls: refresh button, toggle label (22px checkbox), select,
  slider. `touch-action: manipulation` on the button.
- Banner wraps. Under 700px, body padding is 12px.
- Response Timeline: every second label/time is staggered vertically. The
  strip scrolls inside its card when narrower than 656px.
- Chart tooltips: `bindTooltip()` uses Pointer Events.
  - Mouse: hover as before.
  - Touch or pen: a tap shows the tooltip; a tap elsewhere hides it.

`serve_dashboard.py`, the plist templates, the live LaunchAgents and
`.github/workflows/lint.yml` are **unchanged**.

## Results after the change
| Suite | Result |
|---|---|
| `tests/ipad_viewport_test.sh`, both pages × 7 viewports × 4 checks | **56 passed, 0 failed.** Negative control on unmodified master: 24 passed, **32 failed** |
| `tests/dashboard_touch_tooltip_test.sh` (page's own `bindTooltip`, fake touch/pen/mouse events) | **9 passed, 0 failed.** On master: 0 passed, 2 failed |
| `tests/ipad_reconnect_test.sh` (round 2): WebKit; the suite stops and restarts its own server | **9 passed, 0 failed.** On the round-1 page: 4 passed, **5 failed** (R2: the badge became the sample's NORMAL) |
| `tests/ipad_chart_touch_test.sh` (round 2): WebKit; simulated taps hit-tested with `elementFromPoint` | **7 passed, 0 failed.** On the round-1 page: 2 passed, **6 failed** |
| `tests/serve_dashboard_test.sh`, including new **A15** (every route: 401 + challenge / 200 + `no-store` / no cookie / 403 outside allowlist) | **152 passed, 0 failed** |
| A15 mutants: JSON route skips auth; `no-store` dropped on JSON; client allowlist skipped for one page | **3 of 3 caught** |
| Existing UI suites: decision, guardian, incident_learning, incident, snd, takomachi, refresh_cron | 31/0, 19/0, 21/0, 10/0, 22/0, 12/0, 11/0 |
| `bash -n` on new/changed scripts; `node --check` on the `.mjs` | pass |
| ShellCheck | not installed on 800; CI runs it on `tests/*.sh` |

Desktop (1440×900) passes the same 4 checks. The visible changes on desktop:
- text is 1–2px larger in logs, chips and footers
- the refresh button is taller
- timeline labels are staggered

Screenshots and raw measurements, before and after, are outside the repo at
`/Users/masa/waio-work/ipad-evidence/`.

## Access and authentication (verified on 800, read-only)
- The live server binds 127.0.0.1:8000: 200 on loopback, no answer on
  192.168.1.80:8000. Its plist sets only `WAIO_DASHBOARD_BIND`, so it has no
  password and loopback clients only.
- sshd is reachable on 192.168.1.80:22 with no forwarding override, so the
  SSH local-forward route in `IPAD_PRO_ACCESS.md` needs no change on the Mac.
  **Not exercised end to end:** that needs an SSH login from the iPad.
- **Session expiry:** there are no sessions or cookies, and A15 asserts this.
  Access ends with the SSH forward. In LAN mode, Safari holds Basic
  credentials until it quits, with no server-side expiry.
- **Errors:** before any live data has loaded (e.g. opened as a file),
  panels show their embedded sample, labelled "sample". This is unchanged.
  After live data has loaded, a failed refresh keeps it and shows the
  connection notice; see round 2, D1.

## Audit round 2 (2026-10-28)
The round-1 diff was reviewed again, and the refresh path was exercised with
the connection dropping, which is what happens on an iPad over an SSH
forward. Two defects were found, reproduced and fixed. Each has a regression
test that fails on the round-1 page.

**D1 (security-relevant): a lost connection displayed a healthy state.**
- **Before:** `refreshAll()` re-rendered every panel from the embedded
  sample whenever a fetch failed, including after live data had been shown.
  The only clue was the small source label, and "refreshed <time>" was
  still updated.
- **Reproduced** in WebKit with the live fixture at CONTAINMENT:
  1. Stop the server.
  2. Tap Refresh now.
  3. The badge reads **NORMAL** (the sample).
- **Fix:**
  - A panel that has shown live data is never swapped back to the sample.
  - A network failure shows a red notice ("Connection to the dashboard
    server lost at … N panel(s) still show the last live data (from …)").
  - The labels say "last live data -- not current" and
    "refresh failed …".
  - When the server is back, the next refresh clears the notice.
  - With auto-refresh on, `visibilitychange` (returning to the tab;
    iPadOS pauses timers in background tabs) refreshes at once.
  - Auto-refresh is still opt-in, and the listener exists only while it
    is on.
- SND (never served by design) does not count as a failure.

**D2: chart marks were too small to tap.**
- **Measured** at iPad Pro 11" portrait: all 121 chart marks rendered under
  24px (smallest 6.6px), about 11px apart.
- **Fix:** a transparent overlay under the marks covers each plot. For touch
  and pen, a tap anywhere shows the nearest weather point, the nearest
  earthquake marker (top band), or the nearest lag point. The mouse is
  ignored by the overlay, so desktop hover is unchanged.

**Reviewed, no defect:**
- The timeline `nth-child` stagger matches `renderTimeline()`'s
  dot/label/time order inside `#timelinePoints`, which has no other
  children.
- The JS stays within Safari/iPadOS 13+: Pointer Events, `Promise.all`,
  `Set`, `??`.
- The existing Node UI-test stubs have no `document.addEventListener`. The
  visibility listener is only added when auto-refresh is switched on, so
  they are unaffected.

**What "simulated" means here:**
- The reconnect test stops a local server, which is the same failure a
  dropped forward causes in the browser (a network error).
- "Returning to the tab" sets `visibilityState` to "visible" and fires
  the event, because the offscreen view always reports "hidden".
- Taps are `PointerEvent`s with `pointerType: "touch"`, sent to whatever
  `elementFromPoint` returns.
- None of this is a finger on an iPad.

## Unresolved
1. **On-device checks** (see `IPAD_PRO_ACCESS.md`): load over the forward,
   rotate, tap controls and tooltips, and check whether the forward survives
   Termius being in the background.
2. **Not live yet.** The LaunchAgent serves the live checkout (56d46c0). The
   layout reaches the iPad after merge and a checkout update.
3. **Off-LAN access** needs an approved VPN. None exists on 800.
4. **`com.waio.cloudflared-tunnel`** is loaded and crash-looping (15,332
   runs, exit 1). cloudflared is not installed, so nothing is exposed. If it
   is ever fixed while the dashboard runs on the default configuration, the
   dashboard would be public **without a password**. This is an operator
   decision; it was left untouched.
5. The viewport and tooltip tests are not in CI: the viewport test needs
   macOS WebKit, and wiring either one in means editing `lint.yml`, which
   was out of scope.
