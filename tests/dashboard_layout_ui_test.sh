#!/bin/bash
set -uo pipefail

# tests/dashboard_layout_ui_test.sh -- static checks for the WAIO
# "Blue Guardian" dashboard layout (dashboard/index.html). Reads the file
# only; no server, no browser, no network.
#
#  L1  every element id the main inline script looks up exists exactly once
#  L2  no duplicate ids anywhere
#  L3  the main script is still the FIRST <script> block (what the
#      dashboard_*_ui_check.mjs suites extract) and it renders panels
#  L4  the 8 governance sections exist, in order, each with a nav link
#  L5  no external resources (no http(s):// or protocol-relative src/href,
#      no @import, no remote url()) -- serve_dashboard.py serves an
#      allowlist only and the page must stay local-only
#  L6  the startup-screen script fetches nothing and executes nothing
#  L7  viewport meta + responsive breakpoints present (Mac / iPad)

cd "$(dirname "$0")/.." || exit 1

python3 -I - dashboard/index.html <<'PY'
import re, sys

html = open(sys.argv[1], encoding="utf-8").read()
fails = []
passes = 0
def check(name, cond, detail=""):
    global passes
    if cond:
        passes += 1
        print("  PASS: " + name)
    else:
        fails.append(name)
        print("  FAIL: " + name + (" (" + detail + ")" if detail else ""))

first = re.search(r"<script>([\s\S]*?)</script>", html)
check("L3 an inline <script> block exists", first is not None)
main = first.group(1) if first else ""
check("L3 first <script> is the dashboard's main script", "function renderStatus(" in main and "refreshAll()" in main)

ids_markup = re.findall(r'\bid="([A-Za-z0-9_-]+)"', html)
wanted = sorted(set(re.findall(r'getElementById\("([A-Za-z0-9_-]+)"\)', main)))
missing = [i for i in wanted if ids_markup.count(i) != 1]
check("L1 all %d ids used by the main script exist exactly once" % len(wanted), not missing, ", ".join(missing[:10]))
dups = sorted({i for i in ids_markup if ids_markup.count(i) > 1})
check("L2 no duplicate ids", not dups, ", ".join(dups[:10]))

secs = ["sec-system", "sec-security", "sec-threat", "sec-incident", "sec-agents", "sec-audit", "sec-policy", "sec-network"]
pos = [html.find('<section class="sec" id="%s"' % s) for s in secs]
check("L4 all 8 sections present", all(p >= 0 for p in pos), str(list(zip(secs, pos))))
check("L4 sections in governance order", pos == sorted(pos))
check("L4 every section has a nav link", all(('href="#%s"' % s) in html for s in secs))
titles = ["WAIO SYSTEM STATUS", "SECURITY MONITOR", "THREAT DETECTION", "INCIDENT RESPONSE",
          "AI AGENT STATUS", "AUDIT LOG", "POLICY MANAGEMENT", "NETWORK / NODE STATUS"]
check("L4 section titles", all(t in html for t in titles))

ext = re.findall(r'(?:src|href)\s*=\s*"(?:https?:)?//[^"]*"', html, re.I)
check("L5 no external src/href", not ext, ", ".join(ext[:5]))
check("L5 no @import", "@import" not in html)
check("L5 no remote url()", not re.search(r"url\(\s*['\"]?(?:https?:)?//", html, re.I))

scripts = re.findall(r"<script>([\s\S]*?)</script>", html)
boot = [s for s in scripts if "bootScreen" in s]
check("L6 startup-screen script present", len(boot) == 1 and scripts.index(boot[0]) > 0)
b = boot[0] if boot else ""
check("L6 startup screen makes no request", not re.search(r"\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|import\s*\(", b))
check("L6 startup screen has no eval / innerHTML", not re.search(r"\beval\s*\(|new Function|innerHTML", b))
check("L6 startup screen self-dismisses", "setTimeout(finish, 3000)" in b)

check("L7 viewport meta", 'name="viewport"' in html)
check("L7 iPad / narrow breakpoints", "@media (max-width: 1180px)" in html and "@media (max-width: 860px)" in html)
check("L7 reduced-motion respected", "prefers-reduced-motion" in html)

print("\n=== Results: %d passed, %d failed ===" % (passes, len(fails)))
sys.exit(1 if fails else 0)
PY
