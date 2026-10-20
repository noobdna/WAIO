#!/bin/bash
set -uo pipefail

# tests/request_correlation_test.sh -- regression suite for the
# distributed sub-threshold probe detector
# (security/request_correlation/request_correlation_lib.py).
#
# Every request log below is SYNTHETIC, generated in-process from
# documentation address space (198.51.100.0/24, 203.0.113.0/24,
# 192.0.2.0/24). Nothing is scanned or contacted.
#   R-series: the rotation pattern GMO reported (per-IP limit evaded by
#     switching IP just under it) is detected, with severity factors.
#   F-series: false-positive guards (crowd, single heavy source, steady
#     concurrent sources, allowlist).
#   N-series: malformed / incomplete input is dropped and counted.
#   K-series: the output is accepted by killswitch_lib and stays dry-run.
#   D-series: static guards (no I/O, no network, no addresses in output).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

PASS=0
FAIL=0
declare -a FAILURES=()

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected='$expected' actual='$actual')")
    echo "  FAIL: $label (expected='$expected' actual='$actual')"
  fi
}

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected to contain '$needle')")
    echo "  FAIL: $label (expected to contain '$needle', got: $haystack)"
  fi
}

LIB="security/request_correlation/request_correlation_lib.py"

# run <python body> -- body sees: rc (module), gen helpers, and prints its result
run() {
  python3 -I - "$1" <<'PY'
import sys
sys.path.insert(0, 'security/request_correlation')
import request_correlation_lib as rc

T0 = 1792800000  # 2026-10-21T00:00:00Z

def ts(t):
    return rc.fmt_ts(t)

def rotation(n_src=30, per_src=85, dur=50, gap=5, status=404, net="198.51.100.", start=T0, streams=1, wave=False):
    """Each source sends per_src requests over dur seconds, then stops;
    the next starts gap seconds later (hand-over). streams=k runs k such
    hand-over chains in parallel; wave=True starts every source at once."""
    out = []
    for s in range(streams):
        t = start + 3 * s
        for i in range(s, n_src, streams):
            t0 = start if wave else t
            for k in range(per_src):
                out.append({"ts": ts(t0 + dur * k / per_src), "src": "%s%d.%d" % ("198.51.", 100 + s % 100, i % 250 + 1) if streams > 1 else "%s%d" % (net, i % 250 + 1),
                            "target": "shop", "path": "/probe/%d" % (k % 40), "status": status})
            t += dur + gap
    return out

def norm(raws, salt="test-salt", allow=()):
    nets, exact = rc.parse_allowlist(allow)
    evs, drops = [], {}
    for r in raws:
        e, why = rc.normalize(r, salt, nets, exact)
        if e:
            evs.append(e)
        else:
            drops[why] = drops.get(why, 0) + 1
    return evs, drops

exec(sys.argv[1])
PY
}

echo "[R1] rotation just under the per-source limit is detected"
R1="$(run "d, s = rc.detect(norm(rotation())[0]); x = d[0]; print(len(d), x['type'], x['severity'], x['evidence']['rotating_sources'] >= 10, x['evidence']['sequential_ratio'] >= 0.9)")"
assert_eq "R1 one HIGH distributed_probe (404 probing), >=10 rotating sources, sequential" "1 distributed_probe high True True" "$R1"
assert_eq "R1 fires before the campaign ends (time_to_detect < full duration)" "True" "$(run "d, s = rc.detect(norm(rotation())[0]); print(d[0]['evidence']['time_to_detect_s'] < 30 * 55)")"
assert_eq "R1 time_to_detect is about min_quitters hand-overs + one silent window" "True" "$(run "d, s = rc.detect(norm(rotation())[0]); t = d[0]['evidence']['time_to_detect_s']; print(9 * 55 <= t <= 12 * 55 + 60)")"
assert_eq "R2 same rotation with 200s (no probing) -> MEDIUM" "medium" "$(run "d, s = rc.detect(norm(rotation(status=200))[0]); print(d[0]['severity'])")"
assert_eq "R3 automation-grade speed raises one level (fast hand-over, 404s -> CRITICAL)" "critical" "$(run "d, s = rc.detect(norm(rotation(dur=10, gap=1))[0]); print(d[0]['severity'])")"
assert_contains "R3 speed factor is named in the summary" "$(run "d, s = rc.detect(norm(rotation(dur=10, gap=1))[0]); print(d[0]['summary'])")" "automation-grade"
assert_eq "R4 fires once per target, not once per extra source" "1" "$(run "d, s = rc.detect(norm(rotation(n_src=80))[0]); print(len(d))")"
assert_eq "R5 ATT&CK references attached" "T1595.002 T1090.002 T1190" "$(run "d, s = rc.detect(norm(rotation())[0]); print(' '.join(d[0]['attack_ids']))")"

echo "[R6] parallel hand-over streams are still rotation (a strictly-sequential test missed these)"
for k in 2 3 5; do
  assert_eq "R6 $k parallel streams detected" "1" "$(run "print(len(rc.detect(norm(rotation(n_src=20 * $k, streams=$k))[0])[0]))")"
done
assert_eq "R6 evidence names the concurrency it saw" "True" "$(run "d = rc.detect(norm(rotation(n_src=60, streams=3))[0])[0][0]; print(2 <= d['evidence']['peak_concurrency'] <= 4)")"
echo "[R7] a probing wave (many near-limit sources at once, 404s) is detected, at end of input"
assert_eq "R7 wave of 30 with 404s -> probing_wave HIGH+" "probing_wave True" "$(run "d = rc.detect(norm(rotation(streams=30, wave=True))[0])[0][0]; print(d['evidence']['pattern'], d['severity'] in ('high', 'critical'))")"

echo "[F1] false-positive guards"
assert_eq "F1 crowd: 300 sources x 5 requests, overlapping -> nothing" "0" "$(run "
raws = [dict(ts=ts(T0 + (i * 7 + k * 13) % 600), src=('203.0.113.%d' % (i % 250 + 1)) if i < 250 else ('192.0.2.%d' % (i - 249)), target='shop', path='/item/%d' % k, status=200) for i in range(300) for k in range(5)]
print(len(rc.detect(norm(raws)[0])[0]))")"
assert_eq "F2 one heavy source over the limit (NAT) -> not correlated, only counted" "0 1" "$(run "
raws = [dict(ts=ts(T0 + k * 0.3), src='203.0.113.9', target='shop', path='/', status=200) for k in range(500)]
d, s = rc.detect(norm(raws)[0]); print(len(d), s['over_threshold_sources'])")"
assert_eq "F3 steady concurrent sources near the band (CDN/health checks) never go silent -> nothing" "0" "$(run "
raws = [dict(ts=ts(T0 + k * 0.75), src='203.0.113.%d' % i, target='shop', path='/health', status=200) for i in range(1, 21) for k in range(1200)]
print(len(rc.detect(norm(raws)[0])[0]))")"
assert_eq "F4 rotation from an allowlisted range is removed before detection" "0" "$(run "print(len(rc.detect(norm(rotation(), allow=['198.51.100.0/24'])[0])[0]))")"
assert_eq "F5 too few quitters (below min_quitters) -> nothing" "0" "$(run "print(len(rc.detect(norm(rotation(n_src=8))[0])[0]))")"
assert_eq "F6 sources that cross the limit are not 'quitters'" "0" "$(run "print(len(rc.detect(norm(rotation(per_src=120))[0])[0]))")"
assert_eq "F7 far below the band (crawler politeness) -> nothing" "0" "$(run "print(len(rc.detect(norm(rotation(per_src=20))[0])[0]))")"
assert_eq "F8 wave of near-limit sources with ordinary 200s (scheduled-job fleet) -> nothing" "0" "$(run "print(len(rc.detect(norm(rotation(streams=30, wave=True, status=200))[0])[0]))")"
assert_eq "F9 12 unrelated heavy clients an hour apart -> nothing (no hand-over chain)" "0" "$(run "print(len(rc.detect(norm(rotation(n_src=12, gap=3600, status=200))[0])[0]))")"
assert_eq "F9 same spacing with 404s (broken-bookmark heavy users) -> nothing" "0" "$(run "print(len(rc.detect(norm(rotation(n_src=12, gap=3600))[0])[0]))")"
assert_eq "F10 sequential CI jobs from different runners 10 min apart -> nothing" "0" "$(run "print(len(rc.detect(norm(rotation(n_src=12, gap=550, status=200))[0])[0]))")"
assert_eq "F10 a rotation chain still fires among unrelated spaced-out heavy clients" "1 True" "$(run "
d = rc.detect(norm(rotation(n_src=12, gap=3600, status=200, net='203.0.113.') + rotation(n_src=12, start=T0 + 600))[0])[0]
print(len(d), d[0]['evidence']['rotating_sources'] <= 12)")"
assert_eq "F10 boundary: ~115 s quiet between hand-overs (< max_handover_gap_s 120) still links" "1" "$(run "print(len(rc.detect(norm(rotation(gap=115))[0])[0]))")"
assert_eq "F10 boundary: ~130 s quiet between hand-overs does not link" "0" "$(run "print(len(rc.detect(norm(rotation(gap=130))[0])[0]))")"

echo "[N1] malformed and incomplete input"
assert_eq "N1 drops counted by reason" "allowlisted=1 bad_ts=2 no_src=1 no_target=1 not_object=1" "$(run "
raws = [dict(ts='yesterday', src='a', target='t'), dict(src='a', target='t'), dict(ts=ts(T0), target='t'), dict(ts=ts(T0), src='a'), 'junk', dict(ts=ts(T0), src='10.0.0.1', target='t')]
e, d = norm(raws, allow=['10.0.0.0/8']); print(' '.join('%s=%d' % kv for kv in sorted(d.items())))")"
assert_eq "N2 empty input -> no detections, no crash" "0 0" "$(run "d, s = rc.detect([]); print(len(d), s['targets'])")"
assert_eq "N3 query string dropped from path" "/login" "$(run "print(rc.normalize(dict(ts=ts(T0), src='a', target='t', path='/login?user=x&token=y'), 's')[0]['path'])")"

echo "[K1] killswitch integration stays dry-run"
K1="$(run "
sys.path.insert(0, 'security/killswitch'); import killswitch_lib as ks
d, s = rc.detect(norm(rotation())[0])
ev, err = ks.normalize_event(d[0])
print(ev, err)")"
assert_eq "K1 killswitch REJECTS this source today (accepts only snd_home/snd_id) -- no path from this detector to containment" "None source must be snd_home or snd_id" "$K1"
assert_eq "K2 detection recommends human review only" "HUMAN_REVIEW" "$(run "print(rc.detect(norm(rotation())[0])[0][0]['recommended_action'])")"

echo "[I1] regressions modeled on published incidents (traffic shapes only; no real addresses)"
# I1a -- Cisco Talos, "Large-scale brute-force activity targeting VPNs, SSH
#   services with commonly used login credentials", published 2024-04-16,
#   https://blog.talosintelligence.com/large-scale-brute-force-activity-targeting-vpns-ssh-services-with-commonly-used-login-credentials/
#   (retrieved 2026-10-20). Source states: brute-force attacks against VPN
#   services and other login interfaces, "originating from TOR exit nodes and
#   a range of other anonymizing tunnels and proxies"; source IPs "are likely
#   to change", so IP blocking alone is insufficient.
#   Technique: T1110 Brute Force (T1110.003 password spraying per Cisco's
#   linked guidance), through proxies (T1090.003 Multi-hop Proxy).
#   Modeled shape: each proxy source sends login attempts just under the
#   per-source limit, fails (401), then hands over to the next source.
#   Detection condition: rotation of near-limit sources with 4xx -> HIGH.
#   Defense: MFA, lockout/rate limits per ACCOUNT (not per source IP),
#   anonymizer blocking; this detector only raises HUMAN_REVIEW.
assert_eq "I1a VPN login brute force rotating through proxies (401s) -> detected, high or critical" "1 True" "$(run "
raws = [dict(r, path='/remote/login', status=401) for r in rotation(n_src=40)]
d = rc.detect(norm(raws)[0])[0]; print(len(d), d[0]['severity'] in ('high', 'critical') if d else None)")"
# I1b -- Okta Identity Threat Research, credential-stuffing surge observed
#   2024-04-19..2024-04-26, attributed to residential proxies, combo lists
#   and scripting tools. PRIMARY SOURCE NOT RETRIEVED on 2026-10-20 (the
#   sec.okta.com URLs tried returned 404; secondary coverage returned 403);
#   facts here rest on a search summary of secondary reports and must be
#   re-checked before being cited elsewhere.
#   Technique: T1110.004 Credential Stuffing via residential proxies.
#   Modeled shape: thousands of sources, a handful of attempts each.
#   Detection condition: NONE -- this detector correlates near-limit
#   sources, and low-and-slow stuffing never approaches a per-source limit.
#   This test pins that known gap of the ROTATION signal so its coverage is
#   never over-claimed; the separate stuffing signal covers it (I2).
#   Defense that does apply: per-account failure rates, breached-password
#   checks, MFA, blocking anonymizing services at the IdP.
assert_eq "I1b low-and-slow stuffing from 2000 residential-proxy sources -> NOT detected (known gap, by design)" "0" "$(run "
raws = [dict(ts=ts(T0 + (i * 3 + k * 600) % 3600), src='10.%d.%d.%d' % (i // 65536 % 256, i // 256 % 256, i % 256), target='shop', path='/login', status=401) for i in range(2000) for k in range(3)]
print(len(rc.detect(norm(raws)[0])[0]))")"

echo "[I2] distributed credential stuffing (low and slow) -- the gap I1b pins for the rotation signal"
# Same Okta-shaped traffic as I1b, through the separate stuffing signal.
STUFF="raws = [dict(ts=ts(T0 + (i * 3 + k * 600) % 3600), src='10.%d.%d.%d' % (i // 65536 % 256, i // 256 % 256, i % 256), target='shop', path='/login', status=401) for i in range(2000) for k in range(3)]"
assert_eq "I2 Okta-shaped stuffing (2000 sources x 3 failed logins) -> detected high, T1110.004" "1 distributed_credential_stuffing high True" "$(run "$STUFF
d = rc.detect_credential_stuffing(norm(raws)[0]); print(len(d), d[0]['type'], d[0]['severity'], 'T1110.004' in d[0]['attack_ids'])")"
assert_eq "I2 the rotation signal still does not claim it (I1b unchanged)" "0" "$(run "$STUFF
print(len(rc.detect(norm(raws)[0])[0]))")"
assert_eq "I2 no source address in the stuffing detection" "0" "$(run "$STUFF
import json, re; print(len(re.findall(r'(?<![0-9.])10\.[0-9]+\.[0-9]+\.[0-9]+', json.dumps(rc.detect_credential_stuffing(norm(raws)[0])))))")"
NORMAL="import random; random.seed(7)
raws = []
for i in range(2000):
    t = T0 + random.uniform(0, 3600); src = '172.16.%d.%d' % (i // 256, i % 256); r = random.random()
    if r < 0.90: raws.append(dict(ts=ts(t), src=src, target='shop', path='/login', status=302))
    elif r < 0.98: raws += [dict(ts=ts(t), src=src, target='shop', path='/login', status=401), dict(ts=ts(t + 20), src=src, target='shop', path='/login', status=302)]
    else: raws.append(dict(ts=ts(t), src=src, target='shop', path='/login', status=401))"
assert_eq "F11 ordinary logins (90% ok, 8% typo then ok, 2% give up) -> nothing" "0" "$(run "$NORMAL
print(len(rc.detect_credential_stuffing(norm(raws)[0])))")"
assert_eq "F12 stuffing below min_sources (60 sources) -> nothing" "0" "$(run "
raws = [dict(ts=ts(T0 + i), src='10.0.0.%d' % i, target='shop', path='/login', status=401) for i in range(60)]
print(len(rc.detect_credential_stuffing(norm(raws)[0])))")"
assert_eq "F13 failures on non-auth paths (404 crawl of 500 sources) -> nothing" "0" "$(run "
raws = [dict(ts=ts(T0 + i), src='10.0.%d.%d' % (i // 256, i % 256), target='shop', path='/item/%d' % i, status=401) for i in range(500)]
print(len(rc.detect_credential_stuffing(norm(raws)[0])))")"
assert_eq "F14 heavy per-source brute force (I1a shape) is rotation's job, not stuffing" "0" "$(run "
raws = [dict(r, path='/remote/login', status=401) for r in rotation(n_src=40)]
print(len(rc.detect_credential_stuffing(norm(raws)[0])))")"
assert_eq "I2 150 stuffing sources in 10 min on top of 2000 ordinary logins/hour -> detected" "1" "$(run "$NORMAL
raws += [dict(ts=ts(T0 + i * 4), src='10.9.%d.%d' % (i // 256, i % 256), target='shop', path='/login', status=401) for i in range(150)]
print(len(rc.detect_credential_stuffing(norm(raws)[0])))")"
assert_eq "I2 known limit: 100 stuffing sources spread over an hour of 2000 ordinary logins -> not detected (documented)" "0" "$(run "$NORMAL
raws += [dict(ts=ts(T0 + i * 36), src='10.9.%d.%d' % (i // 256, i % 256), target='shop', path='/login', status=401) for i in range(100)]
print(len(rc.detect_credential_stuffing(norm(raws)[0])))")"
# Ordinary users only (no attacker), 300 logins per 10 min for 6 hours; each
# source logs in once, and a share of them fails once and gives up.
GIVEUP="import random; random.seed(3)
def users(share):
    return [dict(ts=ts(T0 + random.uniform(0, 21600)), src='172.17.%d.%d' % (i // 256, i % 256), target='shop', path='/login',
                 status=401 if random.random() < share else 302) for i in range(10800)]"
assert_eq "F15 no attacker, 15% of 10800 login sources fail once and give up over 6 h -> nothing" "0" "$(run "$GIVEUP
print(len(rc.detect_credential_stuffing(norm(users(0.15))[0])))")"
assert_eq "F15 known false positive: no attacker, 40% give up -> fires (documented; HUMAN_REVIEW only)" "1" "$(run "$GIVEUP
print(len(rc.detect_credential_stuffing(norm(users(0.40))[0])))")"
assert_eq "F15 known false positive: an auth outage (every login 401 for 10 min) -> fires (documented)" "1" "$(run "
raws = [dict(ts=ts(T0 + i * 2), src='172.18.%d.%d' % (i // 256, i % 256), target='shop', path='/login', status=401) for i in range(300)]
print(len(rc.detect_credential_stuffing(norm(raws)[0])))")"

echo "[D1] data minimization and static guards"
assert_eq "D1 no source address anywhere in the detection" "0" "$(run "
import json; d, s = rc.detect(norm(rotation())[0]); print(json.dumps(d).count('198.51.100.'))")"
assert_eq "D1 salt changes the hashes (not a fixed reversible mapping)" "False" "$(run "print(rc.hash_src('198.51.100.1', 'a') == rc.hash_src('198.51.100.1', 'b'))")"
assert_eq "D1 no I/O, network or subprocess in the lib" "0" "$(grep -vE '^\s*#' "$LIB" | grep -cE '^\s*(import|from)\s+(os|socket|ssl|urllib|http|requests|subprocess)\b|\bopen\(|\b(eval|exec)\s*\(')"
assert_eq "D1 killswitch untouched by this change (still no distributed_probe mapping)" "0" "$(grep -c 'distributed_probe' security/killswitch/killswitch_lib.py)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
