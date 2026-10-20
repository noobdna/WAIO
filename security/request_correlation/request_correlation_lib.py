"""security/request_correlation/request_correlation_lib.py -- detects
DISTRIBUTED, SUB-THRESHOLD probing: many sources that each stay just
under a per-source rate limit, then go quiet and hand over to the next
source. Pure computation, no I/O.

Why this exists: GMO Cybersecurity by Ierae (2026-10-15, "相次ぐ不正アクセス
に備える３つのポイント") reported attackers who evaded a per-IP WAF rate rule
by switching to another IP just before the threshold, using several
hundred IPs in total. Its 2026-10-19 post tied that campaign to the
agentic pentest tool ARTEX, and CrowdStrike (2026-10-07) reported ARTEX
against South Korean finance. A per-source threshold cannot see this
pattern by construction; it needs correlation ACROSS sources.

INPUT (waio.web.request_event.v1, one object per line; other fields dropped):
  ts      YYYY-MM-DDTHH:MM:SS[.fff]Z (UTC)
  src     client address or opaque id -- hashed on read, never stored
  target  service / host id being requested
  path    request path (query string dropped)
  status  HTTP status (int)

SIGNAL ("rotation"), per target:
  a "quitter" is a source whose peak count in any `window_s` window is
  within [near_ratio * per_src_threshold, per_src_threshold) -- i.e. it
  approached the limit without crossing it -- and which has then been
  silent for at least `window_s`. Fires when, in time order,
  quitters >= min_quitters, counted within one hand-over chain (each
  quitter starts at most max_handover_gap_s after the chain so far went
  quiet; unrelated near-limit sources hours apart never add up), AND either
    ROTATION: few quitters are active at once relative to how many have
      passed through -- peak_concurrency / quitters <= max_concurrency_ratio.
      This holds for one hand-over stream and for several parallel ones
      (an earlier pairwise "strictly sequential" test missed 2+ streams);
    or PROBING WAVE: many near-limit sources at once, but only together
      with 4xx probing (ratio_4xx >= probe_4xx_ratio). A wave of ordinary
      2xx traffic (a fleet of scheduled jobs) is left alone.
  Probing context and aggregate speed also raise severity.

False-positive guards, each with a test:
  - ordinary crowds (many sources, few requests each) never enter the
    near-threshold band;
  - one heavy source over the threshold (NAT, a real client) is the
    per-source limiter's job and is only counted, never correlated;
  - steady concurrent sources (CDN, health checks, load-balanced
    clients) are not sequential and do not go silent;
  - unrelated heavy clients spread over hours (or scheduled jobs from
    different runners minutes apart) are separate chains, not one rotation;
  - operator-declared allowlisted sources (CIDR or exact) are removed
    before anything else.

OUTPUT: a detection in the killswitch event field shape (source,
event_id, type, severity, target_ref, summary, observed_at), plus
evidence. killswitch_lib.normalize_event TODAY ACCEPTS ONLY
source=snd_home|snd_id, so it rejects this detection: there is no path
from here to containment, by design of the current control plane.
Accepting a new source and mapping "distributed_probe" to an action are
DuCoPA control-plane changes, left as reviewed proposals.
recommended_action is always HUMAN_REVIEW.

DATA MINIMIZATION: sources are salted SHA-256 hashes (salt from the
caller). No address reaches the output or the summary. With an empty
salt, an IPv4 hash can be reversed by enumeration, so callers should
pass a secret salt.
"""

import datetime
import hashlib
import ipaddress
import re

SCHEMA_INPUT = "waio.web.request_event.v1"
SCHEMA_DETECTION = "waio.request_correlation.detection.v1"

DEFAULTS = {
    "window_s": 60,
    "per_src_threshold": 100,
    "near_ratio": 0.7,
    "min_quitters": 10,
    "max_concurrency_ratio": 0.34,
    "probe_4xx_ratio": 0.5,
    "speed_rps": 5.0,
    "max_handover_gap_s": 120,
}

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def parse_ts(text):
    if not isinstance(text, str) or not _TS_RE.match(text):
        return None
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ" if "." in text else "%Y-%m-%dT%H:%M:%SZ"
    return datetime.datetime.strptime(text, fmt).replace(tzinfo=datetime.timezone.utc).timestamp()


def fmt_ts(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_src(src, salt):
    return hashlib.sha256((salt + "|" + src).encode()).hexdigest()[:16]


def parse_allowlist(entries):
    nets, exact = [], set()
    for e in entries or []:
        e = str(e).strip()
        if not e or e.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(e, strict=False))
        except ValueError:
            exact.add(e)
    return nets, exact


def _allowlisted(src, nets, exact):
    if src in exact:
        return True
    try:
        ip = ipaddress.ip_address(src)
    except ValueError:
        return False
    return any(ip in n for n in nets)


def normalize(raw, salt, nets=(), exact=frozenset()):
    """-> (event | None, drop_reason). Drops anything incomplete."""
    if not isinstance(raw, dict):
        return None, "not_object"
    ts = parse_ts(raw.get("ts"))
    src = raw.get("src")
    target = raw.get("target")
    if ts is None:
        return None, "bad_ts"
    if not isinstance(src, str) or not src:
        return None, "no_src"
    if not isinstance(target, str) or not target:
        return None, "no_target"
    if _allowlisted(src, nets, exact):
        return None, "allowlisted"
    status = raw.get("status")
    path = str(raw.get("path") or "/").split("?", 1)[0][:256]
    return {"ts": ts, "src": hash_src(src, salt), "target": target[:128], "path": path,
            "status": status if isinstance(status, int) else 0}, ""


class _Src(object):
    __slots__ = ("first", "last", "times", "peak", "count", "c4xx", "paths")

    def __init__(self, ts):
        self.first = self.last = ts
        self.times = []
        self.peak = 0
        self.count = 0
        self.c4xx = 0
        self.paths = set()


def _evaluate(srcs, now, c):
    w, thr = c["window_s"], c["per_src_threshold"]
    quitters = _largest_chain([s for s in srcs.values() if c["near_ratio"] * thr <= s.peak < thr and s.last <= now - w],
                              c["max_handover_gap_s"])
    if len(quitters) < c["min_quitters"]:
        return None
    conc = _peak_concurrency(quitters)
    if conc <= c["max_concurrency_ratio"] * len(quitters):
        return (now, quitters, "rotation", conc)
    q4 = sum(s.c4xx for s in quitters)
    qn = sum(s.count for s in quitters)
    if qn and q4 / float(qn) >= c["probe_4xx_ratio"]:
        return (now, quitters, "probing_wave", conc)
    return None


def _largest_chain(srcs, max_gap):
    """Largest group of sources linked by hand-over: in first-seen order,
    each starts no more than max_gap after every earlier one in the group
    went quiet. Parallel streams and waves overlap, so they stay linked."""
    best, cur, cur_last = [], [], None
    for s in sorted(srcs, key=lambda x: x.first):
        if cur and s.first - cur_last > max_gap:
            cur = []
        cur.append(s)
        cur_last = s.last if len(cur) == 1 else max(cur_last, s.last)
        if len(cur) > len(best):
            best = list(cur)
    return best


def _peak_concurrency(srcs):
    """Largest number of sources whose [first, last] lifetimes overlap."""
    points = sorted([(s.first, 1) for s in srcs] + [(s.last, -1) for s in srcs], key=lambda p: (p[0], p[1]))
    cur = peak = 0
    for _, d in points:
        cur += d
        peak = max(peak, cur)
    return peak


def _sequential_ratio(srcs):
    """Fraction of consecutive (by first-seen) pairs where the next source
    starts no earlier than halfway through the previous one's life."""
    s = sorted(srcs, key=lambda x: x.first)
    if len(s) < 2:
        return 0.0
    ok = sum(1 for a, b in zip(s, s[1:]) if b.first >= a.first + (a.last - a.first) / 2.0)
    return ok / float(len(s) - 1)


def detect(events, cfg=None):
    """events: normalized events (any order). -> (detections, stats).
    Evaluates in time order and fires at most once per target, at the
    first moment the rotation condition holds (that moment is the
    detection time used for time_to_detect_s)."""
    c = dict(DEFAULTS, **(cfg or {}))
    w, thr = c["window_s"], c["per_src_threshold"]
    by_target = {}
    for e in sorted(events, key=lambda x: x["ts"]):
        by_target.setdefault(e["target"], []).append(e)

    detections = []
    stats = {"targets": len(by_target), "over_threshold_sources": 0}
    for target in sorted(by_target):
        srcs = {}
        fired = None
        for e in by_target[target]:
            now = e["ts"]
            st = srcs.get(e["src"])
            if st is None:
                st = srcs[e["src"]] = _Src(now)
            st.last = now
            st.count += 1
            st.times.append(now)
            while st.times and st.times[0] <= now - w:
                st.times.pop(0)
            st.peak = max(st.peak, len(st.times))
            if 400 <= e["status"] < 500:
                st.c4xx += 1
            st.paths.add(e["path"])
            if not fired:
                fired = _evaluate(srcs, now, c)
        if not fired and by_target[target]:
            # Batch input: if everything went quiet at once, no later event
            # would ever trigger the check. Evaluate once at end of input
            # plus one window (a streaming caller would use a timer).
            fired = _evaluate(srcs, by_target[target][-1]["ts"] + w, c)
        stats["over_threshold_sources"] += sum(1 for s in srcs.values() if s.peak >= thr)
        if not fired:
            continue
        now, quitters, pattern, conc = fired
        seq = _sequential_ratio(quitters)
        start = min(s.first for s in quitters)
        reqs = sum(s.count for s in quitters)
        c4xx = sum(s.c4xx for s in quitters)
        paths = set().union(*(s.paths for s in quitters))
        span = max(now - start, 1.0)
        rps = reqs / span
        ratio_4xx = c4xx / float(reqs) if reqs else 0.0
        risk = "MEDIUM"
        factors = ["%s: %d sources each stopped at %d-%d%% of the per-source limit, at most %d active at once"
                   % (pattern, len(quitters), int(100 * min(s.peak for s in quitters) / thr),
                      int(100 * max(s.peak for s in quitters) / thr), conc)]
        if ratio_4xx >= c["probe_4xx_ratio"]:
            risk = "HIGH"
            factors.append("probing: %.0f%% 4xx across %d distinct paths" % (100 * ratio_4xx, len(paths)))
        if rps >= c["speed_rps"]:
            risk = RISK_ORDER[min(RISK_ORDER.index(risk) + 1, len(RISK_ORDER) - 1)]
            factors.append("speed: %.1f req/s sustained across sources (automation-grade; prioritise)" % rps)
        detections.append({
            "schema": SCHEMA_DETECTION,
            "source": "request_correlation",
            "event_id": "rc-" + hashlib.sha256(("%s|%d" % (target, int(start))).encode()).hexdigest()[:16],
            "type": "distributed_probe",
            "severity": risk.lower(),
            "target_ref": target,
            "summary": "%s on %s; %d rotating sources, %d requests" % ("; ".join(factors), target, len(quitters), reqs),
            "observed_at": fmt_ts(now),
            "evidence": {
                "first_seen_at": fmt_ts(start),
                "time_to_detect_s": int(now - start),
                "rotating_sources": len(quitters),
                "pattern": pattern,
                "peak_concurrency": conc,
                "sequential_ratio": round(seq, 3),
                "requests": reqs,
                "ratio_4xx": round(ratio_4xx, 3),
                "distinct_paths": len(paths),
                "aggregate_rps": round(rps, 2),
                "source_hashes": sorted(s_hash for s_hash, s in srcs.items() if s in quitters)[:20],
                "config": {k: c[k] for k in sorted(DEFAULTS)},
            },
            "attack_ids": ["T1595.002", "T1090.002", "T1190"],
            "recommended_action": "HUMAN_REVIEW",
            "killswitch_mapping": "not accepted by killswitch today (source must be snd_home/snd_id; type unmapped); a reviewed DuCoPA change would be needed",
        })
    return detections, stats


# --- distributed credential stuffing (low and slow) ----------------------
# The rotation signal above needs sources near a per-source limit. Stuffing
# through residential proxies (Okta, 2024-04) keeps every source far below
# any limit: thousands of sources, a few failed logins each. This separate
# signal looks only at authentication paths and fires when, within one
# sliding window, many sources made only a few attempts, all failed, none
# ever succeeded, and they are a substantial share of all sources on those
# paths. A user who mistypes and then logs in is not "pure-fail"; one who
# mistypes and leaves is, which is why a share, not just a count, is needed.
# Known limit: a small attack hidden in a much larger stream of ordinary
# logins stays below min_pure_share. Per-account failure limits and MFA
# cover that; this is a HUMAN_REVIEW signal only.

STUFFING_DEFAULTS = {
    "window_s": 600,
    "auth_path_re": r"(?i)(log[-_]?in|sign[-_]?in|auth|session|token|oauth|password)",
    "max_attempts_per_source": 5,
    "min_sources": 100,
    "min_pure_share": 0.3,
}


class _Auth(object):
    __slots__ = ("times", "fails", "succ")

    def __init__(self):
        self.times = []
        self.fails = []
        self.succ = 0


def _pure(st, cap):
    return 0 < len(st.times) <= cap and st.succ == 0 and len(st.fails) == len(st.times)


def detect_credential_stuffing(events, cfg=None):
    """events: normalized events (any order). -> detections (at most one per
    target), same envelope as detect()."""
    c = dict(STUFFING_DEFAULTS, **(cfg or {}))
    w, cap = c["window_s"], c["max_attempts_per_source"]
    auth = re.compile(c["auth_path_re"])
    by_target = {}
    for e in sorted(events, key=lambda x: x["ts"]):
        if auth.search(e["path"]):
            by_target.setdefault(e["target"], []).append(e)
    detections = []
    for target in sorted(by_target):
        evs = by_target[target]
        srcs, pure, ever_ok = {}, set(), set()
        head = 0
        for e in evs:
            now = e["ts"]
            while evs[head]["ts"] <= now - w:  # expire one old event at a time
                old = evs[head]
                head += 1
                st = srcs.get(old["src"])
                if st and st.times and st.times[0] <= now - w:
                    st.times.pop(0)
                    if st.fails and st.fails[0] <= now - w:
                        st.fails.pop(0)
                    if not st.times:
                        del srcs[old["src"]]
                        pure.discard(old["src"])
                        continue
                    (pure.add if _pure(st, cap) and old["src"] not in ever_ok else pure.discard)(old["src"])
            st = srcs.setdefault(e["src"], _Auth())
            st.times.append(now)
            if e["status"] in (401, 403):
                st.fails.append(now)
            elif 200 <= e["status"] < 400:
                st.succ += 1
                ever_ok.add(e["src"])
            (pure.add if _pure(st, cap) and e["src"] not in ever_ok else pure.discard)(e["src"])
            if len(pure) >= c["min_sources"] and len(pure) >= c["min_pure_share"] * len(srcs):
                attempts = sum(len(srcs[h].times) for h in pure)
                detections.append({
                    "schema": SCHEMA_DETECTION,
                    "source": "request_correlation",
                    "event_id": "cs-" + hashlib.sha256(("%s|%d" % (target, int(now))).encode()).hexdigest()[:16],
                    "type": "distributed_credential_stuffing",
                    "severity": "high",
                    "target_ref": target,
                    "summary": "credential stuffing pattern on %s: %d sources in %ds each made 1-%d failed login attempts and never succeeded (%.0f%% of sources on auth paths)"
                               % (target, len(pure), w, cap, 100.0 * len(pure) / len(srcs)),
                    "observed_at": fmt_ts(now),
                    "evidence": {
                        "pure_fail_sources": len(pure),
                        "auth_sources_in_window": len(srcs),
                        "failed_attempts": attempts,
                        "window_s": w,
                        "source_hashes": sorted(pure)[:20],
                        "config": {k: c[k] for k in sorted(STUFFING_DEFAULTS)},
                    },
                    "attack_ids": ["T1110.004", "T1090.003"],
                    "recommended_action": "HUMAN_REVIEW",
                    "killswitch_mapping": "not accepted by killswitch today (source must be snd_home/snd_id; type unmapped)",
                })
                break
    return detections

