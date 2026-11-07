#!/usr/bin/env python3
"""security/corporate_intel/ci.py -- WAIO Corporate Intelligence CLI (P1).

Offline by default. Commands:

  ingest    --source {kev,nvd,epss} --file PATH [--fetched-at TS] [--http-status N]
            Parse a response body already on disk (fixture or a manual
            download) into the state store. Never touches the network.
  fetch     --source {kev,nvd,epss} --online [--cve ID ...] [--cves-from-kev N]
            Fetch via ci_fetch.sh (egress_check-gated). Refuses without
            --online. On any failure the previous data is kept and the
            source is marked stale.
  normalize [--inventory PATH]       Build normalized/cves.json.
  report    --inventory PATH [--now TS] [--top N]
            Correlate + score; writes reports/report-<ts>.json and
            prints a redacted summary.
  status    Print per-source fetch status.

State dir: $WAIO_CI_STATE_DIR or security/state/corporate_intel/ (gitignored).
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from ci_lib import correlate, cveid, epss, kev, normalize, nvd, provenance, redact, risk  # noqa: E402
from ci_lib.store import MAX_BODY_BYTES, Store, StoreError  # noqa: E402

PARSERS = {"kev": kev.parse, "nvd": nvd.parse, "epss": epss.parse}
FETCH_SH = os.path.join(HERE, "ci_fetch.sh")
NVD_INTERVAL_S = 6.5  # keyless NVD limit is 5 requests / 30 s


def _nvd_interval():
    # only an isolated test run (tests/lib/test_isolation.sh) may shorten it
    if os.environ.get("WAIO_TEST_ROOT") and os.environ.get("WAIO_CI_NVD_INTERVAL_S"):
        return max(0.0, float(os.environ["WAIO_CI_NVD_INTERVAL_S"]))
    return NVD_INTERVAL_S


def log(msg):
    print(redact.redact(f"[CORPORATE INTEL] {msg}"), file=sys.stderr)


def emit(text):
    print(redact.redact(text))


def _read_body(path):
    size = os.path.getsize(path)
    if size > MAX_BODY_BYTES:
        raise StoreError(f"body exceeds {MAX_BODY_BYTES} bytes")
    with open(path, "rb") as f:
        return f.read()


def ingest_body(store, source, body, fetched_at, http_status=200, url=None, replace_all=None):
    """Parse + store one response body. Parse failure leaves stored data
    untouched and marks the source stale. Returns counts dict."""
    if not body.strip():
        raise ValueError(f"{source}: empty response body")
    kwargs = {} if source == "kev" else {"url": url}
    records, stats = PARSERS[source](body, fetched_at, http_status, **kwargs)
    store.save_raw(source, body)
    counts = store.merge_source(source, records, replace_all=(source == "kev") if replace_all is None else replace_all)
    counts.update({k: v for k, v in stats.items() if k in ("entries", "invalid_id", "duplicates", "invalid_score")})
    return counts


def cmd_ingest(args, store):
    fetched_at = args.fetched_at or provenance.iso(provenance.utc_now())
    try:
        body = _read_body(args.file)
        counts = ingest_body(store, args.source, body, fetched_at, args.http_status)
    except (ValueError, StoreError, OSError) as e:
        store.record_failure(args.source, fetched_at, e)
        log(f"ingest {args.source} FAILED, previous data kept, source marked stale: {e}")
        return 2
    store.record_success(args.source, fetched_at)
    log(f"ingest {args.source}: {json.dumps(counts, sort_keys=True)}")
    return 0


def _run_fetch(source, out_path, ids):
    env = dict(os.environ)
    env["WAIO_CI_ONLINE"] = "1"
    env.pop("NVD_API_KEY", None)  # P1 is keyless by policy; never forwarded
    proc = subprocess.run(["bash", FETCH_SH, source, out_path, *ids], env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    status = proc.stdout.decode("utf-8", "replace").strip()[-3:]
    if proc.returncode != 0:
        raise RuntimeError(f"fetch {source} failed (rc={proc.returncode}, http={status or '000'}): "
                           f"{proc.stderr.decode('utf-8', 'replace').strip()[-300:]}")
    return int(status) if status.isdigit() else 0


def cmd_fetch(args, store):
    if not args.online:
        log("fetch refused: offline mode is the default; pass --online (requires approved egress allowlist entries)")
        return 3
    ids = []
    for raw in args.cve or []:
        c = cveid.normalize(raw)
        if not c:
            log(f"fetch refused: invalid CVE id {raw!r}")
            return 2
        ids.append(c)
    if args.cves_from_kev:
        ids.extend(sorted(store.load_source("kev").get("records", {}))[: args.cves_from_kev])
    ids = sorted(set(ids))
    if args.source == "kev" and ids:
        log("fetch kev takes no CVE ids")
        return 2
    if args.source in ("nvd", "epss") and not ids:
        log(f"fetch {args.source} needs --cve or --cves-from-kev")
        return 2

    batches = [[]] if args.source == "kev" else (
        [[c] for c in ids] if args.source == "nvd" else
        [ids[i:i + epss.MAX_BATCH] for i in range(0, len(ids), epss.MAX_BATCH)])
    failed, rc = [], 0
    with tempfile.TemporaryDirectory(prefix="waio-ci-fetch-") as tmp:
        for n, batch in enumerate(batches):
            if args.source == "nvd" and n:
                time.sleep(_nvd_interval())
            out = os.path.join(tmp, f"body-{n}.json")
            fetched_at = provenance.iso(provenance.utc_now())
            url = (kev.SOURCE_URL if args.source == "kev" else
                   nvd.source_url(batch[0]) if args.source == "nvd" else epss.source_url(batch))
            try:
                status = _run_fetch(args.source, out, batch)
                counts = ingest_body(store, args.source, _read_body(out), fetched_at, status, url)
                log(f"fetch {args.source} {','.join(batch) or 'catalog'}: {json.dumps(counts, sort_keys=True)}")
            except (RuntimeError, ValueError, StoreError, OSError, subprocess.TimeoutExpired) as e:
                failed.extend(batch or ["*"])
                log(f"fetch {args.source} FAILED, previous data kept: {e}")
                rc = 2
                if args.source == "nvd" and ("http=403" in str(e) or "http=429" in str(e)):
                    log("NVD rate limit hit: aborting this cycle")
                    failed.extend(c for b in batches[n + 1:] for c in b)
                    break
    now = provenance.iso(provenance.utc_now())
    if failed:
        store.record_failure(args.source, now, f"{len(failed)} item(s) failed",
                             [] if "*" in failed else failed)
    else:
        store.record_success(args.source, now)
    return rc


def _load_inventory(path):
    with open(path, "rb") as f:
        inv = json.loads(f.read().decode("utf-8"))
    if not isinstance(inv, dict) or not isinstance(inv.get("assets"), list):
        raise ValueError("inventory must be an object with an 'assets' list")
    return inv


def cmd_normalize(args, store):
    recs = normalize.build(store)
    store.write_json(("normalized", "cves.json"), recs)
    log(f"normalized {len(recs)} CVE record(s)")
    return 0


def build_report(store, inventory, now):
    recs = normalize.build(store)
    store.write_json(("normalized", "cves.json"), recs)
    assets = {a.get("id"): a for a in inventory["assets"]}
    findings = []
    for m in correlate.correlate(inventory, recs):
        rec, asset = recs[m["cve_id"]], assets[m["asset_id"]]
        r = risk.score_risk(rec, asset)
        c = risk.score_confidence(rec, m["match_level"], now)
        findings.append({
            **m,
            "asset_name": asset.get("name"),
            "risk": r,
            "confidence": c,
            "kev_listed": bool(rec.get("kev")),
            "provenance": {s: rec[s]["provenance"] for s in ("kev", "nvd", "epss") if rec.get(s)},
        })
    findings.sort(key=lambda f: (-f["risk"]["score"], -f["confidence"]["score"], f["asset_id"], f["cve_id"]))
    return {
        "schema": "waio-corporate-intel-report/1",
        "generated_at": provenance.iso(now),
        "organization": inventory.get("organization", {}),
        "synthetic": bool(inventory.get("synthetic")),
        "source_status": {s: store.load_status(s) for s in ("kev", "nvd", "epss")},
        "summary": {
            "cves_known": len(recs),
            "findings": len(findings),
            "by_tier": {t: sum(1 for f in findings if f["risk"]["tier"] == t) for t in ("P1", "P2", "P3", "P4")},
            "low_confidence": sum(1 for f in findings if f["confidence"]["level"] == "LOW"),
        },
        "findings": findings,
    }


def cmd_report(args, store):
    try:
        inventory = _load_inventory(args.inventory)
    except (OSError, ValueError) as e:
        log(f"report refused: {e}")
        return 2
    now = provenance.parse_ts(args.now) if args.now else provenance.utc_now()
    if now is None:
        log("report refused: bad --now")
        return 2
    rep = build_report(store, inventory, now)
    safe = json.loads(redact.redact(json.dumps(rep, ensure_ascii=False)))
    path = store.write_json(("reports", f"report-{provenance.iso(now).replace(':', '')}.json"), safe)
    s = rep["summary"]
    emit(f"report: {path}")
    emit(f"findings={s['findings']} P1={s['by_tier']['P1']} P2={s['by_tier']['P2']} "
         f"P3={s['by_tier']['P3']} P4={s['by_tier']['P4']} low_confidence={s['low_confidence']}")
    for f in rep["findings"][: args.top]:
        emit(f"  {f['risk']['tier']} risk={f['risk']['score']:>6} conf={f['confidence']['level']:<6} "
             f"{f['asset_id']} {f['cve_id']} [{f['match_level']}]"
             + (" KEV" if f["kev_listed"] else "")
             + (f" missing={','.join(f['risk']['missing'])}" if f["risk"]["missing"] else ""))
    return 0


def cmd_status(args, store):
    for s in ("kev", "nvd", "epss"):
        emit(json.dumps(store.load_status(s) or {"source": s, "never_fetched": True}, sort_keys=True))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="ci.py", description=__doc__.split("\n\n")[0])
    p.add_argument("--state-dir")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("ingest")
    a.add_argument("--source", choices=PARSERS, required=True)
    a.add_argument("--file", required=True)
    a.add_argument("--fetched-at")
    a.add_argument("--http-status", type=int, default=200)
    a = sub.add_parser("fetch")
    a.add_argument("--source", choices=PARSERS, required=True)
    a.add_argument("--online", action="store_true")
    a.add_argument("--cve", action="append")
    a.add_argument("--cves-from-kev", type=int, default=0)
    sub.add_parser("normalize")
    a = sub.add_parser("report")
    a.add_argument("--inventory", required=True)
    a.add_argument("--now")
    a.add_argument("--top", type=int, default=20)
    sub.add_parser("status")
    args = p.parse_args(argv)
    store = Store(args.state_dir)
    try:
        return {"ingest": cmd_ingest, "fetch": cmd_fetch, "normalize": cmd_normalize,
                "report": cmd_report, "status": cmd_status}[args.cmd](args, store)
    except StoreError as e:
        log(f"refused: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
