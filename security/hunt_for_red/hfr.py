#!/usr/bin/env python3
"""security/hunt_for_red/hfr.py -- HUNT FOR RED P1 command line.

Writes only under HFR_HOME (default ~/waio-ops/hunt-for-red), never in
this repo (D-2). No network access (fetching is P3; D-3 allows passive
methods only). See hfr_lib.py's header for the integrity limits.

  hfr.py case-open  CASE --title T --scope-json J --approved-by human:X --approved-at TS --approval-ref R --cap-minutes N --cap-yen N [--candidate ID ...]
  hfr.py capture    CASE --file F --source-id S --method M --url U --fetched-at TS --content-type CT --verification V [--published-at TS] [--candidate-id ID]
  hfr.py claim      CASE --text T --class C --rationale R --attribution true|false [--supports ID ...] [--contradicts ID ...] [--alternative TEXT ...] [--supersedes ID]
  hfr.py ioc        CASE --type T --value V --first-capture ID --status S [--note N]   (V is defanged before it is stored)
  hfr.py cost       CASE --kind K [--minutes N] [--yen N] [--note N]
  hfr.py event      CASE --event E --reason R [--stop-condition N] [--approved-by human:X]
  hfr.py verify     CASE
  hfr.py manifest   CASE
Every writing command needs --agent (who is recording) and takes --host 800|750.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hfr_lib as hl  # noqa: E402


def _home():
    return os.environ.get("HFR_HOME") or os.path.expanduser("~/waio-ops/hunt-for-red")


def _bool(s):
    if s not in ("true", "false"):
        raise argparse.ArgumentTypeError("true or false")
    return s == "true"


def main(argv=None):
    p = argparse.ArgumentParser(prog="hfr.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    def w(name):
        sp = sub.add_parser(name)
        sp.add_argument("case_id")
        sp.add_argument("--agent", required=True)
        sp.add_argument("--host", default="800", choices=hl.HOSTS)
        return sp

    sp = w("case-open")
    sp.add_argument("--title", required=True)
    sp.add_argument("--scope-json", required=True)
    sp.add_argument("--approved-by", required=True)
    sp.add_argument("--approved-at", required=True)
    sp.add_argument("--approval-ref", required=True)
    sp.add_argument("--cap-minutes", type=int, required=True)
    sp.add_argument("--cap-yen", type=int, required=True)
    sp.add_argument("--candidate", action="append", default=[])

    sp = w("capture")
    sp.add_argument("--file", required=True)
    for a in ("--source-id", "--method", "--url", "--fetched-at", "--content-type", "--verification"):
        sp.add_argument(a, required=True)
    sp.add_argument("--published-at")
    sp.add_argument("--candidate-id")

    sp = w("claim")
    sp.add_argument("--text", required=True)
    sp.add_argument("--class", dest="cls", required=True)
    sp.add_argument("--rationale", required=True)
    sp.add_argument("--attribution", type=_bool, required=True)
    sp.add_argument("--supports", action="append", default=[])
    sp.add_argument("--contradicts", action="append", default=[])
    sp.add_argument("--alternative", action="append", default=[])
    sp.add_argument("--supersedes")

    sp = w("ioc")
    sp.add_argument("--type", dest="ioc_type", required=True)
    sp.add_argument("--value", required=True)
    sp.add_argument("--first-capture", required=True)
    sp.add_argument("--status", required=True)
    sp.add_argument("--note")
    sp.add_argument("--supersedes")

    sp = w("cost")
    sp.add_argument("--kind", required=True)
    sp.add_argument("--minutes", type=int, default=0)
    sp.add_argument("--yen", type=int, default=0)
    sp.add_argument("--note")

    sp = w("event")
    sp.add_argument("--event", required=True)
    sp.add_argument("--reason", required=True)
    sp.add_argument("--stop-condition", type=int)
    sp.add_argument("--approved-by")

    for name in ("verify", "manifest"):
        sp = sub.add_parser(name)
        sp.add_argument("case_id")

    a = p.parse_args(argv)
    try:
        led = hl.Ledger(_home(), a.case_id)
        if a.cmd == "verify":
            print(json.dumps(hl.verify_case(led), ensure_ascii=False, sort_keys=True))
            return 0
        if a.cmd == "manifest":
            hl.verify_case(led)
            print(led.write_manifest())
            return 0
        if a.cmd == "case-open":
            try:
                scope = json.loads(a.scope_json)
            except ValueError:
                raise hl.HFRError("--scope-json is not valid JSON")
            rec = led.append("case", {
                "title": a.title, "scope": scope, "approved_by": a.approved_by,
                "approved_at": a.approved_at, "approval_ref": a.approval_ref,
                "cost_cap": {"minutes": a.cap_minutes, "yen": a.cap_yen},
                "linked_candidates": a.candidate}, a.agent, a.host)
            led.append("event", {"event": "OPENED", "reason": "case opened under %s" % a.approval_ref}, a.agent, a.host)
        elif a.cmd == "capture":
            f = {"source_id": a.source_id, "method": a.method, "url": a.url, "fetched_at": a.fetched_at,
                 "content_type": a.content_type, "verification": a.verification, "published_at": a.published_at}
            if a.candidate_id:
                f["candidate_id"] = a.candidate_id
            rec = led.capture_file(a.file, f, a.agent, a.host)
        elif a.cmd == "claim":
            f = {"text": a.text, "class": a.cls, "rationale": a.rationale, "attribution": a.attribution,
                 "supports": a.supports, "contradicts": a.contradicts, "alternatives": a.alternative}
            if a.supersedes:
                f["supersedes"] = a.supersedes
            rec = led.append("claim", f, a.agent, a.host)
        elif a.cmd == "ioc":
            f = {"ioc_type": a.ioc_type, "value_defanged": hl.defang(a.value, a.ioc_type),
                 "first_capture": a.first_capture, "status": a.status}
            if a.note:
                f["note"] = a.note
            if a.supersedes:
                f["supersedes"] = a.supersedes
            rec = led.append("ioc", f, a.agent, a.host)
        elif a.cmd == "cost":
            f = {"kind": a.kind, "minutes": a.minutes, "yen": a.yen}
            if a.note:
                f["note"] = a.note
            rec = led.append("cost", f, a.agent, a.host)
        elif a.cmd == "event":
            f = {"event": a.event, "reason": a.reason}
            if a.stop_condition is not None:
                f["stop_condition"] = a.stop_condition
            if a.approved_by:
                f["approved_by"] = a.approved_by
            rec = led.append("event", f, a.agent, a.host)
        print(rec["record_id"])
        return 0
    except hl.HFRError as e:
        sys.stderr.write("[HFR] REFUSED: %s\n" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
