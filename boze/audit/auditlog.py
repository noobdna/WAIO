#!/usr/bin/env python3
"""boze/audit/auditlog.py -- BOZE append-only, hash-chained audit log.

Tamper-EVIDENCE, not tamper-prevention (same stance as security/lib.sh's
verify_audit_log_integrity): anyone who can write the file can still
rewrite it, but they cannot do so without verify() noticing, unless they
also rewrite the checkpoint AND every external anchor taken since.

Format: one JSON object per line (UTF-8, sorted keys, no spaces):
  seq             1, 2, 3, ... with no gaps
  ts              UTC ISO-8601 timestamp
  actor, action   short identifiers (no control characters)
  payload_sha256  SHA-256 of the exact payload the action was about
                  (the payload itself is never stored here)
  detail          small JSON object (optional context, <= 4 KiB)
  prev_hash       SHA-256 of the previous line's exact bytes (without
                  the trailing newline); 64 zeros for the first line.
                  Same chaining rule as security/lib.sh's audit_log().

Design choices:
  * One writer at a time via fcntl.flock on "<log>.lock". This replaces
    mkdir-based locking, which raced in WAIO (#168/#172/#188).
  * "<log>.checkpoint" records seq, line hash and byte size of the last
    line written. A truncated tail, which a hash chain alone cannot see,
    shows up as a mismatch against it. head() output is meant to be
    copied off-host as an anchor; verify(anchors=...) checks those too.
  * Fail closed: append() refuses to write when the log no longer
    matches its checkpoint, so nothing is chained onto a tampered log.
    The one exception is a crash between the log write and the
    checkpoint update. That leaves exactly one complete, correctly
    chained extra line, which is accepted and rolled forward.
  * Opened with O_APPEND, so it works with `chflags uappnd` on the log.

Python 3.9 standard library only.
"""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
import sys

GENESIS = "0" * 64
MAX_DETAIL_BYTES = 4096
MAX_ID_LEN = 128
REQUIRED_KEYS = ("seq", "ts", "actor", "action", "payload_sha256", "detail", "prev_hash")


class AuditError(Exception):
    """Raised when the log cannot be appended to safely."""


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _check_id(name, value):
    if not isinstance(value, str) or not value or len(value) > MAX_ID_LEN:
        raise AuditError("%s must be a non-empty string of at most %d chars" % (name, MAX_ID_LEN))
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise AuditError("%s contains control characters" % name)


def _paths(log_path):
    return log_path + ".checkpoint", log_path + ".lock"


def _read_checkpoint(cp_path):
    try:
        with open(cp_path, "r", encoding="utf-8") as f:
            cp = json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        raise AuditError("checkpoint unreadable: %s" % e)
    if not isinstance(cp, dict) or not all(k in cp for k in ("seq", "line_sha256", "size")):
        raise AuditError("checkpoint malformed")
    return cp


def _write_checkpoint(cp_path, seq, line_sha, size):
    tmp = cp_path + ".tmp"
    data = json.dumps({"seq": seq, "line_sha256": line_sha, "size": size}, sort_keys=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, cp_path)


def _read_range(path, start, end):
    with open(path, "rb") as f:
        f.seek(start)
        return f.read(end - start)


def _last_line_at(path, size):
    """Return the bytes of the last complete line ending exactly at `size`."""
    if size == 0:
        return None
    chunk = 8192
    pos = size
    buf = b""
    while pos > 0:
        step = min(chunk, pos)
        pos -= step
        buf = _read_range(path, pos, pos + step) + buf
        if not buf.endswith(b"\n"):
            raise AuditError("log does not end with a newline at checkpoint size")
        idx = buf.rfind(b"\n", 0, len(buf) - 1)
        if idx != -1:
            return buf[idx + 1:-1]
    return buf[:-1]


def _parse(line_bytes):
    try:
        rec = json.loads(line_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(rec, dict) or not all(k in rec for k in REQUIRED_KEYS):
        return None
    return rec


def _state_under_lock(log_path, cp_path):
    """Return (seq, last_line_sha, size) after checking log vs checkpoint."""
    size = os.path.getsize(log_path) if os.path.exists(log_path) else 0
    cp = _read_checkpoint(cp_path)
    if cp is None:
        if size != 0:
            raise AuditError("log exists but checkpoint is missing")
        return 0, GENESIS, 0
    if size < cp["size"]:
        raise AuditError("log is shorter than checkpoint (truncated?)")
    if cp["size"] > 0:
        last = _last_line_at(log_path, cp["size"])
        if last is None or _sha(last) != cp["line_sha256"]:
            raise AuditError("last line does not match checkpoint (edited?)")
    elif cp["seq"] != 0:
        raise AuditError("checkpoint malformed")
    if size == cp["size"]:
        return cp["seq"], cp["line_sha256"], size
    # Crash recovery: accept exactly one complete, correctly chained extra line.
    extra = _read_range(log_path, cp["size"], size)
    if extra.count(b"\n") != 1 or not extra.endswith(b"\n"):
        raise AuditError("unexpected data after checkpoint")
    rec = _parse(extra[:-1])
    if rec is None or rec["seq"] != cp["seq"] + 1 or rec["prev_hash"] != cp["line_sha256"]:
        raise AuditError("unexpected data after checkpoint")
    line_sha = _sha(extra[:-1])
    _write_checkpoint(cp_path, rec["seq"], line_sha, size)
    return rec["seq"], line_sha, size


def append(log_path, actor, action, payload=b"", detail=None):
    """Append one record. Returns the record dict (with its line hash)."""
    _check_id("actor", actor)
    _check_id("action", action)
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    if not isinstance(payload, (bytes, bytearray)):
        raise AuditError("payload must be bytes or str")
    detail = {} if detail is None else detail
    if not isinstance(detail, dict):
        raise AuditError("detail must be a JSON object")
    try:
        detail_json = json.dumps(detail, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        raise AuditError("detail not JSON-serialisable: %s" % e)
    if len(detail_json.encode("utf-8")) > MAX_DETAIL_BYTES:
        raise AuditError("detail larger than %d bytes" % MAX_DETAIL_BYTES)

    cp_path, lock_path = _paths(log_path)
    lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        seq, prev_sha, size = _state_under_lock(log_path, cp_path)
        rec = {
            "seq": seq + 1,
            "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "actor": actor,
            "action": action,
            "payload_sha256": _sha(bytes(payload)),
            "detail": detail,
            "prev_hash": prev_sha,
        }
        line = json.dumps(rec, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        fd = os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            data = line + b"\n"
            if os.write(fd, data) != len(data):
                raise AuditError("short write")
            os.fsync(fd)
        finally:
            os.close(fd)
        line_sha = _sha(line)
        _write_checkpoint(cp_path, rec["seq"], line_sha, size + len(line) + 1)
        rec["line_sha256"] = line_sha
        return rec
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def verify(log_path, anchors=None, use_checkpoint=True):
    """Check the whole chain. Returns a dict; result["ok"] is the verdict."""
    errors = []
    anchors = dict(anchors or {})
    seen_anchor = set()
    prev_sha = GENESIS
    expected_seq = 1
    size = 0
    try:
        f = open(log_path, "rb")
    except FileNotFoundError:
        f = None
    if f is not None:
        with f:
            for raw in f:
                size += len(raw)
                if not raw.endswith(b"\n"):
                    errors.append("seq %d: incomplete trailing line" % expected_seq)
                    break
                line = raw[:-1]
                rec = _parse(line)
                if rec is None:
                    errors.append("seq %d: unparseable or missing keys" % expected_seq)
                    break
                if rec["seq"] != expected_seq:
                    errors.append("expected seq %d, found %r (deleted/reordered?)" % (expected_seq, rec["seq"]))
                if rec["prev_hash"] != prev_sha:
                    errors.append("seq %r: prev_hash mismatch (previous line edited/removed?)" % rec["seq"])
                prev_sha = _sha(line)
                if rec["seq"] in anchors:
                    seen_anchor.add(rec["seq"])
                    if anchors[rec["seq"]] != prev_sha:
                        errors.append("seq %r: does not match external anchor" % rec["seq"])
                expected_seq = rec["seq"] + 1 if isinstance(rec["seq"], int) else expected_seq + 1
    last_seq = expected_seq - 1
    for s in sorted(set(anchors) - seen_anchor):
        errors.append("anchor seq %d not present (truncated?)" % s)
    if use_checkpoint:
        try:
            cp = _read_checkpoint(_paths(log_path)[0])
        except AuditError as e:
            cp = None
            errors.append(str(e))
        if cp is None and size > 0 and not any("checkpoint" in e for e in errors):
            errors.append("checkpoint missing")
        elif cp is not None and (cp["seq"] != last_seq or cp["line_sha256"] != prev_sha or cp["size"] != size):
            errors.append("log does not match checkpoint (seq %d vs %d)" % (last_seq, cp["seq"]))
    return {"ok": not errors, "last_seq": last_seq, "last_line_sha256": prev_sha,
            "size": size, "errors": errors}


def head(log_path):
    """Return {"seq", "line_sha256"} of the last line, for off-host anchoring."""
    r = verify(log_path)
    return {"seq": r["last_seq"], "line_sha256": r["last_line_sha256"], "ok": r["ok"]}


def _parse_anchor(text):
    seq, _, h = text.partition(":")
    if not seq.isdigit() or len(h) != 64:
        raise argparse.ArgumentTypeError("anchor must be SEQ:SHA256")
    return int(seq), h.lower()


def main(argv=None):
    p = argparse.ArgumentParser(prog="auditlog", description="BOZE append-only audit log")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("append")
    a.add_argument("--log", required=True)
    a.add_argument("--actor", required=True)
    a.add_argument("--action", required=True)
    a.add_argument("--payload-file", help="file whose bytes are hashed (use - for stdin)")
    a.add_argument("--detail-json", default="{}")
    v = sub.add_parser("verify")
    v.add_argument("--log", required=True)
    v.add_argument("--anchor", action="append", type=_parse_anchor, default=[])
    h = sub.add_parser("head")
    h.add_argument("--log", required=True)
    args = p.parse_args(argv)

    if args.cmd == "append":
        payload = b""
        if args.payload_file == "-":
            payload = sys.stdin.buffer.read()
        elif args.payload_file:
            with open(args.payload_file, "rb") as f:
                payload = f.read()
        try:
            detail = json.loads(args.detail_json)
            rec = append(args.log, args.actor, args.action, payload, detail)
        except (AuditError, ValueError) as e:
            print("auditlog: append refused: %s" % e, file=sys.stderr)
            return 1
        print(json.dumps({"seq": rec["seq"], "line_sha256": rec["line_sha256"]}))
        return 0
    if args.cmd == "verify":
        r = verify(args.log, anchors=dict(args.anchor))
        print(json.dumps(r, ensure_ascii=False))
        return 0 if r["ok"] else 2
    r = head(args.log)
    print(json.dumps(r))
    return 0 if r["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
