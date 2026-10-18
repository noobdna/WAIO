#!/bin/bash
set -uo pipefail

# tests/response60_isolation_test.sh -- proves tests/response60_test.sh
# never touches the real Emergency Shutdown lock, worker registry, audit
# log, Guardian state or desktop notifications of the checkout it runs
# from.
#
# Safe by construction: it never creates anything at THIS checkout's
# real security/state/SHUTDOWN.lock (doing so would be a real shutdown).
# Instead it copies the tree into a temp dir, plants a SENTINEL lock at
# that copy's "real" path, and runs the copy's response60_test.sh:
#   - the run must PASS -- an un-isolated test reads the sentinel and
#     ABORTs ("a shutdown is already active");
#   - the sentinel's bytes, inode and mtime must be unchanged;
#   - the copy's registry, real audit log, Guardian state and
#     notification path must be untouched.

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
code_only() { grep -vE '^[[:space:]]*#' "$1"; }
fstat() { python3 -c 'import os,sys; s=os.stat(sys.argv[1]); print(s.st_ino, s.st_mtime_ns, s.st_size)' "$1" 2>/dev/null || echo absent; }
fsum() { if [ -f "$1" ]; then shasum -a 256 "$1" | cut -d' ' -f1; else echo absent; fi; }

echo "=== response60_test.sh isolation suite ==="

T="$(mktemp -d "${TMPDIR:-/tmp}/waio-r60-iso.XXXXXX")"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/copy" "$T/bin"
git ls-files -z --cached --others --exclude-standard | xargs -0 tar cf - 2>/dev/null | (cd "$T/copy" && tar xf -)
mkdir -p "$T/copy/security/state" "$T/copy/logs"

# The sentinel: in the copy only. Its presence at the default path is
# exactly what an un-isolated response60_test.sh would see as an active
# shutdown.
SENTINEL="$T/copy/security/state/SHUTDOWN.lock"
printf 'reason: SENTINEL -- response60 isolation test, must never be read or modified\ntriggered_at: 2000-01-01T00:00:00Z\n' > "$SENTINEL"
SENT_SUM="$(fsum "$SENTINEL")"; SENT_STAT="$(fstat "$SENTINEL")"
REG_SUM="$(fsum "$T/copy/workers/registry.conf")"

# An outer osascript stub: if response60 ever reached a real notifier on
# PATH ahead of its own stub, this file would appear.
printf '#!/bin/bash\necho called >> "%s/outer-osascript.calls"\n' "$T" > "$T/bin/osascript"; chmod +x "$T/bin/osascript"

echo ""
echo "[R1] static: every lock/audit/Guardian override is exported before security/lib.sh is first sourced"
first_source="$(code_only tests/response60_test.sh | grep -n 'source security/lib.sh' | head -1 | cut -d: -f1)"
for v in WAIO_SHUTDOWN_LOCK WAIO_AUDIT_LOG WAIO_AUDIT_LOG_CHECKPOINT WAIO_GUARDIAN_STATE_FILE WAIO_GUARDIAN_QUARANTINE_FILE WAIO_EGRESS_ALLOWLIST WAIO_RECOVER_RECONCILE_MARKER; do
  line="$(code_only tests/response60_test.sh | grep -n "^export $v=" | head -1 | cut -d: -f1)"
  assert_eq "R1 $v exported before lib.sh" "true" "$([ -n "$line" ] && [ -n "$first_source" ] && [ "$line" -lt "$first_source" ] && echo true || echo false)"
done
assert_eq "R1 no reference to the checkout's own registry path outside the isolated copy" "0" "$(code_only tests/response60_test.sh | grep -cE '"\$ORIG_DIR/workers|\$SCRIPT_DIR/workers' || true)"

echo ""
echo "[R2] dynamic: the copy's response60_test.sh passes despite a sentinel lock at its real path"
OUT="$(cd "$T/copy" && PATH="$T/bin:$PATH" RESPONSE60_JSON_OUT="$T/response60.json" bash tests/response60_test.sh 2>&1)"; RC=$?
assert_eq "R2 exit 0" "0" "$RC"
assert_contains "R2 OVERALL: PASS" "$OUT" "OVERALL: PASS"
assert_eq "R2 did not ABORT on the sentinel" "false" "$([[ "$OUT" == *"ABORT"* ]] && echo true || echo false)"

echo ""
echo "[R3] the real-path lock, registry, audit log, Guardian state and notifier are untouched"
assert_eq "R3 sentinel content unchanged" "$SENT_SUM" "$(fsum "$SENTINEL")"
assert_eq "R3 sentinel inode/mtime/size unchanged" "$SENT_STAT" "$(fstat "$SENTINEL")"
assert_eq "R3 registry unchanged" "$REG_SUM" "$(fsum "$T/copy/workers/registry.conf")"
assert_eq "R3 no registry backup left behind" "0" "$(find "$T/copy/workers" -name 'registry.conf.*' | wc -l | tr -d ' ')"
assert_eq "R3 real audit log never created" "absent" "$(fsum "$T/copy/logs/security-audit.jsonl")"
assert_eq "R3 real Guardian state never created" "absent" "$(fsum "$T/copy/security/state/GUARDIAN_STATE")"
assert_eq "R3 outer notifier never called" "absent" "$(fsum "$T/outer-osascript.calls")"
assert_eq "R3 dashboard JSON went only to the override path" "absent" "$(fsum "$T/copy/logs/response60-latest.json")"
assert_contains "R3 override JSON written and shows PASS" "$(cat "$T/response60.json" 2>/dev/null)" '"overall": "PASS"'
assert_eq "R3 no response60 temp copy left behind" "0" "$(ls "${TMPDIR:-/tmp}" | grep -c '^waio-response60\.' || true)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
