#!/bin/bash
set -uo pipefail

# security/mail_forensics/preserve_evidence.sh -- evidence preservation
# step for ONE suspicious email, before anyone reads it by hand:
#
#   preserve_evidence.sh <message.eml|.emlx> <case-name>
#
# Creates $MAIL_FORENSICS_CASE_ROOT/case-<UTC date>-<case-name>.noindex/
# (default root ~/quarantine; ".noindex" keeps Spotlight out of it),
# then:
#   1. copies the message to evidence/original.<ext> (cp -p), makes the
#      copy read-only (0400) and verifies source and copy SHA-256 match;
#   2. appends acquisition facts (UTC time, source path, size, mtime) to
#      notes/log.txt and the hashes to notes/hashes.txt;
#   3. runs mail_forensics_lib.py on the COPY and saves notes/analysis.json
#      (also hashed).
#
# Safety rules, enforced here:
#   - the source is only ever read (cp -p, shasum); this suite's P-series
#     checks its hash and mtime are unchanged;
#   - an existing evidence/original.* is never overwritten: a second
#     acquisition of the same case is refused, not merged;
#   - symlinks and non-regular files are refused (no following a link out
#     of the mail store into something else);
#   - no network call, no message rendering, no attachment extraction to
#     disk, and no delete/quarantine/report action on the real mailbox.
#     Deciding what to do with the mail stays with a human.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CASE_ROOT="${MAIL_FORENSICS_CASE_ROOT:-$HOME/quarantine}"

die() { echo "preserve_evidence: $*" >&2; exit 2; }

[ $# -eq 2 ] || die "usage: preserve_evidence.sh <message.eml|.emlx> <case-name>"
SRC="$1"
NAME="$2"

[[ "$NAME" =~ ^[a-z0-9][a-z0-9-]{0,47}$ ]] || die "case-name must be 1-48 chars of a-z, 0-9, '-' (got '$NAME')"
[ -L "$SRC" ] && die "refusing a symlink: $SRC"
[ -f "$SRC" ] || die "not a regular file: $SRC"
[ -r "$SRC" ] || die "not readable: $SRC"

case "$SRC" in
  *.emlx) EXT="emlx" ;;
  *) EXT="eml" ;;
esac

CASE_DIR="$CASE_ROOT/case-$(date -u +%Y%m%d)-$NAME.noindex"
EVIDENCE="$CASE_DIR/evidence/original.$EXT"
if compgen -G "$CASE_DIR/evidence/original.*" >/dev/null; then
  die "evidence already preserved in $CASE_DIR -- refusing to overwrite"
fi

umask 077
mkdir -p "$CASE_DIR/evidence" "$CASE_DIR/notes" || die "cannot create $CASE_DIR"

SRC_SHA="$(shasum -a 256 "$SRC" | cut -d' ' -f1)"
cp -p "$SRC" "$EVIDENCE" || die "copy failed"
chmod 0400 "$EVIDENCE"
COPY_SHA="$(shasum -a 256 "$EVIDENCE" | cut -d' ' -f1)"
if [ "$SRC_SHA" != "$COPY_SHA" ]; then
  die "hash mismatch after copy (source $SRC_SHA, copy $COPY_SHA) -- evidence left in place for inspection"
fi

{
  echo "acquired_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "source=$SRC"
  echo "size=$(wc -c < "$SRC" | tr -d ' ') mtime=$(stat -c '%y' "$SRC" 2>/dev/null || stat -f '%Sm' "$SRC")"
  echo "evidence=$EVIDENCE"
} >> "$CASE_DIR/notes/log.txt"
{
  echo "$SRC_SHA  $SRC"
  echo "$COPY_SHA  $EVIDENCE"
} >> "$CASE_DIR/notes/hashes.txt"

if python3 -I "$SCRIPT_DIR/mail_forensics_lib.py" "$EVIDENCE" > "$CASE_DIR/notes/analysis.json"; then
  echo "$(shasum -a 256 "$CASE_DIR/notes/analysis.json" | cut -d' ' -f1)  $CASE_DIR/notes/analysis.json" >> "$CASE_DIR/notes/hashes.txt"
  echo "analysis_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ) ok" >> "$CASE_DIR/notes/log.txt"
else
  echo "analysis_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ) FAILED (evidence still preserved)" >> "$CASE_DIR/notes/log.txt"
  echo "preserve_evidence: evidence preserved, but analysis failed -- see $CASE_DIR/notes/log.txt" >&2
  echo "$CASE_DIR"
  exit 1
fi

echo "$CASE_DIR"
exit 0
