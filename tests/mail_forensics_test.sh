#!/bin/bash
set -uo pipefail

# tests/mail_forensics_test.sh -- regression suite for the static,
# read-only suspicious-email analyzer
# (security/mail_forensics/mail_forensics_lib.py).
#
#   U-series: pure helpers (domain alignment, Authentication-Results /
#     Received parsing, anchor-text mismatch) called directly.
#   M-series: whole-message analysis of SYNTHETIC fixtures written to a
#     temp dir by this suite -- a clean aligned mail, a phishing mail
#     modelled on the 2026-10-19 tax-agency case (spoofed display name,
#     no DMARC, Reply-To elsewhere, anchor showing one domain and linking
#     to another, risky attachment), and a Cloudflare Email Routing
#     forwarded copy. Only example.* / .invalid / .test names; no real
#     mail or address ever enters this repository.
#   D-series: static guards proving the module's "no network, no
#     execution, no writes, human review only" claims in the code.

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

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected NOT to contain '$needle')")
    echo "  FAIL: $label (expected NOT to contain '$needle', got: $haystack)"
  fi
}

LIB="security/mail_forensics/mail_forensics_lib.py"
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mail-forensics-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

py() { python3 -I -c "import sys; sys.path.insert(0, 'security/mail_forensics'); import mail_forensics_lib as mf; $1"; }
# field <file> <python expr over r> -- analyze a fixture and print one value
field() { python3 -I -c "import sys, json; sys.path.insert(0, 'security/mail_forensics'); import mail_forensics_lib as mf; r = mf.analyze_file(sys.argv[1]); print($2)" "$1"; }
codes() { field "$1" "' '.join(i['code'] for i in r['indicators'])"; }

echo "[U1] domain helpers"
assert_eq "U1 addr_domain ignores display name" "example.com" "$(py "print(mf.addr_domain('\"bank.example.org\" <a@Example.COM>'))")"
assert_eq "U1 org_domain keeps go.jp 3rd level" "nta.go.jp" "$(py "print(mf.org_domain('www.e-tax.nta.go.jp'))")"
assert_eq "U1 subdomain aligns with parent" "True" "$(py "print(mf.aligned('mail.example.com', 'example.com'))")"
assert_eq "U1 look-alike does not align" "False" "$(py "print(mf.aligned('example.com.evil.test', 'example.com'))")"

echo "[U2] Authentication-Results parsing (comments stripped, props kept)"
assert_eq "U2 authserv + methods" "mx.example.net spf=pass dkim=fail dmarc=fail" "$(py "a, rs = mf.parse_auth_results('mx.example.net; spf=pass (sender ok; x) smtp.mailfrom=a.test; dkim=fail header.d=b.test; dmarc=fail header.from=c.test'); print(a, ' '.join(r['method'] + '=' + r['result'] for r in rs))")"
assert_eq "U2 header.d prop" "b.test" "$(py "print(mf.parse_auth_results('mx; dkim=pass header.d=b.test header.s=s1')[1][0]['props']['header.d'])")"

echo "[U3] Received parsing"
assert_eq "U3 ip in brackets" "192.0.2.10" "$(py "print(mf.parse_received('from relay.example.test (relay.example.test [192.0.2.10]) by mx.example.net with ESMTPS id 1; Mon, 19 Oct 2026 09:33:00 +0000')['ip'])")"
assert_eq "U3 date after semicolon" "Mon, 19 Oct 2026 09:33:00 +0000" "$(py "print(mf.parse_received('from a by b; Mon, 19 Oct 2026 09:33:00 +0000')['date'])")"

echo "[U4] anchor text mismatch"
assert_eq "U4 shown nta.go.jp, href elsewhere" "login.evil.test" "$(py "print(mf.anchor_mismatches('<a href=\"https://login.evil.test/x\">https://www.nta.go.jp/</a>')[0]['href_domain'])")"
assert_eq "U4 matching anchor not flagged" "0" "$(py "print(len(mf.anchor_mismatches('<a href=\"https://www.nta.go.jp/a\">www.nta.go.jp</a>')))")"
assert_eq "U4 plain-word anchor not flagged" "0" "$(py "print(len(mf.anchor_mismatches('<a href=\"https://evil.test/\">click here</a>')))")"

# --- fixtures ---------------------------------------------------------

cat > "$FIXTURE_DIR/clean.eml" <<'EOF'
Authentication-Results: mx.cloudflare.net; spf=pass smtp.mailfrom=news@example.com; dkim=pass header.d=example.com header.s=s1; dmarc=pass header.from=example.com
Received: from mail.example.com (mail.example.com [192.0.2.20]) by mx.cloudflare.net with ESMTPS id A1; Mon, 19 Oct 2026 01:00:00 +0000
Return-Path: <bounce@example.com>
From: Example News <news@example.com>
To: user@example.org
Subject: October newsletter
Date: Mon, 19 Oct 2026 01:00:00 +0000
Message-ID: <abc123@mail.example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Read more at https://www.example.com/news
EOF

cat > "$FIXTURE_DIR/phish.eml" <<'EOF'
Authentication-Results: mx.cloudflare.net; spf=softfail smtp.mailfrom=info@mixed.phish.test; dkim=none; dmarc=none header.from=mixed.phish.test
Authentication-Results: mx.cloudflare.net; spf=pass; dkim=pass header.d=mixed.phish.test; dmarc=pass header.from=mixed.phish.test
Received: from vm-01 (unknown [198.51.100.7]) by mx.cloudflare.net with ESMTP id B2; Mon, 19 Oct 2026 09:33:00 +0000
Return-Path: <bounce@other.test>
From: "www.nta.go.jp" <info@mixed.phish.test>
Reply-To: <collect@reply.invalid>
To: game@example.org
Subject: =?utf-8?B?44CQ6YeN6KaB44CR57SN56iO44Gu44GK55+l44KJ44Gb?=
Date: Mon, 19 Oct 2026 09:32:58 +0000
Message-ID: <e1d5-0001@sender.invalid>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="B"

--B
Content-Type: text/html; charset=utf-8

<p>Pay now: <a href="https://login.phish.test/pay?id=1">https://www.nta.go.jp/taxes</a></p>
--B
Content-Type: application/zip
Content-Disposition: attachment; filename="tax_notice.zip"
Content-Transfer-Encoding: base64

aGVsbG8=
--B--
EOF
# The second, "dmarc=pass" Authentication-Results above sits BELOW the
# first one from the same authserv-id -- i.e. it is the kind of header a
# sender can pre-insert. The analyzer must use the topmost one only.

cat > "$FIXTURE_DIR/forwarded.eml" <<'EOF'
Return-Path: <SRS0=AbCd=xx=example.com=news@example.org>
X-Forwarded-To: owner@example.net
X-Forwarded-For: game@example.org owner@example.net
Received: from ba-ia.cloudflare-email.net (ba-ia.cloudflare-email.net [104.30.10.80]) by mx.example.net with ESMTPS id C3; Mon, 19 Oct 2026 02:00:05 +0000
Authentication-Results: mx.cloudflare.net; spf=pass smtp.mailfrom=news@example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com
Received: from mail.example.com (mail.example.com [192.0.2.20]) by cloudflare-email.net (cloudflare) id C2 for <game@example.org>; Mon, 19 Oct 2026 02:00:00 +0000
From: Example <news@example.com>
To: game@example.org
Subject: hello
Date: Mon, 19 Oct 2026 02:00:00 +0000
Message-ID: <fwd1@example.com>
Content-Type: text/plain

hi
EOF

printf '%s\n' "$(wc -c < "$FIXTURE_DIR/clean.eml" | tr -d ' ')" > "$FIXTURE_DIR/clean.emlx"
cat "$FIXTURE_DIR/clean.eml" >> "$FIXTURE_DIR/clean.emlx"
printf '<?xml version="1.0"?><plist><dict/></plist>\n' >> "$FIXTURE_DIR/clean.emlx"

FIXTURE_SUMS_BEFORE="$(shasum -a 256 "$FIXTURE_DIR"/*.eml* | sort)"

echo "[M1] clean, fully aligned mail"
assert_eq "M1 risk LOW" "LOW" "$(field "$FIXTURE_DIR/clean.eml" "r['risk']")"
assert_eq "M1 no indicators" "" "$(codes "$FIXTURE_DIR/clean.eml")"
assert_eq "M1 verdict from trusted hop" "mx.cloudflare.net pass pass" "$(field "$FIXTURE_DIR/clean.eml" "r['auth_verdict']['source'], r['auth_verdict']['spf'], r['auth_verdict']['dmarc']" | tr -d "(),'")"
assert_eq "M1 recommended action is human review" "HUMAN_REVIEW" "$(field "$FIXTURE_DIR/clean.eml" "r['recommended_action']")"

echo "[M2] phishing fixture (tax-agency pattern)"
P_CODES="$(codes "$FIXTURE_DIR/phish.eml")"
for c in DMARC_NONE SPF_FAIL DKIM_NOT_ALIGNED REPLY_TO_DOMAIN_MISMATCH RETURN_PATH_DOMAIN_MISMATCH MESSAGE_ID_DOMAIN_MISMATCH DISPLAY_NAME_DOMAIN_MISMATCH HTML_ANCHOR_TEXT_MISMATCH RISKY_ATTACHMENT; do
  assert_contains "M2 flags $c" "$P_CODES" "$c"
done
assert_not_contains "M2 trusted hop present -> no AUTH_UNTRUSTED_SOURCE" "$P_CODES" "AUTH_UNTRUSTED_SOURCE"
assert_eq "M2 topmost (not pre-inserted 'pass') header used" "none" "$(field "$FIXTURE_DIR/phish.eml" "r['auth_verdict']['dmarc']")"
assert_eq "M2 risk HIGH" "HIGH" "$(field "$FIXTURE_DIR/phish.eml" "r['risk']")"
assert_eq "M2 still only a recommendation" "HUMAN_REVIEW" "$(field "$FIXTURE_DIR/phish.eml" "r['recommended_action']")"
assert_eq "M2 attachment sha256 of decoded bytes ('hello')" "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 5" "$(field "$FIXTURE_DIR/phish.eml" "r['attachments'][0]['sha256'], r['attachments'][0]['size']" | tr -d "(),'")"
assert_eq "M2 encoded subject decoded" "【重要】納税のお知らせ" "$(field "$FIXTURE_DIR/phish.eml" "r['headers']['Subject']")"
assert_eq "M2 sender IP from Received" "198.51.100.7" "$(field "$FIXTURE_DIR/phish.eml" "r['received'][0]['ip']")"
assert_eq "M2 URL recorded, not fetched" "https://login.phish.test/pay?id=1" "$(field "$FIXTURE_DIR/phish.eml" "r['urls'][0]")"

echo "[M3] untrusted auth source"
assert_contains "M3 trusted list without the real hop -> AUTH_UNTRUSTED_SOURCE" "$(python3 -I -c "import sys; sys.path.insert(0, 'security/mail_forensics'); import mail_forensics_lib as mf; print([i['code'] for i in mf.analyze_file(sys.argv[1], ('mx.other.test',))['indicators']])" "$FIXTURE_DIR/clean.eml")" "AUTH_UNTRUSTED_SOURCE"

echo "[M4] Cloudflare Email Routing forwarded copy"
assert_eq "M4 routing detected" "True" "$(field "$FIXTURE_DIR/forwarded.eml" "r['forwarding']['cloudflare_email_routing']")"
assert_eq "M4 SRS return path recognised" "True" "$(field "$FIXTURE_DIR/forwarded.eml" "r['forwarding']['srs_return_path']")"
assert_eq "M4 receiving alias recovered" "game@example.org" "$(field "$FIXTURE_DIR/forwarded.eml" "r['forwarding']['received_alias']")"
assert_not_contains "M4 SRS rewrite is not a Return-Path mismatch" "$(codes "$FIXTURE_DIR/forwarded.eml")" "RETURN_PATH_DOMAIN_MISMATCH"
assert_eq "M4 risk LOW" "LOW" "$(field "$FIXTURE_DIR/forwarded.eml" "r['risk']")"

echo "[M5] Apple Mail .emlx wrapper"
assert_eq "M5 emlx parses like the eml" "news@example.com LOW" "$(field "$FIXTURE_DIR/clean.emlx" "r['from_address'], r['risk']" | tr -d "(),'")"

echo "[M6] CLI"
CLI_OUT="$(python3 -I "$LIB" "$FIXTURE_DIR/phish.eml")"; CLI_RC=$?
assert_eq "M6 CLI exit 0" "0" "$CLI_RC"
assert_contains "M6 CLI prints JSON with source hash" "$CLI_OUT" "\"source_sha256\": \"$(shasum -a 256 "$FIXTURE_DIR/phish.eml" | cut -d' ' -f1)\""
python3 -I "$LIB" >/dev/null 2>&1; assert_eq "M6 usage error exit 2" "2" "$?"

echo "[P1] preserve_evidence.sh: copy, read-only, hashes, analysis"
PRESERVE="security/mail_forensics/preserve_evidence.sh"
export MAIL_FORENSICS_CASE_ROOT="$FIXTURE_DIR/cases"
SRC_MTIME_BEFORE="$(stat -c '%Y' "$FIXTURE_DIR/phish.eml" 2>/dev/null || stat -f '%m' "$FIXTURE_DIR/phish.eml")"
P_CASE="$(bash "$PRESERVE" "$FIXTURE_DIR/phish.eml" tax-agency 2>&1)"; P_RC=$?
assert_eq "P1 exit 0" "0" "$P_RC"
assert_eq "P1 case dir under the overridden root, .noindex, UTC-dated" "$MAIL_FORENSICS_CASE_ROOT/case-$(date -u +%Y%m%d)-tax-agency.noindex" "$P_CASE"
assert_eq "P1 copy is byte-identical" "$(shasum -a 256 "$FIXTURE_DIR/phish.eml" | cut -d' ' -f1)" "$(shasum -a 256 "$P_CASE/evidence/original.eml" 2>/dev/null | cut -d' ' -f1)"
assert_eq "P1 copy is read-only (0400)" "400" "$(stat -c '%a' "$P_CASE/evidence/original.eml" 2>/dev/null || stat -f '%Lp' "$P_CASE/evidence/original.eml")"
assert_eq "P1 hashes.txt lists source, copy, analysis" "3" "$(wc -l < "$P_CASE/notes/hashes.txt" | tr -d ' ')"
assert_contains "P1 log records acquisition and analysis" "$(cat "$P_CASE/notes/log.txt")" "analysis_utc="
assert_eq "P1 analysis.json is the analyzer's verdict on the copy" "HIGH HUMAN_REVIEW" "$(python3 -I -c "import json,sys; r=json.load(open(sys.argv[1])); print(r['risk'], r['recommended_action'])" "$P_CASE/notes/analysis.json")"
assert_eq "P1 analysis.json hash recorded matches file" "$(shasum -a 256 "$P_CASE/notes/analysis.json" | cut -d' ' -f1)" "$(grep 'analysis.json' "$P_CASE/notes/hashes.txt" | cut -d' ' -f1)"
assert_eq "P1 source mtime unchanged" "$SRC_MTIME_BEFORE" "$(stat -c '%Y' "$FIXTURE_DIR/phish.eml" 2>/dev/null || stat -f '%m' "$FIXTURE_DIR/phish.eml")"

echo "[P2] preserve_evidence.sh refusals"
bash "$PRESERVE" "$FIXTURE_DIR/clean.eml" tax-agency >/dev/null 2>&1; P2_RC=$?
assert_eq "P2 second acquisition into an existing case refused (exit 2)" "2" "$P2_RC"
assert_eq "P2 ...and the first evidence is untouched" "$(shasum -a 256 "$FIXTURE_DIR/phish.eml" | cut -d' ' -f1)" "$(shasum -a 256 "$P_CASE/evidence/original.eml" | cut -d' ' -f1)"
ln -s "$FIXTURE_DIR/clean.eml" "$FIXTURE_DIR/link.eml"
bash "$PRESERVE" "$FIXTURE_DIR/link.eml" via-link >/dev/null 2>&1; assert_eq "P2 symlink source refused" "2" "$?"
bash "$PRESERVE" "$FIXTURE_DIR/clean.eml" "../escape" >/dev/null 2>&1; assert_eq "P2 path-like case name refused" "2" "$?"
bash "$PRESERVE" "$FIXTURE_DIR/missing.eml" missing >/dev/null 2>&1; assert_eq "P2 missing source refused" "2" "$?"
assert_eq "P2 refusals created no case dirs" "1" "$(find "$MAIL_FORENSICS_CASE_ROOT" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
rm -f "$FIXTURE_DIR/link.eml"

echo "[P3] .emlx keeps its extension"
P3_CASE="$(bash "$PRESERVE" "$FIXTURE_DIR/clean.emlx" emlx-case 2>/dev/null)"
assert_eq "P3 stored as original.emlx" "true" "$([ -f "$P3_CASE/evidence/original.emlx" ] && echo true || echo false)"

echo "[P4] a source file name starting with '-' is preserved, not parsed as an option"
mkdir -p "$FIXTURE_DIR/p4"
cp "$FIXTURE_DIR/clean.eml" "$FIXTURE_DIR/p4/-dash.eml"
P4_CASE="$(cd "$FIXTURE_DIR/p4" && bash "$OLDPWD/$PRESERVE" -dash.eml dash-name 2>/dev/null)"; P4_RC=$?
assert_eq "P4 exit 0" "0" "$P4_RC"
assert_eq "P4 copy is byte-identical" "$(shasum -a 256 -- "$FIXTURE_DIR/p4/-dash.eml" | cut -d' ' -f1)" "$(shasum -a 256 -- "$P4_CASE/evidence/original.eml" 2>/dev/null | cut -d' ' -f1)"

echo "[P5] the copy step itself never follows a link or blocks on a FIFO, and never overwrites"
COPY="security/mail_forensics/copy_evidence.py"
assert_eq "P5 copy helper present (refusals below are not vacuous)" "true" "$([ -f "$COPY" ] && echo true || echo false)"
mkdir -p "$FIXTURE_DIR/p5"
ln -s "$FIXTURE_DIR/clean.eml" "$FIXTURE_DIR/p5/link.eml"
python3 -I "$COPY" "$FIXTURE_DIR/p5/link.eml" "$FIXTURE_DIR/p5/out-link" >/dev/null 2>&1
assert_eq "P5 symlink source refused at open time (exit 2)" "2" "$?"
assert_eq "P5 ...and nothing was written" "false" "$([ -e "$FIXTURE_DIR/p5/out-link" ] && echo true || echo false)"
mkfifo "$FIXTURE_DIR/p5/fifo.eml"
python3 -I "$COPY" "$FIXTURE_DIR/p5/fifo.eml" "$FIXTURE_DIR/p5/out-fifo" >/dev/null 2>&1
assert_eq "P5 FIFO source refused without blocking (exit 2)" "2" "$?"
echo existing > "$FIXTURE_DIR/p5/exists"
python3 -I "$COPY" "$FIXTURE_DIR/clean.eml" "$FIXTURE_DIR/p5/exists" >/dev/null 2>&1
assert_eq "P5 existing destination refused (exit 2)" "2" "$?"
assert_eq "P5 ...and left untouched" "existing" "$(cat "$FIXTURE_DIR/p5/exists")"
ln -s "$FIXTURE_DIR/p5/elsewhere" "$FIXTURE_DIR/p5/dest-link"
python3 -I "$COPY" "$FIXTURE_DIR/clean.eml" "$FIXTURE_DIR/p5/dest-link" >/dev/null 2>&1
assert_eq "P5 symlinked destination refused (exit 2)" "2" "$?"
assert_eq "P5 ...and the link target was not created" "false" "$([ -e "$FIXTURE_DIR/p5/elsewhere" ] && echo true || echo false)"

echo "[P6] the copy step creates the evidence read-only and reports the hash of the bytes it copied"
P6_OUT="$(python3 -I "$COPY" "$FIXTURE_DIR/clean.eml" "$FIXTURE_DIR/p5/out-ok")"; P6_RC=$?
assert_eq "P6 exit 0" "0" "$P6_RC"
assert_eq "P6 created 0400" "400" "$(stat -c '%a' "$FIXTURE_DIR/p5/out-ok" 2>/dev/null || stat -f '%Lp' "$FIXTURE_DIR/p5/out-ok")"
assert_eq "P6 reported sha256 = source sha256" "$(shasum -a 256 "$FIXTURE_DIR/clean.eml" | cut -d' ' -f1)" "$(printf '%s\n' "$P6_OUT" | cut -d' ' -f1)"
assert_eq "P6 mtime carried over (cp -p semantics)" "$(stat -c '%Y' "$FIXTURE_DIR/clean.eml" 2>/dev/null || stat -f '%m' "$FIXTURE_DIR/clean.eml")" "$(stat -c '%Y' "$FIXTURE_DIR/p5/out-ok" 2>/dev/null || stat -f '%m' "$FIXTURE_DIR/p5/out-ok")"

echo "[P7] a copy killed mid-way leaves no evidence file, so re-preserving is not refused"
# copy_evidence.py is SIGTERMed while copying a large sparse source into the
# case's evidence path. Before the fix the 0400 destination was created
# first and filled in place, so the kill left a truncated original.eml that
# preserve_evidence.sh then refused as "already preserved". The driver
# polls the evidence dir and kills as soon as anything appears there; if
# the copy finished first (very fast disk) the case is SKIPPED, not passed.
P7_CASE="$MAIL_FORENSICS_CASE_ROOT/case-$(date -u +%Y%m%d)-killed-copy.noindex"
mkdir -p "$P7_CASE/evidence" "$FIXTURE_DIR/p7"
P7_RESULT="$(python3 -I -c "
import os, signal, subprocess, sys, time
copy, src, dest = sys.argv[1:4]
with open(src, 'wb') as f:
    f.truncate(256 << 20)  # sparse: cheap to create, real bytes to copy
d = os.path.dirname(dest)
p = subprocess.Popen([sys.executable, '-I', copy, src, dest], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
deadline = time.monotonic() + 30
while p.poll() is None and not os.listdir(d) and time.monotonic() < deadline:
    time.sleep(0.0005)
if p.poll() is None and os.listdir(d):
    p.send_signal(signal.SIGTERM)
rc = p.wait()
os.unlink(src)
print('killed' if rc == -signal.SIGTERM else 'finished rc=%d' % rc)
" "$COPY" "$FIXTURE_DIR/p7/big.eml" "$P7_CASE/evidence/original.eml")"
if [ "$P7_RESULT" = "killed" ]; then
  assert_eq "P7 no evidence/original.eml after the kill" "false" "$([ -e "$P7_CASE/evidence/original.eml" ] && echo true || echo false)"
  P7_OUT="$(bash "$PRESERVE" "$FIXTURE_DIR/clean.eml" killed-copy 2>&1)"; P7_RC=$?
  assert_eq "P7 re-preserving the same case succeeds (exit 0)" "0" "$P7_RC"
  assert_not_contains "P7 ...and is not refused as already preserved" "$P7_OUT" "already preserved"
  assert_eq "P7 retried copy is byte-identical" "$(shasum -a 256 "$FIXTURE_DIR/clean.eml" | cut -d' ' -f1)" "$(shasum -a 256 "$P7_CASE/evidence/original.eml" 2>/dev/null | cut -d' ' -f1)"
else
  echo "  SKIP: P7 copy could not be interrupted before it finished ($P7_RESULT)"
fi
rm -rf "$FIXTURE_DIR/p7"

echo "[P8] the copy is published only when complete and never over an existing file"
assert_eq "P8 publish step uses link() (fails if DEST exists, never overwrites)" "1" "$(grep -cE '^\s*os\.link\(' "$COPY")"
assert_eq "P8 no rename/replace (which would overwrite DEST)" "0" "$(grep -cE '\bos\.(rename|replace)\(' "$COPY")"
mkdir -p "$FIXTURE_DIR/p8"
python3 -I "$COPY" "$FIXTURE_DIR/clean.eml" "$FIXTURE_DIR/p8/out" >/dev/null 2>&1
assert_eq "P8 successful copy leaves only DEST (no temp file behind)" "out" "$(ls -A "$FIXTURE_DIR/p8")"
unset MAIL_FORENSICS_CASE_ROOT

echo "[D1] evidence files were only read"
assert_eq "D1 fixture hashes unchanged after analysis" "$FIXTURE_SUMS_BEFORE" "$(shasum -a 256 "$FIXTURE_DIR"/*.eml* | sort)"

echo "[D2] no network / execution / write capability in the module"
assert_eq "D2 no network or subprocess imports" "0" "$(grep -cE '^\s*(import|from)\s+(socket|ssl|urllib|http|requests|subprocess|smtplib|imaplib|poplib|ftplib|webbrowser)\b' "$LIB")"
assert_eq "D2 no eval/exec/os.system" "0" "$(grep -cE '\b(eval|exec|os\.system|os\.popen)\s*\(' "$LIB")"
assert_eq "D2 the only open() is read-binary" "open(path, \"rb\")" "$(grep -oE '\bopen\([^)]*\)' "$LIB")"
assert_eq "D2 no action verbs beyond HUMAN_REVIEW" "0" "$(grep -cE '\"(DELETE|QUARANTINE|REPORT|REPLY|BLOCK)\"' "$LIB")"

echo "[D3] preserve_evidence.sh has no network or mailbox-changing command"
assert_eq "D3 no network tool" "0" "$(grep -vE '^\s*#' security/mail_forensics/preserve_evidence.sh | grep -cE '\b(curl|wget|nc|ssh|scp|osascript|open)\b')"
assert_eq "D3 no rm/mv anywhere" "0" "$(grep -vE '^\s*#' security/mail_forensics/preserve_evidence.sh | grep -cE '\b(rm|mv)\b')"
assert_eq "D3 default case root is outside the repo (~/quarantine)" "1" "$(grep -c 'MAIL_FORENSICS_CASE_ROOT:-\$HOME/quarantine' security/mail_forensics/preserve_evidence.sh)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
