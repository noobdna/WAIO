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

# --- R-series: regressions found in review of PR #176 -----------------
# Fixtures live in a sub-directory so D1's top-level hash set is unchanged.
R_DIR="$FIXTURE_DIR/r"; mkdir -p "$R_DIR"
R_HDR='From: Good Sender <a@good.example>
To: b@example.org
Subject: t
Message-ID: <1@good.example>
MIME-Version: 1.0'
# timed_codes <file> <seconds> -- indicator codes, or TIMEOUT if analysis
# does not finish within the bound (the child is killed, so a regression
# fails fast instead of hanging the suite).
timed_codes() { python3 -I -c "
import subprocess, sys
code = \"import sys; sys.path.insert(0, 'security/mail_forensics'); import mail_forensics_lib as mf; r = mf.analyze_file(sys.argv[1]); print(' '.join(i['code'] for i in r['indicators']))\"
try:
    p = subprocess.run([sys.executable, '-I', '-c', code, sys.argv[1]], capture_output=True, text=True, timeout=float(sys.argv[2]))
    print(p.stdout.strip() if p.returncode == 0 else 'ERROR rc=%d' % p.returncode)
except subprocess.TimeoutExpired:
    print('TIMEOUT')
" "$1" "$2"; }

echo "[R1] url_domain: userinfo ends at backslash / ? / # (WHATWG)"
assert_eq "R1 backslash before @ is not userinfo" "evil.test" "$(py "print(mf.url_domain('https://evil.test\\\\@good.example/'))")"
assert_eq "R1 '?' before @ is not userinfo" "evil.test" "$(py "print(mf.url_domain('https://evil.test?@good.example/'))")"
assert_eq "R1 '#' before @ is not userinfo" "evil.test" "$(py "print(mf.url_domain('https://evil.test#@good.example/'))")"
assert_eq "R1 real userinfo still skipped" "good.example" "$(py "print(mf.url_domain('https://user:pw@good.example/x'))")"
printf '%s\nContent-Type: text/html\n\n<a href="https://evil.test\\@good.example/">good.example</a>\n' "$R_HDR" > "$R_DIR/backslash.eml"
R1_CODES="$(codes "$R_DIR/backslash.eml")"
assert_contains "R1 backslash-userinfo link flagged as anchor mismatch" "$R1_CODES" "HTML_ANCHOR_TEXT_MISMATCH"
assert_contains "R1 backslash-userinfo link flagged as foreign URL" "$R1_CODES" "URL_DOMAIN_NOT_ALIGNED"

echo "[R2] anchors with unquoted / single-quoted href"
assert_eq "R2 unquoted href mismatch found" "evil.test" "$(py "print(mf.anchor_mismatches('<a href=https://evil.test/x>good.example</a>')[0]['href_domain'])")"
assert_eq "R2 single-quoted href mismatch found" "evil.test" "$(py "print(mf.anchor_mismatches(\"<a href='https://evil.test/x'>good.example</a>\")[0]['href_domain'])")"
printf '%s\nContent-Type: text/html\n\n<a href=https://evil.test/x>good.example</a>\n' "$R_HDR" > "$R_DIR/unquoted.eml"
assert_contains "R2 unquoted-href mail flagged" "$(codes "$R_DIR/unquoted.eml")" "HTML_ANCHOR_TEXT_MISMATCH"

echo "[R3] risky attachments: trailing dot/space, unnamed executable part"
printf '%s\nContent-Type: multipart/mixed; boundary=B\n\n--B\nContent-Type: text/plain\n\nhi\n--B\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename="invoice.exe."\nContent-Transfer-Encoding: base64\n\nTVo=\n--B--\n' "$R_HDR" > "$R_DIR/trailing-dot.eml"
assert_contains "R3 'invoice.exe.' flagged RISKY_ATTACHMENT" "$(codes "$R_DIR/trailing-dot.eml")" "RISKY_ATTACHMENT"
printf '%s\nContent-Type: multipart/mixed; boundary=B\n\n--B\nContent-Type: text/plain\n\nhi\n--B\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename="invoice.scr "\nContent-Transfer-Encoding: base64\n\nTVo=\n--B--\n' "$R_HDR" > "$R_DIR/trailing-space.eml"
assert_contains "R3 'invoice.scr ' flagged RISKY_ATTACHMENT" "$(codes "$R_DIR/trailing-space.eml")" "RISKY_ATTACHMENT"
printf '%s\nContent-Type: multipart/mixed; boundary=B\n\n--B\nContent-Type: text/plain\n\nhi\n--B\nContent-Type: application/x-msdownload\nContent-Transfer-Encoding: base64\n\nTVo=\n--B--\n' "$R_HDR" > "$R_DIR/noname.eml"
assert_eq "R3 unnamed x-msdownload part is listed" "application/x-msdownload 2" "$(field "$R_DIR/noname.eml" "' '.join(str(a[k]) for a in r['attachments'] for k in ('content_type', 'size'))")"
assert_contains "R3 unnamed x-msdownload part flagged RISKY_ATTACHMENT" "$(codes "$R_DIR/noname.eml")" "RISKY_ATTACHMENT"
assert_not_contains "R3 clean mail still has no RISKY_ATTACHMENT" "$(codes "$FIXTURE_DIR/clean.eml")" "RISKY_ATTACHMENT"

echo "[R4] display name with fullwidth dots (U+FF0E)"
printf 'From: =?utf-8?b?%s?= <x@evil.test>\nTo: b@example.org\nSubject: t\n\nhi\n' "$(printf 'Tax Office nta\357\274\216go\357\274\216jp' | base64 | tr -d '\n')" > "$R_DIR/fullwidth.eml"
assert_contains "R4 fullwidth 'nta．go．jp' flagged DISPLAY_NAME_DOMAIN_MISMATCH" "$(codes "$R_DIR/fullwidth.eml")" "DISPLAY_NAME_DOMAIN_MISMATCH"

echo "[R5] no quadratic blow-up on hostile input (bound 5 s; >15 s before fix)"
python3 -I -c "import sys; open(sys.argv[1], 'w').write(sys.argv[2] + '\nReceived: from x by y ([' + ':' * 32000 + '\n\nhi\n')" "$R_DIR/received-colons.eml" "$R_HDR"
assert_not_contains "R5 32 KB '[:::' Received header analyzed < 5 s" "$(timed_codes "$R_DIR/received-colons.eml" 5)" "TIMEOUT"
python3 -I -c "import sys; open(sys.argv[1], 'w').write(sys.argv[2] + '\nContent-Type: text/html\n\n' + '<a href=\"https://e.test/\">x' * 8000 + '\n')" "$R_DIR/unclosed-anchors.eml" "$R_HDR"
R5_CODES="$(timed_codes "$R_DIR/unclosed-anchors.eml" 5)"
assert_not_contains "R5 216 KB of unclosed <a href> analyzed < 5 s" "$R5_CODES" "TIMEOUT"
assert_not_contains "R5 unclosed anchors analysis did not crash" "$R5_CODES" "ERROR"
assert_eq "R5 bracketed IPv6 Received still parsed" "2001:db8::1" "$(py "print(mf.parse_received('from a (a [2001:db8::1]) by b; Mon, 19 Oct 2026 09:33:00 +0000')['ip'])")"

echo "[D1] evidence files were only read"
assert_eq "D1 fixture hashes unchanged after analysis" "$FIXTURE_SUMS_BEFORE" "$(shasum -a 256 "$FIXTURE_DIR"/*.eml* | sort)"

echo "[D2] no network / execution / write capability in the module"
assert_eq "D2 no network or subprocess imports" "0" "$(grep -cE '^\s*(import|from)\s+(socket|ssl|urllib|http|requests|subprocess|smtplib|imaplib|poplib|ftplib|webbrowser)\b' "$LIB")"
assert_eq "D2 no eval/exec/os.system" "0" "$(grep -cE '\b(eval|exec|os\.system|os\.popen)\s*\(' "$LIB")"
assert_eq "D2 the only open() is read-binary" "open(path, \"rb\")" "$(grep -oE '\bopen\([^)]*\)' "$LIB")"
assert_eq "D2 no action verbs beyond HUMAN_REVIEW" "0" "$(grep -cE '\"(DELETE|QUARANTINE|REPORT|REPLY|BLOCK)\"' "$LIB")"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
