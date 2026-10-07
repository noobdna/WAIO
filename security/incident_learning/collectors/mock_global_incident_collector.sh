#!/bin/bash
set -uo pipefail

# security/incident_learning/collectors/mock_global_incident_collector.sh
# -- Phase 98 (Global Incident Intelligence & Auto-Learning): a fixed,
# no-network Collector exercising the pipeline's own newly-added
# classification (incident_type/affected_sector/claimed_impact/
# attack_pattern) and correlation (related_incidents) capabilities,
# the same role mock_collector.sh (Step 2) already plays for the
# original CVE/IOC-shaped extraction -- that file is left completely
# untouched by this phase (several existing tests assert on its exact
# sample count/ids).
#
# Collector contract compliance (see mock_collector.sh's own header
# for the full base contract -- id/source/source_type/source_url/
# collected_at/raw_text/corroborating_sources, unchanged): this file
# additionally demonstrates the four NEW optional fields
# incident_normalizer.sh now reads (published_at/country/region/
# language) -- every real Collector remains free to omit all four.
#
# Every entity named below (company names, membership programs,
# people) is ENTIRELY FICTIONAL ("Example ...", example.invalid
# domains) -- same posture as mock_collector.sh's own fabricated CVE/
# IOC samples, and a direct, explicit requirement of this phase's own
# design: this pipeline's generic classification mechanism must never
# have a real company name hardcoded anywhere in its code. These
# samples are deliberately shaped like the real-world scenarios this
# phase was motivated by (a carsharing-service breach, a restaurant-
# chain breach, an overseas retailer breach, an unverified membership-
# data-sale allegation) WITHOUT naming any real organization.
#
# Deliberately spans two different "countries" with the SAME
# attack_pattern (GLOBAL-MOCK-0002 or JP/data_breach and
# GLOBAL-MOCK-0004 US/data_breach; GLOBAL-MOCK-0001 JP/account_takeover
# and GLOBAL-MOCK-0003 US/account_takeover) specifically so
# incident_correlator.sh has real cross-country matches to find in
# this fixture set, end to end.

NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

emit() {
  python3 -c "
import json, sys
d = {
    'id': sys.argv[1],
    'source': 'mock_global_incident_collector',
    'source_type': sys.argv[2],
    'source_url': sys.argv[3],
    'collected_at': sys.argv[4],
    'raw_text': sys.argv[5],
    'published_at': sys.argv[6],
    'country': sys.argv[7],
    'region': sys.argv[8],
}
language = sys.argv[9]
if language:
    d['language'] = language
corrob = sys.argv[10]
if corrob:
    d['corroborating_sources'] = json.loads(corrob)
print(json.dumps(d, ensure_ascii=False))
" "$1" "$2" "$3" "$4" "$5" "${6:-}" "${7:-unknown}" "${8:-unknown}" "${9:-}" "${10:-}"
}

# GLOBAL-MOCK-0001: JP, automotive carsharing, account takeover via
# unauthorized login -- single source, not self-described as
# unverified (so it still has a real evidence_source_type to score on).
emit "GLOBAL-MOCK-0001" "news" "https://example.invalid/jp-news/0001" "$NOW" \
"カーシェアリングサービスを運営するExample CarShare JP社は、会員のアカウントに対する不正ログインが発生し、一部会員の登録情報が第三者に閲覧された可能性があると発表した。被害に遭った会員は数百名規模とみられる。Mitigation: 全会員へパスワード再設定を要請。" \
"2026-10-01T09:00:00Z" "JP" "APAC" "ja" ""

# GLOBAL-MOCK-0002: JP, food service (yakiniku-style chain), data
# breach -- vendor advisory, independently corroborated (so it can
# organically clear the confidence floor without a human override).
emit "GLOBAL-MOCK-0002" "vendor_advisory" "https://example.invalid/jp-advisory/0002" "$NOW" \
"焼肉チェーンを展開するExample Yakiniku Holdings社の予約システムを運営するベンダーは、顧客情報が流出した疑いがあることを確認したと発表した。個人情報が流出した可能性がある対象顧客に通知を行っている。Mitigation: 対象顧客への個別通知とコールセンターの設置。" \
"2026-09-28T03:00:00Z" "JP" "APAC" "ja" \
'["https://example.invalid/jp-news/0002b"]'

# GLOBAL-MOCK-0003: overseas (US), retail e-commerce, account takeover
# via credential stuffing -- same attack_pattern as GLOBAL-MOCK-0001
# (incident_type=account_takeover), different country, for
# incident_correlator.sh to actually link.
emit "GLOBAL-MOCK-0003" "news" "https://example.invalid/us-news/0003" "$NOW" \
"Example MegaRetail Global, a major online retailer, disclosed that a subset of customer accounts were compromised via credential stuffing, likely using credentials reused from unrelated prior breaches. Affected customers were notified and prompted to reset their passwords. Mitigation: enable multi-factor authentication on all accounts." \
"2026-09-30T14:00:00Z" "US" "NA" "en" ""

# GLOBAL-MOCK-0004: overseas (Germany), healthcare, data breach -- same
# attack_pattern as GLOBAL-MOCK-0002 (incident_type=data_breach),
# different country/sector, for incident_correlator.sh to link.
# language intentionally omitted here, to exercise
# incident_normalizer.sh's own Hiragana/Katakana-presence fallback
# heuristic (this raw_text has none, so it correctly falls back to
# 'en', not a guess at German).
emit "GLOBAL-MOCK-0004" "vendor_advisory" "https://example.invalid/de-advisory/0004" "$NOW" \
"Example EU HealthNet, a regional healthcare provider, confirmed that personal information of patients was exposed after a misconfigured database was found accessible without authentication. The vendor has notified affected customers and regulators." \
"2026-09-25T11:00:00Z" "DE" "EU" "" \
'["https://example.invalid/de-news/0004b"]'

# GLOBAL-MOCK-0005: JP, retail/membership program, an UNVERIFIED,
# single-source allegation that member data was being sold -- the
# deliberate low-confidence case (same role as mock_collector.sh's own
# MOCK-2026-0003), shaped after the "membership-data-sale allegation"
# scenario this phase was motivated by, with an entirely fictional
# membership program. Shares attack_pattern 'data_breach' with
# GLOBAL-MOCK-0002/0004 -- correlation is a property of PATTERN, not
# of verification status, so this still shows up in their
# related_incidents despite scoring UNVERIFIED/LOW (see
# incident_correlator.sh's own header).
emit "GLOBAL-MOCK-0005" "unknown" "https://example.invalid/jp-forum/0005" "$NOW" \
"会員制の通販サイトを運営するExample Membership Co.の会員情報が闇サイトで不正に販売されていた疑いがあるとの未確認の情報が掲示板に投稿された。運営からの公式発表はなく、単独の情報源であり裏付けはない。No vendor confirmation. Single source. No corroboration found." \
"2026-10-05T18:00:00Z" "JP" "APAC" "ja" ""
