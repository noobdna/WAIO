"""security/incident_learning/critical_infra_watch.py -- WAIO Global
Cyber Intelligence Patrol, additional analysis section: "Critical
Infrastructure & Military Precursor Watch".

Scope (explicit, user-approved before implementation): military/
defense, government, telecom, electricity, gas, water, transportation,
satellite/space, and cloud/IT supply chain. Tracks, from ALREADY-
COLLECTED Incident Learning candidates only (the same
security/state/incident_learning/candidates/*.json
global_patrol_report.py already reads -- this module makes NO network
calls and runs NO new Collector): intrusion, long-dwell claims,
identity/authentication-fabric compromise, exploitation of significant
vulnerabilities, claimed OT/ICS impact, and multi-country activity
sharing an attack pattern.

Explicit, non-negotiable safety rules (user-approved, enforced
STRUCTURALLY below, not just by convention -- see
tests/critical_infra_watch_test.sh's own S-series for the guards this
module must never fail):

  S1. A single incident -- however sensitive its sector, however many
      sector/signal cues it matches -- NEVER by itself produces a
      precursor hypothesis. `claimed_attribution_mentions` (what the
      SOURCE TEXT claims) and `precursor_hypotheses` (this module's
      OWN pattern-based inference) are two entirely separate output
      keys for exactly this reason: a government/military-sector
      breach that some source attributes to a nation-state is still
      just ONE confirmed_activity entry with a claimed-attribution
      annotation, never, on its own, a "military precursor". A
      hypothesis requires MULTIPLE independently-corroborated
      confirmed_activity records sharing the SAME attack_pattern
      across AT LEAST TWO DISTINCT COUNTRIES (see
      `_group_by_pattern_across_countries` below) -- never sector
      membership, never a single attribution claim, never a single
      OT/ICS or long-dwell cue, alone.
  S2. No numerical probability, percentage, or predicted attack date
      is ever computed or emitted anywhere in this module's output
      schema -- not "unavailable", structurally ABSENT (no field name
      for it exists at all). Every dict this module returns is
      asserted, by its own test suite, to contain no key matching
      probability/likelihood/eta/confidence_percent/predicted_date.
  S3. "確認済みの事実" (confirmed_activity, built from the SAME
      confidence_level knowledge_manager.sh already derives),
      "公的機関による評価" (regulatory_statements -- see below: a
      narrower, separately-labeled subset of claimed_attribution
      cues specifically naming a government/regulatory body, e.g.
      "Financial Services Commission", "金融庁", "CISA said" --
      STILL a claim quoted from the source text, never independently
      verified by this module), and "WAIO独自の仮説"
      (precursor_hypotheses) are three STRUCTURALLY SEPARATE top-level
      keys in every section this module builds. They are never
      merged, and a hypothesis entry never inherits/repeats an
      attribution or regulatory-statement claim as if it were its own
      finding -- it only references the member candidate ids, so the
      original claim stays traceable to its own entry.
  S4. Where upstream data cannot support a determination (e.g. a
      candidate's own `country` is "unknown", or a sector cannot be
      matched by this module's own keyword table), this module reports
      "判定不能" explicitly (`sector_labels=[]` / entries in
      `data_limitations`) -- it never guesses a sector, country, or
      attribution from context.

Independent sector classification (explicit design decision, approved
before implementation): `incident_normalizer.sh`'s own
AFFECTED_SECTOR_KEYWORDS table is NOT extended or modified by this
module -- the sectors this watch needs (military/defense, electricity,
gas, water, transportation, satellite/space) do not exist in that
shared, heavily-reused core classifier, and extending it would widen
this change's blast radius onto every OTHER consumer of
incident_normalizer.sh's own affected_sector field. This module keeps
its own, separate, narrower keyword table (`CRITICAL_SECTOR_KEYWORDS`)
scanned directly over `raw_text`, scoped ONLY to this watch feature --
same "report what's cued, never infer beyond it" posture as every
other classification layer in this pipeline (Phase 94/98), just kept
structurally independent so a tuning change here can never change how
any other candidate (outside this section) gets classified.

No I/O for the pure `build_section()`/classification functions below
(same "pure function of already-loaded dicts" discipline as
security/intelligence/intelligence_lib.py) -- the only I/O in this
file is the tiny `resolve` CLI at the bottom, which touches ONLY this
module's own carryover state file (never a candidate file, never
security/knowledge/, never any Control Plane file).
"""

import json
import os
import sys

# Independent from incident_normalizer.sh's own AFFECTED_SECTOR_KEYWORDS
# by explicit design (see module docstring). Bilingual, generic,
# company-name-agnostic cues only. A candidate may match more than one
# -- these are cross-cutting infrastructure categories, not mutually
# exclusive industries, so this returns a LIST, not a single primary
# label (unlike incident_normalizer.sh's own affected_sector).
CRITICAL_SECTOR_KEYWORDS = [
    ("military_defense", [
        "military", "defense ministry", "defence ministry", "armed forces",
        "army", "navy", "air force", "defense contractor", "defence contractor",
        "防衛省", "自衛隊", "防衛産業", "軍",
    ]),
    ("government", [
        "government agency", "federal agency", "national government",
        "ministry", "government network",
        "政府機関", "省庁", "官公庁",
    ]),
    ("telecom", [
        "telecom operator", "telecommunications", "mobile carrier", "isp",
        "通信事業者", "携帯キャリア", "通信インフラ",
    ]),
    ("energy_electricity", [
        "power grid", "electric utility", "power plant", "electricity provider",
        "電力網", "電力会社", "発電所",
    ]),
    ("energy_gas", [
        "gas utility", "natural gas", "gas pipeline",
        "ガス事業者", "ガス管",
    ]),
    ("water", [
        "water utility", "water treatment", "water supply system",
        "水道事業者", "上水道", "浄水場",
    ]),
    ("transportation", [
        "railway operator", "airline", "airport authority", "port authority",
        "metro operator", "transit agency",
        "鉄道事業者", "航空会社", "空港", "港湾",
    ]),
    ("satellite_space", [
        "satellite operator", "space agency", "satellite communications",
        "ground station",
        "衛星事業者", "宇宙機関", "人工衛星",
    ]),
    ("cloud_it_supply_chain", [
        "cloud provider", "managed service provider", "software supply chain",
        "it supply chain",
        "クラウド事業者", "ITサプライチェーン", "ソフトウェアサプライチェーン",
    ]),
]

# Signal cues, EN+JA, fixed phrase tables -- these ENRICH a hypothesis's
# own reasoning text when one is already independently justified (S1's
# multi-country/same-pattern/corroborated gate); they never themselves
# gate a hypothesis.
LONG_DWELL_CUES = [
    "undetected for", "long-dwell", "dwell time of", "had access since",
    "present in the network since", "had been present since",
    "長期潜伏", "潜伏していた", "数年前から存在",
]
OT_ICS_CUES = [
    "industrial control system", "scada", "operational technology",
    "control system", "physical damage to", "ot network",
    "制御系", "産業制御システム", "物理的損傷",
]
ATTRIBUTION_CUES = [
    "attributed to", "linked to", "believed to be", "state-sponsored",
    "nation-state", "と見られる", "とされる", "の関与が指摘",
]
# A narrower subset of attribution-shaped text that ALSO names a
# government/regulatory body as the one making the statement --
# labeled separately (S3: "公的機関による評価") because the SPEAKER is a
# named authority, not because this module treats it as any more
# verified. Still a quoted claim, never independently confirmed here.
REGULATORY_STATEMENT_CUES = [
    "cisa said", "cisa warned", "financial services commission",
    "ministry of defense said", "ministry of defence said",
    "government said", "agency said",
    "金融庁", "防衛省は", "当局は", "政府は",
]


def classify_critical_sectors(raw_text):
    """Returns the list of CRITICAL_SECTOR_KEYWORDS labels whose own
    cues appear in raw_text. Empty list ('判定不能') is a normal,
    expected outcome -- never backfilled by inference from any other
    field (S4)."""
    text_lower = (raw_text or "").lower()
    return sorted({
        label for label, phrases in CRITICAL_SECTOR_KEYWORDS
        if any(p.lower() in text_lower for p in phrases)
    })


def _any_cue(text_lower, cues):
    return any(c.lower() in text_lower for c in cues)


def detect_signal_tags(raw_text):
    """Fixed-cue detection only -- reports what's cued, infers nothing
    beyond it. Returns a sorted list of tag names."""
    text_lower = (raw_text or "").lower()
    tags = []
    if _any_cue(text_lower, LONG_DWELL_CUES):
        tags.append("long_dwell_claimed")
    if _any_cue(text_lower, OT_ICS_CUES):
        tags.append("ot_ics_impact_claimed")
    if _any_cue(text_lower, ATTRIBUTION_CUES):
        tags.append("attribution_claimed")
    if _any_cue(text_lower, REGULATORY_STATEMENT_CUES):
        tags.append("regulatory_statement_claimed")
    return sorted(tags)


def _is_confirmed_activity(level):
    return level in ("MEDIUM", "HIGH", "CONFIRMED")


def _corroborated(c):
    """>=1 independent corroborating source beyond the candidate's own
    primary source_url -- the minimum bar S1/requirement 2 demands
    before a candidate may even be considered as one leg of a
    multi-signal hypothesis. A single-source candidate can still be
    listed under confirmed_activity (its own confidence_level already
    reflects that), it just can never be a hypothesis's own evidence
    leg."""
    return len(c.get("corroborating_sources") or []) >= 1


def _group_by_pattern_across_countries(scoped_confirmed):
    """S1's own gate: group confirmed, in-scope candidates by
    attack_pattern, keep only groups spanning >=2 DISTINCT KNOWN
    (not 'unknown') countries with >=2 members. This is the ONLY path
    into precursor_hypotheses in this entire module -- sector
    membership, signal tags, and attribution claims never appear in
    this function at all."""
    groups = {}
    for c in scoped_confirmed:
        pattern = c.get("attack_pattern") or "unclassified"
        if pattern == "unclassified":
            continue
        groups.setdefault(pattern, []).append(c)
    result = []
    for pattern, members in groups.items():
        countries = {m.get("country") for m in members if m.get("country") and m.get("country") != "unknown"}
        if len(members) >= 2 and len(countries) >= 2:
            result.append((pattern, members))
    return result


def _alternative_explanations(pattern):
    alts = [
        "複数の報道が同一の一次情報を参照しているだけで、独立した攻撃活動ではない可能性(二次報道の重複)",
        "同種の攻撃手法が流行した結果、時期が偶然重なった可能性(相関関係であり因果関係ではない)",
    ]
    if pattern.startswith("vulnerability_disclosure"):
        alts.append("同一の公開CVE/ベンダーアドバイザリに対し、複数地域が独立に反応しただけの可能性")
    return alts


def _member_summary(c, level_map):
    return {
        "id": c.get("id"),
        "country": c.get("country") or "unknown",
        "incident_type": c.get("incident_type") or "unclassified",
        "confidence_level": level_map.get(c.get("id"), "UNVERIFIED"),
        "source_url": c.get("source_url"),
        "source": c.get("source"),
        "source_type": c.get("source_type"),
    }


def _original_sources(members):
    seen = []
    for m in members:
        entry = {"source": m.get("source"), "source_type": m.get("source_type"), "source_url": m.get("source_url")}
        if entry not in seen:
            seen.append(entry)
    return seen


def build_section(candidates, level_map, prev_carryover, generated_at):
    """Pure function (no I/O): returns (section_dict, new_carryover_list).

    candidates     -- the FULL current known candidate set (not just
                       this cycle's new ones -- cross-country
                       correlation legitimately spans candidates
                       collected in different 72h cycles).
    level_map      -- {id: confidence_level}, the SAME precomputed map
                       global_patrol_report.py already builds via
                       knowledge_manager.sh's own canonical derivation.
    prev_carryover -- the previous cycle's own carryover list (loaded
                       by the caller), each entry already shaped like
                       this function's own output (see module
                       docstring's requirement 2 field list).
    generated_at   -- this cycle's own UTC timestamp.
    """
    scoped = []
    for c in candidates:
        sectors = classify_critical_sectors(c.get("raw_text") or "")
        if not sectors:
            continue
        tags = detect_signal_tags(c.get("raw_text") or "")
        level = level_map.get(c.get("id"), "UNVERIFIED")
        scoped.append((c, sectors, tags, level))

    confirmed_activity = []
    claimed_attribution_mentions = []
    regulatory_statements = []
    scoped_confirmed_candidates = []

    for c, sectors, tags, level in scoped:
        entry = {
            "id": c.get("id"),
            "critical_sectors": sectors,
            "incident_type": c.get("incident_type") or "unclassified",
            "attack_pattern": c.get("attack_pattern") or "unclassified",
            "country": c.get("country") or "unknown",
            "confidence_level": level,
            "signal_tags": tags,
            "source_url": c.get("source_url"),
            "source": c.get("source"),
        }
        if _is_confirmed_activity(level):
            confirmed_activity.append(entry)
            scoped_confirmed_candidates.append(c)
        if "attribution_claimed" in tags:
            claimed_attribution_mentions.append({**entry, "caveat": "出典テキスト中の帰属表現を検知したのみであり、公式発表か報道側の推測かは本モジュールでは区別できない(未確認情報として扱うこと)。"})
        if "regulatory_statement_claimed" in tags:
            regulatory_statements.append({**entry, "caveat": "特定の公的機関名を含む記述を検知したのみであり、当該機関の発表内容を本モジュールが独立に検証したものではない。"})

    # S1's own, sole gate into precursor_hypotheses: operates ONLY on
    # scoped_confirmed_candidates (original candidate dicts, so
    # .get("country")/.get("raw_text") are directly usable) -- never
    # on sector membership, signal tags, or attribution claims alone.
    corroborated_ids = {c.get("id") for c in scoped_confirmed_candidates if _corroborated(c)}

    precursor_hypotheses = []
    precursor_hypotheses_suppressed = []
    for pattern, members in _group_by_pattern_across_countries(scoped_confirmed_candidates):
        member_ids = [m.get("id") for m in members]
        if not all(mid in corroborated_ids for mid in member_ids):
            precursor_hypotheses_suppressed.append({
                "attack_pattern": pattern,
                "member_ids": member_ids,
                "reason": "単一出典(独立した裏付けなし)のcandidateを含むため前兆評価不能。評価には全メンバーの独立裏付けが必要。",
            })
            continue
        countries = sorted({m.get("country") for m in members if m.get("country") and m.get("country") != "unknown"})
        level_tags = sorted({t for m in members for t in detect_signal_tags(m.get("raw_text") or "")})
        hypothesis = {
            "attack_pattern": pattern,
            "member_ids": sorted(m.get("id") for m in members),
            "countries_involved": countries,
            "member_summaries": [_member_summary(m, level_map) for m in members],
            "contributing_signal_tags": level_tags,
            "risk_increase_reasoning": (
                f"{len(members)}件の確認済み事案が、{len(countries)}か国({', '.join(countries)})にわたり"
                f"同一の攻撃パターン({pattern})を共有しており、かつ各事案は単一出典ではなく独立した裏付けを持つ。"
                + (f" 付随する兆候タグ: {', '.join(level_tags)}。" if level_tags else "")
            ),
            "alternative_explanations": _alternative_explanations(pattern),
            "independent_sources": _original_sources(members),
            "confidence_caveat": "これは仮説であり、確認された攻撃予告や軍事衝突の予兆の確定ではない。発生確率・攻撃予定日は数値化しない。単独の侵害事案やセクター所属のみから軍事的意図を推定したものではない。",
        }
        precursor_hypotheses.append(hypothesis)

    data_limitations = []
    unknown_country_count = sum(1 for c, *_ in scoped if (c.get("country") or "unknown") == "unknown")
    if unknown_country_count:
        data_limitations.append(f"重要インフラ関連と判定された候補のうち{unknown_country_count}件はcountryが不明(判定不能)であり、国別の多国間相関評価から除外した(推測していない)。")
    if not scoped:
        data_limitations.append("今回の既知candidate集合の中に、本モジュールの業種キーワードに一致するものはなかった(判定対象なし)。")

    # --- carryover: persist open CRITICAL findings across cycles ---
    prev_open = {e["key"]: e for e in (prev_carryover or []) if e.get("status") == "open"}
    prev_resolved = {e["key"]: e for e in (prev_carryover or []) if e.get("status") != "open"}

    def _carryover_key_for_confirmed(entry):
        return f"confirmed:{entry['id']}"

    def _carryover_key_for_hypothesis(h):
        return "hypothesis:" + h["attack_pattern"] + ":" + ",".join(h["member_ids"])

    new_open_keys = set()
    new_carryover = []

    for entry in confirmed_activity:
        if entry["confidence_level"] not in ("HIGH", "CONFIRMED"):
            continue
        key = _carryover_key_for_confirmed(entry)
        if key in prev_resolved:
            # A human already resolved this exact finding (see the
            # `resolve` CLI below) -- it must NEVER auto-reopen just
            # because the same candidate is still sitting at
            # HIGH/CONFIRMED. Only a genuinely NEW finding (a
            # different key -- e.g. a new hypothesis formed from an
            # additional corroborating candidate) surfaces fresh.
            continue
        new_open_keys.add(key)
        prior = prev_open.get(key)
        new_carryover.append({
            "key": key,
            "finding_type": "confirmed_activity",
            "member_ids": [entry["id"]],
            "original_source": [{"source": entry["source"], "source_url": entry["source_url"]}],
            "first_seen_at": prior["first_seen_at"] if prior else generated_at,
            "last_checked_at": generated_at,
            "evidence_status": f"confidence_level={entry['confidence_level']}",
            "unresolved_reason": "人間ゲート(incident_human_gate.sh)による審査がまだ完了していない、または重要インフラ関連として継続監視が必要と判断されたため。",
            "status": "open",
        })

    for h in precursor_hypotheses:
        key = _carryover_key_for_hypothesis(h)
        if key in prev_resolved:
            continue
        new_open_keys.add(key)
        prior = prev_open.get(key)
        new_carryover.append({
            "key": key,
            "finding_type": "precursor_hypothesis",
            "member_ids": h["member_ids"],
            "original_source": h["independent_sources"],
            "first_seen_at": prior["first_seen_at"] if prior else generated_at,
            "last_checked_at": generated_at,
            "evidence_status": f"{len(h['member_ids'])}件の確認済み事案、{len(h['countries_involved'])}か国",
            "unresolved_reason": "複数国にまたがる同一攻撃パターンの仮説であり、人間による評価・解消がまだ行われていないため。",
            "status": "open",
        })

    # Carry forward any PREVIOUSLY open item that is still open this
    # cycle but didn't get rebuilt above (e.g. a confirmed_activity
    # candidate whose confidence_level dropped below HIGH this cycle
    # for some reason, yet a human has not resolved the original
    # finding) -- never silently drop an unresolved item; only an
    # explicit `resolve` call (see CLI below) removes it from "open".
    for key, prior in prev_open.items():
        if key not in new_open_keys:
            carried = dict(prior)
            carried["last_checked_at"] = generated_at
            new_carryover.append(carried)

    # Resolved items stay in the file (audit trail) but are never
    # re-surfaced as "open" -- carried through byte-for-byte.
    for key, prior in prev_resolved.items():
        if key not in {c["key"] for c in new_carryover}:
            new_carryover.append(prior)

    section = {
        "scope_sectors": [s for s, _ in CRITICAL_SECTOR_KEYWORDS],
        "confirmed_activity": confirmed_activity,
        "claimed_attribution_mentions": claimed_attribution_mentions,
        "regulatory_statements": regulatory_statements,
        "precursor_hypotheses": precursor_hypotheses,
        "precursor_hypotheses_suppressed": precursor_hypotheses_suppressed,
        "carryover_open": [c for c in new_carryover if c.get("status") == "open"],
        "data_limitations": data_limitations,
        "method_caveats": [
            "業種分類(critical_sectors)はincident_normalizer.shのaffected_sectorとは独立した、本モジュール専用のキーワード判定であり、既存パイプラインの分類結果を変更するものではない。",
            "本セクションは既存5 Collectorの収集結果のみを対象とする(新規収集・外部照会は行わない)。",
            "precursor_hypothesesは、複数の確認済み事案が同一攻撃パターンで2か国以上にわたり、かつ各事案が独立した裏付けを持つ場合にのみ生成する。単独の侵害事案・セクター所属・帰属言及のみから生成することはない。",
            "発生確率・攻撃予定日を数値化するフィールドは存在しない。",
        ],
    }
    return section, new_carryover


def render_markdown_section(section):
    lines = []
    lines.append("## 7. Critical Infrastructure & Military Precursor Watch")
    lines.append("対象: 軍事・防衛/政府/通信/電力/ガス/水道/交通/衛星・宇宙/クラウド・ITサプライチェーン")
    lines.append("")
    lines.append(f"- 確認済み事実 (confirmed_activity): {len(section['confirmed_activity'])}件")
    lines.append(f"- 帰属言及の検知 (claimed_attribution_mentions, 未確認): {len(section['claimed_attribution_mentions'])}件")
    lines.append(f"- 公的機関による言及の検知 (regulatory_statements, 未確認): {len(section['regulatory_statements'])}件")
    lines.append(f"- WAIO独自の仮説 (precursor_hypotheses): {len(section['precursor_hypotheses'])}件")
    lines.append(f"- 前兆評価不能として抑制 (precursor_hypotheses_suppressed): {len(section['precursor_hypotheses_suppressed'])}件")
    lines.append(f"- 継続監視中(未解決, carryover_open): {len(section['carryover_open'])}件")
    lines.append("")
    if section["precursor_hypotheses"]:
        lines.append("### WAIO独自の仮説(将来の攻撃の確定ではない)")
        for h in section["precursor_hypotheses"]:
            lines.append(f"- attack_pattern={h['attack_pattern']} / 対象国: {', '.join(h['countries_involved'])} / メンバー: {', '.join(h['member_ids'])}")
            lines.append(f"  - リスク上昇の理由: {h['risk_increase_reasoning']}")
            lines.append(f"  - 代替説明: {'; '.join(h['alternative_explanations'])}")
            lines.append(f"  - 注記: {h['confidence_caveat']}")
    if section["carryover_open"]:
        lines.append("")
        lines.append("### 継続監視中の未解決項目(次回以降も再掲)")
        for item in section["carryover_open"]:
            lines.append(
                f"- [{item['finding_type']}] key={item['key']} / 初検知: {item['first_seen_at']} / "
                f"最終確認: {item['last_checked_at']} / evidence: {item['evidence_status']} / "
                f"未解決理由: {item['unresolved_reason']}"
            )
    if section["data_limitations"]:
        lines.append("")
        lines.append("### データの限界(推測せず『判定不能』として報告)")
        for note in section["data_limitations"]:
            lines.append(f"- {note}")
    lines.append("")
    lines.append("### 本セクションの前提・限界")
    for note in section["method_caveats"]:
        lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------
# Minimal CLI: ONLY a human-invoked `resolve` command, touching ONLY
# this module's own carryover state file. Never touches candidate
# files, security/knowledge/, Guardian, or the Decision Engine -- same
# "human gate requires an explicit, non-empty reason" convention as
# knowledge_manager.sh's own approve/reject/hold.
# ---------------------------------------------------------------------

def _load_carryover(path):
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_carryover(path, items):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def cli_resolve(carryover_path, key, reason, resolved_at):
    if not reason or not reason.strip():
        sys.stderr.write("ERROR: a non-empty reason is required to resolve a carryover item\n")
        return 1
    items = _load_carryover(carryover_path)
    found = False
    for item in items:
        if item.get("key") == key:
            item["status"] = "resolved"
            item["resolved_at"] = resolved_at
            item["resolution_reason"] = reason
            found = True
    if not found:
        sys.stderr.write(f"ERROR: no carryover item with key '{key}' found in {carryover_path}\n")
        return 1
    _save_carryover(carryover_path, items)
    print(f"[CRITICAL INFRA WATCH] resolved '{key}': {reason}")
    return 0


def main(argv):
    if len(argv) >= 1 and argv[0] == "resolve":
        if len(argv) < 4:
            sys.stderr.write("Usage: critical_infra_watch.py resolve CARRYOVER_PATH KEY REASON\n")
            return 1
        import datetime
        resolved_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return cli_resolve(argv[1], argv[2], argv[3], resolved_at)
    sys.stderr.write("Usage: critical_infra_watch.py resolve CARRYOVER_PATH KEY REASON\n")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
