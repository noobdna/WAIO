"""security/incident_learning/global_patrol_report.py -- WAIO Global
Cyber Intelligence Patrol: the report-generation half of
global_patrol_cron.sh (see that file's own header for the full
schedule design). Pure read-only reporting over already-collected
Incident Learning Engine state -- this module makes NO network calls
of its own (every real network fetch already happened inside the
Collectors invoked by incident_learning_cron.sh, a separate process
run earlier by global_patrol_cron.sh) and calls NONE of
knowledge_manager.sh's mutating
commands, incident_human_gate.sh, any Guardian tool, or the Decision
Engine -- see global_patrol_cron.sh's own header for the exact list
this is structurally guarded against (tests/global_patrol_cron_test.sh's
G-series).

Usage (always invoked by global_patrol_cron.sh, documented here for
direct/test invocation too):
    python3 global_patrol_report.py \
        CANDIDATES_DIR STATE_PATH OUTPUT_DIR GENERATED_AT_ISO \
        LEVELS_JSON_PATH [PIPELINE_STATUS] [CRITICAL_CARRYOVER_PATH]

  CANDIDATES_DIR    -- security/state/incident_learning/candidates
                       (or a fixture override), one JSON file per
                       Incident Learning candidate -- the SAME files
                       dashboard/collect_incident_learning_status.sh
                       already reads elsewhere in this repo. Never
                       written to by this module.
  STATE_PATH        -- this Patrol's own last-run snapshot (JSON):
                       {"last_run_at": ..., "known_candidate_ids": [...],
                        "attack_pattern_distribution": {...}}.
                       Read if present (absence means "first patrol
                       run ever" -- every known candidate is reported
                       as new, which is the correct, honest behavior
                       for a first run, not a bug to special-case
                       around). Written ONLY after the report below
                       is fully built, via a temp-file + os.replace
                       atomic rename -- same all-or-nothing commit
                       discipline as security/continuity.sh's own
                       snapshot writers, so a crash/kill mid-run never
                       leaves a half-written or inconsistent state
                       file; the previous snapshot is preserved
                       byte-for-byte if this run fails before that
                       point.
  OUTPUT_DIR        -- where the two report files (timestamped +
                       "-latest") are written. Defaults to logs/
                       (already gitignored) via the caller.
  GENERATED_AT_ISO  -- this patrol run's own UTC timestamp, supplied
                       by the caller (not computed twice).
  LEVELS_JSON_PATH  -- {candidate_id: "UNVERIFIED"|"LOW"|"MEDIUM"|
                       "HIGH"|"CONFIRMED"}, precomputed by
                       global_patrol_cron.sh via
                       knowledge_manager.sh's own canonical
                       candidate_confidence_level() -- deliberately
                       NOT re-derived here from status/confidence_score,
                       to avoid two independently-maintained copies of
                       that threshold logic ever drifting apart.
  PIPELINE_STATUS   -- "ok" or "degraded" (default "unknown"): whether
                       this cycle's call into incident_learning_cron.sh
                       itself succeeded. Surfaced in the report, never
                       hidden -- "実行失敗時はエラーを記録し、次回実行を
                       妨げない" applies to the REPORT's own honesty
                       about this cycle's data completeness, not just
                       to the log file.
  CRITICAL_CARRYOVER_PATH -- optional override for the Critical
                       Infrastructure & Military Precursor Watch's own
                       persistent carryover file (see
                       critical_infra_watch.py's own header). Defaults
                       to a sibling of STATE_PATH
                       (security/incident_learning's own "patrol"
                       state directory) -- no global_patrol_cron.sh
                       change is required for a real deployment; this
                       override exists only for test fixture isolation.

Diffing policy ("新規情報を優先する", the user's own explicit framing):
"new since last patrol" = candidate id not present in the PREVIOUS
patrol's own known_candidate_ids set. This is deliberately NOT a
time-window filter (e.g. "created_at within the last 72h") -- the
existing hourly incident_learning_cron.sh schedule runs independently
of this 72h one, so a candidate could have been collected at any point
between two patrol runs; the only question this diff actually needs to
answer is "has THIS Patrol reported on this id before", which an
explicit remembered id-set answers exactly, with no clock-skew/missed-
cycle edge cases a time-window check would be exposed to.

Fact/estimate/unconfirmed separation (explicit safety requirement):
every count in this report is a count of ALREADY-PUBLISHED, ALREADY-
COLLECTED candidate records -- never an estimate of unpublished
incidents, and never a breach-rate projection over any larger
population (this module computes no percentage of any assumed total
organization count anywhere). claimed_impact strings are reproduced
verbatim from the source text (already labeled as a "claim attributed
to the source" by incident_normalizer.sh, Phase 98) and are never
treated as confirmed fact by this module either.
"""

import glob
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import critical_infra_watch  # noqa: E402 -- Critical Infrastructure & Military Precursor Watch section (see that module's own header for scope/safety rules). Pure, read-only, makes no external-process or network call of its own.

# Static, desk-review mapping from an incident's own `incident_type`
# (incident_normalizer.sh's own Phase 98 primary category) to a
# DESCRIPTION of what WAIO's existing modules could, in principle,
# observe for that category -- never a claim that any specific
# incident in this report was actually detected or contained by WAIO.
# Every string below is phrased as a possibility/scope statement
# ("可能性がある"/"対象外"/"のみ"), by explicit design requirement: see
# global_patrol_cron.sh's own header, "公開情報を収集しただけで...判定
# してはならない".
WAIO_ASSESSMENT_TABLE = {
    "ransomware": {
        "detectability": (
            "WAIOが当該ベンダー/サービスに依存している場合に限り、"
            "security/ssh_exposure監視やegress_allowlistの固定ホスト"
            "方式がVPN/リモートアクセス機器経由の初期侵入に類する兆候"
            "の一部を観測できる可能性がある。WAIOが依存していない組織"
            "の被害は観測対象外。"
        ),
        "required_logs_sensors": "SSH Exposure Monitor, egress_allowlist通信ログ, (未実装)ベンダーアドバイザリCollector",
        "containment_stage": "WAIO自身が依存するworker/segmentの隔離のみ（Guardian、人間承認が必要）。外部ベンダー自体への封じ込めは権限外。",
        "kill60sec_relevance": "Kill60SecはWAIO自身のworker/segmentのDetection→Containmentのみを対象とするSLA。外部組織の被害はそもそも対象外。",
        "snd_takomachi_notes": "SND@HOMEは無関係（自宅LAN監視、別プロジェクト）。Takomachiは自社LLM経路であり本事案と直接の関係はない。",
    },
    "data_breach": {
        "detectability": (
            "証明書透明性ログ・ベンダーアドバイザリ等の受動的OSINT"
            "（THREAT_LANDSCAPE_PATROL_ANALYSIS.md 7章で設計検討済み、"
            "未実装）が将来的にWAIO依存先の露出兆候を捉えられる可能性"
            "があるが、現時点のWAIOにはこの種の侵害を直接検知する機能"
            "はない。"
        ),
        "required_logs_sensors": "（未実装）証明書透明性ログ/ベンダーアドバイザリCollector",
        "containment_stage": "WAIOが当該サービスのAPI/認証情報に依存する場合のみ、該当segmentの隔離を人間が判断可能。",
        "kill60sec_relevance": "対象外（WAIO自身のworker/segmentの被害ではないため、Kill60SecのSLA計測対象に含まれない）。",
        "snd_takomachi_notes": "連携なし。",
    },
    "account_takeover": {
        "detectability": (
            "OAuth/SSO等の認証連携が侵害された場合、WAIO自身がその"
            "認証連携に依存していればShadow AI Monitor/SSH Exposure"
            "Monitor等の既存センサーの観測範囲に入る可能性があるが、"
            "外部組織のアカウント侵害そのものを検知する機能はない。"
        ),
        "required_logs_sensors": "Shadow AI Monitor, SSH Exposure Monitor（いずれもWAIO自身のホストが対象）",
        "containment_stage": "WAIO自身の認証連携を無効化・隔離する判断材料にはなるが、実行は常に人間が行う。",
        "kill60sec_relevance": "WAIO自身の認証情報が影響を受ける場合のみ関係する可能性がある。それ以外は対象外。",
        "snd_takomachi_notes": "連携なし。",
    },
    "ddos": {
        "detectability": (
            "WAIO自身が提供する公開エンドポイントが対象になる場合を除き、"
            "外部組織への可用性攻撃を観測する機能はない。"
        ),
        "required_logs_sensors": "該当なし（WAIO自身が標的になる場合のみ、egress/受信ログが参考になり得る）。",
        "containment_stage": "対象外。",
        "kill60sec_relevance": "対象外。",
        "snd_takomachi_notes": "連携なし。",
    },
    "phishing": {
        "detectability": "WAIO自身の運用者/従業員が対象になる場合を除き、外部組織へのフィッシングを観測する機能はない。",
        "required_logs_sensors": "該当なし。",
        "containment_stage": "対象外。",
        "kill60sec_relevance": "対象外。",
        "snd_takomachi_notes": "連携なし。",
    },
    "vulnerability_disclosure": {
        "detectability": (
            "既存のCISA KEV Collector/GHSA Collectorが同種のCVE/"
            "アドバイザリをすでに収集対象としている可能性がある。"
            "WAIOが当該ソフトウェア/ベンダーに依存している場合、"
            "既存の収集結果と突合することで観測できる可能性がある。"
        ),
        "required_logs_sensors": "CISA KEV Collector, GHSA Collector（既存、無改修で利用可）",
        "containment_stage": "該当する依存関係がある場合のみ、パッチ適用/依存停止の判断材料になる（実行は人間）。",
        "kill60sec_relevance": "対象外（脆弱性開示は攻撃の実行ではないため、Detection→ContainmentのSLA計測対象ではない）。",
        "snd_takomachi_notes": "連携なし。",
    },
    "unclassified": {
        "detectability": "分類が確立していないため、WAIOの既存モジュールとの対応関係を評価できない。",
        "required_logs_sensors": "評価不能。",
        "containment_stage": "評価不能。",
        "kill60sec_relevance": "評価不能。",
        "snd_takomachi_notes": "評価不能。",
    },
}

DEFAULT_ASSESSMENT = {
    "detectability": "この incident_type は評価テーブルに未登録のため、個別の人間判断が必要（自動評価不能）。",
    "required_logs_sensors": "不明",
    "containment_stage": "不明",
    "kill60sec_relevance": "不明",
    "snd_takomachi_notes": "不明",
}


def _load_json(path, default):
    if not path or not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _bucket(items, key_fn):
    out = {}
    for item in items:
        k = key_fn(item)
        k = k if k else "unknown"
        out[k] = out.get(k, 0) + 1
    return out


def _candidate_summary(c, level_map):
    cid = c.get("id")
    return {
        "id": cid,
        "source": c.get("source"),
        "source_type": c.get("source_type"),
        "source_url": c.get("source_url"),
        "country": c.get("country") or "unknown",
        "region": c.get("region") or "unknown",
        "affected_sector": c.get("affected_sector") or "unknown",
        "incident_type": c.get("incident_type") or "unclassified",
        "attack_pattern": c.get("attack_pattern") or "unclassified",
        "status": c.get("status"),
        "confidence_level": level_map.get(cid, "UNVERIFIED"),
        "confidence_score": c.get("confidence_score"),
        # Date separation, honestly reflecting the Collector contract:
        # occurred_at/discovered_at are NOT fields any existing
        # Collector or incident_normalizer.sh ever populates -- there
        # is no source of truth for "when did the organization itself
        # first detect this" anywhere in this pipeline today, so both
        # are always "不明", never guessed from published_at/
        # collected_at.
        "occurred_at": "不明",
        "discovered_at": "不明",
        "published_at": c.get("published_at") or "不明",
        "collected_at": c.get("collected_at") or "不明",
        "claimed_impact": c.get("claimed_impact") or [],
        "related_incidents": c.get("related_incidents") or [],
        "corroborating_sources": c.get("corroborating_sources") or [],
    }


def _assess(c):
    table_entry = WAIO_ASSESSMENT_TABLE.get(c.get("incident_type") or "unclassified", DEFAULT_ASSESSMENT)
    return {
        "id": c.get("id"),
        "incident_type": c.get("incident_type") or "unclassified",
        **table_entry,
    }


def _render_markdown(report):
    lines = []
    lines.append("# WAIO Global Cyber Intelligence Patrol Report")
    lines.append("")
    lines.append(f"- generated_at: {report['generated_at']}")
    lines.append(f"- previous_run_at: {report['previous_run_at'] or '（初回巡回のため無し）'}")
    lines.append(f"- pipeline_status_this_cycle: {report['pipeline_status']}")
    lines.append(f"- is_first_run: {report['is_first_run']}")
    lines.append("")

    lines.append("## 1. Global Incident Summary")
    t = report["totals"]
    lines.append(f"- 既知candidate総数: {t['all_known_candidates']}")
    lines.append(f"- 前回巡回からの新規candidate数: {t['new_since_last_patrol']}")
    lines.append(f"- 人間ゲート待ち（CANDIDATE/HOLD）: {len(report['action_items_before_next_patrol']['pending_human_gate'])}")
    lines.append("")

    lines.append("## 2. 新規インシデント一覧")
    if not report["new_incidents"]:
        lines.append("（前回巡回以降、新規candidateはありません）")
    for c in report["new_incidents"]:
        lines.append(
            f"- **{c['id']}** [{c['confidence_level']}] {c['incident_type']} / "
            f"{c['affected_sector']} / {c['country']}-{c['region']}"
        )
        lines.append(f"  - 発生日: {c['occurred_at']} / 発見日: {c['discovered_at']} / 公表日(published_at): {c['published_at']} / 取得日時(collected_at): {c['collected_at']}")
        lines.append(f"  - 出典: {c['source_url']} (source={c['source']}, source_type={c['source_type']})")
        if c["claimed_impact"]:
            lines.append(f"  - 被害規模（出典の記述、未検証）: {'; '.join(c['claimed_impact'])}")
        if c["related_incidents"]:
            lines.append(f"  - 関連candidate: {', '.join(c['related_incidents'])}")
    lines.append("")

    lines.append("## 3. 国・地域・業種別の傾向")
    lines.append(f"- 国別: {json.dumps(report['trends']['by_country'], ensure_ascii=False)}")
    lines.append(f"- 地域別: {json.dumps(report['trends']['by_region'], ensure_ascii=False)}")
    lines.append(f"- 業種別: {json.dumps(report['trends']['by_sector'], ensure_ascii=False)}")
    lines.append(f"- インシデント種別: {json.dumps(report['trends']['by_incident_type'], ensure_ascii=False)}")
    lines.append("")

    lines.append("## 4. 攻撃手法の変化（前回巡回比）")
    if not report["attack_method_changes"]:
        lines.append("（前回巡回からの attack_pattern 分布に変化はありません）")
    for change in report["attack_method_changes"]:
        sign = "+" if change["delta"] >= 0 else ""
        lines.append(
            f"- {change['attack_pattern']}: {change['previous_count']} -> {change['current_count']} ({sign}{change['delta']})"
        )
    lines.append("")

    lines.append("## 5. WAIOの検知・封じ込め改善案（机上評価、新規インシデントのみ）")
    lines.append("注記: 以下は「公開情報の分類結果」に対する机上の対応表であり、実際に検知・封じ込めが行われたことを意味しません。")
    if not report["waio_assessment"]:
        lines.append("（評価対象の新規candidateはありません）")
    for a in report["waio_assessment"]:
        lines.append(f"- **{a['id']}** ({a['incident_type']})")
        lines.append(f"  - 検知できる可能性: {a['detectability']}")
        lines.append(f"  - 必要なログ・センサー: {a['required_logs_sensors']}")
        lines.append(f"  - 封じ込め可能な段階: {a['containment_stage']}")
        lines.append(f"  - Kill60Secへの関連: {a['kill60sec_relevance']}")
        lines.append(f"  - SND@HOME・Takomachi連携: {a['snd_takomachi_notes']}")
    lines.append("")

    lines.append("## 6. 次回巡回までの重要事項")
    ai = report["action_items_before_next_patrol"]
    lines.append(f"- 今回の収集(incident_learning_cron.sh)状態: {report['pipeline_status']}")
    if ai["pending_human_gate"]:
        lines.append(f"- 人間ゲート待ちのcandidate: {', '.join(ai['pending_human_gate'])}")
    else:
        lines.append("- 人間ゲート待ちのcandidateはありません")
    lines.append("")

    lines.append(critical_infra_watch.render_markdown_section(report["critical_infrastructure_watch"]))

    lines.append("## データ品質に関する注記（事実・推定・未確認の分離）")
    for note in report["data_quality_notes"]:
        lines.append(f"- {note}")
    lines.append("")

    return "\n".join(lines)


def main(argv):
    if len(argv) < 5:
        sys.stderr.write(
            "Usage: global_patrol_report.py CANDIDATES_DIR STATE_PATH OUTPUT_DIR "
            "GENERATED_AT_ISO LEVELS_JSON_PATH [PIPELINE_STATUS]\n"
        )
        return 1

    candidates_dir, state_path, output_dir, generated_at, levels_path = argv[0:5]
    pipeline_status = argv[5] if len(argv) > 5 and argv[5] else "unknown"
    # Critical Infrastructure & Military Precursor Watch's own carryover
    # state file. Defaults to a sibling of STATE_PATH -- no new env var
    # or global_patrol_cron.sh change needed for the default case; a
    # 7th positional arg may still override it (used by this module's
    # own test suite for fixture isolation).
    critical_carryover_path = (
        argv[6] if len(argv) > 6 and argv[6]
        else os.path.join(os.path.dirname(state_path) or ".", "critical_watch_carryover.json")
    )

    is_first_run = not os.path.exists(state_path)
    prev_state = _load_json(state_path, {})
    prev_run_at = prev_state.get("last_run_at")
    known_ids = set(prev_state.get("known_candidate_ids", []))
    prev_attack_pattern = prev_state.get("attack_pattern_distribution", {})

    level_map = _load_json(levels_path, {})

    candidates = []
    for path in sorted(glob.glob(os.path.join(candidates_dir, "*.json"))):
        d = _load_json(path, None)
        if not isinstance(d, dict) or not d.get("id"):
            continue
        candidates.append(d)

    current_ids = sorted({c["id"] for c in candidates})
    new_candidates = [c for c in candidates if c["id"] not in known_ids]

    by_country = _bucket(candidates, lambda c: c.get("country"))
    by_region = _bucket(candidates, lambda c: c.get("region"))
    by_sector = _bucket(candidates, lambda c: c.get("affected_sector"))
    by_incident_type = _bucket(candidates, lambda c: c.get("incident_type"))
    by_attack_pattern = _bucket(candidates, lambda c: c.get("attack_pattern"))

    attack_method_changes = []
    for pattern in sorted(set(by_attack_pattern) | set(prev_attack_pattern)):
        now_n = by_attack_pattern.get(pattern, 0)
        prev_n = prev_attack_pattern.get(pattern, 0)
        if now_n != prev_n:
            attack_method_changes.append({
                "attack_pattern": pattern,
                "previous_count": prev_n,
                "current_count": now_n,
                "delta": now_n - prev_n,
            })

    pending_human_gate = sorted(c["id"] for c in candidates if c.get("status") in ("CANDIDATE", "HOLD"))

    prev_critical_carryover = critical_infra_watch._load_carryover(critical_carryover_path)
    critical_section, new_critical_carryover = critical_infra_watch.build_section(
        candidates, level_map, prev_critical_carryover, generated_at
    )

    report = {
        "generated_at": generated_at,
        "previous_run_at": prev_run_at,
        "is_first_run": is_first_run,
        "pipeline_status": pipeline_status,
        "totals": {
            "all_known_candidates": len(candidates),
            "new_since_last_patrol": len(new_candidates),
        },
        "new_incidents": [_candidate_summary(c, level_map) for c in new_candidates],
        "trends": {
            "by_country": by_country,
            "by_region": by_region,
            "by_sector": by_sector,
            "by_incident_type": by_incident_type,
        },
        "attack_method_changes": attack_method_changes,
        "waio_assessment": [_assess(c) for c in new_candidates],
        "critical_infrastructure_watch": critical_section,
        "action_items_before_next_patrol": {
            "pending_human_gate": pending_human_gate,
            "critical_watch_open_count": len(critical_section["carryover_open"]),
        },
        "data_quality_notes": [
            "本レポートの件数は、既にcollectors経由で取得・normalize済みのcandidateレコードの集計であり、未公表の被害・未検知の事案は含まれない（それらは定義上『不明』であり、発生した事実として扱っていない）。",
            "被害規模(claimed_impact)は出典の記述の引用であり、WAIOが独立に検証した数値ではない。",
            "候補の母数・調査方法が不明なため、本レポートの件数から国内外全体の侵害率を推定することはしない。",
            "confidence_level（UNVERIFIED/LOW/MEDIUM/HIGH/CONFIRMED）はsecurity/incident_learning/knowledge_manager.shの既存定義に準拠する。CONFIRMEDは人間承認を経てPROMOTEDに達した場合のみ。",
            "本レポートのWAIO評価(5章)は机上の対応表であり、実際の検知・封じ込めの実行結果ではない。",
        ],
    }

    os.makedirs(output_dir, exist_ok=True)
    ts_tag = generated_at.replace(":", "").replace("-", "")
    json_path = os.path.join(output_dir, f"global-patrol-report-{ts_tag}.json")
    md_path = os.path.join(output_dir, f"global-patrol-report-{ts_tag}.md")
    latest_json_path = os.path.join(output_dir, "global-patrol-report-latest.json")
    latest_md_path = os.path.join(output_dir, "global-patrol-report-latest.md")

    tmp_json = json_path + ".tmp"
    with open(tmp_json, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    os.replace(tmp_json, json_path)
    shutil.copyfile(json_path, latest_json_path)

    md_text = _render_markdown(report)
    tmp_md = md_path + ".tmp"
    with open(tmp_md, "w", encoding="utf-8") as f:
        f.write(md_text)
    os.replace(tmp_md, md_path)
    shutil.copyfile(md_path, latest_md_path)

    # Commit the new snapshot ONLY after both report files above were
    # written successfully -- all-or-nothing, same as
    # security/continuity.sh's own snapshot writers: a failure above
    # (e.g. disk full) raises before this point and last_patrol.json
    # is left byte-for-byte as it was, so a retried/next run still
    # correctly treats everything since the LAST SUCCESSFUL report as
    # new.
    new_state = {
        "last_run_at": generated_at,
        "known_candidate_ids": current_ids,
        "attack_pattern_distribution": by_attack_pattern,
    }
    os.makedirs(os.path.dirname(state_path) or ".", exist_ok=True)
    tmp_state = state_path + ".tmp"
    with open(tmp_state, "w", encoding="utf-8") as f:
        json.dump(new_state, f, ensure_ascii=False, indent=2)
    os.replace(tmp_state, state_path)

    # Same all-or-nothing commit discipline, same point in the run (both
    # report files already written successfully) -- the Critical
    # Infrastructure Watch's own carryover file.
    critical_infra_watch._save_carryover(critical_carryover_path, new_critical_carryover)

    print(
        f"[GLOBAL PATROL REPORT] {json_path} written "
        f"({len(new_candidates)} new of {len(candidates)} known candidates; "
        f"pipeline_status={pipeline_status})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
