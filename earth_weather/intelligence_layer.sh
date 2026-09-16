#!/bin/bash
set -uo pipefail

# earth_weather/intelligence_layer.sh -- Earth & Weather Intelligence
# PoC, Intelligence Layer step. No network call. Reads
# earth_weather/data/correlation_report.json (Correlation Engine
# output) and turns it into a plain classification + human-readable
# summary -- it adds no new statistics of its own, only interpretation
# text, and that interpretation is required to state the non-causal
# caveat every single time, not just when a result happens to be
# statistically significant.
#
# Classification per variable (never "significant" alone -- always
# paired with the raw/corrected distinction the Correlation Engine
# already computed):
#   insufficient_data              -- too few earthquakes in-window
#   no_notable_signal              -- best |r| lag not significant even
#                                      at the uncorrected (raw) p<0.05
#   weak_signal_uncorrected_only   -- significant at raw p<0.05 but NOT
#                                      after Bonferroni correction --
#                                      the multiple-comparisons-expected
#                                      case; explicitly flagged as
#                                      likely noise, not a finding
#   signal_survives_correction     -- still significant after
#                                      Bonferroni correction; still
#                                      NOT evidence of causation, and
#                                      still needs independent
#                                      replication before it means
#                                      anything

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

DATA_DIR="${EW_DATA_DIR:-earth_weather/data}"
REPORT="$DATA_DIR/correlation_report.json"
SUMMARY_JSON="$DATA_DIR/intelligence_summary.json"
SUMMARY_TXT="$DATA_DIR/intelligence_summary.txt"

mkdir -p "$DATA_DIR"

if [ ! -f "$REPORT" ]; then
  echo "[INTELLIGENCE LAYER] ERROR: no correlation_report.json found -- run correlation_engine.sh first"
  exit 1
fi

python3 - "$REPORT" "$SUMMARY_JSON" "$SUMMARY_TXT" <<'PYEOF'
import json, sys, datetime

report_path, summary_json_path, summary_txt_path = sys.argv[1:4]

with open(report_path) as f:
    report = json.load(f)

VAR_LABELS = {
    "pressure_hpa": "気圧",
    "temperature_c": "気温",
    "precipitation_mm": "降水量",
    "humidity_pct": "湿度",
    "wind_speed_kmh": "風速",
}

now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
lines = []
lines.append("=== Earth & Weather Intelligence: 相関分析サマリー ===")
lines.append(f"generated_at: {now}")
lines.append("")
lines.append("重要: 本分析は気象と地震の間に「統計的な関連」が観測されるかどうかを")
lines.append("検証するものであり、因果関係の有無を示すものでは一切ありません。")
lines.append("")

classifications = {}

if report.get("status") == "insufficient_data":
    reason = report.get("reason")
    lines.append(f"status: insufficient_data -- {reason}")
    for var in report.get("variables", {}):
        classifications[var] = {"classification": "insufficient_data"}
else:
    cov = report.get("data_coverage", {})
    win = report.get("window", {})
    lookback_hours = win.get("lookback_hours")
    eq_radius_km = win.get("eq_radius_km")
    eq_in_window = cov.get("earthquakes_in_radius_and_window")
    total_tests = win.get("total_tests")
    bonferroni_alpha = win.get("bonferroni_alpha")
    lines.append(
        f"対象期間: 直近 {lookback_hours} 時間 / "
        f"半径 {eq_radius_km}km 以内の地震 "
        f"{eq_in_window} 件 / "
        f"検定数(変数×ラグ) {total_tests} 件 "
        f"(Bonferroni補正後 alpha={bonferroni_alpha:.2e})"
    )
    lines.append("")

    for var, data in report.get("variables", {}).items():
        label = VAR_LABELS.get(var, var)
        if data.get("status") != "ok" or not data.get("best"):
            classifications[var] = {"classification": "insufficient_data"}
            lines.append(f"[{label}] insufficient_data")
            continue

        best = data["best"]
        r = best["r"]
        p = best["p_value"]
        lag = best["lag_hours"]
        n = best["n"]

        if best["significant_bonferroni"]:
            classification = "signal_survives_correction"
            note = "多重比較補正後も有意 -- ただし因果関係の証拠ではなく、追試による再現確認が必須。"
        elif best["significant_raw"]:
            classification = "weak_signal_uncorrected_only"
            note = "補正前(raw)のみ有意 -- 多重比較を考慮すると偶然の可能性が高い。参考情報にとどめる。"
        else:
            classification = "no_notable_signal"
            note = "有意な統計的関連は観測されなかった(関連が無いことの証明ではない)。"

        classifications[var] = {
            "classification": classification,
            "best_lag_hours": lag,
            "r": r,
            "p_value": p,
            "n": n,
        }

        raw_sig = best["significant_raw"]
        bonferroni_sig = best["significant_bonferroni"]
        lines.append(
            f"[{label}] best lag={lag:+d}h  r={r:.3f}  p={p:.4f}  n={n}  "
            f"raw_sig={raw_sig}  bonferroni_sig={bonferroni_sig}"
        )
        lines.append(f"  -> {classification}: {note}")

    lines.append("")

lines.append("--- caveats ---")
for c in report.get("caveats", []):
    lines.append(f"- {c}")

summary = {
    "generated_at": now,
    "status": report.get("status"),
    "classifications": classifications,
    "caveats": report.get("caveats", []),
}

with open(summary_json_path, "w") as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)

with open(summary_txt_path, "w") as f:
    f.write("\n".join(lines) + "\n")

print("\n".join(lines))
PYEOF

echo "[INTELLIGENCE LAYER] completed"
