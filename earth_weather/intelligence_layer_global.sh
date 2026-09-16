#!/bin/bash
set -uo pipefail

# earth_weather/intelligence_layer_global.sh -- Earth & Weather
# Intelligence PoC, GLOBAL Intelligence Layer. No network call. Reads
# earth_weather/data/correlation_report_global.json and classifies
# each (station, variable) result and the pooled result -- same
# classification vocabulary as intelligence_layer.sh (insufficient_data
# / no_notable_signal / weak_signal_uncorrected_only /
# signal_survives_correction), always paired with the non-causality
# caveat, never a bare "significant".

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

DATA_DIR="${EW_DATA_DIR:-earth_weather/data}"
REPORT="$DATA_DIR/correlation_report_global.json"
SUMMARY_JSON="$DATA_DIR/intelligence_summary_global.json"
SUMMARY_TXT="$DATA_DIR/intelligence_summary_global.txt"

mkdir -p "$DATA_DIR"

if [ ! -f "$REPORT" ]; then
  echo "[INTELLIGENCE LAYER GLOBAL] ERROR: no correlation_report_global.json found -- run correlation_engine_global.sh first"
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


def classify(best):
    if best is None:
        return "insufficient_data", "有効なラグが計算できなかった。"
    if best.get("significant_bonferroni"):
        return "signal_survives_correction", "多重比較補正後も有意 -- ただし因果関係の証拠ではなく、追試による再現確認が必須。"
    if best.get("significant_raw"):
        return "weak_signal_uncorrected_only", "補正前(raw)のみ有意 -- 多重比較を考慮すると偶然の可能性が高い。"
    return "no_notable_signal", "有意な統計的関連は観測されなかった(関連が無いことの証明ではない)。"


now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
lines = []
lines.append("=== Earth & Weather Intelligence (GLOBAL): 相関分析サマリー ===")
lines.append(f"generated_at: {now}")
lines.append("")
lines.append("重要: 本分析は世界各地の気象と地震の間に統計的な関連が観測されるかどうかを")
lines.append("検証するものであり、因果関係の有無を示すものでは一切ありません。")
lines.append("")

summary = {"generated_at": now, "status": report.get("status"), "pooled": {}, "per_station": {}, "caveats": report.get("caveats", [])}

report_status = report.get("status")
if report_status != "ok":
    reason = report.get("reason")
    lines.append(f"status: {report_status} -- {reason}")
    with open(summary_txt_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    with open(summary_json_path, "w") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print("\n".join(lines))
    sys.exit(0)

win = report.get("window", {})
eq_radius_km = win.get("eq_radius_km")
lag_max_hours = win.get("lag_max_hours")
stations_analyzed = win.get("stations_analyzed")
total_tests = win.get("total_tests")
bonferroni_alpha = win.get("bonferroni_alpha")
lines.append(
    f"半径 {eq_radius_km}km / ラグ範囲 ±{lag_max_hours}h / "
    f"観測点数 {stations_analyzed} / 検定数(全体) {total_tests} 件 "
    f"(Bonferroni補正後 alpha={bonferroni_alpha:.2e})"
)
lines.append("")

lines.append("--- POOLED (全観測点プール) ---")
pooled = report.get("pooled", {})
if pooled.get("status") == "ok":
    for var, data in pooled.get("variables", {}).items():
        label = VAR_LABELS.get(var, var)
        best = data.get("best")
        classification, note = classify(best)
        summary["pooled"][var] = {"classification": classification}
        if best:
            summary["pooled"][var].update({
                "best_lag_hours": best["lag_hours"], "r": best["r"], "p_value": best["p_value"], "n": best["n"],
            })
            r = best["r"]
            p = best["p_value"]
            lag = best["lag_hours"]
            n = best["n"]
            lines.append(f"[{label}] lag={lag:+d}h r={r:.3f} p={p:.4f} n={n} -> {classification}")
        else:
            lines.append(f"[{label}] -> {classification}")
        lines.append(f"  {note}")
else:
    pooled_status = pooled.get("status")
    lines.append(f"pooled status: {pooled_status}")
lines.append("")

lines.append("--- 観測点別 (per-station) ---")
for name, station_data in report.get("per_station", {}).items():
    lines.append(f"[{name}]")
    if station_data.get("status") != "ok":
        n_eq = station_data.get("n_earthquakes_in_radius")
        lines.append(f"  insufficient_data (n_earthquakes_in_radius={n_eq})")
        summary["per_station"][name] = {"status": "insufficient_data"}
        continue
    summary["per_station"][name] = {"status": "ok", "variables": {}}
    for var, data in station_data.get("variables", {}).items():
        label = VAR_LABELS.get(var, var)
        best = data.get("best")
        classification, _ = classify(best)
        summary["per_station"][name]["variables"][var] = {"classification": classification}
        if best:
            r = best["r"]
            p = best["p_value"]
            lag = best["lag_hours"]
            lines.append(f"  [{label}] lag={lag:+d}h r={r:.3f} p={p:.4f} -> {classification}")
        else:
            lines.append(f"  [{label}] -> {classification}")

lines.append("")
lines.append("--- caveats ---")
for c in report.get("caveats", []):
    lines.append(f"- {c}")

with open(summary_json_path, "w") as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)

with open(summary_txt_path, "w") as f:
    f.write("\n".join(lines) + "\n")

print("\n".join(lines))
PYEOF

echo "[INTELLIGENCE LAYER GLOBAL] completed"
