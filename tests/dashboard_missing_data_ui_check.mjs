// tests/dashboard_missing_data_ui_check.mjs -- Node.js half of the
// missing/stale-data regression suite for dashboard/index.html
// (2026-11-06, audit finding D-2). Invoked by
// tests/dashboard_missing_data_ui_test.sh.
//
// It executes the page's real inline <script> under a minimal DOM stub,
// the same approach as tests/dashboard_snd_ui_check.mjs. It asserts
// that when the response60 / segments / Takomachi / SND snapshots are
// missing, the page shows UNKNOWN / UNAVAILABLE, never an embedded
// NORMAL / PASS / AVAILABLE sample, and that old snapshots are
// labelled STALE.

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import vm from "vm";

const REPO_ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const html = fs.readFileSync(path.join(REPO_ROOT, "dashboard", "index.html"), "utf8");
const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
if (!scriptMatch) {
  console.error("FAIL: no inline <script> block found in dashboard/index.html");
  process.exit(1);
}
const pageScript = scriptMatch[1];

class FakeEl {
  constructor() {
    this.textContent = "";
    this.className = "";
    this._innerHTML = "";
    this.children = [];
    this.style = {};
  }
  get innerHTML() { return this._innerHTML; }
  set innerHTML(v) { this._innerHTML = v; this.children = []; }
  appendChild(child) { this.children.push(child); }
  addEventListener() {}
  removeEventListener() {}
}

let pass = 0, fail = 0;
function check(label, actual, expected) {
  if (actual === expected) {
    pass++;
    console.log(`  PASS: ${label}`);
  } else {
    fail++;
    console.log(`  FAIL: ${label} (expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)})`);
  }
}
function checkTrue(label, cond, detail) {
  if (cond) { pass++; console.log(`  PASS: ${label}`); }
  else { fail++; console.log(`  FAIL: ${label} (${detail})`); }
}
const settle = () => new Promise(r => setTimeout(r, 20));

// Builds a fresh page sandbox. fetchImpl(url) returns a Promise like fetch.
function loadPage(fetchImpl) {
  const elements = {};
  const el = (id) => (elements[id] ||= new FakeEl());
  const sandbox = {
    document: {
      getElementById: (id) => el(id),
      createElement: () => new FakeEl(),
      createTextNode: (t) => ({ text: t }),
    },
    window: {},
    localStorage: { getItem: () => null, setItem: () => {} },
    fetch: fetchImpl,
    setInterval: () => 0,
    clearInterval: () => {},
    console,
  };
  vm.createContext(sandbox);
  vm.runInContext(pageScript, sandbox);
  return { sandbox, el };
}
const ok = (body) => Promise.resolve({ ok: true, json: () => Promise.resolve(body) });
const notFound = () => Promise.resolve({ ok: false, status: 404, json: () => Promise.reject(new Error("404")) });

// ---------------------------------------------------------------- M1
console.log("[M1] all four D-2 snapshots missing (HTTP 404): no embedded sample is rendered");
{
  const { el } = loadPage(() => notFound());
  await settle();

  for (const id of ["systemStatusBadge", "redTeamBadge", "blueTeamBadge", "slaBadge", "ncBadge"]) {
    check(`M1 response60 ${id} is UNKNOWN`, el(id).textContent, "UNKNOWN");
    check(`M1 response60 ${id} class`, el(id).className, "badge unknown");
  }
  check("M1 response60 zeny total is a dash, not a score", el("zenyTotal").textContent, "—");
  check("M1 response60 SLA seconds is a dash", el("slaSeconds").textContent, "—");
  checkTrue("M1 response60 source says UNAVAILABLE", el("dataSource").textContent.startsWith("UNAVAILABLE"), el("dataSource").textContent);

  checkTrue("M1 segments count says UNKNOWN", el("segmentCount").textContent.startsWith("UNKNOWN"), el("segmentCount").textContent);
  const segMsg = el("segmentList").children[0];
  checkTrue("M1 segments list shows the UNAVAILABLE reason, not cards", el("segmentList").children.length === 1 && segMsg.textContent.startsWith("UNAVAILABLE"), JSON.stringify(segMsg && segMsg.textContent));
  checkTrue("M1 segments list never claims 'no segments configured'", !(segMsg && segMsg.textContent.includes("no segments configured")), "claimed not configured");

  check("M1 Takomachi badge UNAVAILABLE", el("tkBadge").textContent, "UNAVAILABLE");
  check("M1 Takomachi overview UNAVAILABLE", el("ovTakomachiBadge").textContent, "UNAVAILABLE");
  checkTrue("M1 Takomachi reason names the missing file", el("tkReason").textContent.includes("takomachi-status-latest.json"), el("tkReason").textContent);

  check("M1 SND badge UNKNOWN (not NOT CONFIGURED, not AVAILABLE)", el("snBadge").textContent, "UNKNOWN");
  check("M1 SND overview UNKNOWN", el("ovSndBadge").textContent, "UNKNOWN");
}

// ---------------------------------------------------------------- M2
console.log("[M2] network error (fetch rejects): same UNKNOWN / UNAVAILABLE states");
{
  const { el } = loadPage(() => Promise.reject(new Error("offline")));
  await settle();
  check("M2 response60 system badge UNKNOWN", el("systemStatusBadge").textContent, "UNKNOWN");
  check("M2 Takomachi UNAVAILABLE", el("tkBadge").textContent, "UNAVAILABLE");
  check("M2 SND UNKNOWN", el("snBadge").textContent, "UNKNOWN");
  checkTrue("M2 segments UNKNOWN", el("segmentCount").textContent.startsWith("UNKNOWN"), el("segmentCount").textContent);
}

// ---------------------------------------------------------------- M3
console.log("[M3] page text no longer embeds the removed samples");
for (const name of ["FALLBACK_DATA", "FALLBACK_SEGMENTS", "FALLBACK_TAKOMACHI", "FALLBACK_SND"]) {
  checkTrue(`M3 ${name} is gone`, !new RegExp(`\\b${name}\\b`).test(pageScript), `${name} still present`);
}

// ---------------------------------------------------------------- M4
console.log("[M4] fresh vs stale snapshot labels");
{
  const fresh = new Date(Date.now() - 60 * 1000).toISOString();
  const old = new Date(Date.now() - 19 * 86400 * 1000).toISOString();
  const takomachiFresh = { generated_at: fresh, available: false, reason: "no TAKOMACHI_API_KEY", health: null, agents: null, tasks: null };
  const segmentsOld = { generated_at: old, segments: [], recent_events: [] };
  const { el } = loadPage((url) => {
    if (url.includes("takomachi-status-latest.json")) return ok(takomachiFresh);
    if (url.includes("waio-segments-latest.json")) return ok(segmentsOld);
    return notFound();
  });
  await settle();
  check("M4 fresh Takomachi snapshot is labelled live", el("tkReason").textContent, "no TAKOMACHI_API_KEY");
  checkTrue("M4 19-day-old segments snapshot is labelled STALE", el("segmentCount").textContent.includes("STALE (19d old)"), el("segmentCount").textContent);
}

// ---------------------------------------------------------------- M5
console.log("[M5] snapshotLabel unit checks");
{
  const { sandbox } = loadPage(() => notFound());
  await settle();
  const L = sandbox.snapshotLabel;
  check("M5 recent waio-status is live", L("waio-status", { generated_at: new Date(Date.now() - 30e3).toISOString() }), "live: logs/waio-status-latest.json");
  checkTrue("M5 20-min-old waio-status is STALE", L("waio-status", { generated_at: new Date(Date.now() - 1200e3).toISOString() }).startsWith("STALE (20m old)"), "not stale");
  checkTrue("M5 missing generated_at is UNKNOWN AGE", L("decision-status", {}).startsWith("UNKNOWN AGE"), "not unknown");
  checkTrue("M5 garbage generated_at is UNKNOWN AGE", L("decision-status", { generated_at: "not-a-date" }).startsWith("UNKNOWN AGE"), "not unknown");
}

// ---------------------------------------------------------------- M6
console.log("[M6] real data still renders normally (no regression)");
{
  const { sandbox, el } = loadPage(() => notFound());
  await settle();
  sandbox.renderSnd({ configured: false, available: false, reason: "not configured", lan_status: null, active_alerts: null, terminals: null }, "fixture");
  check("M6 SND configured:false still NOT CONFIGURED", el("snBadge").textContent, "NOT CONFIGURED");
  sandbox.renderSnd({ configured: true, available: true, reason: null, lan_status: { devices_online: 1, devices_total: 2 }, active_alerts: [], terminals: [] }, "fixture");
  check("M6 SND configured+available still AVAILABLE", el("snBadge").textContent, "AVAILABLE");
  sandbox.renderSegments({ generated_at: new Date().toISOString(), segments: [{ segment_id: "S", label: "l", host: "h", port: "1", status: "normal", live_check: "pass", last_event: null }], recent_events: [] }, "fixture");
  checkTrue("M6 real segments still render as cards", el("segmentList").children.length === 1 && el("segmentCount").textContent.startsWith("1 "), el("segmentCount").textContent);
}

console.log(`\n=== Results: ${pass} passed, ${fail} failed ===`);
process.exit(fail === 0 ? 0 : 1);
