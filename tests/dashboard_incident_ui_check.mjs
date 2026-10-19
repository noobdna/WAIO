// tests/dashboard_incident_ui_check.mjs -- Node.js half of the
// incident-timeline origin-labelling regression suite (audit finding
// F-16/F-17 follow-up). Invoked by tests/dashboard_incident_ui_test.sh,
// never run directly by CI.
//
// Same approach as tests/dashboard_takomachi_ui_check.mjs: extracts and
// actually EXECUTES the page's own real inline <script> block under a
// minimal DOM stub, then asserts on the resulting element state.

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import vm from "vm";

const REPO_ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const INDEX_HTML_PATH = path.join(REPO_ROOT, "dashboard", "index.html");

const html = fs.readFileSync(INDEX_HTML_PATH, "utf8");
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

const elements = {};
function el(id) {
  if (!elements[id]) elements[id] = new FakeEl();
  return elements[id];
}

const sandbox = {
  document: {
    getElementById: (id) => el(id),
    createElement: () => new FakeEl(),
    createTextNode: (t) => ({ text: t }),
  },
  window: {},
  localStorage: { getItem: () => null, setItem: () => {} },
  fetch: () => Promise.reject(new Error("stub: no live server in this check")),
  console,
};
vm.createContext(sandbox);
vm.runInContext(pageScript, sandbox);

let pass = 0, fail = 0;
const failures = [];
function check(label, actual, expected) {
  if (actual === expected) {
    pass++;
    console.log(`  PASS: ${label}`);
  } else {
    fail++;
    failures.push(`${label} (expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)})`);
    console.log(`  FAIL: ${label} (expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)})`);
  }
}

const baseIncident = (over) => Object.assign({
  incident_id: 1, status: "resolved",
  detection: { triggered_at: "2026-01-01T00:00:00Z", reason: "r", run_id: "x", worker: "W", destination: "d" },
  duplicate_trigger_count: 0,
  containment: { measured: false, duration_seconds: null, source: null },
  recovery: { measured: true, recovered_at: "2026-01-01T00:00:01Z", actor: "local", reason: "c" },
  notify: { measured: false, note: "" },
}, over);

console.log("[U1] classified snapshot: production/test counts shown, test artifact badged, production not badged");
sandbox.renderIncidentHistory({
  generated_at: new Date().toISOString(),
  total_incidents: 2, open_incidents: 0, production_incidents: 1, test_artifact_incidents: 1,
  incidents: [
    baseIncident({ incident_id: 1, origin: "test_artifact", origin_basis: ["rfc5737_destination"] }),
    baseIncident({ incident_id: 2, origin: "production", origin_basis: [] }),
  ],
}, "test-fixture");
check("U1 production count", String(el("incidentProduction").textContent), "1");
check("U1 test artifact count", String(el("incidentTestArtifacts").textContent), "1");
const u1 = el("incidentList").innerHTML;
const cards = u1.split('<div class="incident-card">').slice(1);
check("U1 two cards", cards.length, 2);
// most recent first: card[0] is incident #2 (production), card[1] is #1 (test artifact)
check("U1 production card has no TEST ARTIFACT badge", cards[0].includes("TEST ARTIFACT"), false);
check("U1 test-artifact card carries TEST ARTIFACT badge", cards[1].includes('badge test_artifact">TEST ARTIFACT'), true);

console.log("[U2] legacy snapshot (no origin fields): counts render '—', cards marked UNCLASSIFIED, never assumed production");
sandbox.renderIncidentHistory({
  generated_at: new Date().toISOString(), total_incidents: 1, open_incidents: 0,
  incidents: [baseIncident({})],
}, "test-fixture");
check("U2 production count placeholder", el("incidentProduction").textContent, "—");
check("U2 test artifact count placeholder", el("incidentTestArtifacts").textContent, "—");
check("U2 card marked UNCLASSIFIED", el("incidentList").innerHTML.includes('badge unclassified">UNCLASSIFIED'), true);

console.log("[U3] a hostile origin value is never echoed into markup");
sandbox.renderIncidentHistory({
  generated_at: new Date().toISOString(), total_incidents: 1, open_incidents: 0,
  production_incidents: 0, test_artifact_incidents: 0,
  incidents: [baseIncident({ origin: '<img src=x onerror=alert(1)>' })],
}, "test-fixture");
check("U3 hostile origin not rendered", el("incidentList").innerHTML.includes("onerror"), false);
check("U3 falls back to UNCLASSIFIED", el("incidentList").innerHTML.includes("UNCLASSIFIED"), true);

console.log(`\n=== Results: ${pass} passed, ${fail} failed ===`);
if (fail > 0) {
  console.log("Failures:");
  failures.forEach(f => console.log(`  - ${f}`));
  process.exit(1);
}
process.exit(0);
