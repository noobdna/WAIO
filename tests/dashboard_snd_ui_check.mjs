// tests/dashboard_snd_ui_check.mjs -- Node.js half of Phase 76's
// regression suite for dashboard/index.html's new "SND" panel.
// Invoked by tests/dashboard_snd_ui_test.sh, never run directly by CI.
//
// Same approach as tests/dashboard_guardian_ui_check.mjs: extracts and
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

console.log("[U1] not configured (this deployment's real, expected default state) renders distinctly from unavailable/available");
sandbox.renderSnd({ configured: false, available: false, reason: "not configured (SND_HOME_API_URL not set)", lan_status: null, system_status: null, active_alerts: null }, "test-fixture");
check("U1 badge text", el("snBadge").textContent, "NOT CONFIGURED");
check("U1 badge class (unknown/gray)", el("snBadge").className, "badge unknown");
check("U1 reason shown", el("snReason").textContent, "not configured (SND_HOME_API_URL not set)");

console.log("[U2] configured but unreachable renders UNAVAILABLE (red)");
sandbox.renderSnd({ configured: true, available: false, reason: "GET /api/lan/status failed (HTTP 000)", lan_status: null, system_status: null, active_alerts: null }, "test-fixture");
check("U2 badge text", el("snBadge").textContent, "UNAVAILABLE");
check("U2 badge class", el("snBadge").className, "badge fail");

console.log("[U3] available with real-shaped lan/system/alerts data renders AVAILABLE (green) and summarizes it");
sandbox.renderSnd({
  configured: true, available: true, reason: null,
  lan_status: { devices_total: 5, devices_online: 4 },
  system_status: { cpu_pct: 12.3 },
  active_alerts: [{ id: "a1", severity: "warning" }],
}, "test-fixture");
check("U3 badge text", el("snBadge").textContent, "AVAILABLE");
check("U3 badge class", el("snBadge").className, "badge pass");
check("U3 lan devices summary", el("snLan").textContent, "4 / 5 online");
check("U3 active alerts count", el("snAlerts").textContent, 1);

console.log("[U4] available but empty (zero devices, zero alerts) renders '0', never '—' or a crash");
sandbox.renderSnd({
  configured: true, available: true, reason: null,
  lan_status: { devices_total: 0, devices_online: 0 },
  system_status: {},
  active_alerts: [],
}, "test-fixture");
check("U4 zero devices summary", el("snLan").textContent, "0 / 0 online");
check("U4 zero alerts count", el("snAlerts").textContent, 0);

console.log(`\n=== Results: ${pass} passed, ${fail} failed ===`);
if (fail > 0) {
  console.log("Failures:");
  failures.forEach(f => console.log(`  - ${f}`));
  process.exit(1);
}
process.exit(0);
