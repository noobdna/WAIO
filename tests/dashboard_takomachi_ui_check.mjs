// tests/dashboard_takomachi_ui_check.mjs -- Node.js half of Phase 76's
// regression suite for dashboard/index.html's new "Takomachi" panel.
// Invoked by tests/dashboard_takomachi_ui_test.sh, never run directly
// by CI.
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

console.log("[U1] no reason at all (older cached snapshot shape) renders NOT MEASURED, never fabricated");
sandbox.renderTakomachi({ available: false, reason: null, health: null, agents: null, tasks: null }, "test-fixture");
check("U1 badge text", el("tkBadge").textContent, "NOT MEASURED");
check("U1 badge class (unknown/gray)", el("tkBadge").className, "badge unknown");

console.log("[U2] unavailable with a reason renders UNAVAILABLE (red) and shows the reason");
sandbox.renderTakomachi({ available: false, reason: "GET /health failed (HTTP 000)", health: null, agents: null, tasks: null }, "test-fixture");
check("U2 badge text", el("tkBadge").textContent, "UNAVAILABLE");
check("U2 badge class", el("tkBadge").className, "badge fail");
check("U2 reason text shown", el("tkReason").textContent, "GET /health failed (HTTP 000)");

console.log("[U3] available with real-shaped health/agents/tasks renders AVAILABLE (green) and summarizes all three");
sandbox.renderTakomachi({
  available: true, reason: null,
  health: { agent_manager: { status: "ok" }, task_queue: { status: "ok" }, plugin_system: { status: "ok" } },
  agents: { available: true, count: 2, by_status: { idle: 1, busy: 1 } },
  tasks: { available: true, count: 1, by_status: { in_progress: 1 } },
}, "test-fixture");
check("U3 badge text", el("tkBadge").textContent, "AVAILABLE");
check("U3 badge class", el("tkBadge").className, "badge pass");
check("U3 health summary", el("tkHealth").textContent, "ok / ok / ok");
check("U3 agents summary", el("tkAgents").textContent, "2 (idle: 1, busy: 1)");
check("U3 tasks summary", el("tkTasks").textContent, "1 (in_progress: 1)");

console.log("[U4] agents/tasks individually unavailable (partial outage) render as '—', not a crash or fabricated count");
sandbox.renderTakomachi({
  available: true, reason: null,
  health: { agent_manager: { status: "ok" }, task_queue: { status: "ok" }, plugin_system: { status: "ok" } },
  agents: { available: false, count: null, by_status: {} },
  tasks: { available: false, count: null, by_status: {} },
}, "test-fixture");
check("U4 agents placeholder", el("tkAgents").textContent, "—");
check("U4 tasks placeholder", el("tkTasks").textContent, "—");

console.log(`\n=== Results: ${pass} passed, ${fail} failed ===`);
if (fail > 0) {
  console.log("Failures:");
  failures.forEach(f => console.log(`  - ${f}`));
  process.exit(1);
}
process.exit(0);
