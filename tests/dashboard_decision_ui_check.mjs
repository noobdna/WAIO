// tests/dashboard_decision_ui_check.mjs -- Node.js half of the
// regression suite for dashboard/index.html's new "System Overview"
// and "Decision Engine" panels. Invoked by
// tests/dashboard_decision_ui_test.sh, never run directly by CI.
//
// Same approach as tests/dashboard_takomachi_ui_check.mjs: extracts
// and actually EXECUTES the page's own real inline <script> block
// under a minimal DOM stub, then asserts on the resulting element
// state by calling renderDecision()/renderOverview()/renderStatus()/
// renderTakomachi()/renderSnd() directly (the same functions the page
// itself calls from refreshAll()).

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

console.log("[U1] none of the four modules have ever run: every section renders 'not run yet', never a fabricated zero");
sandbox.renderDecision({
  shadow_ai: { available: false, total_findings: null, risk_counts: {} },
  attack_graph: { available: false, generated_at: null, node_count: null, edge_count: null, cycle_count: null, attack_path_count: null, highest_risk_node: null },
  intelligence_layer: { available: false, generated_at: null, sources_ingested: {}, entity_count: null, multi_source_entity_count: null, risk_counts: {}, top_entities: [] },
  decision_engine: { available: false, generated_at: null, intelligence_report_generated_at: null, decision_count: null, action_counts: {}, pending_human_approval: [] },
}, "test-fixture");
check("U1 shadow_ai total", el("dcShadowAiTotal").textContent, "not run yet");
check("U1 entity total", el("dcEntityTotal").textContent, "not run yet");
check("U1 decision total", el("dcDecisionTotal").textContent, "not run yet");
check("U1 pending count placeholder", el("dcPendingCount").textContent, "—");
check("U1 attack graph placeholder", el("dcAttackGraph").textContent, "not run yet");

console.log("[U2] real-shaped data (3 shadow_ai findings, 1 MEDIUM risk) renders correctly, including the risk/confidence badge and highest_risk_node summary");
sandbox.renderDecision({
  shadow_ai: { available: true, total_findings: 3, risk_counts: { LOW: 2, MEDIUM: 1, HIGH: 0, CRITICAL: 0 } },
  attack_graph: { available: true, generated_at: "t", node_count: 3, edge_count: 0, cycle_count: 0, attack_path_count: 0, highest_risk_node: { name: "/Library/Develop", risk: "MEDIUM" } },
  intelligence_layer: {
    available: true, generated_at: "t", sources_ingested: { shadow_ai: 3 }, entity_count: 3, multi_source_entity_count: 0,
    risk_counts: { LOW: 2, MEDIUM: 1, HIGH: 0, CRITICAL: 0 },
    top_entities: [{ entity: "/Library/Develop", entity_type: "process", risk: "MEDIUM", confidence: "HIGH", source_modules: ["shadow_ai_monitor"] }],
  },
  decision_engine: { available: true, generated_at: "t", intelligence_report_generated_at: "t", decision_count: 3, action_counts: { NO_ACTION: 2, MONITOR: 1, ALERT_HUMAN: 0, RECOMMEND_CONTAINMENT: 0 }, pending_human_approval: [] },
}, "test-fixture");
check("U2 shadow_ai total", el("dcShadowAiTotal").textContent, "3 (source: test-fixture)");
check("U2 entity total (no multi-source suffix)", el("dcEntityTotal").textContent, "3");
check("U2 decision total", el("dcDecisionTotal").textContent, 3);
check("U2 pending count", el("dcPendingCount").textContent, 0);
check("U2 attack graph summary includes highest risk node", el("dcAttackGraph").textContent, "3 node(s), 0 edge(s), 0 cycle(s), 0 attack path(s) -- highest risk: /Library/Develop (MEDIUM)");
// action_counts = { NO_ACTION: 2, MONITOR: 1, ALERT_HUMAN: 0, RECOMMEND_CONTAINMENT: 0 }
// -- every NONZERO count renders its own chip (NO_ACTION and MONITOR
// both qualify here), in object-key insertion order; only the
// all-zero ALERT_HUMAN/RECOMMEND_CONTAINMENT are correctly skipped.
check("U2 action chip count (NO_ACTION + MONITOR, zero counts skipped)", el("dcActionCounts").children.length, 2);
check("U2 first action chip text (NO_ACTION)", el("dcActionCounts").children[0].textContent, "NO_ACTION: 2");
check("U2 first action chip class uses normal (green)", el("dcActionCounts").children[0].className, "badge normal");
check("U2 second action chip text (MONITOR)", el("dcActionCounts").children[1].textContent, "MONITOR: 1");
check("U2 second action chip class uses monitoring (blue)", el("dcActionCounts").children[1].className, "badge monitoring");
check("U2 top entity row count", el("dcTopEntities").children.length, 1);
check("U2 pending list shows empty placeholder, not a crash", el("dcPendingList").children.length, 1);
check("U2 pending list empty text", el("dcPendingList").children[0].textContent, "empty -- nothing pending human approval");

console.log("[U3] a RECOMMEND_CONTAINMENT decision with a pending entity renders the human_approval_required (red) badge and lists the entity by name");
sandbox.renderDecision({
  shadow_ai: { available: false, total_findings: null, risk_counts: {} },
  attack_graph: { available: false, generated_at: null, node_count: null, edge_count: null, cycle_count: null, attack_path_count: null, highest_risk_node: null },
  intelligence_layer: { available: false, generated_at: null, sources_ingested: {}, entity_count: null, multi_source_entity_count: null, risk_counts: {}, top_entities: [] },
  decision_engine: {
    available: true, generated_at: "t", intelligence_report_generated_at: "t", decision_count: 1,
    action_counts: { NO_ACTION: 0, MONITOR: 0, ALERT_HUMAN: 0, RECOMMEND_CONTAINMENT: 1 },
    pending_human_approval: ["evil.example.com"],
  },
}, "test-fixture");
check("U3 pending count", el("dcPendingCount").textContent, 1);
const containmentChip = el("dcActionCounts").children.find(c => c.textContent === "RECOMMEND_CONTAINMENT: 1");
check("U3 containment chip exists", !!containmentChip, true);
check("U3 containment chip class is human_approval_required (red)", containmentChip ? containmentChip.className : null, "badge human_approval_required");
check("U3 pending list has one entry", el("dcPendingList").children.length, 1);
check("U3 pending list entry text", el("dcPendingList").children[0].textContent, "evil.example.com");

// Note: overviewState is declared `const` at the page script's top
// level -- unlike the render*() functions (plain `function`
// declarations, which vm.runInContext DOES expose as sandbox
// properties), a let/const binding is NOT reachable as
// sandbox.overviewState from outside the executed script. This check
// therefore relies on running BEFORE any renderStatus/renderTakomachi/
// renderSnd call below (U5) ever touches it, so it still observes the
// page's own real initial value ({status: null, takomachi: null, snd:
// null}) rather than resetting it itself.
console.log("[U4] renderOverview: nothing fetched yet (all three panel states still at their real initial value) renders NOT MEASURED, never a fabricated status");
sandbox.renderOverview();
check("U4 SND badge", el("ovSndBadge").textContent, "NOT MEASURED");
check("U4 WAIO badge", el("ovWaioBadge").textContent, "NOT MEASURED");
check("U4 Takomachi badge", el("ovTakomachiBadge").textContent, "NOT MEASURED");

console.log("[U5] renderStatus/renderTakomachi/renderSnd each populate the System Overview strip as a side effect, with no extra fetch");
sandbox.renderStatus({
  generated_at: "t", waio_status: "NORMAL", waio_status_note: "",
  shutdown: { active: false, reason: null, triggered_at: null, age_seconds: null },
  guardian: { authorized_keys_entry_present: true, last_guardian_recovery_at: null },
  guardian_control_plane: { state: "NORMAL", is_blocking: false, quarantined_agents: [], critical_event_counts: {} },
  notify: { auto_notify_enabled: false },
  test_results: null,
}, "test-fixture");
check("U5 WAIO overview badge reflects renderStatus", el("ovWaioBadge").textContent, "NORMAL");
check("U5 WAIO overview detail shows Guardian CP state", el("ovWaioDetail").textContent, "Guardian CP: NORMAL");

sandbox.renderTakomachi({
  available: true, reason: null,
  health: { agent_manager: { status: "ok" }, task_queue: { status: "ok" }, plugin_system: { status: "ok" } },
  agents: { available: true, count: 2, by_status: { idle: 2 } },
  tasks: { available: true, count: 0, by_status: {} },
}, "test-fixture");
check("U5 Takomachi overview badge reflects renderTakomachi", el("ovTakomachiBadge").textContent, "AVAILABLE");
check("U5 Takomachi overview detail shows agent count", el("ovTakomachiDetail").textContent, "2 agent(s)");

sandbox.renderSnd({ configured: false, available: false, reason: null, lan_status: null, active_alerts: null, terminals: null }, "test-fixture");
check("U5 SND overview badge reflects renderSnd (opt-in, unconfigured)", el("ovSndBadge").textContent, "NOT CONFIGURED");

console.log(`\n=== Results: ${pass} passed, ${fail} failed ===`);
if (fail > 0) {
  console.log("Failures:");
  failures.forEach(f => console.log(`  - ${f}`));
  process.exit(1);
}
process.exit(0);
