// tests/dashboard_incident_learning_ui_check.mjs -- Node.js half of
// Phase 76's regression suite for dashboard/index.html's new
// "Incident Learning Engine" panel. Invoked by
// tests/dashboard_incident_learning_ui_test.sh, never run directly by
// CI.
//
// Same approach as tests/dashboard_guardian_ui_check.mjs: extracts and
// actually EXECUTES the page's own real inline <script> block under a
// minimal DOM stub, then asserts on the resulting element state.
// Reads only dashboard/index.html; touches no security/state/ file, no
// real audit log.

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

console.log("[U1] empty state (no candidates at all) renders placeholders everywhere, never fabricated data");
sandbox.renderIncidentLearning({
  counts: {}, total_candidates: 0, promoted_knowledge_entries: 0,
  human_gate_queue: [], candidates: [], recent_events: [],
}, "test-fixture");
check("U1 total text", el("ilTotal").textContent, "0 (source: test-fixture)");
check("U1 promoted text", el("ilPromoted").textContent, 0);
check("U1 queue count", el("ilQueueCount").textContent, 0);
check("U1 status counts placeholder", el("ilStatusCounts").children[0]?.textContent, "no candidates");
check("U1 human gate queue placeholder", el("ilHumanGateQueue").children[0]?.textContent, "empty -- nothing awaiting a human decision");
check("U1 event log placeholder", el("ilEventLog").children[0]?.textContent, "no Incident Learning events recorded");

console.log("[U2] non-zero status counts render as chips with the correct color class per status");
sandbox.renderIncidentLearning({
  counts: { NORMALIZED: 2, CANDIDATE: 1, PROMOTED: 3, REJECTED: 1 },
  total_candidates: 7, promoted_knowledge_entries: 3,
  human_gate_queue: [], candidates: [], recent_events: [],
}, "test-fixture");
const countsChildren = el("ilStatusCounts").children;
check("U2 four status chips rendered", countsChildren.length, 4);
check("U2 NORMALIZED chip text", countsChildren[0]?.textContent, "NORMALIZED: 2");
check("U2 NORMALIZED chip class (in-pipeline, blue)", countsChildren[0]?.className, "badge monitoring");
check("U2 CANDIDATE chip class (needs human, amber)", countsChildren[1]?.className, "badge suspicious");
check("U2 PROMOTED chip class (done, green)", countsChildren[2]?.className, "badge recovered");
check("U2 REJECTED chip class (terminal-negative, red)", countsChildren[3]?.className, "badge failed");

console.log("[U3] Human Gate queue entries render as cards with id, source_type, status badge, and reason");
sandbox.renderIncidentLearning({
  counts: { HOLD: 1 }, total_candidates: 1, promoted_knowledge_entries: 0,
  human_gate_queue: [{ id: "INC-1", status: "HOLD", confidence_score: 72, source: "mock_collector", source_type: "cert", reason: "need more evidence" }],
  candidates: [], recent_events: [],
}, "test-fixture");
const queueChildren = el("ilHumanGateQueue").children;
check("U3 one queue card", queueChildren.length, 1);
const card = queueChildren[0];
check("U3 card id/source_type in head", card.children[0].children[0].textContent, "INC-1 (cert)");
check("U3 card status badge text", card.children[0].children[1].textContent, "HOLD");
check("U3 card status badge class", card.children[0].children[1].className, "badge suspicious");
check("U3 card reason line", card.children[1].textContent, "confidence 72 — need more evidence");

console.log("[U4] recent Incident Learning events render with candidate id, event, result, and reason");
sandbox.renderIncidentLearning({
  counts: {}, total_candidates: 0, promoted_knowledge_entries: 0,
  human_gate_queue: [], candidates: [],
  recent_events: [{ timestamp: "2026-09-18T00:00:00Z", candidate_id: "INC-2", event: "collected", reason: "new raw incident collected from mock_collector", action: "collect", result: "recorded" }],
}, "test-fixture");
const eventChildren = el("ilEventLog").children;
check("U4 one event row", eventChildren.length, 1);
const row = eventChildren[0];
// row.children interleaves the two <span> elements with plain text
// nodes (appendChild(createTextNode(" ")) between them) -- index 0 is
// the timestamp span, index 2 (not 1) is the type span; index 1 is
// the whitespace text node in between.
check("U4 event timestamp", row.children[0].textContent, "2026-09-18T00:00:00Z");
check("U4 event candidate/type", row.children[2].textContent, "INC-2: collected");

console.log("[U5] the pre-existing Segment Recovery panel is untouched by this addition (same renderSegments code path, unaffected)");
sandbox.renderSegments({ segments: [], recent_events: [] }, "test-fixture");
check("U5 segment count still renders", el("segmentCount").textContent, "0 (source: test-fixture)");

console.log(`\n=== Results: ${pass} passed, ${fail} failed ===`);
if (fail > 0) {
  console.log("Failures:");
  failures.forEach(f => console.log(`  - ${f}`));
  process.exit(1);
}
process.exit(0);
