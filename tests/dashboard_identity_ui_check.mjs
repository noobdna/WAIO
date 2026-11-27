// tests/dashboard_identity_ui_check.mjs -- Node.js half of the WAIO identity
// DATA suite (version / active node / human approval in the Blue Guardian
// topbar). Invoked by tests/dashboard_identity_ui_test.sh. Same approach as
// dashboard_guardian_ui_check.mjs: executes the page's REAL inline <script>
// under a minimal DOM stub. Reads only dashboard/index.html.

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
  // A real DOM element clears its child nodes when innerHTML is
  // reassigned (this page's own code relies on that -- see
  // renderStatus's `countsEl.innerHTML = "";` before rebuilding the
  // critical-event-counts list). Mirrored here as a getter/setter so
  // this stub matches that real, load-bearing behavior instead of
  // silently accumulating stale children across renders.
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
  // The real page's own top-level code calls refreshAll() on load, which
  // fetches live JSON snapshots and falls back to the embedded
  // FALLBACK_* constants via .catch() on failure -- exactly the failure
  // path this stub always takes (no live server here). That fallback
  // render happens in a promise microtask queued by this vm.runInContext
  // call; this script's own process.exit() below runs synchronously
  // before Node ever gets a chance to drain that microtask queue, so it
  // never interferes with the deliberate renderStatus() calls below.
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

const baseData = {
  generated_at: "2026-09-17T00:00:00Z",
  waio_status: "NORMAL",
  waio_status_note: "",
  shutdown: { active: false, reason: null, triggered_at: null, age_seconds: null },
  guardian: { authorized_keys_entry_present: true, last_guardian_recovery_at: null },
  notify: { auto_notify_enabled: false },
  recent_events: [],
  test_results: null,
};

const identity = { product: "WAIO", version: "v1.2.3-4-gabc1234", node: "node750" };
const gcp = (state, is_blocking) => ({ state, is_blocking, quarantined_agents: [], critical_event_counts: {} });

console.log("[I1] static markup: identity slots live in the Blue Guardian topbar");
check("I1 idVersion slot", html.includes('id="idVersion"'), true);
check("I1 idNode slot", html.includes('id="idNode"'), true);
check("I1 idApproval slot", html.includes('id="idApproval"'), true);
check("I1 slots are inside .topbar-meta", /class="topbar-meta">\s*<span class="id-meta"/.test(html), true);
check("I1 existing blueTeamNameInline label kept (approved: no rename)", html.includes('<span id="blueTeamNameInline">アオタコ (Takomachi)</span>'), true);

console.log("[I2] identity present + Guardian NORMAL: version/node shown, approval 'none pending'");
sandbox.renderStatus({ ...baseData, identity, guardian_control_plane: gcp("NORMAL", false) }, "test-fixture");
check("I2 version", el("idVersion").textContent, "v1.2.3-4-gabc1234");
check("I2 node", el("idNode").textContent, "node750");
check("I2 approval text", el("idApproval").textContent, "none pending (NORMAL)");
check("I2 approval class", el("idApproval").className, "id-v approval-clear");

console.log("[I3] HUMAN_APPROVAL_REQUIRED is surfaced prominently");
sandbox.renderStatus({ ...baseData, identity, guardian_control_plane: gcp("HUMAN_APPROVAL_REQUIRED", true) }, "test-fixture");
check("I3 approval text", el("idApproval").textContent, "REQUIRED — dispatch held");
check("I3 approval class", el("idApproval").className, "id-v approval-required");

console.log("[I4] BLOCKED / SHUTDOWN shown as blocking");
for (const s of ["BLOCKED", "SHUTDOWN"]) {
  sandbox.renderStatus({ ...baseData, identity, guardian_control_plane: gcp(s, true) }, "test-fixture");
  check(`I4 ${s} text`, el("idApproval").textContent, `${s} — dispatch blocked`);
  check(`I4 ${s} class`, el("idApproval").className, "id-v approval-blocking");
}

console.log("[I5] older snapshot without identity / guardian_control_plane: 'not measured', never fabricated");
sandbox.renderStatus({ ...baseData, guardian_control_plane: undefined }, "test-fixture");
check("I5 version", el("idVersion").textContent, "not measured");
check("I5 node", el("idNode").textContent, "not measured");
check("I5 approval", el("idApproval").textContent, "not measured");

console.log("[I6] status snapshot unavailable resets identity to 'not measured' (D-2 rule: no stale data)");
sandbox.renderStatus({ ...baseData, identity, guardian_control_plane: gcp("NORMAL", false) }, "test-fixture");
sandbox.renderStatusUnavailable("no live data");
check("I6 version reset", el("idVersion").textContent, "not measured");
check("I6 node reset", el("idNode").textContent, "not measured");
check("I6 approval reset", el("idApproval").textContent, "not measured");

console.log("[I7] identity values are rendered as text, never HTML");
sandbox.renderStatus({ ...baseData, identity: { version: "<img src=x>", node: "<b>x</b>" } }, "test-fixture");
check("I7 version via textContent", el("idVersion").textContent, "<img src=x>");
check("I7 innerHTML untouched", el("idVersion").innerHTML, "");

console.log("");
console.log(`=== Results: ${pass} passed, ${fail} failed ===`);
if (fail > 0) {
  console.log("Failures:");
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
process.exit(0);
