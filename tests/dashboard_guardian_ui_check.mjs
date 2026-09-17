// tests/dashboard_guardian_ui_check.mjs -- Node.js half of Phase 63's
// regression suite for dashboard/index.html's new "DuCoPA Guardian
// Control Plane" panel. Invoked by tests/dashboard_guardian_ui_test.sh,
// never run directly by CI.
//
// dashboard/index.html has no prior automated coverage anywhere in this
// repo (it is a "display layer only" static page -- see its own footer
// note). Rather than re-implementing renderStatus()'s logic in a second
// place to compare against (which would only prove two implementations
// agree with each other, not that either is correct), this extracts and
// actually EXECUTES the page's own real inline <script> block under a
// minimal DOM stub (getElementById/createElement/appendChild/
// addEventListener only -- just enough surface for renderStatus() to
// run without a real browser) and asserts on the resulting element
// state. Reads only dashboard/index.html; touches no security/state/
// file, no real audit log.

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

console.log("[U1] guardian_control_plane state WARNING renders: badge, blocking, quarantine list, per-agent counters");
sandbox.renderStatus({
  ...baseData,
  guardian_control_plane: {
    state: "WARNING",
    is_blocking: false,
    quarantined_agents: ["ECHO"],
    critical_event_counts: { ECHO: 2, RPI: 1 },
  },
}, "test-fixture");
check("U1 badge text", el("guardianCpBadge").textContent, "WARNING");
check("U1 badge class (amber, non-blocking)", el("guardianCpBadge").className, "badge warning");
check("U1 blocking = no", el("guardianCpBlocking").textContent, "no");
check("U1 quarantined agents listed", el("guardianCpQuarantined").textContent, "ECHO");
check("U1 critical count ECHO", el("guardianCpCriticalCounts").children[0]?.textContent, "ECHO: 2");
check("U1 critical count RPI", el("guardianCpCriticalCounts").children[1]?.textContent, "RPI: 1");

console.log("[U2] state BLOCKED renders as blocking, with the red/blocked badge class");
sandbox.renderStatus({
  ...baseData,
  guardian_control_plane: { state: "BLOCKED", is_blocking: true, quarantined_agents: [], critical_event_counts: {} },
}, "test-fixture");
check("U2 badge text", el("guardianCpBadge").textContent, "BLOCKED");
check("U2 badge class", el("guardianCpBadge").className, "badge blocked");
check("U2 blocking = yes", el("guardianCpBlocking").textContent, "yes");
check("U2 no agents quarantined -> 'none'", el("guardianCpQuarantined").textContent, "none");
check("U2 no critical events -> placeholder shown", el("guardianCpCriticalCounts").children[0]?.textContent, "no critical events recorded");

console.log("[U3] state NORMAL renders as the green/normal badge class, not blocking");
sandbox.renderStatus({
  ...baseData,
  guardian_control_plane: { state: "NORMAL", is_blocking: false, quarantined_agents: [], critical_event_counts: {} },
}, "test-fixture");
check("U3 badge text", el("guardianCpBadge").textContent, "NORMAL");
check("U3 badge class", el("guardianCpBadge").className, "badge normal");

console.log("[U4] guardian_control_plane absent (older cached snapshot) renders as NOT MEASURED, never fabricated");
const noGcpData = { ...baseData };
sandbox.renderStatus(noGcpData, "test-fixture-no-gcp");
check("U4 badge text", el("guardianCpBadge").textContent, "NOT MEASURED");
check("U4 badge class (unknown/gray)", el("guardianCpBadge").className, "badge unknown");
check("U4 blocking placeholder", el("guardianCpBlocking").textContent, "—");
check("U4 quarantined placeholder", el("guardianCpQuarantined").textContent, "—");

console.log("[U5] the pre-existing 'guardian' (SSH Guardian Recovery Protocol) panel is untouched by this addition");
sandbox.renderStatus({
  ...baseData,
  guardian: { authorized_keys_entry_present: true, last_guardian_recovery_at: "2026-09-01T00:00:00Z" },
  guardian_control_plane: { state: "NORMAL", is_blocking: false, quarantined_agents: [], critical_event_counts: {} },
}, "test-fixture");
check("U5 old guardian badge still reflects authorized_keys_entry_present", el("guardianBadge").textContent, "CONFIGURED");
check("U5 old guardian last-recovery field still populated", el("guardianLastRecovery").textContent, "2026-09-01T00:00:00Z");

console.log(`\n=== Results: ${pass} passed, ${fail} failed ===`);
if (fail > 0) {
  console.log("Failures:");
  failures.forEach(f => console.log(`  - ${f}`));
  process.exit(1);
}
process.exit(0);
