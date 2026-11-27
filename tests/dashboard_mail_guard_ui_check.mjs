// tests/dashboard_mail_guard_ui_check.mjs -- Node.js half of the MAIL GUARD
// dashboard panel suite. Invoked by tests/dashboard_mail_guard_ui_test.sh.
// Same approach as tests/dashboard_takomachi_ui_check.mjs: extracts and
// EXECUTES dashboard/index.html's real inline <script> under a minimal DOM
// stub, then asserts on the resulting element state.

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

console.log("[G1] no snapshot: UNAVAILABLE, every figure is a placeholder, never a count");
sandbox.renderMailGuard({ available: false, reason: "no events pulled yet" }, "none");
check("G1 badge", el("mgBadge").textContent, "UNAVAILABLE");
check("G1 badge class", el("mgBadge").className, "badge unknown");
check("G1 reason", el("mgReason").textContent, "UNAVAILABLE: no events pulled yet (source: none)");
check("G1 counts placeholder", el("mgCounts24").textContent, "—");
check("G1 senders placeholder", el("mgSenders").textContent, "—");

console.log("[G2] failed pull is shown with its reason");
sandbox.renderMailGuard({ available: false, reason: "x", last_pull: { at: "2026-11-28T10:00:00Z", ok: false, reason: "not in the egress allowlist" } }, "none");
check("G2 pull failure", el("mgPull").textContent, "2026-11-28T10:00:00Z FAILED: not in the egress allowlist");

const snap = {
  available: true, mode: "monitor", policy_version: 3, policy_source: "kv", gateway_version: "2.0.0-dev",
  latest_event_at: "2026-11-28T11:00:00Z",
  last_24h: { messages: 12, flagged: 2, by_verdict: { pass: 10, "would-quarantine": 2 }, errors: 0, unmapped_routes: 1,
              top_indicators: [{ name: "DISPLAY_NAME_SPOOF", count: 2 }] },
  last_7d: { messages: 80, flagged: 5, top_flagged_sender_domains: [{ name: "evil.invalid", count: 4 }],
             top_url_blocklist_hits: [] },
  last_pull: { at: "2026-11-28T11:05:00Z", ok: true }, last_publish: { version: 3, mode: "monitor", published_at: "2026-11-27T09:00:00Z" },
  config_warnings: ["quarantine_to_missing"],
};
console.log("[G3] available snapshot renders mode, policy, counts and lists");
sandbox.renderMailGuard(snap, "live: logs/mail-guard-status-latest.json");
check("G3 badge", el("mgBadge").textContent, "MODE: MONITOR");
check("G3 badge class", el("mgBadge").className, "badge monitoring");
check("G3 policy", el("mgPolicy").textContent, "v3 / kv · 2.0.0-dev");
check("G3 24h counts", el("mgCounts24").textContent, "12 / 2");
check("G3 7d counts", el("mgCounts7d").textContent, "80 / 5");
check("G3 verdicts", el("mgVerdicts").textContent, "pass: 10, would-quarantine: 2");
check("G3 indicators", el("mgIndicators").textContent, "DISPLAY_NAME_SPOOF \u00d72");
check("G3 senders", el("mgSenders").textContent, "evil.invalid \u00d74");
check("G3 url hits none", el("mgUrlHits").textContent, "none");
check("G3 errors/unmapped", el("mgErrors").textContent, "0 / 1");
check("G3 pull/publish", el("mgPull").textContent, "2026-11-28T11:05:00Z ok · v3 (monitor) 2026-11-27T09:00:00Z");
check("G3 warnings", el("mgWarnings").textContent, "quarantine_to_missing");

console.log("[G4] enforce mode badge; baseline policy");
sandbox.renderMailGuard(Object.assign({}, snap, { mode: "enforce", policy_version: null, policy_source: "baseline" }), "x");
check("G4 badge class", el("mgBadge").className, "badge protected");
check("G4 baseline policy", el("mgPolicy").textContent, "baseline / baseline · 2.0.0-dev");

console.log("[G5] markup in a domain is rendered as text (textContent), never as HTML");
const evil = Object.assign({}, snap, { last_7d: Object.assign({}, snap.last_7d, { top_flagged_sender_domains: [{ name: "<img src=x onerror=alert(1)>", count: 1 }] }) });
sandbox.renderMailGuard(evil, "x");
check("G5 innerHTML untouched", el("mgSenders").innerHTML, "");
check("G5 shown literally", el("mgSenders").textContent, "<img src=x onerror=alert(1)> \u00d71");

console.log("[G6] refreshAll() fetches the snapshot");
check("G6 page fetches the snapshot", /fetch\("\.\.\/logs\/mail-guard-status-latest\.json"/.test(pageScript), true);
console.log(`\n=== Results: ${pass} passed, ${fail} failed ===`);
if (fail > 0) {
  console.log("Failures:");
  failures.forEach(f => console.log(`  - ${f}`));
  process.exit(1);
}
process.exit(0);
