// tests/dashboard_touch_tooltip_check.mjs -- Node.js half of
// tests/dashboard_touch_tooltip_test.sh. Extracts earth_weather.html's real
// bindTooltip() and its document-level pointerdown handler and runs them
// against fake elements and pointer events: mouse keeps the old hover
// behaviour; touch/pen (iPad) shows on tap and stays until a tap elsewhere.

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import vm from "vm";

const REPO_ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const html = fs.readFileSync(path.join(REPO_ROOT, "dashboard", "earth_weather.html"), "utf8");
const m = html.match(/function bindTooltip[\s\S]*?\n\}\ndocument\.addEventListener\("pointerdown"[\s\S]*?\n\}\);\n/);
let pass = 0, fail = 0;
const check = (label, ok) => { if (ok) { pass++; console.log("  PASS: " + label); } else { fail++; console.log("  FAIL: " + label); } };
check("bindTooltip() and its document pointerdown handler found in earth_weather.html", !!m);
check("no mouse-only listeners left (mousemove/mouseleave/mouseover)", !/addEventListener\("mouse(move|leave|over|out)"/.test(html));
if (!m) { console.log(`\n=== Results: ${pass} passed, ${fail} failed ===`); process.exit(1); }

class Target {
  constructor() { this.h = {}; }
  addEventListener(t, f) { (this.h[t] ||= []).push(f); }
  fire(t, ev) { let stopped = false; const e = { ...ev, type: t, stopPropagation() { stopped = true; } };
    (this.h[t] || []).forEach((f) => f(e)); return stopped; }
}
const tooltip = { style: { opacity: 0, left: "", top: "" }, textContent: "" };
const doc = new Target();
doc.querySelectorAll = (sel) => (sel === ".tooltip" ? [tooltip] : []);
const ctx = { document: doc };
vm.createContext(ctx);
vm.runInContext(m[0] + "\nthis.bindTooltip = bindTooltip;", ctx);

const dot = new Target();
ctx.bindTooltip(dot, tooltip, () => "M5.1 震度4");
// a tap on the mark, as the browser dispatches it: pointerdown on the mark (bubbles to document unless stopped)
const tap = (el, pointerType) => { const stopped = el.fire("pointerdown", { pointerType, offsetX: 10, offsetY: 20 }); if (!stopped) doc.fire("pointerdown", { pointerType }); };

tap(dot, "touch");
check("touch: a tap on a mark shows its tooltip with the mark's text", tooltip.style.opacity === 1 && tooltip.textContent === "M5.1 震度4");
check("touch: tooltip positioned at the tap", tooltip.style.left === "10px" && tooltip.style.top === "20px");
dot.fire("pointerleave", { pointerType: "touch" });
check("touch: lifting the finger (pointerleave) does not hide it", tooltip.style.opacity === 1);
doc.fire("pointerdown", { pointerType: "touch" });
check("touch: a tap anywhere else hides it", tooltip.style.opacity === 0);
tap(dot, "pen");
check("pen (Apple Pencil): a tap shows it too", tooltip.style.opacity === 1);
doc.fire("pointerdown", { pointerType: "pen" });

dot.fire("pointermove", { pointerType: "mouse", offsetX: 3, offsetY: 4 });
check("mouse: hovering shows it (desktop behaviour unchanged)", tooltip.style.opacity === 1 && tooltip.style.left === "3px");
dot.fire("pointerleave", { pointerType: "mouse" });
check("mouse: leaving the mark hides it (desktop behaviour unchanged)", tooltip.style.opacity === 0);

console.log(`\n=== Results: ${pass} passed, ${fail} failed ===`);
process.exit(fail ? 1 : 0);
