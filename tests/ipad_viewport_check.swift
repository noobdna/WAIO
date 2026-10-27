// tests/ipad_viewport_check.swift -- lays dashboard pages out in WebKit (the
// engine iPad Safari uses) at iPad Pro viewport sizes and measures what makes
// a page hard to use on a tablet. Invoked by tests/ipad_viewport_test.sh.
//
//   swift tests/ipad_viewport_check.swift URL OUT_DIR NAME:WxH [NAME:WxH ...]
//
// Prints one JSON object per viewport: horizontal overflow, elements sticking
// out past the right edge, visible text below 12px, and touch targets smaller
// than 44x44 CSS px (Apple HIG minimum). Writes a full-page PNG per viewport
// to OUT_DIR. macOS WKWebView approximates iPad Safari's layout (same WebKit,
// same viewport width); it is not a substitute for a check on the device.

import Cocoa
import WebKit

let args = CommandLine.arguments
guard args.count >= 4, let pageURL = URL(string: args[1]) else {
  FileHandle.standardError.write("usage: ipad_viewport_check.swift URL OUT_DIR NAME:WxH...\n".data(using: .utf8)!)
  exit(2)
}
let outDir = args[2]
let targetURL: URL = pageURL
let viewports: [(String, CGFloat, CGFloat)] = args[3...].compactMap { spec in
  let p = spec.split(separator: ":"); guard p.count == 2 else { return nil }
  let d = p[1].split(separator: "x").compactMap { Double($0) }; guard d.count == 2 else { return nil }
  return (String(p[0]), CGFloat(d[0]), CGFloat(d[1]))
}

let measureJS = """
(() => {
  const W = window.innerWidth;
  const visible = el => { const s = getComputedStyle(el); const r = el.getBoundingClientRect();
    return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0; };
  const inXScroller = el => { for (let p = el.parentElement; p; p = p.parentElement) {
    const o = getComputedStyle(p).overflowX; if (o === 'auto' || o === 'scroll') return true; } return false; };
  const desc = el => el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') +
    (el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\\s+/).join('.') : '');
  const all = [...document.body.querySelectorAll('*')].filter(visible);
  const overflowing = all.filter(el => el.getBoundingClientRect().right > W + 1 && !inXScroller(el)).map(desc);
  const small = []; let minFont = 99;
  for (const el of all) {
    const own = [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
    if (!own) continue;
    const f = parseFloat(getComputedStyle(el).fontSize); minFont = Math.min(minFont, f);
    if (f < 12) small.push(desc(el) + '@' + f);
  }
  // label[for] is excluded: its control is the target and is measured itself. A label
  // wrapping its control (a checkbox row) is the target and is measured.
  const targets = all.filter(el => el.matches('button, a[href], input:not([type=hidden]), select, textarea, label:not([for]), summary, [role=button], [onclick]'))
    .filter(el => el.tagName === 'LABEL' || !el.closest('label'));   // a control inside its label: the label is measured
  const tiny = targets.filter(el => { const r = el.getBoundingClientRect(); return r.width < 44 || r.height < 44; })
    .map(el => { const r = el.getBoundingClientRect(); return desc(el) + '@' + Math.round(r.width) + 'x' + Math.round(r.height); });
  return JSON.stringify({ innerWidth: W, scrollWidth: document.documentElement.scrollWidth,
    hOverflow: document.documentElement.scrollWidth > W + 1,
    overflowing: [...new Set(overflowing)].slice(0, 25), overflowingCount: overflowing.length,
    minFontPx: minFont, smallTextCount: small.length, smallTextSample: [...new Set(small)].slice(0, 12),
    touchTargets: targets.length, tinyTargets: tiny,
    pageHeight: document.documentElement.scrollHeight });
})()
"""

final class Runner: NSObject, WKNavigationDelegate {
  var queue = viewports
  let web: WKWebView
  let window: NSWindow
  var current: (String, CGFloat, CGFloat)?

  override init() {
    let cfg = WKWebViewConfiguration()
    cfg.websiteDataStore = .nonPersistent()
    web = WKWebView(frame: .zero, configuration: cfg)
    web.customUserAgent = "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    window = NSWindow(contentRect: NSRect(x: -20000, y: -20000, width: 100, height: 100),
                      styleMask: [.borderless], backing: .buffered, defer: false)
    window.contentView = web
    super.init()
    web.navigationDelegate = self
  }

  func next() {
    guard !queue.isEmpty else { NSApp.terminate(nil); return }
    current = queue.removeFirst()
    let (_, w, h) = current!
    window.setContentSize(NSSize(width: w, height: h))
    web.frame = NSRect(x: 0, y: 0, width: w, height: h)
    web.load(URLRequest(url: targetURL))
  }

  func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
    // let the page's own fetch() fallbacks and render functions settle
    DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) { self.measure() }
  }

  func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) { fail(error) }
  func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) { fail(error) }
  func fail(_ e: Error) {
    print("{\"viewport\":\"\(current!.0)\",\"error\":\"\(e.localizedDescription)\"}")
    next()
  }

  func measure() {
    let (name, w, h) = current!
    web.evaluateJavaScript(measureJS) { result, err in
      let json = (result as? String) ?? "{\"jsError\":\"\(err.map { "\($0)" } ?? "nil")\"}"
      print("{\"viewport\":\"\(name)\",\"size\":\"\(Int(w))x\(Int(h))\",\"m\":\(json)}")
      self.snapshot(name: name, w: w) { self.next() }
    }
  }

  func snapshot(name: String, w: CGFloat, done: @escaping () -> Void) {
    web.evaluateJavaScript("document.documentElement.scrollHeight") { r, _ in
      let fullH = min(CGFloat((r as? NSNumber)?.doubleValue ?? 1000), 12000)
      self.window.setContentSize(NSSize(width: w, height: fullH))
      self.web.frame = NSRect(x: 0, y: 0, width: w, height: fullH)
      DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
        let c = WKSnapshotConfiguration(); c.rect = NSRect(x: 0, y: 0, width: w, height: fullH)
        self.web.takeSnapshot(with: c) { img, _ in
          if let img = img, let tiff = img.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff),
             let png = rep.representation(using: .png, properties: [:]) {
            try? png.write(to: URL(fileURLWithPath: "\(outDir)/\(name).png"))
          }
          done()
        }
      }
    }
  }
}

let app = NSApplication.shared
app.setActivationPolicy(.prohibited)
let runner = Runner()
DispatchQueue.main.async { runner.next() }
DispatchQueue.main.asyncAfter(deadline: .now() + 180) { print("{\"error\":\"timeout\"}"); exit(3) }
app.run()
