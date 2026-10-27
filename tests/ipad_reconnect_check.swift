// tests/ipad_reconnect_check.swift -- drives one dashboard page in WebKit
// through a scripted scenario. Invoked by tests/ipad_reconnect_test.sh.
//
//   swift tests/ipad_reconnect_check.swift URL STEP [STEP ...]
//
// Steps run in order after the page has loaded:
//   wait:SECONDS   let timers, fetches and renders settle
//   js:CODE        evaluate CODE in the page; its string result is printed
//                  as one line "RESULT <result>"
//   sh:COMMAND     run COMMAND with /bin/sh (the test uses this to stop and
//                  restart its own server, simulating a dropped SSH forward)
// Exit 0 when every step ran; the shell test asserts on the RESULT lines.

import Cocoa
import WebKit

let argv = CommandLine.arguments
guard argv.count >= 3, let startURL = URL(string: argv[1]) else {
  FileHandle.standardError.write("usage: ipad_reconnect_check.swift URL STEP...\n".data(using: .utf8)!)
  exit(2)
}
let pageURL: URL = startURL
let scriptSteps = Array(argv[2...])

final class Scenario: NSObject, WKNavigationDelegate {
  let web: WKWebView
  let window: NSWindow
  var steps = scriptSteps

  override init() {
    let cfg = WKWebViewConfiguration()
    cfg.websiteDataStore = .nonPersistent()
    web = WKWebView(frame: NSRect(x: 0, y: 0, width: 834, height: 1194), configuration: cfg)
    web.customUserAgent = "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    window = NSWindow(contentRect: NSRect(x: -20000, y: -20000, width: 834, height: 1194),
                      styleMask: [.borderless], backing: .buffered, defer: false)
    window.contentView = web
    super.init()
    web.navigationDelegate = self
  }

  func start() { web.load(URLRequest(url: pageURL)) }

  func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { next() }
  func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
    print("ERROR load: \(error.localizedDescription)"); exit(3)
  }

  func next() {
    guard !steps.isEmpty else { exit(0) }
    let step = steps.removeFirst()
    if step.hasPrefix("wait:") {
      let s = Double(step.dropFirst(5)) ?? 1
      DispatchQueue.main.asyncAfter(deadline: .now() + s) { self.next() }
    } else if step.hasPrefix("js:") {
      web.evaluateJavaScript(String(step.dropFirst(3))) { r, e in
        if let e = e { print("RESULT ERROR \(e)") } else { print("RESULT \(r.map { "\($0)" } ?? "null")") }
        self.next()
      }
    } else if step.hasPrefix("sh:") {
      let p = Process()
      p.executableURL = URL(fileURLWithPath: "/bin/sh")
      p.arguments = ["-c", String(step.dropFirst(3))]
      do { try p.run(); p.waitUntilExit() } catch { print("ERROR sh: \(error)") }
      next()
    } else {
      print("ERROR unknown step: \(step)"); exit(2)
    }
  }
}

let app = NSApplication.shared
app.setActivationPolicy(.prohibited)
let scenario = Scenario()
DispatchQueue.main.async { scenario.start() }
DispatchQueue.main.asyncAfter(deadline: .now() + 120) { print("ERROR timeout"); exit(3) }
app.run()
