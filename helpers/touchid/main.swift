// protonmcp-touchid — single-prompt Touch ID helper for proto-mcp.
//
// Spec:
//   - Read one JSON object from stdin (single line or multi-line).
//   - If `confirm` is true, show an NSAlert FIRST: `title` as the
//     headline and the full literal `body` (+ caller) in a scrollable,
//     selectable text view, with Continue / Cancel. Cancel (or Esc)
//     exits 1 without ever reaching Touch ID.
//   - Run LAContext.evaluatePolicy(.deviceOwnerAuthentication) with
//     the body text (plus caller info, when present) as the
//     localizedReason.
//   - Exit 0 on biometric/password success, 1 on deny/cancel/
//     auth-fail, 2 on stdin parse error.
//
// Why the alert exists when confirm is set: the Touch ID sheet
// renders localizedReason in a small, truncating label — long
// recipient lists or subjects get cut off, so the user would be
// approving details they cannot fully see. internal/policy's
// default.yaml promises that confirm:true shows the literal operation
// details before Touch ID; an earlier version of this helper had
// collapsed that into the biometric prompt and silently ignored both
// `confirm` and `title`.
//
// Distribution: ad-hoc signed by swiftc on the dev machine. Phase 7
// adds Developer ID signing + notarization + NSFaceIDUsageDescription
// in an Info.plist when we bundle this as a .app.

import AppKit
import Foundation
import LocalAuthentication

struct Request: Codable {
    let title: String
    let body: String
    let caller: String?
    let confirm: Bool?
}

let data = FileHandle.standardInput.readDataToEndOfFile()
guard let req = try? JSONDecoder().decode(Request.self, from: data) else {
    FileHandle.standardError.write(Data("malformed stdin\n".utf8))
    exit(2)
}

// D30 (Phase 7/A): use .deviceOwnerAuthentication instead of
// .deviceOwnerAuthenticationWithBiometrics so the system falls back
// to the user's login password when biometric hardware is missing
// or disabled (Mac Mini, a Mac with a broken Touch ID sensor, Screen
// Sharing). Without this fallback, every prompted tool was simply
// inoperable on those Macs. Touch ID still runs FIRST on hardware
// that has it.
let ctx = LAContext()
var laError: NSError?
guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &laError) else {
    // Neither biometric NOR password available — extremely rare
    // (only happens with no user account configured for the local
    // session). Treat as deny.
    FileHandle.standardError.write(Data("authentication not available: \(laError?.localizedDescription ?? "unknown")\n".utf8))
    exit(1)
}

// Compose the reason text. macOS's Touch ID dialog renders this
// just below the lock icon; multi-line is supported but kept short.
// Caller info appended on a final line so the user can see which
// process is asking.
var reason = req.body
if let caller = req.caller, !caller.isEmpty {
    reason += "\n\nRequested by: \(caller)"
}

// confirmWithAlert shows the literal request in a modal NSAlert and
// returns true only if the user explicitly clicks Continue.
//
// The body goes into a read-only, selectable NSTextView inside a
// scroll view rather than informativeText: informativeText grows the
// alert without bound and a long recipient list would push the
// buttons off-screen, while a fixed-height scroll view keeps every
// byte reachable. The text view is not editable, so what the user
// reads is exactly what the daemon sent.
func confirmWithAlert(title: String, details: String) -> Bool {
    let app = NSApplication.shared
    // No Dock icon / menu bar, but allowed to own a key window.
    app.setActivationPolicy(.accessory)
    app.activate(ignoringOtherApps: true)

    let alert = NSAlert()
    alert.alertStyle = .warning
    alert.messageText = title.isEmpty ? "proto-mcp approval" : title
    alert.informativeText = "Review the details below. Touch ID (or your password) is requested next."

    let width: CGFloat = 460
    let textView = NSTextView(frame: NSRect(x: 0, y: 0, width: width, height: 10))
    textView.isEditable = false
    textView.isSelectable = true
    textView.isRichText = false
    textView.drawsBackground = false
    textView.font = NSFont.monospacedSystemFont(ofSize: NSFont.smallSystemFontSize, weight: .regular)
    textView.textContainerInset = NSSize(width: 4, height: 4)
    textView.isVerticallyResizable = true
    textView.isHorizontallyResizable = false
    textView.autoresizingMask = [.width]
    textView.textContainer?.widthTracksTextView = true
    textView.textContainer?.containerSize = NSSize(width: width, height: .greatestFiniteMagnitude)
    textView.string = details

    // Size to content, capped so long bodies scroll instead of growing
    // the alert past the screen.
    var height: CGFloat = 60
    if let container = textView.textContainer, let layout = textView.layoutManager {
        layout.ensureLayout(for: container)
        height = layout.usedRect(for: container).height + 2 * textView.textContainerInset.height
    }
    height = min(max(height, 60), 280)

    let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: width, height: height))
    scroll.hasVerticalScroller = true
    scroll.hasHorizontalScroller = false
    scroll.autohidesScrollers = true
    scroll.borderType = .bezelBorder
    scroll.documentView = textView
    alert.accessoryView = scroll

    // First button is the default (Return). Cancel answers Esc.
    alert.addButton(withTitle: "Continue")
    let cancel = alert.addButton(withTitle: "Cancel")
    cancel.keyEquivalent = "\u{1b}"

    alert.window.level = .modalPanel
    return alert.runModal() == .alertFirstButtonReturn
}

if req.confirm == true {
    guard confirmWithAlert(title: req.title, details: reason) else {
        FileHandle.standardError.write(Data("declined at confirmation dialog\n".utf8))
        exit(1)
    }
}

let sem = DispatchSemaphore(value: 0)
var ok = false
ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, evalErr in
    ok = success
    if !success, let e = evalErr {
        FileHandle.standardError.write(Data("evaluatePolicy: \(e.localizedDescription)\n".utf8))
    }
    sem.signal()
}
sem.wait()
exit(ok ? 0 : 1)
