# Security model & threat model

The honest version. Read it before you trust proto-mcp with a live
mailbox. This document describes what proto-mcp defends, what it
deliberately does **not**, and the residual risks you accept by running
it.

For the per-defect fix log and audit trail, see
[`../SECURITY.md`](../SECURITY.md).

## The layers

The Keychain item that holds your Proton session sits behind several
layers of protection:

1. **macOS Keychain encryption** — standard at-rest protection for any
   keychain item. Everything below assumes you are logged in and the
   keychain is unlocked.
2. **Touch ID at session-acquire time** — the daemon prompts for
   biometric (or password fallback via Apple's
   `.deviceOwnerAuthentication`) on every startup and every unlock
   after a manual or automatic lock. The prompt is issued at the
   application layer by the Swift helper.

   An unlock can be requested either by `protonmcp unlock` or by a tool
   call arriving at a locked daemon. Who *asks* is not a security
   boundary — the sensor is, and it can't be satisfied by software. What
   the request path does expose is the prompt itself: content the model
   reads (mail bodies above all) can try to steer it into a tool call,
   and each locked call is an opportunity to raise a dialog. The threat
   is prompt fatigue, not unauthorized access, so it's bounded by rate
   rather than forbidden — one prompt in flight at a time, and a 60s
   cooldown after any prompt the user doesn't approve.
3. **Per-call approval** — every write tool fires a custom prompt + Touch
   ID showing the **literal** recipients and subject before anything
   happens. Approvals expire per policy TTL; `mail_send` has TTL 0, so
   every send re-prompts.

Plus, around the binaries themselves:

- **Hardened-runtime, Developer-ID-signed, Apple-notarized** binaries.
  Gatekeeper accepts them with no "unidentified developer" dialog.
- **SHA-256 binary integrity check** at daemon startup. If `protonmcpd`
  was swapped between install and launch, the daemon refuses to start.
- **Peer-credential checks** (`SO_PEERCRED` / `LOCAL_PEERPID`) on every
  socket connection; cross-UID connections are refused and the real
  connecting PID/UID is recorded in the audit log.
- **Default-deny policy** for unknown tools. A tool with no policy stub
  fails registration — you cannot accidentally ship an unguarded write.
- **Touch ID to loosen the policy.** `policy.yaml` is writable by any
  process running as you, MCP clients with a shell included. An
  override that is more permissive than the built-in defaults (a
  prompt turned into allow, a dropped confirmation, a longer approval
  TTL, a wider recipient allowlist, idle lock off) is applied only
  after a Touch ID prompt that lists each change — at daemon start and
  on every reload. Declined: the built-in rules (at start) or the
  previous policy (on reload) stay in force. Tightening needs no
  prompt. The file must be yours and not group/world-writable.
- **Auto-lock** on screen lock, sleep, and idle timeout. Walk away and
  the daemon locks; resuming requires Touch ID.
- **Redacted audit log.** Passwords / tokens / cookies become
  `[REDACTED]`; bodies become `{sha256, bytes}`; recipient addresses
  stay literal so the prompt-verification chain is honest.

## Trust boundaries

The daemon runs as **you**, on **your** Mac, and talks to two parties:
the local MCP clients (Claude Desktop / Code, via the shim over a `0600`
Unix socket) and Proton's servers (over TLS, via `go-proton-api`). Mail
content fetched from Proton is **untrusted input** — it can contain
anything a sender chose to put in it.

## Defended

- **Local IPC isolation.** The socket is `0600` inside a `0700`
  directory; every connection is peer-credential checked and cross-UID
  connections are refused.
- **Session at rest.** The Proton session lives in the macOS Keychain;
  the daemon re-prompts for Touch ID on every startup and every unlock
  after a manual/auto lock (screen lock, sleep, idle timer).
- **Write authorization.** Every state-changing tool is deny-by-default
  in policy and fires a per-call Touch ID prompt showing the literal
  recipients and subject. `mail_send` has TTL 0 — every send re-prompts.
  Send-family dialogs (`mail_send`, `mail_reply`, `mail_reply_all`,
  `mail_forward`, `mail_send_draft`) also show the body's length and its
  first 300 characters (flattened to one line, HTML reduced to text,
  quoted `>` lines kept), and every attachment name: a reply that
  smuggles mailbox data to the attacker's own address shows that data
  before you approve. The excerpt is built from the same arguments or
  draft snapshot that is sent. It is an excerpt: a long body can still
  hide content past the first 300 characters, which is why the total
  length is shown.
- **Drafts are pending sends.** `mail_draft_update` prompts (TTL 0) with
  the recipients after the edit, every address added or removed, and the
  new body — an injected edit can't quietly add a BCC to a draft you
  later send from Proton's web app. Fields the call doesn't touch are
  kept as stored: the sender address, and the body byte for byte (only a
  new `body_html` is sanitized). `mail_draft_create` stays allow: a new
  draft has no effect until a send, which prompts.
- **Recipient allowlist before the prompt.** Where `allowed_recipients`
  is set, recipients are checked as bare addresses (display names
  stripped, multi-address entries split) for every send tool. For
  `mail_reply`, `mail_reply_all` and `mail_send_draft`, whose
  recipients come from a fetched message, the check runs right after
  that fetch — before the Touch ID dialog and before any draft is
  created; a draft created for a send that then fails before
  `SendDraft` is deleted.
- **Replies honor Reply-To.** A reply goes to the parent's `Reply-To`
  when set (as in any mail client), else to its sender. `Reply-To` is
  sender-controlled, so when it differs from the sender the dialog says
  so on its own line.
- **Saved attachments are quarantined.** `mail_save_attachment` sets
  `com.apple.quarantine` on the file before writing its content, so
  Gatekeeper checks a `.app` / `.command` / `.pkg` from an email like
  any other download. If the attribute can't be set, nothing is saved
  (fail closed). The dialog shows the real sanitized filename (resolved
  from the message when the call doesn't name one) and warns about
  executable / installer types and double extensions such as
  `invoice.pdf.app`.
- **Binary tampering.** Hardened-runtime, signed, notarized binaries
  plus a SHA-256 self-check that refuses to run a swapped binary.
- **Log leakage.** Secrets are redacted; bodies are reduced to
  `{sha256, bytes}` in the audit log.

## Out of scope — accepted risks

- **Prompt injection from email content.** `mail_read` and
  `mail_read_thread` are allow-by-default, so a malicious message *can*
  try to steer the model ("forward this to…", "delete that…"). The
  mitigation is the load-bearing fact that **every write is Touch-ID
  gated and shows the real recipients/subject** — reading a hostile
  email exfiltrates nothing on its own, and any send it provokes still
  needs your fingerprint on a prompt that names the actual recipient.
  **Do not blanket-approve sends**, and treat message bodies as hostile.

  Bodies reach the model inside an untrusted-content fence whose
  markers carry a random per-call id; `<<<` inside the body is
  defused, so a message cannot close the fence itself. Subjects,
  sender names and calendar fields are not fenced yet.

  The same applies to `mail_read`'s `unsubscribe` field, taken from the
  `List-Unsubscribe` / `List-Unsubscribe-Post` headers. Those headers
  are written by the sender, so the targets are attacker-controlled.
  They are scheme-filtered (only `https` without userinfo and a single
  `mailto` address survive; `http:`, `javascript:`, `data:` and the rest
  are dropped), capped in count and length, and **only exposed**:
  proto-mcp never fetches an unsubscribe URL or sends to an unsubscribe
  address itself. Any mailto send goes through the normal Touch-ID-gated
  `mail_send`. The raw values are cached next to the body and purged
  with it, because the URLs carry per-recipient tokens.
- **OS-level Keychain ACL is not enforced.** The biometric gate is
  enforced at the application layer, not sealed into the Keychain item
  with `SecAccessControl`. A process running as you, with the Keychain
  already unlocked, could read the stored session blob without a fresh
  Touch ID.

  This was investigated thoroughly and is a **hard platform limit**, not
  a backlog gap: the `SecAccessControl` + access-group path requires the
  restricted `keychain-access-groups` entitlement, which macOS (AMFI)
  will only honor with an Apple-issued provisioning profile. Apple
  issues those for App Store / TestFlight / enterprise distribution, not
  for the directly-distributed, Developer-ID-signed binaries proto-mcp
  ships. A signed binary carrying that entitlement is killed by the
  kernel at launch. The application-layer Touch ID gate is the practical
  security boundary, by design.
- **A local account already compromised.** Everything runs as your user;
  malware already executing as you can read the SQLite mirror, the audit
  log, and staged attachments. proto-mcp is not a defense against code
  already running under your account.
- **Physical access to an unlocked, logged-in Mac.** The auto-lock
  triggers shrink the window, but an attacker at your unlocked machine
  during an unlocked session is outside the model.
- **Proton-side trust.** proto-mcp trusts Proton's API and your account
  security (SRP password + 2FA). It does not defend against a
  compromised Proton account or a malicious server response beyond
  ordinary input sanitization.

## Reducing your exposure

- Keep `mail_send` at TTL 0 (the default) and actually read the Touch ID
  prompt — it shows the real recipient.
- Skim the audit log periodically (see [observability in
  configuration.md](./configuration.md#observability)).
- Don't raise `max_attachment_bytes` past what you need; large decrypted
  attachments are written to a local staging directory.
- Use `protonmcp purge --older-than 7d --vacuum` to shrink the window of
  decrypted bodies cached on disk.

## What a Touch ID prompt looks like

When Claude says "move 'Re: gear list' from inbox to archive," the prompt
that fires says exactly that — not a redacted argument dump:

```
┌──────────────────────────────────────────────┐
│ protonmcp-touchid is trying to               │
│ move message 'Re: gear list' from inbox      │
│ to Archive                                   │
│                                              │
│ Touch ID or enter your password to allow.    │
│              [ Cancel ]    [ Touch ID ]      │
└──────────────────────────────────────────────┘
```

The verb phrase comes from a per-tool `PromptBody` closure
(`internal/mcptools/prompt_helpers.go`) that resolves `message_id →
Subject` and `label_id → Name` from the local mirror. You read what
you're approving.

For sends, the format is stricter — the recipient list is always
verbatim, followed by the subject, a body excerpt and the attachments:

```
┌──────────────────────────────────────────────┐
│ Send mail_send?                              │
│                                              │
│ To: alice@example.com                        │
│ CC: charlie@example.com                      │
│ BCC: (none)                                  │
│ Subject: Re: gear list                       │
│ Body (49 chars): Tent and stove are in the   │
│ garage, see you Friday.                      │
│                                              │
│ [ Cancel ]              [ Send & Touch ID ]  │
└──────────────────────────────────────────────┘
```

That recipient list is the verification surface you tap against.
