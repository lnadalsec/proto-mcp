package policy

import (
	"fmt"
	"sort"
	"strconv"
)

// LoosenGate is asked to approve an override that is more permissive
// than the embedded default. changes lists each loosening in plain
// words. A non-nil error refuses the override.
//
// The override file is writable by anything running as the user —
// including an MCP client with a shell, i.e. the very party the
// consent prompts exist to check. Without the gate, writing
// `mail_send: {decision: allow}` and sending SIGHUP would turn every
// later send into a silent one.
type LoosenGate func(changes []string) error

var decisionRank = map[Decision]int{
	DecisionAllow:  0,
	DecisionPrompt: 1,
	DecisionDeny:   2,
}

// loosenings lists every way cand is more permissive than base.
// Tightenings are not reported: they need no consent.
func loosenings(base, cand document) []string {
	var out []string

	baseDefault := base.Defaults.Decision
	if baseDefault == "" {
		baseDefault = DecisionDeny
	}
	candDefault := cand.Defaults.Decision
	if candDefault == "" {
		candDefault = DecisionDeny
	}
	if decisionRank[candDefault] < decisionRank[baseDefault] {
		out = append(out, fmt.Sprintf("unknown tools: %s → %s", baseDefault, candDefault))
	}

	names := make([]string, 0, len(cand.Tools))
	for name := range cand.Tools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		c := cand.Tools[name]
		b, known := base.Tools[name]
		if !known {
			b = ToolPolicy{Decision: baseDefault}
		}
		q := strconv.Quote(name)
		if decisionRank[c.Decision] < decisionRank[b.Decision] {
			out = append(out, fmt.Sprintf("%s: %s → %s", q, b.Decision, c.Decision))
		}
		// The remaining fields only compare prompt with prompt: moving
		// from allow to prompt is a tightening whatever its TTL, and
		// leaving prompt is already reported above.
		if c.Decision != DecisionPrompt || b.Decision != DecisionPrompt {
			continue
		}
		if b.Confirm && !c.Confirm {
			out = append(out, fmt.Sprintf("%s: confirmation dialog removed", q))
		}
		if c.TTLDuration() > b.TTLDuration() {
			out = append(out, fmt.Sprintf("%s: approval reused for %s instead of %s",
				q, c.TTLDuration(), b.TTLDuration()))
		}
		if len(b.AllowedRecipients) > 0 && !subset(c.AllowedRecipients, b.AllowedRecipients) {
			out = append(out, fmt.Sprintf("%s: recipient allowlist widened", q))
		}
	}

	if base.IdleLockMinutes > 0 && (cand.IdleLockMinutes == 0 || cand.IdleLockMinutes > base.IdleLockMinutes) {
		if cand.IdleLockMinutes == 0 {
			out = append(out, "idle auto-lock disabled")
		} else {
			out = append(out, fmt.Sprintf("idle auto-lock after %d min instead of %d",
				cand.IdleLockMinutes, base.IdleLockMinutes))
		}
	}
	return out
}

// subset reports whether every entry of a is in b. An empty a means
// "no restriction" for allowed_recipients, so it is never a subset of
// a non-empty b.
func subset(a, b []string) bool {
	if len(a) == 0 {
		return len(b) == 0
	}
	in := make(map[string]bool, len(b))
	for _, s := range b {
		in[s] = true
	}
	for _, s := range a {
		if !in[s] {
			return false
		}
	}
	return true
}

// Loosenings reports every way the override at overridePath is more
// permissive than the embedded default — exactly the list a gated
// engine (the daemon, NewGated with its Touch ID gate) asks the user
// to approve when it loads the override. If that approval is refused,
// the daemon keeps the defaults for the whole override, so display
// tools (`protonmcp policy show`) must not present these entries as
// simply "in force".
//
// Returns nil when there is no override, the file does not exist, or
// it only tightens the defaults. An override that cannot be applied at
// all (unreadable, invalid YAML, group/other-writable) returns an
// error: the daemon would ignore it and run the defaults.
func Loosenings(overridePath string) ([]string, error) {
	if overridePath == "" {
		return nil, nil
	}
	base, err := parseDocument(defaultYAML)
	if err != nil {
		return nil, fmt.Errorf("parse embedded default policy: %w", err)
	}
	cand, err := parseDocument(defaultYAML)
	if err != nil {
		return nil, fmt.Errorf("parse embedded default policy: %w", err)
	}
	e := &Engine{override: overridePath}
	if err := e.applyOverrideInto(&cand); err != nil {
		return nil, err
	}
	return loosenings(base, cand), nil
}
