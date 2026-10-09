package policy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestOverride(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // umask-proof
		t.Fatal(err)
	}
	return p
}

func TestLoosenings(t *testing.T) {
	base, err := parseDocument(defaultYAML)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		override string
		want     []string // substrings; empty = no loosening
	}{
		{"send allowed", "tools:\n  mail_send: {decision: allow}\n", []string{`"mail_send": prompt → allow`}},
		{"confirm dropped", "tools:\n  mail_send: {decision: prompt, ttl: \"0\"}\n", []string{`"mail_send": confirmation dialog removed`}},
		{"ttl raised", "tools:\n  mail_move: {decision: prompt, ttl: 1h}\n", []string{`"mail_move": approval reused for 1h0m0s instead of 5m0s`}},
		{"unknown tools allowed", "defaults: {decision: allow}\n", []string{"unknown tools: deny → allow"}},
		{"new tool allowed", "tools:\n  mail_delete_permanent: {decision: allow}\n", []string{`"mail_delete_permanent": deny → allow`}},
		{"tightening", "tools:\n  mail_read: {decision: prompt, ttl: 1m}\n  mail_move: {decision: deny}\n", nil},
		{"same as default", "tools:\n  mail_send: {decision: prompt, confirm: true, ttl: \"0\"}\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cand, _ := parseDocument(defaultYAML)
			e := &Engine{override: writeTestOverride(t, tc.override, 0o600)}
			if err := e.applyOverrideInto(&cand); err != nil {
				t.Fatal(err)
			}
			got := loosenings(base, cand)
			if len(tc.want) == 0 && len(got) != 0 {
				t.Fatalf("want no loosening, got %q", got)
			}
			all := strings.Join(got, "\n")
			for _, w := range tc.want {
				if !strings.Contains(all, w) {
					t.Errorf("missing %q in %q", w, got)
				}
			}
		})
	}
}

func TestNewGated_RefusedLooseningKeepsDefaults(t *testing.T) {
	p := writeTestOverride(t, "tools:\n  mail_send: {decision: allow}\n", 0o600)
	var asked []string
	gate := func(changes []string) error { asked = changes; return errors.New("declined") }
	e, err := NewGated(context.Background(), p, nil, gate)
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) == 0 {
		t.Fatal("gate was not consulted")
	}
	if d, _ := e.Decide("mail_send", nil, Caller{}); d != DecisionPrompt {
		t.Fatalf("mail_send decision = %s, want prompt (override refused)", d)
	}
}

func TestReload_RefusedLooseningKeepsPrevious(t *testing.T) {
	p := writeTestOverride(t, "tools:\n  mail_read: {decision: deny}\n", 0o600)
	gate := func([]string) error { return errors.New("declined") }
	e, err := NewGated(context.Background(), p, nil, gate)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := e.Decide("mail_read", nil, Caller{}); d != DecisionDeny {
		t.Fatalf("tightening should apply without the gate, got %s", d)
	}
	if err := os.WriteFile(p, []byte("tools:\n  mail_send: {decision: allow}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(); err == nil {
		t.Fatal("Reload accepted a refused loosening")
	}
	if d, _ := e.Decide("mail_send", nil, Caller{}); d != DecisionPrompt {
		t.Fatalf("mail_send = %s after refused reload, want prompt", d)
	}
	if d, _ := e.Decide("mail_read", nil, Caller{}); d != DecisionDeny {
		t.Fatalf("previous policy lost after refused reload: mail_read = %s", d)
	}
}

func TestNewGated_ApprovedLooseningApplies(t *testing.T) {
	p := writeTestOverride(t, "tools:\n  mail_move: {decision: allow}\n", 0o600)
	e, err := NewGated(context.Background(), p, nil, func([]string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := e.Decide("mail_move", nil, Caller{}); d != DecisionAllow {
		t.Fatalf("approved override not applied: %s", d)
	}
}

func TestOverride_GroupWritableIsRefused(t *testing.T) {
	p := writeTestOverride(t, "tools:\n  mail_read: {decision: deny}\n", 0o664)
	e, err := New(context.Background(), p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := e.Decide("mail_read", nil, Caller{}); d != DecisionAllow {
		t.Fatalf("group-writable override was applied (mail_read = %s)", d)
	}
}
