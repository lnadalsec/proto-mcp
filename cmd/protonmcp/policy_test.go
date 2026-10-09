package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeOverride(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// `policy show` used to present a loosening override as in force even
// though the daemon only applies it after a Touch ID approval (and
// runs the defaults if refused). It must flag those entries.
func TestPolicyShowFlagsLoosenings(t *testing.T) {
	p := writeOverride(t, "tools:\n  mail_send: {decision: allow}\n")
	var out bytes.Buffer
	if err := writePolicyShow(context.Background(), &out, p); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "LOOSENS the default policy") {
		t.Fatalf("no loosening warning in output:\n%s", s)
	}
	if !strings.Contains(s, `#   - "mail_send": prompt → allow`) {
		t.Errorf("loosened entry not listed:\n%s", s)
	}
	if !strings.Contains(s, "Touch ID") {
		t.Errorf("output doesn't say approval is required:\n%s", s)
	}
}

func TestPolicyShowNoWarningForTightening(t *testing.T) {
	p := writeOverride(t, "tools:\n  mail_read: {decision: deny}\n")
	var out bytes.Buffer
	if err := writePolicyShow(context.Background(), &out, p); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(out.String(), "#") {
		t.Errorf("tightening-only override should print no header:\n%s", out.String())
	}
}
