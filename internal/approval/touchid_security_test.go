package approval

// Helper trust checks (SECURITY D4 / PROTO-127) not already covered by
// path_safety_test.go.
//
// Known gap, kept documented here: the production-mode refusal of
// PROTONMCP_TOUCHID can't be unit-tested directly — testing.Testing()
// is true for the whole `go test` run, and driving cmd/protonmcp far
// enough to reach ResolveHelperPath needs a Keychain. The gate is a
// few lines at the top of resolveHelperPath in path.go with an error
// message naming SECURITY D4; removing it is a reviewable change.

import (
	"os"
	"path/filepath"
	"testing"
)

func writeHelper(t *testing.T, dir string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, "protonmcp-touchid")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // umask-proof
		t.Fatal(err)
	}
	return p
}

func TestIsExecutable(t *testing.T) {
	dir := t.TempDir()
	if isExecutable(dir) {
		t.Error("a directory must not count as an executable helper")
	}
	if isExecutable(filepath.Join(dir, "missing")) {
		t.Error("a missing path must not count as executable")
	}
	p := writeHelper(t, dir, 0o644)
	if isExecutable(p) {
		t.Error("a 0644 file must not count as executable")
	}
	if err := os.Chmod(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if !isExecutable(p) {
		t.Error("a 0700 file should count as executable")
	}
}

// PROTO-127: the Homebrew case — a group-writable (0775) directory
// such as an admin-group /usr/local/bin is just as much a substitution
// vector as a world-writable one.
func TestOwnerWritableOnlyRejectsGroupWritable(t *testing.T) {
	dir := t.TempDir()
	p := writeHelper(t, dir, 0o755)
	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatal(err)
	}
	if ownerWritableOnly(p) {
		t.Error("a helper in a group-writable directory must be rejected")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o775); err != nil {
		t.Fatal(err)
	}
	if ownerWritableOnly(p) {
		t.Error("a group-writable helper file must be rejected")
	}
	if ownerWritableOnly(filepath.Join(dir, "missing")) {
		t.Error("a missing helper must not be trusted")
	}
}

// A helper that is owner-writable-only but NOT executable is skipped:
// both checks must pass for a candidate to be returned.
func TestResolveHelperPathRequiresExecutable(t *testing.T) {
	dir := t.TempDir()
	p := writeHelper(t, dir, 0o644)
	t.Setenv("PROTONMCP_TOUCHID", p)
	if got, _ := resolveHelperPath(""); got == p {
		t.Errorf("resolveHelperPath returned a non-executable helper: %q", got)
	}
}
