package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Anti-downgrade tests for the signature self-heal path. A valid
// Developer ID signature proves a binary is ours, not that it is the
// current release: every old (possibly vulnerable) release carries the
// same signature. These tests fake the signature check so the version
// floor logic can be exercised without a real signed binary.

type downgradeFixture struct {
	in      integrityInputs
	bin     string
	binHash string
}

// newDowngradeFixture lays out an app-support dir with an
// expected_sha256 that does NOT match the fake "running" binary, an
// optional accepted_version floor, and a signature check that always
// passes — i.e. the exact situation of a signed binary swapped in.
func newDowngradeFixture(t *testing.T, floor *string, version string) downgradeFixture {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "protonmcpd")
	if err := os.WriteFile(bin, []byte("signed build "+version), 0o755); err != nil {
		t.Fatal(err)
	}
	binHash, err := sha256File(bin)
	if err != nil {
		t.Fatal(err)
	}
	expectedPath := filepath.Join(dir, "expected_sha256")
	if err := os.WriteFile(expectedPath, []byte(strings.Repeat("e", 64)+"  "+bin+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	versionPath := filepath.Join(dir, acceptedVersionFile)
	if floor != nil {
		if err := os.WriteFile(versionPath, []byte(*floor), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return downgradeFixture{
		in: integrityInputs{
			expectedPath: expectedPath,
			versionPath:  versionPath,
			executable:   func() (string, error) { return bin, nil },
			version:      version,
			verifySig:    func(string) error { return nil },
		},
		bin:     bin,
		binHash: binHash,
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func strp(s string) *string { return &s }

func readTrim(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// TestSelfHealRefusesSignedDowngrade is the regression test for the
// finding: an older signed release swapped over the installed one must
// not be re-pinned.
func TestSelfHealRefusesSignedDowngrade(t *testing.T) {
	f := newDowngradeFixture(t, strp("1.4.0\n"), "1.3.9")
	err := verifyIntegrity(quietLogger(), f.in)
	if err == nil {
		t.Fatal("older signed binary was accepted by the self-heal; downgrade attack possible")
	}
	if !strings.Contains(err.Error(), "downgrade refused") {
		t.Errorf("unexpected error: %v", err)
	}
	// Neither record may move on a refusal.
	if got, _, _ := readExpectedSha256(f.in.expectedPath); got != strings.Repeat("e", 64) {
		t.Errorf("expected_sha256 was rewritten on a refused downgrade: %s", got)
	}
	if got := readTrim(t, f.in.versionPath); got != "1.4.0" {
		t.Errorf("accepted_version changed on a refused downgrade: %q", got)
	}
}

func TestSelfHealAcceptsUpgradeAndRaisesFloor(t *testing.T) {
	f := newDowngradeFixture(t, strp("1.4.0\n"), "1.10.0")
	if err := verifyIntegrity(quietLogger(), f.in); err != nil {
		t.Fatalf("signed upgrade refused: %v", err)
	}
	if got, _, _ := readExpectedSha256(f.in.expectedPath); got != f.binHash {
		t.Errorf("expected_sha256 not re-pinned: %s", got)
	}
	if got := readTrim(t, f.in.versionPath); got != "1.10.0" {
		t.Errorf("accepted_version = %q, want 1.10.0", got)
	}
}

func TestSelfHealAcceptsSameVersion(t *testing.T) {
	f := newDowngradeFixture(t, strp("1.4.0"), "1.4.0")
	if err := verifyIntegrity(quietLogger(), f.in); err != nil {
		t.Fatalf("re-signed build of the same release refused: %v", err)
	}
}

// TestSelfHealNoFloorAcceptsAndRecords keeps upgrades from installs
// that predate the floor working, and checks the floor gets created.
func TestSelfHealNoFloorAcceptsAndRecords(t *testing.T) {
	f := newDowngradeFixture(t, nil, "1.2.3")
	if err := verifyIntegrity(quietLogger(), f.in); err != nil {
		t.Fatalf("upgrade with no recorded floor refused: %v", err)
	}
	if got := readTrim(t, f.in.versionPath); got != "1.2.3" {
		t.Errorf("accepted_version = %q, want 1.2.3", got)
	}
	info, err := os.Stat(f.in.versionPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("accepted_version mode = %o, want 600", perm)
	}
}

// A corrupted floor must fail closed, or deleting/garbling it would be
// a one-step bypass of the downgrade check.
func TestSelfHealMalformedFloorRefuses(t *testing.T) {
	f := newDowngradeFixture(t, strp("garbage|\n"), "9.9.9")
	if err := verifyIntegrity(quietLogger(), f.in); err == nil {
		t.Fatal("malformed accepted_version was treated as no floor")
	}
}

func TestSelfHealUnversionedSignedBinaryRefusedWhenFloorExists(t *testing.T) {
	for _, v := range []string{"dev", "1.0.2-3-gabc1234", "1.0.2-dirty", ""} {
		t.Run(v, func(t *testing.T) {
			f := newDowngradeFixture(t, strp("1.0.0"), v)
			if err := verifyIntegrity(quietLogger(), f.in); err == nil {
				t.Fatalf("signed binary with non-release version %q accepted", v)
			}
		})
	}
}

// TestHashMatchRecordsFloorEvenIfLower: an operator who deliberately
// downgrades re-runs `protonmcp daemon install`, which re-pins the
// hash. That consent path must reset the floor, or the next signed
// patch release of the older line would be refused forever.
func TestHashMatchRecordsFloorEvenIfLower(t *testing.T) {
	f := newDowngradeFixture(t, strp("2.0.0"), "1.5.0")
	if err := rewriteExpectedSha256(f.in.expectedPath, f.binHash, f.bin); err != nil {
		t.Fatal(err)
	}
	f.in.verifySig = func(string) error {
		t.Fatal("signature check must not run when the hash matches")
		return nil
	}
	if err := verifyIntegrity(quietLogger(), f.in); err != nil {
		t.Fatalf("hash match refused: %v", err)
	}
	if got := readTrim(t, f.in.versionPath); got != "1.5.0" {
		t.Errorf("accepted_version = %q, want 1.5.0", got)
	}
}

// Source builds report "dev"; they must not poison the floor.
func TestHashMatchDoesNotRecordDevVersion(t *testing.T) {
	f := newDowngradeFixture(t, nil, "dev")
	if err := rewriteExpectedSha256(f.in.expectedPath, f.binHash, f.bin); err != nil {
		t.Fatal(err)
	}
	if err := verifyIntegrity(quietLogger(), f.in); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.in.versionPath); !os.IsNotExist(err) {
		t.Errorf("dev version was recorded as a floor (stat err=%v)", err)
	}
}

func TestParseReleaseVersion(t *testing.T) {
	good := map[string][3]int{
		"1.0.2":    {1, 0, 2},
		"v1.0.2":   {1, 0, 2},
		"10.20.30": {10, 20, 30},
		" 1.2.3\n": {1, 2, 3},
	}
	for in, want := range good {
		got, ok := parseReleaseVersion(in)
		if !ok || got != want {
			t.Errorf("parseReleaseVersion(%q) = %v,%v want %v", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "dev", "1.2", "1.2.3.4", "1.2.3-rc1", "1.0.2-3-gabc", "a.b.c", "1.2.3 x", "1234567890.0.0"} {
		if _, ok := parseReleaseVersion(in); ok {
			t.Errorf("parseReleaseVersion(%q) accepted a non-release version", in)
		}
	}
	a, _ := parseReleaseVersion("1.9.0")
	b, _ := parseReleaseVersion("1.10.0")
	if compareVersions(a, b) != -1 || compareVersions(b, a) != 1 || compareVersions(a, a) != 0 {
		t.Error("compareVersions must order numerically, not lexically")
	}
}
