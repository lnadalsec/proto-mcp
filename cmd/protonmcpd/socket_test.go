package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shortTempDir returns a temp dir short enough for a Unix socket path
// (sun_path is 104 bytes on macOS; t.TempDir() under /var/folders is
// often too long).
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "pmcpd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func TestResolveSocketPathOverrideCreatesPrivateDir(t *testing.T) {
	base := shortTempDir(t)
	sock := filepath.Join(base, "sub", "d.sock")

	got, err := resolveSocketPath(sock)
	if err != nil {
		t.Fatalf("resolveSocketPath: %v", err)
	}
	if got != sock {
		t.Errorf("path = %q, want %q", got, sock)
	}
	info, err := os.Stat(filepath.Join(base, "sub"))
	if err != nil {
		t.Fatalf("socket dir not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("socket dir mode = %#o, want 0700", perm)
	}
}

func TestResolveSocketPathOverrideRefusesOpenDir(t *testing.T) {
	base := shortTempDir(t)
	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil { // umask-proof
		t.Fatal(err)
	}
	_, err := resolveSocketPath(filepath.Join(open, "d.sock"))
	if err == nil || !strings.Contains(err.Error(), "group/other") {
		t.Fatalf("want refusal for a 0755 socket dir, got %v", err)
	}
	// A user-chosen directory must not be silently chmodded.
	info, _ := os.Stat(open)
	if perm := info.Mode().Perm(); perm != 0o755 {
		t.Errorf("override dir mode changed to %#o", perm)
	}
}

func TestEnsurePrivateSocketDirRefusesSymlink(t *testing.T) {
	base := shortTempDir(t)
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateSocketDir(link, true); err == nil {
		t.Fatal("symlinked socket dir must be refused")
	}
}

func TestEnsurePrivateSocketDirTightensOwnDir(t *testing.T) {
	base := shortTempDir(t)
	dir := filepath.Join(base, "app")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateSocketDir(dir, true); err != nil {
		t.Fatalf("ensurePrivateSocketDir: %v", err)
	}
	info, _ := os.Stat(dir)
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("mode = %#o, want 0700 after tightening", perm)
	}
}

func TestOpenSocketMode0600(t *testing.T) {
	base := shortTempDir(t)
	sock := filepath.Join(base, "d.sock")
	l, err := openSocket(sock)
	if err != nil {
		t.Fatalf("openSocket: %v", err)
	}
	defer l.Close()
	info, err := os.Lstat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s is not a socket", sock)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket mode = %#o, want 0600", perm)
	}
}
