package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for the symlink-preserving and concurrency-checked config
// write path used by install / uninstall.

// captureStdout runs fn with os.Stdout redirected and returns what it
// printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdout-*")
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = orig }()
	fn()
	_ = f.Close()
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func setRenameHook(t *testing.T, fn func(string)) {
	t.Helper()
	orig := beforeConfigRename
	beforeConfigRename = fn
	t.Cleanup(func() { beforeConfigRename = orig })
}

// dotfilesLayout makes home/.claude.json a symlink (relative or
// absolute) to dotfiles/claude.json, as dotfiles managers do.
func dotfilesLayout(t *testing.T, relative bool) (link, real string) {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	dots := filepath.Join(root, "dotfiles")
	for _, d := range []string{home, dots} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	real = filepath.Join(dots, "claude.json")
	if err := os.WriteFile(real, []byte(preserveFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	link = filepath.Join(home, ".claude.json")
	dest := real
	if relative {
		dest = filepath.Join("..", "dotfiles", "claude.json")
	}
	if err := os.Symlink(dest, link); err != nil {
		t.Fatal(err)
	}
	return link, real
}

func assertStillSymlink(t *testing.T, link, wantDest string) {
	t.Helper()
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s was replaced by a regular file; the dotfiles symlink is gone", link)
	}
	got, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if got != wantDest {
		t.Errorf("symlink now points at %q, want %q", got, wantDest)
	}
}

func TestInstallPreservesSymlinkedConfig(t *testing.T) {
	for _, relative := range []bool{false, true} {
		name := "absolute"
		if relative {
			name = "relative"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			link, real := dotfilesLayout(t, relative)
			dest, err := os.Readlink(link)
			if err != nil {
				t.Fatal(err)
			}

			captureStdout(t, func() {
				if err := installInto(tempTarget(link), "/opt/homebrew/bin/protonmcp-shim", nil, false); err != nil {
					t.Fatalf("installInto: %v", err)
				}
			})
			assertStillSymlink(t, link, dest)
			got := readJSONFile(t, real)
			if _, ok := got["mcpServers"].(map[string]any)["protonmcp"]; !ok {
				t.Error("install did not write through the symlink to the real file")
			}
			if got["theme"] == nil {
				t.Error("install lost the user's other top-level keys")
			}
			// No stray temp file next to the link or the target.
			for _, dir := range []string{filepath.Dir(link), filepath.Dir(real)} {
				matches, _ := filepath.Glob(filepath.Join(dir, ".*.json-*"))
				if len(matches) != 0 {
					t.Errorf("temp files left behind in %s: %v", dir, matches)
				}
			}

			captureStdout(t, func() {
				if err := uninstallFrom(tempTarget(link)); err != nil {
					t.Fatalf("uninstallFrom: %v", err)
				}
			})
			assertStillSymlink(t, link, dest)
			if _, ok := readJSONFile(t, real)["mcpServers"].(map[string]any)["protonmcp"]; ok {
				t.Error("uninstall did not write through the symlink")
			}
		})
	}
}

// A dangling symlink must not be silently replaced by a regular file.
func TestInstallRefusesDanglingSymlink(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	link := filepath.Join(dir, ".claude.json")
	if err := os.Symlink(filepath.Join(dir, "missing", "claude.json"), link); err != nil {
		t.Fatal(err)
	}
	err := installInto(tempTarget(link), "/x/protonmcp-shim", nil, false)
	if err == nil {
		t.Fatal("install over a dangling symlink succeeded")
	}
	info, lerr := os.Lstat(link)
	if lerr != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("dangling symlink was replaced (lstat err=%v)", lerr)
	}
}

// TestInstallRetriesWhenClientRewritesConfig simulates Claude Code
// rewriting ~/.claude.json between our read and our rename. The first
// attempt must notice and start over from the fresh contents, so the
// concurrent write survives alongside our entry.
func TestInstallRetriesWhenClientRewritesConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfgPath := filepath.Join(t.TempDir(), ".claude.json")
	if err := os.WriteFile(cfgPath, []byte(preserveFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	calls := 0
	setRenameHook(t, func(target string) {
		calls++
		if calls == 1 {
			if err := os.WriteFile(target, []byte(`{"concurrent":"client-write","theme":"dark"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	})

	captureStdout(t, func() {
		if err := installInto(tempTarget(cfgPath), "/x/protonmcp-shim", nil, false); err != nil {
			t.Fatalf("installInto: %v", err)
		}
	})
	if calls != 2 {
		t.Errorf("write attempts = %d, want 2 (one collision, one retry)", calls)
	}
	got := readJSONFile(t, cfgPath)
	if got["concurrent"] != "client-write" {
		t.Errorf("the client's concurrent write was clobbered: %#v", got)
	}
	if _, ok := got["mcpServers"].(map[string]any)["protonmcp"]; !ok {
		t.Errorf("our entry missing after retry: %#v", got)
	}
}

// When the client keeps rewriting, give up without replacing its file.
func TestInstallGivesUpWhenConfigKeepsChanging(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfgPath := filepath.Join(t.TempDir(), ".claude.json")
	if err := os.WriteFile(cfgPath, []byte(preserveFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	n := 0
	setRenameHook(t, func(target string) {
		n++
		body := `{"concurrent":` + strings.Repeat("1", n) + `}`
		if err := os.WriteFile(target, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	})

	err := installInto(tempTarget(cfgPath), "/x/protonmcp-shim", nil, false)
	if !errors.Is(err, errConfigChanged) {
		t.Fatalf("err = %v, want errConfigChanged", err)
	}
	if n != configWriteAttempts {
		t.Errorf("attempts = %d, want %d", n, configWriteAttempts)
	}
	got := readJSONFile(t, cfgPath)
	if _, ok := got["mcpServers"]; ok {
		t.Errorf("config was replaced despite the concurrent writer: %#v", got)
	}
	if matches, _ := filepath.Glob(filepath.Join(filepath.Dir(cfgPath), ".*.json-*")); len(matches) != 0 {
		t.Errorf("temp files left behind: %v", matches)
	}
}

func TestUninstallConcurrentRewriteRetries(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfgPath := filepath.Join(t.TempDir(), ".claude.json")
	if err := os.WriteFile(cfgPath, []byte(`{"mcpServers":{"protonmcp":{"command":"/x"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	setRenameHook(t, func(target string) {
		calls++
		if calls == 1 {
			body := `{"concurrent":true,"mcpServers":{"protonmcp":{"command":"/x"},"other":{"command":"/y"}}}`
			if err := os.WriteFile(target, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	})
	captureStdout(t, func() {
		if err := uninstallFrom(tempTarget(cfgPath)); err != nil {
			t.Fatalf("uninstallFrom: %v", err)
		}
	})
	got := readJSONFile(t, cfgPath)
	servers, _ := got["mcpServers"].(map[string]any)
	if got["concurrent"] != true || servers["other"] == nil || servers["protonmcp"] != nil {
		t.Errorf("uninstall retry result wrong: %#v", got)
	}
}

// TestUninstallMissingConfigReportsAbsent covers the formerly dead
// branch: loadClaudeDesktopConfig maps a missing file to an empty
// config, so the ErrNotExist check after it could never fire and the
// user was told "not registered" instead of "config does not exist".
// It must also not create the file.
func TestUninstallMissingConfigReportsAbsent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfgPath := filepath.Join(t.TempDir(), ".claude.json")
	out := captureStdout(t, func() {
		if err := uninstallFrom(tempTarget(cfgPath)); err != nil {
			t.Fatalf("uninstallFrom: %v", err)
		}
	})
	if !strings.Contains(out, "config does not exist") {
		t.Errorf("output = %q, want the missing-config message", out)
	}
	if _, err := os.Lstat(cfgPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("uninstall created %s (err=%v)", cfgPath, err)
	}
}
