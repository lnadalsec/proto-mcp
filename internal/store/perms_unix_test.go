//go:build unix

package store

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// SECURITY M-2: under an ordinary 0o022 umask, the database and the
// -wal / -shm sidecars SQLite creates during migration must all end up
// 0o600, and a directory Open creates 0o700. Before the fix only files
// that existed before the migrations were chmod'ed, so the sidecars
// kept 0o644.
//
// Not parallel: umask is process-wide.
func TestOpenSetsOwnerOnlyPerms(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })

	dir := filepath.Join(t.TempDir(), "protonmcp")
	path := filepath.Join(dir, "store.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// A write keeps the WAL in use; the files must stay owner-only.
	if err := s.UpsertMessage(context.Background(), Message{ID: "m1", ThreadID: "m1", Date: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", filepath.Base(p), err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s perms = %#o, want 0o600", filepath.Base(p), perm)
		}
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir perms = %#o, want 0o700", perm)
	}
}
