package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// resumeLockTimeout caps how long TryResume waits for another process
// (CLI vs daemon) to finish its own resume. A resume is a couple of
// HTTP round-trips; past this, something is wedged and we proceed
// unserialized — the post-failure keystore re-read in TryResume still
// prevents wiping tokens another process just saved.
const resumeLockTimeout = 30 * time.Second

// resumeLockPoll is the retry interval while the lock is held elsewhere.
const resumeLockPoll = 50 * time.Millisecond

// resumeLockPath is where the cross-process resume lock lives. A
// package var so tests can point it at a temp dir.
var resumeLockPath = func() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, "Library", "Application Support", "protonmcp", "resume.lock"), nil
}

// lockResume takes an exclusive flock(2) on the resume lock file so
// only one process at a time turns the stored refresh token into a
// live session (and persists any rotation). Proton refresh tokens are
// single-use: two processes resuming concurrently from the same blob
// means one of them burns the token under the other, which used to
// end with the loser wiping the Keychain entry the winner had just
// saved.
//
// flock is advisory and tied to the open file description, so it is
// released automatically if the process dies — no stale-lock cleanup.
// The returned func releases the lock.
func lockResume(ctx context.Context) (func(), error) {
	path, err := resumeLockPath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("resume lock dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open resume lock: %w", err)
	}
	fd := int(f.Fd()) // #nosec G115 -- a file descriptor always fits in int

	ctx, cancel := context.WithTimeout(ctx, resumeLockTimeout)
	defer cancel()
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(fd, syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			_ = f.Close()
			return nil, fmt.Errorf("flock resume lock: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("waiting for resume lock: %w", ctx.Err())
		case <-time.After(resumeLockPoll):
		}
	}
}
