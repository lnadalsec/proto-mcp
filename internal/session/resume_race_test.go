package session

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/lnadalsec/proto-mcp/internal/keystore"
	protonclient "github.com/lnadalsec/proto-mcp/internal/proton"
	"github.com/lnadalsec/proto-mcp/internal/secret"
)

// fakeKeychain is an in-memory stand-in for the Keychain entry.
type fakeKeychain struct {
	mu      sync.Mutex
	live    *keystore.Live
	deletes int
	// afterLoad, if set, runs after the n-th Load (1-based) — used to
	// simulate another process rotating the tokens mid-resume.
	afterLoad func(n int)
	loads     int
}

func (k *fakeKeychain) load() (keystore.Live, error) {
	k.mu.Lock()
	k.loads++
	n := k.loads
	var out keystore.Live
	found := k.live != nil
	if found {
		out = *k.live
		out.SaltedKeyPass = k.live.SaltedKeyPass.Clone()
	}
	hook := k.afterLoad
	k.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	if !found {
		return keystore.Live{}, keystore.ErrNotFound
	}
	return out, nil
}

func (k *fakeKeychain) save(l keystore.Live) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	cp := l
	cp.SaltedKeyPass = l.SaltedKeyPass.Clone()
	k.live = &cp
	return nil
}

func (k *fakeKeychain) delete() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.deletes++
	k.live = nil
	return nil
}

func (k *fakeKeychain) refreshToken() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.live == nil {
		return ""
	}
	return k.live.RefreshToken
}

func storedLive(ref string) *keystore.Live {
	return &keystore.Live{
		Email:         "me@proton.me",
		UID:           "uid-1",
		AccessToken:   "acc-" + ref,
		RefreshToken:  ref,
		SaltedKeyPass: secret.New([]byte("salted-key-pass-32-bytes-long!!!")),
	}
}

// installFakes swaps the package seams for the duration of the test.
func installFakes(t *testing.T, kc *fakeKeychain,
	resume func(ctx context.Context, mgr *gpa.Manager, args protonclient.ResumeArgs) (*protonclient.Session, error)) {
	t.Helper()
	oldLoad, oldSave, oldDelete, oldResume, oldLock := keystoreLoad, keystoreSave, keystoreDelete, resumeSession, resumeLockPath
	t.Cleanup(func() {
		keystoreLoad, keystoreSave, keystoreDelete, resumeSession, resumeLockPath = oldLoad, oldSave, oldDelete, oldResume, oldLock
	})
	lockFile := filepath.Join(t.TempDir(), "resume.lock")
	resumeLockPath = func() (string, error) { return lockFile, nil }
	keystoreLoad, keystoreSave, keystoreDelete = kc.load, kc.save, kc.delete
	resumeSession = resume
}

func expiredErr() error {
	return fmt.Errorf("%w: refresh 422", protonclient.ErrSessionExpired)
}

// Tokens genuinely dead and still the ones stored: the entry is wiped.
func TestTryResumeExpiredWipesUnchangedEntry(t *testing.T) {
	kc := &fakeKeychain{live: storedLive("ref-1")}
	installFakes(t, kc, func(context.Context, *gpa.Manager, protonclient.ResumeArgs) (*protonclient.Session, error) {
		return nil, expiredErr()
	})
	_, err := TryResume(context.Background())
	if !errors.Is(err, protonclient.ErrSessionExpired) {
		t.Fatalf("want ErrSessionExpired, got %v", err)
	}
	if kc.deletes != 1 {
		t.Errorf("deletes = %d, want 1", kc.deletes)
	}
}

// Another process rotated the tokens while we were resuming with the
// old ones (our refresh got 422 because the token was burned). We must
// NOT delete the winner's fresh tokens; we retry with them instead.
func TestTryResumeLostRaceKeepsWinnersTokens(t *testing.T) {
	kc := &fakeKeychain{live: storedLive("ref-1")}
	kc.afterLoad = func(n int) {
		if n == 1 { // winner saves ref-2 right after our first Load
			_ = kc.save(*storedLive("ref-2"))
		}
	}
	var seen []string
	installFakes(t, kc, func(_ context.Context, _ *gpa.Manager, args protonclient.ResumeArgs) (*protonclient.Session, error) {
		seen = append(seen, args.RefreshToken)
		if args.RefreshToken == "ref-1" {
			return nil, expiredErr()
		}
		return nil, errors.New("resume get user: 503") // transient; enough to observe the retry
	})
	_, err := TryResume(context.Background())
	if errors.Is(err, protonclient.ErrSessionExpired) {
		t.Errorf("lost race reported as expired: %v", err)
	}
	if kc.deletes != 0 {
		t.Errorf("loser wiped the winner's tokens (deletes = %d)", kc.deletes)
	}
	if got := kc.refreshToken(); got != "ref-2" {
		t.Errorf("stored refresh token = %q, want winner's ref-2", got)
	}
	if len(seen) != 2 || seen[0] != "ref-1" || seen[1] != "ref-2" {
		t.Errorf("resume attempts = %v, want [ref-1 ref-2]", seen)
	}
}

// A transient (non-auth) failure never touches the Keychain.
func TestTryResumeTransientErrorKeepsEntry(t *testing.T) {
	kc := &fakeKeychain{live: storedLive("ref-1")}
	installFakes(t, kc, func(context.Context, *gpa.Manager, protonclient.ResumeArgs) (*protonclient.Session, error) {
		return nil, errors.New("resume get user: 503 service unavailable")
	})
	if _, err := TryResume(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if kc.deletes != 0 || kc.refreshToken() != "ref-1" {
		t.Errorf("transient error touched the Keychain (deletes=%d, ref=%q)", kc.deletes, kc.refreshToken())
	}
}

// A token rotation that happens inside Resume is persisted even when
// Resume then fails transiently.
func TestTryResumePersistsRotationOnTransientFailure(t *testing.T) {
	kc := &fakeKeychain{live: storedLive("ref-1")}
	installFakes(t, kc, func(_ context.Context, _ *gpa.Manager, args protonclient.ResumeArgs) (*protonclient.Session, error) {
		args.OnAuthUpdate("uid-1", "acc-2", "ref-2") // SDK auto-refresh
		return nil, errors.New("resume get addresses: 503")
	})
	if _, err := TryResume(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if got := kc.refreshToken(); got != "ref-2" {
		t.Errorf("stored refresh token = %q, want rotated ref-2", got)
	}
}

// Resumes are serialized across processes: while another holder has
// the flock, TryResume waits and only then reads the Keychain.
func TestTryResumeWaitsForResumeLock(t *testing.T) {
	kc := &fakeKeychain{live: storedLive("ref-1")}
	installFakes(t, kc, func(context.Context, *gpa.Manager, protonclient.ResumeArgs) (*protonclient.Session, error) {
		return nil, errors.New("transient")
	})

	unlock, err := lockResume(context.Background()) // "the other process"
	if err != nil {
		t.Fatalf("lockResume: %v", err)
	}
	done := make(chan struct{})
	go func() {
		_, _ = TryResume(context.Background())
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("TryResume ran while another holder had the resume lock")
	case <-time.After(300 * time.Millisecond):
	}
	kc.mu.Lock()
	loads := kc.loads
	kc.mu.Unlock()
	if loads != 0 {
		t.Fatalf("Keychain read before the lock was acquired (loads = %d)", loads)
	}

	unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("TryResume did not proceed after the lock was released")
	}
}

func TestLockResumeHonorsContext(t *testing.T) {
	kc := &fakeKeychain{}
	installFakes(t, kc, nil)
	unlock, err := lockResume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := lockResume(ctx); err == nil {
		t.Fatal("second lockResume should fail once ctx expires")
	}
}
