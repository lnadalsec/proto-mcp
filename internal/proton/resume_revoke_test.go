package proton

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// fakeProton is a minimal stand-in for the Proton API: the handler
// decides GET /core/v4/users and POST /auth/v4/refresh responses and
// the fake records whether DELETE /auth/v4 (server-side revoke) ran.
type fakeProton struct {
	mu        sync.Mutex
	revoked   int
	userCalls int
	users     func(call int) (int, string)
	refresh   func() (int, string)
}

func (f *fakeProton) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodDelete && r.URL.Path == "/auth/v4":
		f.revoked++
		_, _ = w.Write([]byte(`{"Code":1000}`))
	case r.Method == http.MethodGet && r.URL.Path == "/core/v4/users":
		f.userCalls++
		code, body := f.users(f.userCalls)
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	case r.Method == http.MethodPost && r.URL.Path == "/auth/v4/refresh" && f.refresh != nil:
		code, body := f.refresh()
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"Code":2501,"Error":"not found"}`))
	}
}

func (f *fakeProton) revokes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revoked
}

func resumeAgainst(t *testing.T, f *fakeProton, onAuth func(uid, acc, ref string)) error {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	mgr := gpa.New(gpa.WithHostURL(srv.URL), gpa.WithRetryCount(0))
	t.Cleanup(mgr.Close)
	pass := secret.New([]byte("salted-key-pass-32-bytes-long!!!"))
	defer pass.Zero()
	_, err := Resume(context.Background(), mgr, ResumeArgs{
		Email:         "me@proton.me",
		UID:           "uid-1",
		AccessToken:   "acc-1",
		RefreshToken:  "ref-1",
		SaltedKeyPass: pass,
		OnAuthUpdate:  onAuth,
	})
	if err == nil {
		t.Fatal("Resume unexpectedly succeeded against the fake")
	}
	return err
}

const (
	body503 = `{"Code":503,"Error":"service unavailable"}`
	body429 = `{"Code":2028,"Error":"too many requests"}`
	body401 = `{"Code":401,"Error":"invalid access token"}`
	body422 = `{"Code":10013,"Error":"Invalid refresh token"}`
)

// A transient failure (5xx / 429) must neither revoke the session
// server-side nor be reported as an expired session (which would make
// session.TryResume wipe the Keychain).
func TestResumeTransientErrorDoesNotRevoke(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
	}{
		{"503", http.StatusServiceUnavailable, body503},
		{"500", http.StatusInternalServerError, body503},
		{"429", http.StatusTooManyRequests, body429},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeProton{users: func(int) (int, string) { return tc.code, tc.body }}
			err := resumeAgainst(t, f, nil)
			if errors.Is(err, ErrSessionExpired) {
				t.Errorf("transient %s mapped to ErrSessionExpired: %v", tc.name, err)
			}
			if n := f.revokes(); n != 0 {
				t.Errorf("transient %s revoked the session server-side (%d DELETE /auth/v4)", tc.name, n)
			}
		})
	}
}

// A dead refresh token (401 → refresh 422) is a genuine auth error:
// ErrSessionExpired, and the best-effort revoke is allowed.
func TestResumeDeadRefreshTokenIsExpired(t *testing.T) {
	f := &fakeProton{
		users:   func(int) (int, string) { return http.StatusUnauthorized, body401 },
		refresh: func() (int, string) { return http.StatusUnprocessableEntity, body422 },
	}
	err := resumeAgainst(t, f, nil)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("want ErrSessionExpired, got %v", err)
	}
}

// Refresh succeeds (tokens rotated, old refresh token burned), then a
// transient error: the rotated tokens must reach OnAuthUpdate so the
// caller can persist them, and nothing is revoked.
func TestResumePersistsRotationBeforeTransientFailure(t *testing.T) {
	f := &fakeProton{
		users: func(call int) (int, string) {
			if call == 1 {
				return http.StatusUnauthorized, body401
			}
			return http.StatusServiceUnavailable, body503
		},
		refresh: func() (int, string) {
			return http.StatusOK, `{"Code":1000,"UID":"uid-1","AccessToken":"acc-2","RefreshToken":"ref-2","Scope":"full"}`
		},
	}
	var gotAcc, gotRef string
	err := resumeAgainst(t, f, func(_, acc, ref string) { gotAcc, gotRef = acc, ref })
	if errors.Is(err, ErrSessionExpired) {
		t.Errorf("transient failure after refresh mapped to ErrSessionExpired: %v", err)
	}
	if gotAcc != "acc-2" || gotRef != "ref-2" {
		t.Errorf("OnAuthUpdate got (%q, %q), want rotated (acc-2, ref-2)", gotAcc, gotRef)
	}
	if n := f.revokes(); n != 0 {
		t.Errorf("revoked a valid, freshly rotated session (%d DELETE /auth/v4)", n)
	}
}

func TestIsAuthExpiredStatus(t *testing.T) {
	for sc, want := range map[int]bool{
		400: true, 401: true, 422: true,
		403: false, 409: false, 429: false, 500: false, 502: false, 503: false,
	} {
		if got := isAuthExpiredStatus(sc); got != want {
			t.Errorf("isAuthExpiredStatus(%d) = %v, want %v", sc, got, want)
		}
	}
}
