// Package session is the non-interactive subset of session
// acquisition — the bits both `protonmcp serve-stdio` and the new
// `protonmcpd` daemon need.
//
// Interactive login (SRP + TOTP prompt) stays in cmd/protonmcp
// because it depends on internal/cli's /dev/tty prompts. The
// resume-from-Keychain path is what's shared here.
package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
)

// Bundle is everything a long-running subcommand needs to talk to
// Proton + clean up afterward.
type Bundle struct {
	Session *protonclient.Session
	Manager *gpa.Manager
	Jar     http.CookieJar
}

// Close releases the Manager. Use Bundle.Session.Close() (no server
// revoke) for normal exit; call Bundle.Session.CloseAndRevoke() before
// this only when explicitly logging out.
func (b *Bundle) Close() {
	if b.Manager != nil {
		b.Manager.Close()
	}
}

// GetSession satisfies internal/serve.SessionBundle so the Runtime
// setup can extract the bare *Session without internal/serve
// importing this package's containing main (which would be a cycle).
func (b *Bundle) GetSession() *protonclient.Session {
	return b.Session
}

// ErrLoginRequired marks session failures that no amount of retrying
// can fix — only a human running `protonmcp login` from a terminal
// can. D44: protonmcpd matches this with errors.Is and exits 0 so
// launchd (KeepAlive SuccessfulExit=false) leaves the daemon down
// instead of crash-looping a Touch ID prompt every ~10 seconds.
var ErrLoginRequired = errors.New("login required")

// loginRequired builds an error that both carries the human-facing
// remediation message and matches ErrLoginRequired via errors.Is.
func loginRequired(format string, args ...any) error {
	args = append([]any{ErrLoginRequired}, args...)
	return fmt.Errorf("%w: "+format, args...)
}

// noStoredSessionMsg is shared by CheckStored (pre-gate fast path)
// and AcquireResumeOnly (post-gate) so the operator sees the same
// remediation text regardless of which check caught it first.
const noStoredSessionMsg = "no stored Proton session — run `protonmcp login` from a terminal " +
	"before launching the MCP server (MCP can't prompt for credentials)"

// CheckStored fails fast — wrapped in ErrLoginRequired — when no
// session blob exists in the Keychain. The check is attributes-only
// (keystore.Exists), so it neither reads the secret payload nor
// warrants a Touch ID prompt. Callers run this BEFORE the startup
// gate in serve.Setup; that's the whole point (D43).
//
// A Keychain query error (as opposed to a clean "not found") returns
// nil: proceed and let the real Load inside TryResume surface it
// with full context after the gate.
func CheckStored() error {
	ok, err := keystore.Exists()
	if err != nil || ok {
		return nil
	}
	return loginRequired(noStoredSessionMsg)
}

// AcquireResumeOnly tries to rebuild a session from the Keychain
// blob alone. If that fails — for any reason — it returns a clear
// error instead of falling through to interactive prompts.
//
// Used by `protonmcp serve-stdio` and protonmcpd, both spawned by
// launchd / Claude Desktop with no controlling TTY. Falling through
// to a prompt in that environment fails opaquely; this returns a
// message that points the user at `protonmcp login` instead.
// Both failure branches match ErrLoginRequired (see above).
func AcquireResumeOnly(ctx context.Context) (*Bundle, error) {
	bundle, err := TryResume(ctx)
	if err != nil {
		if errors.Is(err, keystore.ErrNotFound) {
			return nil, loginRequired(noStoredSessionMsg)
		}
		return nil, loginRequired(
			"stored session unusable (%v) — run `protonmcp logout && protonmcp login` "+
				"from a terminal to refresh credentials", err)
	}
	return bundle, nil
}

// Keystore / Proton seams. Package vars so tests can substitute fakes
// for the Keychain and the network; production never reassigns them.
var (
	keystoreLoad   = keystore.Load
	keystoreSave   = keystore.Save
	keystoreDelete = keystore.Delete
	resumeSession  = protonclient.Resume
)

// TryResume opens an existing Keychain entry, rebuilds the jar +
// Manager, and calls Resume. Returns keystore.ErrNotFound when
// there's nothing to resume so callers can fall through to
// interactive login (which lives in cmd/protonmcp).
//
// Concurrency with other processes (daemon vs CLI sharing one
// Keychain entry):
//   - resumes are serialized by an flock (lockResume), so two
//     processes never spend the same single-use refresh token;
//   - an ErrSessionExpired only wipes the Keychain entry if the entry
//     STILL holds the tokens that just failed. If another process
//     rotated them meanwhile (e.g. the daemon's background refresh,
//     which is not under the lock), we retry once with the fresh
//     tokens instead of deleting them.
func TryResume(ctx context.Context) (*Bundle, error) {
	unlock, lerr := lockResume(ctx)
	if lerr != nil {
		if ctx.Err() != nil {
			return nil, lerr
		}
		slog.Warn("resume lock unavailable; resuming without cross-process serialization",
			"err", lerr.Error())
	} else {
		defer unlock()
	}

	for attempt := 0; ; attempt++ {
		stored, err := keystoreLoad()
		if err != nil {
			return nil, err
		}
		usedUID, usedRefresh := stored.UID, stored.RefreshToken
		bundle, err := resumeFromStored(ctx, &stored)
		stored.Zero()
		if err == nil {
			return bundle, nil
		}
		if !errors.Is(err, protonclient.ErrSessionExpired) {
			return nil, err
		}

		// Proton says the tokens are dead. Before wiping, make sure
		// they are still the ones in the Keychain.
		cur, cerr := keystoreLoad()
		if cerr != nil {
			// Already gone (another process logged out) or unreadable:
			// either way, don't delete what we can't see.
			return nil, err
		}
		rotated := cur.UID != usedUID || cur.RefreshToken != usedRefresh
		cur.Zero()
		if !rotated {
			_ = keystoreDelete()
			return nil, err
		}
		if attempt >= 1 {
			// Rotated under us twice in a row: leave the entry for its
			// owner rather than looping or deleting it.
			return nil, err
		}
		slog.Info("stored session was rotated by another process during resume; retrying with the new tokens")
	}
}

// resumeFromStored runs one Resume attempt from a loaded Keychain
// blob and, on success, persists the (possibly rotated) tokens and
// wires the keystore sync hook.
func resumeFromStored(ctx context.Context, stored *keystore.Live) (*Bundle, error) {
	jar := protonclient.NewCookieJar()
	protonclient.PreloadJar(jar, stored.Cookies)
	mgr := protonclient.NewManager(jar)

	// Persist a rotation that happens INSIDE Resume (auto-refresh on
	// an expired access token) right away: if a later step of Resume
	// fails transiently, the old refresh token is already burned and
	// the rotated pair would otherwise be lost.
	// SECURITY D10 / B-3: our own clone of the salted pass, zeroed when
	// this attempt is over; the caller zeroes stored.
	skp := stored.SaltedKeyPass.Clone()
	defer skp.Zero()
	email := stored.Email
	onRotate := func(uid, accessToken, refreshToken string) {
		if err := keystoreSave(keystore.Live{
			Email:         email,
			UID:           uid,
			AccessToken:   accessToken,
			RefreshToken:  refreshToken,
			SaltedKeyPass: skp,
			Cookies:       protonclient.JarCookies(jar),
		}); err != nil {
			slog.Warn("token rotation during resume not persisted", "err", err.Error())
		}
	}

	sess, err := resumeSession(ctx, mgr, protonclient.ResumeArgs{
		Email:         stored.Email,
		UID:           stored.UID,
		AccessToken:   stored.AccessToken,
		RefreshToken:  stored.RefreshToken,
		SaltedKeyPass: stored.SaltedKeyPass,
		OnAuthUpdate:  onRotate,
	})
	if err != nil {
		mgr.Close()
		return nil, err
	}

	bundle := &Bundle{Session: sess, Manager: mgr, Jar: jar}

	// Important: NewClientWithRefresh hands back rotated tokens but
	// does NOT fire the SDK's AuthHandler — that hook only triggers
	// on the auto-refresh-on-401 path inside the Client. Without an
	// explicit save here, the Keychain still holds the OLD refresh
	// token and the next process hits 400 / 422 on its own resume.
	if err := Persist(bundle); err != nil {
		slog.Warn("failed to update Keychain with rotated tokens", "err", err.Error())
	}

	WireKeystoreSync(bundle)
	return bundle, nil
}

// Persist writes the session's resumable fields (tokens, salted
// pass, cookies) to the Keychain. Called at first-login time and
// immediately after a successful Resume — Resume's refresh response
// carries rotated tokens that must replace the stored ones.
func Persist(b *Bundle) error {
	access, refresh := b.Session.Tokens()
	// D16: serialize a private clone, never the live SaltedKeyPass — a
	// concurrent Session.Close() zeroes the shared backing array and
	// would corrupt the marshaled bytes. SaltedKeyPassCopy takes the
	// copy under authMu; we own it and zero it when done.
	skp := b.Session.SaltedKeyPassCopy()
	defer skp.Zero()
	return keystoreSave(keystore.Live{
		Email:         b.Session.Email,
		UID:           b.Session.UID,
		AccessToken:   access,
		RefreshToken:  refresh,
		SaltedKeyPass: skp,
		Cookies:       protonclient.JarCookies(b.Jar),
	})
}

// WireKeystoreSync installs OnAuthUpdate so any SDK-driven token
// rotation also re-saves the Keychain blob (including refreshed
// cookies). Without this, a long-running backfill that triggers a
// refresh would leave the Keychain holding a now-invalidated
// refresh token.
func WireKeystoreSync(b *Bundle) {
	b.Session.OnAuthUpdate = func(uid, accessToken, refreshToken string) {
		// D16: clone under authMu rather than serializing the live
		// SaltedKeyPass — this fires on a background-sync refresh and can
		// race a Close()-driven Zero() of the shared backing array.
		skp := b.Session.SaltedKeyPassCopy()
		defer skp.Zero()
		err := keystoreSave(keystore.Live{
			Email:         b.Session.Email,
			UID:           uid,
			AccessToken:   accessToken,
			RefreshToken:  refreshToken,
			SaltedKeyPass: skp,
			Cookies:       protonclient.JarCookies(b.Jar),
		})
		if err != nil {
			slog.Warn("token rotation not persisted", "err", err.Error())
		}
	}
}
