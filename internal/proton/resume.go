package proton

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/go-resty/resty/v2"

	"github.com/lnadalsec/proto-mcp/internal/secret"
)

// ErrSessionExpired wraps the family of errors that mean "the stored
// refresh token is no longer valid — the user must re-authenticate".
// Callers detect this with errors.Is and respond by wiping the
// Keychain entry and falling back to a full Login.
var ErrSessionExpired = errors.New("proton: stored session expired or revoked")

// ResumeArgs is the minimum state needed to rebuild a Session without
// running the full SRP + 2FA + salt-fetch flow. All fields are
// populated from a Keychain blob.
type ResumeArgs struct {
	Email         string
	UID           string
	AccessToken   string // current access token (may still be valid)
	RefreshToken  string // refresh token (single-use on Proton's side)
	SaltedKeyPass secret.Secret

	// OnAuthUpdate, if set, is installed as the Session's OnAuthUpdate
	// BEFORE the first API call, so a token rotation triggered inside
	// Resume itself (auto-refresh on an expired access token) is
	// persisted even if a later step of Resume fails. Without it, a
	// transient error after the refresh would drop the only valid
	// refresh token — the stored one is single-use and already burned.
	OnAuthUpdate func(uid, accessToken, refreshToken string)
}

// Resume rebuilds a Session from a previously-stored access + refresh
// token pair and salted mailbox password.
//
// Implementation note (this was hard to find):
//
// Proton's refresh tokens are SINGLE-USE — calling /auth/v4/refresh
// rotates both the access and refresh tokens, and the old refresh
// token becomes invalid immediately. proton-bridge gets away with
// NewClientWithRefresh because they keep one Client alive for the
// entire daemon lifetime and only rotate when an access token actually
// expires.
//
// Our model is one process per CLI invocation. If every invocation
// called NewClientWithRefresh, we'd burn a refresh token every time;
// the first whoami would work (it consumed the login-issued refresh
// token), and the second would 400 because the rotated token from
// the first refresh is itself one-time-use that the first whoami
// already burned implicitly... well, more accurately: there's a
// race in our persistence that no amount of patching can solve as
// long as we keep refreshing.
//
// Resume now builds a Client with mgr.NewClient(uid, acc, ref) — no
// refresh call. The SDK's auto-refresh-on-401 path inside Client.do
// only fires when the access token has actually expired. If our
// stored access token is still valid (the common case for a tight
// CLI loop), no refresh happens, no token rotation, nothing to
// persist.
//
// On expiry the auto-refresh fires, the AuthHandler captures the
// rotated bundle, and the keystore-sync OnAuthUpdate hook writes the
// new pair back to disk so the next process can pick up where we
// left off.
//
// Resume does NOT retry on network errors — a single attempt is the
// right policy. The caller (CLI shell) is the natural retry
// boundary; a buggy MCP client looping on auth failure should not
// hammer Proton's anti-abuse.
func Resume(ctx context.Context, mgr *gpa.Manager, args ResumeArgs) (*Session, error) {
	if args.UID == "" || args.RefreshToken == "" {
		return nil, errors.New("proton: resume requires UID + RefreshToken")
	}
	if args.SaltedKeyPass.Empty() {
		return nil, errors.New("proton: resume requires saltedKeyPass — re-login required")
	}

	client := mgr.NewClient(args.UID, args.AccessToken, args.RefreshToken)

	// Build the Session and install the AuthHandler IMMEDIATELY, before
	// any API call. If GetUser / GetAddresses below trigger the
	// auto-refresh-on-401 path (because the stored access token has
	// expired), the SDK fires AuthHandler with the rotated bundle —
	// our handler keeps Session.AccessToken / RefreshToken current and
	// the OnAuthUpdate hook (wired by the caller) writes the new pair
	// back to the Keychain.
	sess := newResumedSession(client, args)
	sess.installAuthHandler()
	sess.installCalendarMemberHook()

	// closeAndWrap releases the client. It revokes the session
	// server-side ONLY when Proton itself said the credentials are
	// dead (revoke=true): the session is unusable anyway and the
	// revoke is best-effort hygiene. On 5xx / 429 / network errors,
	// or a local unlock failure, the session is still valid and is
	// the one stored in the Keychain (or just rotated into it via
	// OnAuthUpdate) — revoking it would turn a transient outage into
	// a forced re-login, and could kill a session another process
	// (CLI vs daemon) is actively using.
	closeAndWrap := func(revoke bool, format string, vals ...any) error {
		if revoke {
			revokeCtx, cancel := detachedShutdownCtx()
			defer cancel()
			_ = client.AuthDelete(revokeCtx)
		}
		client.Close()
		return fmt.Errorf(format, vals...)
	}

	user, err := client.GetUser(ctx)
	if err != nil {
		// If the access token had expired AND the auto-refresh failed
		// (refresh token is dead), the SDK surfaces a 401 / 422 / 400
		// here. Map those to ErrSessionExpired so the CLI clears the
		// Keychain and re-prompts cleanly.
		if isAuthExpired(err) {
			return nil, closeAndWrap(true, "%w: %v", ErrSessionExpired, err)
		}
		return nil, closeAndWrap(false, "resume get user: %w", err)
	}
	addrs, err := client.GetAddresses(ctx)
	if err != nil {
		if isAuthExpired(err) {
			return nil, closeAndWrap(true, "%w: %v", ErrSessionExpired, err)
		}
		return nil, closeAndWrap(false, "resume get addresses: %w", err)
	}

	userKR, addrKRs, err := gpa.Unlock(user, addrs, args.SaltedKeyPass.Bytes(), nil)
	if err != nil {
		return nil, closeAndWrap(false, "resume unlock: %w — keystore blob may be stale, run `protonmcp login` again", err)
	}

	sess.User = user
	sess.Addresses = addrs
	sess.UserKR = userKR
	sess.AddrKRs = addrKRs
	return sess, nil
}

// isAuthExpired distinguishes "token dead" from other failure modes
// (network down, server 500, etc.) so callers know whether to wipe
// the keystore or retry later.
//
// Proton's auth endpoints can signal dead-token in several shapes:
//
//   - HTTP 401 wrapped as gpa.APIError (classic unauthorized)
//   - HTTP 422 with Code=10013 ("Invalid refresh token") wrapped as
//     resty.ResponseError — what /auth/v4/refresh actually returns
//     when the token has been revoked by an AuthDelete call
//
// Only 400 / 401 / 422 count — the same set the SDK itself treats as
// "de-auth" on refresh, plus the classic 401. Everything else (429
// rate limiting, 409, 5xx, network errors, …) is transient: it must
// neither wipe the Keychain entry nor revoke the session, or an
// outage would force a re-login.
func isAuthExpired(err error) bool {
	var apiErr *gpa.APIError
	if errors.As(err, &apiErr) {
		return isAuthExpiredStatus(apiErr.Status)
	}
	var respErr *resty.ResponseError
	if errors.As(err, &respErr) && respErr.Response != nil {
		return isAuthExpiredStatus(respErr.Response.StatusCode())
	}
	return false
}

func isAuthExpiredStatus(sc int) bool {
	switch sc {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusUnprocessableEntity:
		return true
	}
	return false
}

// newResumedSession builds the Session Resume returns from the stored
// fields. Split out so the #123 ownership contract is testable without
// a network round-trip.
func newResumedSession(client *gpa.Client, args ResumeArgs) *Session {
	return &Session{
		Client:       client,
		Email:        args.Email,
		UID:          args.UID,
		AccessToken:  args.AccessToken,
		RefreshToken: args.RefreshToken,
		// Issue #123: own a private copy. Callers (session.TryResume,
		// logout) defer Zero() on the Secret they passed in, and a value
		// copy shares its backing array — without Clone the live
		// session's pass became 32 zero bytes the moment they returned,
		// and the next OnAuthUpdate persisted that to the Keychain.
		SaltedKeyPass: args.SaltedKeyPass.Clone(),
		OnAuthUpdate:  args.OnAuthUpdate,
	}
}
