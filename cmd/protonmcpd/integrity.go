package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lnadalsec/proto-mcp/internal/buildinfo"
)

// D24 (Phase 7/C) — binary integrity check at daemon startup.
//
// When `protonmcp daemon install` runs, it records the SHA-256 of
// the protonmcpd binary into
// ~/Library/Application Support/protonmcp/expected_sha256.
//
// On every daemon launch, we recompute our own SHA-256 (via
// os.Executable() → open + hash) and compare. Mismatch means
// somebody replaced the binary at the recorded path between
// install and launch — refuse to start. Operator must re-run
// `protonmcp daemon install` to record the new hash.
//
// Failure modes:
//   * File missing → log warning, continue. Older installs that
//     predate Phase 7/C won't have the file; we don't break them.
//     A fresh `protonmcp daemon install` writes the file.
//   * Hash mismatch, binary still validly signed by expectedTeamID →
//     a legitimate upgrade (brew, or a fresh signed build). Re-record
//     the hash and continue. Without this, every `brew upgrade --cask
//     proto-mcp` left the daemon permanently down with no
//     user-visible explanation, because launchd's
//     KeepAlive{SuccessfulExit:false} honours the clean exit below.
//     Only if the embedded release version (internal/buildinfo) is not
//     older than the last accepted one (accepted_version): every old
//     release is validly signed too, so the signature alone would let
//     a vulnerable older build be swapped in (anti-downgrade).
//   * Hash mismatch, signed but older than accepted_version (or the
//     floor is malformed, or the binary carries no release version) →
//     refuse, same exit path as below.
//   * Hash mismatch, signature absent / ad-hoc / wrong team → refuse
//     to start with a clear error to stderr, then exit 0 (PROTO-113)
//     so launchd leaves the daemon down instead of respawning it into
//     the same failure every ~10s. Operator either restores the
//     original binary or re-runs install.
//   * Format error in the file → treat as missing (warn + continue).
//
// This is defense-in-depth: macOS code signing (Phase 7/C signing
// proper) is the primary protection. Integrity checking catches
// the case where a signed binary is swapped with an unsigned one
// after Gatekeeper has already approved the original path.
//
// Why the signature, not the hash, is the real trust anchor: a pinned
// hash cannot tell "the vendor shipped a new version" apart from
// "someone swapped the binary", so it rejects both. A Developer ID
// signature answers exactly the question being asked — is this still
// our binary — and an attacker able to produce one holds the signing
// key, at which point the hash pin buys nothing either. Ad-hoc-signed
// source builds keep the strict hash pin, having no signature to
// anchor to.

// VerifyBinaryIntegrity runs the SHA-256 check. Returns nil if the
// check passes OR if the expected_sha256 file is missing (graceful
// degrade for installs that predate this feature). Returns an error
// if the file exists but the hash doesn't match.
func VerifyBinaryIntegrity(logger *slog.Logger) error {
	expectedPath, err := expectedSha256Path()
	if err != nil {
		// Couldn't resolve $HOME — extremely rare. Continue
		// rather than block a daemon that might otherwise work.
		logger.Warn("integrity check skipped: could not resolve expected_sha256 path",
			"err", err.Error())
		return nil
	}
	return verifyIntegrity(logger, integrityInputs{
		expectedPath: expectedPath,
		versionPath:  filepath.Join(filepath.Dir(expectedPath), acceptedVersionFile),
		executable:   os.Executable,
		version:      buildinfo.Version(),
		verifySig:    verifyDeveloperIDSignature,
	})
}

// integrityInputs carries everything verifyIntegrity reads from the
// environment, so tests can drive the downgrade logic with a fake
// signature check and an arbitrary embedded version instead of needing
// a real Developer-ID-signed binary.
type integrityInputs struct {
	expectedPath string                 // expected_sha256 record
	versionPath  string                 // accepted_version floor
	executable   func() (string, error) // os.Executable in production
	version      string                 // buildinfo.Version() of the running binary
	verifySig    func(path string) error
}

func verifyIntegrity(logger *slog.Logger, in integrityInputs) error {
	expectedPath := in.expectedPath
	expected, recordedPath, err := readExpectedSha256(expectedPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Warn("integrity check skipped: no expected_sha256 file",
				"path", expectedPath,
				"hint", "run `protonmcp daemon install` to record the binary hash")
			return nil
		}
		// Malformed → treat as advisory only. Logs loudly so the
		// operator notices, but doesn't block startup.
		logger.Warn("integrity check skipped: expected_sha256 unreadable",
			"path", expectedPath, "err", err.Error())
		return nil
	}

	exe, err := in.executable()
	if err != nil {
		return fmt.Errorf("integrity check: os.Executable: %w", err)
	}
	actual, err := sha256File(exe)
	if err != nil {
		return fmt.Errorf("integrity check: hash %s: %w", exe, err)
	}

	if actual != expected {
		// The overwhelmingly common cause of a mismatch is a
		// legitimate upgrade: `brew upgrade --cask proto-mcp` swaps the
		// binary, the recorded hash goes stale, and the daemon refuses
		// to start until someone re-runs `protonmcp daemon install`.
		// Nothing tells the user that, so the tools just stop working.
		//
		// Before failing, ask the stronger question the hash was only
		// ever a proxy for: is this binary still one of OURS? A valid
		// Developer ID signature chaining to the Apple root and
		// carrying our team identifier answers yes, survives every
		// legitimate upgrade, and cannot be forged by the local
		// attacker this check exists to stop (they'd need our signing
		// key). If it holds, re-record the hash and carry on.
		sigErr := in.verifySig(exe)
		if sigErr != nil {
			// Not signed by us — this is the swap the check is for.
			// Ad-hoc-signed source builds land here too, which is
			// correct: they get the strict hash pin, since there's no
			// signature to anchor trust to.
			return fmt.Errorf(
				"binary integrity check FAILED\n"+
					"  running:   %s\n"+
					"  running sha256:    %s\n"+
					"  expected (from install): %s\n"+
					"  expected path: %s\n"+
					"  signature check: %v\n"+
					"  The binary was replaced after install and is not signed by the "+
					"expected Developer ID (team %s). Either restore the original "+
					"binary or, if you built this yourself, re-run "+
					"`protonmcp daemon install` to record the new hash",
				exe, actual, expected, recordedPath, sigErr, expectedTeamID,
			)
		}

		// A valid signature proves the binary is ours, not that it is
		// CURRENT. Every release we ever shipped carries the same
		// signature, including ones with since-fixed vulnerabilities,
		// so without this check an attacker could drop an old signed
		// build in place and the self-heal would bless it. Only an
		// operator-run `protonmcp daemon install` (which re-pins the
		// hash and so never reaches this branch) may go backwards.
		if derr := checkNotDowngrade(in.versionPath, in.version); derr != nil {
			return fmt.Errorf(
				"binary integrity check FAILED\n"+
					"  running:   %s\n"+
					"  running sha256:    %s\n"+
					"  expected (from install): %s\n"+
					"  version check: %v\n"+
					"  The binary is validly signed (team %s) but is not at least "+
					"the last version this daemon accepted, so it was not re-pinned "+
					"automatically. If you downgraded on purpose, re-run "+
					"`protonmcp daemon install`",
				exe, actual, expected, derr, expectedTeamID,
			)
		}

		logger.Warn("binary changed since install; signature still trusted, re-recording hash",
			"path", exe,
			"was", expected[:16]+"…",
			"now", actual[:16]+"…",
			"version", in.version,
			"team_id", expectedTeamID)
		if werr := rewriteExpectedSha256(expectedPath, actual, exe); werr != nil {
			// The signature check already passed, which is the
			// real authorization. A failed re-record just means
			// we'll repeat this dance next launch.
			logger.Warn("could not re-record expected_sha256",
				"path", expectedPath, "err", werr.Error())
		}
		recordAcceptedVersion(logger, in.versionPath, in.version)
		return nil
	}

	// The hash matches the operator's own install record, the strongest
	// consent available here: record this version as the floor even if
	// it is lower than the previous one (a deliberate downgrade
	// followed by `protonmcp daemon install`).
	recordAcceptedVersion(logger, in.versionPath, in.version)
	logger.Info("binary integrity check passed",
		"sha256", actual[:16]+"…")
	return nil
}

// acceptedVersionFile sits next to expected_sha256 and holds the
// release version ("1.2.3") of the last daemon binary that passed the
// integrity check. It is the anti-downgrade floor for the signature
// self-heal path.
//
// Like expected_sha256 it is writable by the user the daemon runs as,
// so it does not stop an attacker already executing as that user (who
// could equally rewrite the hash record). It stops the narrower swap
// of an older, signed, vulnerable protonmcpd over the installed one
// without touching the records. See docs/security.md.
const acceptedVersionFile = "accepted_version"

// releaseVersionRE matches the versions release builds are stamped
// with (the Makefile strips the tag's leading "v"). Anything else —
// "dev", a `git describe` string like "1.0.2-3-gabc1234", "-dirty" —
// is not a release and cannot be ordered against one.
var releaseVersionRE = regexp.MustCompile(`^v?(\d{1,9})\.(\d{1,9})\.(\d{1,9})$`)

// parseReleaseVersion returns the numeric major/minor/patch of a
// release version string, or ok=false if s is not one.
func parseReleaseVersion(s string) (v [3]int, ok bool) {
	m := releaseVersionRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return v, false
	}
	for i := range v {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// compareVersions returns -1, 0 or +1 as a is older than, equal to or
// newer than b.
func compareVersions(a, b [3]int) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

// checkNotDowngrade returns nil if candidate may be auto-accepted on
// the signature path given the floor recorded at versionPath.
//
//   - No floor recorded (install predating this check): accept. The
//     first accepted start records one.
//   - Floor unreadable or malformed: refuse. Treating it as missing
//     would let anyone able to corrupt the file switch the check off.
//   - Candidate not a release version: refuse. Signed release builds
//     are always stamped; an unstamped signed binary cannot be ordered.
//   - Candidate older than the floor: refuse. Equal is fine — a
//     re-signed build of the same release is not a downgrade.
func checkNotDowngrade(versionPath, candidate string) error {
	data, err := os.ReadFile(versionPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("version floor %s unreadable: %w", versionPath, err)
	}
	floorStr := strings.TrimSpace(string(data))
	floor, ok := parseReleaseVersion(floorStr)
	if !ok {
		return fmt.Errorf("version floor %s is malformed (%q)", versionPath, floorStr)
	}
	cand, ok := parseReleaseVersion(candidate)
	if !ok {
		return fmt.Errorf("running version %q is not a release version; "+
			"cannot compare it with last accepted %s", candidate, floorStr)
	}
	if compareVersions(cand, floor) < 0 {
		return fmt.Errorf("downgrade refused: running version %s is older than "+
			"last accepted %s", candidate, floorStr)
	}
	return nil
}

// recordAcceptedVersion stores version as the new floor. Non-release
// versions (source builds) are not recorded: they cannot be ordered,
// and recording "dev" would make the next signed upgrade trip the
// malformed-floor rule. Failures are logged, not fatal — the integrity
// decision has already been made.
func recordAcceptedVersion(logger *slog.Logger, versionPath, version string) {
	if _, ok := parseReleaseVersion(version); !ok {
		return
	}
	version = strings.TrimSpace(version)
	if cur, err := os.ReadFile(versionPath); err == nil && strings.TrimSpace(string(cur)) == version {
		return
	}
	if err := writeFileAtomic(versionPath, version+"\n"); err != nil {
		logger.Warn("could not record accepted version",
			"path", versionPath, "err", err.Error())
	}
}

// expectedTeamID is the Apple Developer Team identifier that signs
// released proto-mcp binaries. It is the trust anchor for the
// upgrade-survival path in VerifyBinaryIntegrity: a binary bearing a
// valid Developer ID signature from this team is ours regardless of its
// hash, so replacing it via a signed release is allowed while replacing
// it with anything else is not.
//
// Changing this constant changes who can silently replace the daemon.
const expectedTeamID = "346JJCHZP7"

// codesignTimeout bounds the codesign subprocess. Signature checks are
// local (no OCSP round trip with --verify alone) and finish in
// milliseconds; the timeout only exists so a wedged codesign can't hang
// daemon startup forever.
const codesignTimeout = 10 * time.Second

// verifyDeveloperIDSignature reports nil if path carries a valid,
// unbroken code signature that chains to the Apple root and was issued
// to expectedTeamID.
//
// The requirement string is evaluated by codesign itself rather than
// parsed out of `codesign -dv` text, which matters: `anchor apple
// generic` forces a real chain to Apple's root, so an attacker cannot
// satisfy it by ad-hoc signing a binary that merely claims our team
// identifier in its metadata.
func verifyDeveloperIDSignature(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), codesignTimeout)
	defer cancel()

	// Two syntax details that both fail closed but silently, so they're
	// worth spelling out:
	//   * "-R=<text>" — bare "-R <text>" makes codesign read the
	//     requirement from a FILE of that name, which errors out with
	//     "No such file or directory".
	//   * the team ID is quoted — it starts with digits, and unquoted
	//     the requirement lexer reads it as a number and rejects the
	//     expression.
	// Either mistake turns every check into an error, which would make
	// the self-heal dead code and send legitimate upgrades down the
	// hard-fail path. TestVerifyDeveloperIDSignatureAcceptsReleaseBinary
	// is what keeps that honest.
	req := fmt.Sprintf(`-R=anchor apple generic and certificate leaf[subject.OU] = %q`, expectedTeamID)
	cmd := exec.CommandContext(ctx, "/usr/bin/codesign",
		"--verify", "--strict", req, path)

	// codesign writes its diagnostics to stderr; capture them so the
	// failure message in the log says *why* (unsigned, ad-hoc, wrong
	// team, modified since signing) rather than just "exit status 1".
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return errors.New(detail)
	}
	return nil
}

// rewriteExpectedSha256 replaces the recorded hash after a verified
// upgrade. Writes to a temp file in the same directory and renames, so
// a crash mid-write can't leave a truncated record that the next launch
// would read as "malformed" and skip.
func rewriteExpectedSha256(path, hash, binPath string) error {
	return writeFileAtomic(path, hash+"  "+binPath+"\n")
}

// writeFileAtomic writes content to path at 0600 through a temp file
// in the same directory plus rename.
func writeFileAtomic(path, content string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed

	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func expectedSha256Path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "protonmcp", "expected_sha256"), nil
}

// readExpectedSha256 parses the one-line "<hex>  <path>\n" format
// `protonmcp daemon install` writes. Returns the hex hash and the
// recorded path. Whitespace between the two fields is one-or-more
// spaces / tabs (matches `shasum`'s output format).
func readExpectedSha256(path string) (string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return "", "", fmt.Errorf("empty file")
	}
	line := strings.TrimSpace(scanner.Text())
	// Split on first run of whitespace.
	idx := strings.IndexAny(line, " \t")
	if idx == -1 {
		return "", "", fmt.Errorf("malformed: expected '<hash>  <path>', got %q", line)
	}
	hash := strings.TrimSpace(line[:idx])
	recorded := strings.TrimSpace(line[idx:])
	if len(hash) != 64 { // SHA-256 hex
		return "", "", fmt.Errorf("malformed: hash length is %d, expected 64", len(hash))
	}
	return hash, recorded, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
