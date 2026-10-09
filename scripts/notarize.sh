#!/usr/bin/env bash
# notarize.sh — submit an archive to Apple's notary service and FAIL
# unless Apple accepted it.
#
# `xcrun notarytool submit --wait` exits 0 as soon as the submission
# reaches a terminal state, including "Invalid" (rejected) — so a
# pipeline that only checks the exit code happily continues and ships
# an un-notarized artifact that Gatekeeper then blocks on users'
# machines. Ask for JSON and check `status` ourselves.
#
# Usage: scripts/notarize.sh <archive.zip> [keychain-profile]
#   profile defaults to $NOTARY_PROFILE, then "protonmcp-notary".

set -euo pipefail

ARCHIVE="${1:-}"
PROFILE="${2:-${NOTARY_PROFILE:-protonmcp-notary}}"

if [ -z "$ARCHIVE" ] || [ ! -f "$ARCHIVE" ]; then
    echo "usage: $0 <archive.zip> [keychain-profile]" >&2
    exit 2
fi

OUT=$(mktemp)
trap 'rm -f "$OUT"' EXIT

echo "submitting $ARCHIVE to notarytool (profile: $PROFILE)…"
if ! xcrun notarytool submit "$ARCHIVE" \
        --keychain-profile "$PROFILE" \
        --wait \
        --output-format json > "$OUT"; then
    echo "error: notarytool submit failed:" >&2
    cat "$OUT" >&2
    exit 1
fi

# plutil reads JSON property lists natively; no python/jq dependency.
STATUS=$(plutil -extract status raw -o - "$OUT" 2>/dev/null || true)
SUBMISSION_ID=$(plutil -extract id raw -o - "$OUT" 2>/dev/null || true)

if [ "$STATUS" != "Accepted" ]; then
    echo "error: notarization was not accepted (status: '${STATUS:-unknown}', submission: '${SUBMISSION_ID:-unknown}')." >&2
    cat "$OUT" >&2
    if [ -n "$SUBMISSION_ID" ]; then
        echo "  Apple's reasons:  xcrun notarytool log $SUBMISSION_ID --keychain-profile $PROFILE" >&2
    fi
    exit 1
fi

echo "Notarization Accepted (submission $SUBMISSION_ID)."
