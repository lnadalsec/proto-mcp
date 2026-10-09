# shellcheck shell=bash
# distribution.sh — single source of truth for WHERE proto-mcp is
# published. Sourced by release.sh and bootstrap-tap.sh; not executable
# on its own.
#
# The default is the upstream project (just-an-oldsalt/proto-mcp),
# which is also what Formula/proto-mcp.rb downloads from. A fork that
# publishes its own signed releases must say so explicitly:
#
#   PROTO_MCP_OWNER=<github-owner> make release VERSION=v1.2.3
#   PROTO_MCP_OWNER=<github-owner> ./scripts/bootstrap-tap.sh 1.2.3 <sha256>
#
# Nothing here switches the distribution channel silently: release.sh
# refuses to run when `origin` is not $PROTO_MCP_REPO, so a fork can't
# end up tagging its own repo while the cask points at another one.

PROTO_MCP_OWNER="${PROTO_MCP_OWNER:-just-an-oldsalt}"
PROTO_MCP_REPO_NAME="${PROTO_MCP_REPO_NAME:-proto-mcp}"

# GitHub owner: alphanumerics and single hyphens. Repo: alphanumerics,
# '.', '_', '-'. Validated because both are spliced into URLs and into
# a sed expression that rewrites the cask.
if ! [[ "$PROTO_MCP_OWNER" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,38})$ ]]; then
    echo "error: PROTO_MCP_OWNER '$PROTO_MCP_OWNER' is not a valid GitHub owner name." >&2
    exit 1
fi
if ! [[ "$PROTO_MCP_REPO_NAME" =~ ^[A-Za-z0-9._-]{1,100}$ ]]; then
    echo "error: PROTO_MCP_REPO_NAME '$PROTO_MCP_REPO_NAME' is not a valid repository name." >&2
    exit 1
fi

PROTO_MCP_REPO="$PROTO_MCP_OWNER/$PROTO_MCP_REPO_NAME"

# The owner/repo baked into Formula/proto-mcp.rb. bootstrap-tap.sh
# rewrites it to $PROTO_MCP_REPO in the tap copy (a no-op by default).
PROTO_MCP_FORMULA_REPO="just-an-oldsalt/proto-mcp"

# origin_repo prints "owner/name" for the origin remote, from either
# the SSH (git@github.com:owner/name.git) or HTTPS form.
origin_repo() {
    local url
    url=$(git remote get-url origin 2>/dev/null) || return 1
    url="${url%.git}"
    url="${url#git@github.com:}"
    url="${url#ssh://git@github.com/}"
    url="${url#https://github.com/}"
    printf '%s\n' "$url"
}

export PROTO_MCP_OWNER PROTO_MCP_REPO_NAME PROTO_MCP_REPO PROTO_MCP_FORMULA_REPO
