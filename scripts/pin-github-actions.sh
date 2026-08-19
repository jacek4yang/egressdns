#!/usr/bin/env bash
#
# Resolve every `uses:` reference in .github/workflows to an immutable commit SHA.
#
# A tag is a moving pointer. `actions/checkout@v4` means "whatever the v4 tag points at
# the next time CI runs", and a branch reference such as `@master` is worse still: it
# means "whatever that repository's maintainer pushed most recently". Either one lets a
# third party change what runs in a workflow that has a token in its environment. Pinning
# to a commit SHA makes the reference immutable; Dependabot can still propose updates
# because the trailing `# vX.Y.Z` comment records the human-readable version.
#
# Usage:
#   ./scripts/pin-github-actions.sh            # rewrite the workflow files in place
#   ./scripts/pin-github-actions.sh --check    # fail if anything is not SHA-pinned
#
# The GitHub API rate-limits unauthenticated requests to 60 per hour per address. Export
# GITHUB_TOKEN (any token with public read access) to raise that to 5,000.
#
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOWS="${ROOT}/.github/workflows"
CHECK_ONLY=0

[ "${1:-}" = "--check" ] && CHECK_ONLY=1

if [ ! -d "$WORKFLOWS" ]; then
    echo "no workflows directory at ${WORKFLOWS}" >&2
    exit 1
fi

api() {
    local url="$1"
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" \
            -H "Accept: application/vnd.github+json" "$url"
    else
        curl -fsSL -H "Accept: application/vnd.github+json" "$url"
    fi
}

# Resolve owner/repo@ref to a commit SHA, dereferencing annotated tags.
resolve() {
    local repo="$1" ref="$2" json sha type
    for kind in tags heads; do
        if json="$(api "https://api.github.com/repos/${repo}/git/ref/${kind}/${ref}" 2>/dev/null)"; then
            sha="$(printf '%s' "$json" | sed -n 's/.*"sha"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{40\}\)".*/\1/p' | head -1)"
            type="$(printf '%s' "$json" | sed -n 's/.*"type"[[:space:]]*:[[:space:]]*"\([a-z]*\)".*/\1/p' | head -1)"
            if [ "$type" = "tag" ]; then
                # Annotated tag: one more hop to the commit it points at.
                json="$(api "https://api.github.com/repos/${repo}/git/tags/${sha}")"
                sha="$(printf '%s' "$json" | sed -n 's/.*"sha"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{40\}\)".*/\1/p' | tail -1)"
            fi
            [ -n "$sha" ] && { printf '%s' "$sha"; return 0; }
        fi
    done
    return 1
}

status=0
for file in "$WORKFLOWS"/*.yml "$WORKFLOWS"/*.yaml; do
    [ -e "$file" ] || continue
    # Collect every `uses:` value that is not already a 40-hex SHA and not a local path.
    while IFS= read -r spec; do
        repo="${spec%@*}"
        ref="${spec##*@}"
        case "$repo" in ./*|.) continue ;; esac
        if printf '%s' "$ref" | grep -Eq '^[0-9a-f]{40}$'; then
            continue
        fi
        if [ "$CHECK_ONLY" -eq 1 ]; then
            echo "not pinned: ${spec}  (${file##*/})" >&2
            status=1
            continue
        fi
        if sha="$(resolve "$repo" "$ref")"; then
            echo "pinning ${spec} -> ${sha}"
            # Replace `repo@ref` with `repo@sha # ref`, leaving any existing comment out.
            escaped_repo="$(printf '%s' "$repo" | sed 's/[\/&]/\\&/g')"
            sed -i "s|uses: ${escaped_repo}@${ref}\([[:space:]]*#.*\)\{0,1\}$|uses: ${repo}@${sha} # ${ref}|" "$file"
        else
            echo "could not resolve ${spec}; leave it and retry (rate limit?)" >&2
            status=1
        fi
        # Only real YAML keys count. Matching `uses:` anywhere on a line would also
        # match the word inside a comment or a step name.
    done < <(grep -Eho '^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*[^[:space:]#]+' "$file" \
             | sed -E 's/^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*//' | sort -u)
done

if [ "$CHECK_ONLY" -eq 1 ] && [ "$status" -eq 0 ]; then
    echo "every action reference is pinned to a commit SHA"
fi
exit "$status"
