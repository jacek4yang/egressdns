#!/usr/bin/env bash
#
# Publish the first EgressDNS release to GitHub.
#
#   ./scripts/publish-first-release.sh <OWNER>/<REPO>
#
# Requires an authenticated `gh` CLI. The script pushes `main`, creates and pushes the
# v1.0.0 tag, and then shows the Actions run that builds the release assets.
#
# It refuses to run against a dirty working tree, and it never force-pushes.

set -Eeuo pipefail

readonly TAG="v1.0.0"

log()  { printf '[release] %s\n' "$*" >&2; }
die()  { printf '[release] error: %s\n' "$*" >&2; exit 1; }

[ "$#" -eq 1 ] || die "usage: $0 <OWNER>/<REPO>"
REPO="$1"
printf '%s' "$REPO" | grep -Eq '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$' ||
    die "repository '$REPO' is not in <owner>/<name> form"

command -v git >/dev/null 2>&1 || die "git is not installed"
command -v gh  >/dev/null 2>&1 || die "the GitHub CLI (gh) is not installed"

gh auth status >/dev/null 2>&1 || die "gh is not authenticated; run: gh auth login"

git rev-parse --git-dir >/dev/null 2>&1 || die "not inside a git repository"

if [ -n "$(git status --porcelain)" ]; then
    git status --short >&2
    die "the working tree is not clean; commit or stash first"
fi

branch="$(git rev-parse --abbrev-ref HEAD)"
if [ "$branch" != "main" ]; then
    log "current branch is '$branch'; renaming to main"
    git branch -M main
fi

remote_url="https://github.com/${REPO}.git"
if git remote get-url origin >/dev/null 2>&1; then
    current="$(git remote get-url origin)"
    if [ "$current" != "$remote_url" ] && [ "$current" != "git@github.com:${REPO}.git" ]; then
        log "origin currently points at $current"
        read -r -p "Replace origin with $remote_url? [y/N] " reply
        case "$reply" in
            y|Y|yes|YES) git remote set-url origin "$remote_url" ;;
            *) die "aborted" ;;
        esac
    fi
else
    log "adding origin $remote_url"
    git remote add origin "$remote_url"
fi

log "pushing main"
git push -u origin main

if git rev-parse "$TAG" >/dev/null 2>&1; then
    log "tag $TAG already exists locally"
else
    log "creating tag $TAG"
    git tag -a "$TAG" -m "EgressDNS $TAG"
fi

log "pushing tag $TAG"
git push origin "$TAG"

log "waiting for the release workflow to appear"
sleep 5
gh run list --repo "$REPO" --workflow release.yml --limit 5 || true

cat >&2 <<MSG

The tag has been pushed. GitHub Actions is now building:

  egressdns-${TAG}-linux-x86_64.tar.gz
  egressdns-${TAG}-linux-aarch64.tar.gz
  SHA256SUMS

Watch it with:

  gh run watch --repo ${REPO}

Once the release is published, the one-command installer works:

  curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/install.sh" \\
    | sudo bash -s -- --repo "${REPO}"

MSG
