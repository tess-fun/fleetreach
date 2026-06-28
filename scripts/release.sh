#!/usr/bin/env bash
#
# Cut a new fleetreach release: bump the version, test, tag, and publish all 17
# crates to crates.io in dependency order, then push.
#
#   ./scripts/release.sh 1.0.1              # full release
#   ./scripts/release.sh 1.0.1 --dry-run    # bump + test only, then revert (no publish/push)
#
# Notes:
#  - crates.io versions are immutable; pick a fresh version (semver).
#  - Version *updates* are not subject to the new-crate rate limit, so this runs
#    in minutes (unlike the first publish). A mild per-publish throttle is retried.
#  - reach-driver is intentionally NOT published (nightly rustc_private; excluded
#    from the workspace). Static reachability is built from source by the user.
#
set -euo pipefail

NEW="${1:-}"
DRY="${2:-}"
[ -n "$NEW" ] || { echo "usage: $0 <new-version> [--dry-run]   e.g. $0 1.0.1"; exit 2; }
[[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-].+)?$ ]] || { echo "!! '$NEW' is not a semver version"; exit 2; }

cd "$(git rev-parse --show-toplevel)"

# Publish order: dependency-topological (core/reach first, cli last).
ORDER=(core reach scan report correlate go npm pypi rubygems packagist nuget julia swift hex ghactions maven cli)
OLD="$(sed -nE 's/^version = "([0-9][^"]*)".*/\1/p' Cargo.toml | head -1)"

echo ">> fleetreach release: $OLD -> $NEW ${DRY:+(dry run)}"

# --- preconditions ---
[ "$(git branch --show-current)" = "main" ] || { echo "!! not on main"; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "!! working tree not clean — commit or stash first"; exit 1; }
if [ -z "$DRY" ]; then
  { [ -f "$HOME/.cargo/credentials.toml" ] || [ -f "$HOME/.cargo/credentials" ]; } \
    || { echo "!! not logged in to crates.io — run: cargo login <token>"; exit 1; }
fi
[ "$OLD" != "$NEW" ] || { echo "!! version is already $NEW"; exit 1; }
grep -q "## \[$NEW\]\|## $NEW" CHANGELOG.md 2>/dev/null \
  || echo ">> reminder: CHANGELOG.md has no '## [$NEW]' entry yet (optional, but nice to add)."

# --- bump versions ---
# 1) the single [workspace.package] version (first `version = "OLD"` in the root manifest)
perl -i -pe 'if (!$d && /^version = "\Q'"$OLD"'\E"$/) { s/"\Q'"$OLD"'\E"/"'"$NEW"'"/; $d=1 }' Cargo.toml
# 2) every inter-crate path-dep version requirement, kept in lockstep
perl -i -pe 's/(fleetreach-[a-z]+ = \{ path = "\.\.\/[a-z]+", version = ")[^"]+(")/${1}'"$NEW"'${2}/g' crates/*/Cargo.toml

# refresh the lockfile to the new versions
cargo update --workspace --quiet

echo ">> running the full test suite (release gate)"
cargo test --workspace

if [ "$DRY" = "--dry-run" ]; then
  echo ">> dry run OK — would publish: ${ORDER[*]/#/fleetreach-}"
  git checkout -- Cargo.toml Cargo.lock crates/*/Cargo.toml
  echo ">> reverted version bump."
  exit 0
fi

# --- confirm (irreversible) ---
printf ">> About to TAG v%s and PUBLISH 17 crates to crates.io. This is permanent. Continue? [y/N] " "$NEW"
read -r ans; [ "$ans" = "y" ] || [ "$ans" = "Y" ] || { echo ">> aborted; reverting bump"; git checkout -- Cargo.toml Cargo.lock crates/*/Cargo.toml; exit 1; }

# --- commit + tag ---
git add -A
git commit -m "release: $NEW"
git tag -a "v$NEW" -m "fleetreach $NEW"

# --- publish in dependency order (resumable: skips anything already up) ---
for c in "${ORDER[@]}"; do
  echo ">> publishing fleetreach-$c $NEW"
  while true; do
    if out="$(cargo publish -p "fleetreach-$c" 2>&1)"; then echo "   ok"; break; fi
    if grep -qiE "already (exists|uploaded)" <<<"$out"; then echo "   already published, skipping"; break; fi
    if grep -qiE "too many|429 " <<<"$out"; then echo "   throttled; retrying in 60s"; sleep 60; continue; fi
    echo "   FAILED:"; tail -n 8 <<<"$out"; exit 1
  done
done

# --- push ---
git push origin main
git push origin "v$NEW"
echo ">> released fleetreach $NEW  🎉"
