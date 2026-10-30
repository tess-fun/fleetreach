#!/bin/sh
#
# Install a prebuilt fleetreach binary from a GitHub release, verifying its SHA-256.
#
#   curl -fsSL https://raw.githubusercontent.com/tess-fun/fleetreach/main/scripts/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --version 1.2.0 --to ~/.local/bin
#
# Environment: FLEETREACH_VERSION (default: latest), FLEETREACH_INSTALL_DIR (default:
# ~/.local/bin), FLEETREACH_BASE_URL (download base, for mirrors and tests).
set -eu

version="${FLEETREACH_VERSION:-latest}"
dest="${FLEETREACH_INSTALL_DIR:-$HOME/.local/bin}"
while [ $# -gt 0 ]; do
  case "$1" in
    --version) version="$2"; shift 2 ;;
    --to) dest="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

fail() { echo "fleetreach install: $*" >&2; exit 1; }

case "$(uname -s)" in
  Linux) os=unknown-linux-gnu ;;
  Darwin) os=apple-darwin ;;
  *) fail "no prebuilt binary for $(uname -s); use: cargo install fleetreach-cli --features network" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=aarch64 ;;
  *) fail "no prebuilt binary for $(uname -m)" ;;
esac
target="$arch-$os"

if [ "$version" = latest ]; then
  url="https://github.com/tess-fun/fleetreach/releases/latest"
  # The redirect target ends in /tag/vX.Y.Z.
  version="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$url" | sed -n 's#.*/tag/v##p')"
  [ -n "$version" ] || fail "could not determine the latest release"
fi
version="${version#v}"
base="${FLEETREACH_BASE_URL:-https://github.com/tess-fun/fleetreach/releases/download/v$version}"
archive="fleetreach-$version-$target.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$base/$archive" -o "$tmp/$archive" || fail "download failed: $base/$archive"
curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" || fail "download failed: $base/SHA256SUMS"

expected="$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")"
[ -n "$expected" ] || fail "$archive is not listed in SHA256SUMS"
if command -v sha256sum > /dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$archive" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')"
fi
[ "$expected" = "$actual" ] || fail "checksum mismatch for $archive (expected $expected, got $actual)"

tar -xzf "$tmp/$archive" -C "$tmp"
mkdir -p "$dest"
install -m 0755 "$tmp/fleetreach-$version-$target/fleetreach" "$dest/fleetreach"
echo "installed fleetreach $version to $dest/fleetreach"
case ":$PATH:" in
  *":$dest:"*) ;;
  *) echo "note: $dest is not on PATH" ;;
esac
