#!/usr/bin/env bash
# Dogfood the static reachability engine on fleetreach's own tree.
#
# Builds the pinned-nightly reach-driver, then runs the self-validating
# `dogfood` example, which compiles the whole fleetreach closure under the
# driver and asserts soundness/consistency invariants on the real graph.
#
# This is intentionally heavy (it builds the full workspace under the driver) and
# meant to be run on demand — not in the fast CI suite. Exits non-zero if any
# invariant fails.
#
# Usage: scripts/dogfood-reach.sh [TARGET_MANIFEST_DIR]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TOOLCHAIN="nightly-2026-06-01"
DRIVER="crates/reach-driver/target/debug/fleetreach-reach-driver"

if ! rustup toolchain list | grep -q "$TOOLCHAIN"; then
  echo "==> installing $TOOLCHAIN (rustc-dev/rust-src/llvm-tools)"
  rustup toolchain install "$TOOLCHAIN" \
    --component rustc-dev rust-src llvm-tools --profile minimal
fi

echo "==> building the reach-driver ($TOOLCHAIN)"
( cd crates/reach-driver && cargo build )

echo "==> running the dogfood example on the real tree"
exec cargo run -p fleetreach-reach --example dogfood -- "$DRIVER" "$@"
