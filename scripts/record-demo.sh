#!/bin/sh
# Re-record the README's terminal GIF (assets/demo/fleetreach.gif) with VHS.
# Needs `vhs` (brew install vhs) and a release build: cargo build --release --features network.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root/website/demo"
vhs "$root/assets/demo/fleetreach.tape"
