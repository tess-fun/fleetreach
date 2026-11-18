# Sourced, hidden, at the start of fleetreach.tape: the recording runs in website/demo on the
# demo fleet and its frozen advisory data, offline, with an empty HOME, the same way
# website/scripts/examples.mjs runs the site's examples, so the GIF shows what the site shows.
FR_BIN="${FLEETREACH:-$(cd ../.. && pwd)/target/release/fleetreach}"
FR_HOME="$(mktemp -d)"
mkdir -p "$FR_HOME/bin" "$FR_HOME/.m2"
# A fixed rustc, so the Rust toolchain's own advisories do not depend on the machine.
printf '#!/bin/sh\necho "rustc 1.89.0 (29483883e 2025-08-04)"\n' > "$FR_HOME/bin/rustc"
chmod +x "$FR_HOME/bin/rustc"
export PATH="$FR_HOME/bin:$PATH" HOME="$FR_HOME" XDG_CACHE_HOME="$FR_HOME"
export FLEETREACH_OSV_SYNC=off MAVEN_REPO_LOCAL="$PWD/data/m2" SOURCE_DATE_EPOCH=1793523600

# The command as a reader types it, pointed at the frozen data (examples.mjs `actual`).
fleetreach() {
  local args=() a
  for a in "$@"; do
    if [ "$a" = --enrich ]; then args+=(--kev-file data/kev.json --epss-file data/epss.csv)
    else args+=("$a"); fi
  done
  [ "$1" = scan ] && args+=(--offline --db data/advisory-db)
  "$FR_BIN" "${args[@]}"
}

fleetreach scan -f json --enrich > report.json 2>/dev/null
export PS1='\[\e[38;5;209m\]$\[\e[0m\] '
clear
