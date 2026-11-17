#!/bin/bash
# Differential test of fleetreach's Gradle version order (gradle_cmp) against Gradle's own
# DefaultVersionComparator, in a throwaway container with no network.
#
# usage: run.sh VERSIONS_FILE WORK_DIR
#   VERSIONS_FILE  one version per line (real ones: the version folders of a Gradle cache)
#   WORK_DIR       gets pairs.txt, out.txt (Gradle's signs) and ours.txt (fleetreach's)
# Prints the number of pairs on which the two disagree; 0 is a pass.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mkdir -p "$2" && cd "$2" && pwd)
python3 -I "$here/mkpairs.py" "$1" "$work/pairs.txt" >/dev/null
cp "$here/build.gradle" "$work/build.gradle"
echo "rootProject.name='gvc'" > "$work/settings.gradle"
docker run --rm --network none -v "$work:/w" -w /w gradle:8.14.3-jdk17 gradle -q --offline cmp
cargo run -q --release -p fleetreach-maven --example maven_vercmp -- gradle < "$work/pairs.txt" > "$work/ours.txt"
paste "$work/out.txt" "$work/ours.txt" | awk '$1 != $2' | wc -l
