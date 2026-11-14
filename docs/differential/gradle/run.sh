#!/bin/bash
# Resolve one repo with real Gradle, in a throwaway container: its own wrapper on JDK 21,
# then JDK 17 if that fails. Build scripts run inside the container only.
#
# usage: run.sh REPO_DIR OUT_DIR
#   OUT_DIR/<name>.out   the FA / FAUNRESOLVED lines
#   OUT_DIR/<name>.log   Gradle's output
#   OUT_DIR/<name>.status  ok-jdk21, ok-jdk17 or failed
# The Gradle home (wrapper distributions, module cache) is the docker volume fa-gradle-home.
set -u
repo=$(cd "$1" && pwd); out=$(mkdir -p "$2" && cd "$2" && pwd); name=$(basename "$repo")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
for jdk in 21 17; do
  rm -rf "$work/src"; cp -R "$repo" "$work/src"; rm -rf "$work/src/.git"
  if [ -f "$work/src/gradlew" ]; then cmd="sh ./gradlew"; else cmd="gradle"; fi
  cname="fa-gradle-$$-$jdk"
  # macOS has no timeout(1): the container is killed after 20 minutes instead.
  ( sleep 1200; docker kill "$cname" >/dev/null 2>&1 ) & killer=$!
  docker run --rm --name "$cname" -m 3500m \
    -v fa-gradle-home:/home/gradle/.gradle -v "$work/src":/src -v "$here/init.gradle":/fa/init.gradle:ro \
    -w /src -e GRADLE_USER_HOME=/home/gradle/.gradle -e GRADLE_OPTS=-Xmx1536m "gradle:8.14.3-jdk$jdk" \
    sh -c "$cmd -q --no-daemon --no-configuration-cache --continue --init-script /fa/init.gradle faDeps" \
    > "$out/$name.log" 2>&1
  kill "$killer" 2>/dev/null; wait "$killer" 2>/dev/null
  grep -E '^FA(UNRESOLVED)? ' "$out/$name.log" > "$out/$name.out"
  if [ -s "$out/$name.out" ]; then echo "ok-jdk$jdk" > "$out/$name.status"; rm -rf "$work"; exit 0; fi
done
echo failed > "$out/$name.status"; rm -rf "$work"
