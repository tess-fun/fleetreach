#!/bin/sh
# Real Maven's dependency:tree for every project of a corpus, with no network: dependency POMs
# from a Maven-layout folder and plugins from a local repository, both read-only file:// repos.
#
#   run.sh CORPUS_DIR POMS PLUGIN_REPO
#
# Writes CORPUS_DIR/out/pNNN.txt (tree), .log, and .fail when Maven could not resolve it (a POM
# the folder lacks). Then: python3 -I score.py CORPUS_DIR/out SBOM_DIR [OLD_SBOM_DIR]
set -eu
corpus=$1 poms=$2 plugins=$3
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$corpus/out" "$corpus/m2"
docker run --rm --network none \
  -v "$corpus/projects:/src:ro" -v "$here/settings.xml:/settings.xml:ro" \
  -v "$poms:/deps:ro" -v "$plugins:/plugins:ro" \
  -v "$corpus/m2:/root/.m2/repository" -v "$corpus/out:/out" \
  maven:3.9.9-eclipse-temurin-21 sh -c '
    for d in /src/p*; do
      n=$(basename "$d"); mkdir -p "/w/$n"; cp "$d/pom.xml" "/w/$n/"
      (cd "/w/$n" && mvn -q -B -s /settings.xml \
        org.apache.maven.plugins:maven-dependency-plugin:3.7.0:tree -DoutputFile="/out/$n.txt" \
        >"/out/$n.log" 2>&1) || echo FAIL >"/out/$n.fail"
    done'
