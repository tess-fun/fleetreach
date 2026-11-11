#!/bin/sh
# One entry in a throwaway container. The Maven local repository is shared (volume vul4j-m2) and
# Central comes from Google's mirror, as Central rate-limits fresh containers.
H=$(cd "$(dirname "$0")" && pwd)
cd "${VUL4J_WORK:-$HOME/fa-testbed/vul4j}" || exit 1
mkdir -p out err
docker run --rm --platform linux/amd64 -v vul4j-m2:/root/.m2/repository \
  -v "$H/settings.xml:/root/.m2/settings.xml:ro" -v "$PWD/out:/out" \
  -v "$H:/h:ro" vul4j:oracle timeout 3600 python3 /h/oracle.py "$1" >/dev/null 2>"err/$1.err"
echo "$1 $(test -f "out/$1/status.json" && echo done || echo failed)"
