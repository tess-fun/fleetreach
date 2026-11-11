#!/bin/sh
# Remaps the sinks of every done entry (sinks.py) in one container.
H=$(cd "$(dirname "$0")" && pwd)
cd "${VUL4J_WORK:-$HOME/fa-testbed/vul4j}" || exit 1
docker run --rm --platform linux/amd64 -v "$PWD/out:/out" -v "$H:/h:ro" vul4j:oracle sh -c \
  'for d in /out/VUL4J-*; do grep -q "\"stage\": \"done\"" $d/status.json 2>/dev/null && python3 /h/sinks.py $d /opt/jdks/jdk11; done'
