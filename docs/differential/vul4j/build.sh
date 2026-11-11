#!/bin/sh
# Builds vul4j:oracle. vul4j is GPL-3, so its Dockerfile is not copied here: this clones it at
# the commit the corpus used, edits the clone's Dockerfile, and adds JaCoCo on top.
#   - the two warmup RUN lines go: they reproduce all 79 entries at build time;
#   - the virtualenv moves to /opt/vul4j-venv, outside the copied source tree.
set -e
H=$(cd "$(dirname "$0")" && pwd)
W=${VUL4J_WORK:-$HOME/fa-testbed/vul4j}
mkdir -p "$W"
cd "$W"
test -d repo || git clone https://github.com/tuhh-softsec/vul4j repo
git -C repo checkout -q bca934d14bad4743eb27c944e3365cdeae8d9764
awk '/^RUN vul4j-warmup$/ || /^RUN rm -rf \/root\/vul4j_data\/reproduction / { next }
  /^RUN uv sync --frozen --no-dev$/ { print "ENV UV_PROJECT_ENVIRONMENT=/opt/vul4j-venv" }
  { sub("^ENV PATH=/vul4j/.venv/bin:", "ENV PATH=/opt/vul4j-venv/bin:"); print }' \
  repo/Dockerfile > repo/Dockerfile.base
docker build --platform linux/amd64 -f repo/Dockerfile.base -t vul4j:base repo
docker build --platform linux/amd64 -t vul4j:oracle "$H"
