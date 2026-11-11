#!/bin/sh
# Runs every PoV entry not yet done, two containers at a time.
H=$(cd "$(dirname "$0")" && pwd)
cd "${VUL4J_WORK:-$HOME/fa-testbed/vul4j}" || exit 1
python3 -I -c "import csv;[print(r['vul_id']) for r in csv.DictReader(open('repo/dataset/vul4j_dataset.csv')) if not r['vul_id'].endswith('-S')]" |
  while read -r v; do test -f "out/$v/status.json" || echo "$v"; done |
  xargs -P2 -n1 sh "$H/one.sh"
