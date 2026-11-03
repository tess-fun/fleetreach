#!/usr/bin/env python3
"""Refresh the OS end-of-life snapshot behind image scans' end-of-life warnings
(crates/os/data/eol.tsv).

Run at release time: python3 scripts/update-eol.py
Source: endoflife.date (https://endoflife.date, data MIT-licensed), one public product list per
distribution; no fleet data is sent anywhere. Each row is a release: product, cycle, the end of
its free security support (`eol`, a date or `ended` when the date is unknown) and the end of
paid extended support (ELTS, ESM, ELS, LTSS) when there is one. Releases still supported with
no end date are left out.
"""
import datetime, json, os, subprocess

OUT = os.path.join(os.path.dirname(__file__), "..", "crates", "os", "data", "eol.tsv")
UA = "fleetreach-eol-data (https://github.com/tess-fun/fleetreach)"
# The endoflife.date products for the distributions `fleetreach_os::eol` maps os-release to.
PRODUCTS = [
    "almalinux", "alpine-linux", "amazon-linux", "centos", "centos-stream", "debian", "fedora",
    "mageia", "opensuse", "oracle-linux", "photon", "rhel", "rocky-linux", "sles",
    "suse-linux-micro", "ubuntu",
]

def get(url):
    # curl rather than urllib: it uses the system certificate store everywhere.
    return subprocess.run(
        ["curl", "-fsSL", "--max-time", "60", "-A", UA, url],
        check=True, capture_output=True, text=True,
    ).stdout

def date(v):
    return v if isinstance(v, str) else None

rows = []
for product in PRODUCTS:
    for c in json.loads(get(f"https://endoflife.date/api/{product}.json")):
        eol = c.get("eol")
        if eol is True:
            eol = "ended"
        elif not isinstance(eol, str):
            continue
        extended = date(c.get("extendedSupport")) or "-"
        rows.append((product, str(c["cycle"]), eol, extended))
rows.sort()
with open(OUT, "w") as f:
    f.write(f"# endoflife.date snapshot {datetime.date.today().isoformat()}, MIT-licensed data.\n")
    f.write("# Regenerate with scripts/update-eol.py. product, cycle, eol, extended support.\n")
    for r in rows:
        f.write("\t".join(r) + "\n")
print(f"eol.tsv: {len(rows)} releases")
