#!/usr/bin/env python3
"""Refresh the popular-package name lists behind the typosquat signal (crates/cli/data/popular).

Run at release time: python3 scripts/update-popular.py
Sources (public, downloaded as whole lists; no fleet data is sent anywhere):
  npm   - npm-high-impact (most depended-on and downloaded npm packages), via unpkg
  PyPI  - top-pypi-packages (30-day downloads) by Hugo van Kemenade
  Cargo - crates.io API, crates sorted by all-time downloads (top 5,000)
"""
import json, os, re, subprocess, time

OUT = os.path.join(os.path.dirname(__file__), "..", "crates", "cli", "data", "popular")
UA = {"User-Agent": "fleetreach-popular-data (https://github.com/tess-fun/fleetreach)"}

def get(url):
    # curl rather than urllib: it uses the system certificate store everywhere.
    return subprocess.run(
        ["curl", "-fsSL", "--max-time", "60", "-A", UA["User-Agent"], url],
        check=True, capture_output=True, text=True,
    ).stdout

def write(name, names):
    names = sorted({n.strip() for n in names if n.strip()})
    with open(os.path.join(OUT, name), "w") as f:
        f.write("\n".join(names) + "\n")
    print(f"{name}: {len(names)} names")

npm = re.findall(r"'([^']+)'", get("https://unpkg.com/npm-high-impact@1/lib/top.js"))
write("npm.txt", npm)
pypi = [r["project"] for r in json.loads(get("https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"))["rows"]]
write("pypi.txt", pypi)
crates = []
for page in range(1, 51):
    data = json.loads(get(f"https://crates.io/api/v1/crates?sort=downloads&per_page=100&page={page}"))
    crates += [c["name"] for c in data["crates"]]
    time.sleep(1.1)  # crates.io asks for at most one request per second
write("cargo.txt", crates)
