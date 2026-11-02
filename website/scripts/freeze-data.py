"""Freeze the advisory data behind the website's demo fleet.

Copies, from a full osv.dev export cache and a RustSec advisory-db clone, every record that
names a package the demo fleet (fleet.toml, and the one-ecosystem fleets in ecosystems/) uses,
into website/demo/data. The examples are then generated
against that frozen copy, so they only change when fleetreach does.

    python3 -I website/scripts/freeze-data.py ~/.cache/fleetreach/osv ~/.cargo/advisory-db

With --only, only the named osv.dev ecosystems are frozen again and everything else in
website/demo/data is left as it is, so adding an ecosystem does not move the other examples:

    python3 -I website/scripts/freeze-data.py ~/.cache/fleetreach/osv --only Hex,Julia

Run from the repository root, with a fleetreach binary on PATH (or FLEETREACH=<path>).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "demo")
DATA = os.path.join(DEMO, "data")

# purl type -> osv.dev ecosystem directory
ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "gem": "RubyGems",
    "golang": "Go",
    "githubactions": "GitHub Actions",
    "maven": "Maven",
    "composer": "Packagist",
    "nuget": "NuGet",
    "swift": "SwiftURL",
    "hex": "Hex",
    "julia": "Julia",
}


def norm(eco, name):
    name = name.lower()
    if eco == "PyPI":
        name = name.replace("_", "-").replace(".", "-")
    return name


def configs():
    eco = os.path.join(DEMO, "ecosystems")
    return [os.path.join(DEMO, "fleet.toml")] + [
        os.path.join(eco, f) for f in sorted(os.listdir(eco)) if f.endswith(".toml")
    ]


def fleet_packages(binary):
    """{ecosystem dir: {normalised name}} and the set of crate names, from per-repo SBOMs."""
    scratch = tempfile.mkdtemp()
    # A fresh HOME and cache: the POMs the Java repo needs are fetched into the cache, then
    # kept as data/m2, which the examples use as the local Maven repository.
    env = dict(os.environ, HOME=scratch, XDG_CACHE_HOME=scratch, FLEETREACH_OSV_SYNC="off")
    boms = []
    for i, config in enumerate(configs()):
        out = os.path.join(scratch, f"out{i}")
        subprocess.run(
            [binary, "sbom", "-q", "--maven-fetch", "-c", config, "-o", out], check=True, env=env
        )
        boms += [os.path.join(out, f) for f in os.listdir(out)]
    poms = os.path.join(scratch, "fleetreach", "maven")
    names, crates = {}, set()
    for f in boms:
        bom = json.load(open(f))
        for c in bom.get("components", []):
            purl = c.get("purl", "")
            kind = purl[4:].split("/", 1)[0]
            if kind == "cargo":
                crates.add(c["name"])
            elif kind in ECOSYSTEMS:
                eco = ECOSYSTEMS[kind]
                sep = ":" if eco == "Maven" else "/"
                full = c["name"] if not c.get("group") else c["group"] + sep + c["name"]
                names.setdefault(eco, set()).add(norm(eco, full))
    return names, crates, scratch, poms


def freeze_osv(cache, names):
    for eco, wanted in sorted(names.items()):
        dest = os.path.join(DATA, "osv", eco)
        os.makedirs(dest, exist_ok=True)
        kept = 0
        with zipfile.ZipFile(os.path.join(cache, eco, "all.zip")) as z:
            for entry in z.namelist():
                record = json.loads(z.read(entry))
                if record.get("withdrawn"):
                    continue
                if any(
                    norm(eco, a.get("package", {}).get("name", "")) in wanted
                    for a in record.get("affected", [])
                ):
                    with open(os.path.join(dest, record["id"] + ".json"), "w") as f:
                        json.dump(record, f, indent=1, sort_keys=True)
                        f.write("\n")
                    kept += 1
        print(f"{eco}: {kept} records for {len(wanted)} packages")


def freeze_rustsec(db, crates):
    dest = os.path.join(DATA, "advisory-db")
    kept = 0
    for crate in sorted(crates):
        src = os.path.join(db, "crates", crate)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(dest, "crates", crate))
            kept += len(os.listdir(src))
    print(f"RustSec: {kept} advisories for {len(crates)} crates")


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def curl(url):
    return subprocess.run(["curl", "-fsSL", url], check=True, capture_output=True).stdout


def fleet_cves(binary):
    """The CVE ids of every finding on the frozen data."""
    scratch = tempfile.mkdtemp()
    env = dict(
        os.environ,
        HOME=scratch,
        XDG_CACHE_HOME=scratch,
        FLEETREACH_OSV_SYNC="off",
        MAVEN_REPO_LOCAL=os.path.join(DATA, "m2"),
    )
    report = subprocess.run(
        [binary, "scan", "-q", "-f", "json", "--offline",
         "--db", os.path.join(DATA, "advisory-db"), "--osv-dir", os.path.join(DATA, "osv")],
        cwd=DEMO, env=env, capture_output=True, check=False,
    ).stdout
    shutil.rmtree(scratch)
    cves = set()
    for v in json.loads(report)["vulnerabilities"]:
        cves.update(a for a in [v["advisory_id"], *v.get("aliases", [])] if a.startswith("CVE-"))
    return sorted(cves)


def freeze_signals(cves):
    """The KEV entries and EPSS scores for the fleet's CVEs, as --kev-file / --epss-file."""
    kev = json.loads(curl(KEV_URL))
    kev["vulnerabilities"] = [v for v in kev["vulnerabilities"] if v["cveID"] in set(cves)]
    kev["count"] = len(kev["vulnerabilities"])
    with open(os.path.join(DATA, "kev.json"), "w") as f:
        json.dump(kev, f, indent=1)
        f.write("\n")
    rows, header = [], None
    for i in range(0, len(cves), 100):
        page = json.loads(curl(EPSS_URL + "?limit=100&cve=" + ",".join(cves[i : i + 100])))
        header = header or page["data"][0]["date"]
        rows += [(d["cve"], d["epss"], d["percentile"]) for d in page["data"]]
    with open(os.path.join(DATA, "epss.csv"), "w") as f:
        f.write(f"#model_version:api,score_date:{header}T00:00:00Z\n")
        f.write("cve,epss,percentile\n")
        for row in sorted(rows):
            f.write(",".join(row) + "\n")
    print(f"KEV: {kev['count']} of {len(cves)} CVEs; EPSS: {len(rows)} scores")


def main():
    binary = os.environ.get("FLEETREACH", "fleetreach")
    if len(sys.argv) == 4 and sys.argv[2] == "--only":
        only = sys.argv[3].split(",")
        names, _, scratch, _ = fleet_packages(binary)
        shutil.rmtree(scratch)
        for eco in only:
            shutil.rmtree(os.path.join(DATA, "osv", eco), ignore_errors=True)
        freeze_osv(sys.argv[1], {e: names.get(e, set()) for e in only})
        return
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    names, crates, scratch, poms = fleet_packages(binary)
    shutil.rmtree(DATA, ignore_errors=True)
    freeze_osv(sys.argv[1], names)
    freeze_rustsec(sys.argv[2], crates)
    shutil.copytree(poms, os.path.join(DATA, "m2"))
    shutil.rmtree(scratch)
    os.makedirs(os.path.join(DATA, "advisory-db", "rust"), exist_ok=True)
    open(os.path.join(DATA, "advisory-db", "rust", ".keep"), "w").close()
    freeze_signals(fleet_cves(binary))


if __name__ == "__main__":
    main()
