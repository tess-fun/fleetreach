#!/usr/bin/env python3
"""Check which of fleetreach's VEX documents Trivy and Grype apply to images.

usage: vex_consumers.py <fleetreach binary> <fleet.toml> <advisory-db dir> <out dir>

The fleet names OCI layouts (`[[image]] path = ...`) and `vex_assertion`s on their OS
packages. For OpenVEX (`-f vex`) and CSAF (`-f csaf-vex`) this writes the document, runs
Trivy 0.73.0 and Grype v0.121.1 on every image with it, and prints, per tool and image, the
(CVE, package) pairs each statement set as not_affected should suppress against the pairs
the tool suppressed. A pair the tool does not report at all is listed apart: no VEX can
suppress it.

Needs Docker with the `trivy-cache` and `grype-db` volumes already holding their databases;
the scans run offline. Expected today: Trivy applies both formats; Grype applies OpenVEX and
no CSAF, since it matches a CSAF product only by exact purl with its own qualifiers.
"""
import json, os, re, subprocess, sys

TRIVY = "aquasec/trivy:0.73.0"
GRYPE = "anchore/grype:v0.121.1"


def images(config):
    with open(config) as f:
        text = f.read()
    return re.findall(r'\[\[image\]\]\s*id\s*=\s*"([^"]+)"\s*path\s*=\s*"([^"]+)"', text)


def expected(vex):
    """(repo, CVE, binary) for every not_affected statement of an OpenVEX document."""
    out = set()
    for s in vex["statements"]:
        if s["status"] != "not_affected":
            continue
        ids = [s["vulnerability"]["name"]] + s["vulnerability"].get("aliases", [])
        cves = [i for i in ids if i.startswith("CVE-")]
        repo = next(p["@id"].rsplit(":", 1)[-1] for p in s["products"] if p["@id"].startswith("urn:"))
        for p in s["products"]:
            if p["@id"].startswith("pkg:"):
                name = p["@id"].split("@")[0].rsplit("/", 1)[-1]
                out.update((repo, c, name) for c in cves)
    return out


def trivy(layout, vex_dir, vex_file):
    run = subprocess.run(["docker", "run", "--rm", "-v", "trivy-cache:/root/.cache/trivy",
                          "-v", f"{os.path.dirname(layout)}:/imgs:ro", "-v", f"{vex_dir}:/vex:ro", TRIVY,
                          "image", "--skip-db-update", "--skip-java-db-update", "--offline-scan",
                          "--scanners", "vuln", "--vex", f"/vex/{vex_file}", "--show-suppressed",
                          "-f", "json", "-q", "--input", f"/imgs/{os.path.basename(layout)}"],
                         capture_output=True, text=True)
    d = json.loads(run.stdout)
    found, gone = set(), set()
    for r in d.get("Results", []):
        found.update((v["VulnerabilityID"], v["PkgName"]) for v in r.get("Vulnerabilities", []))
        for m in r.get("ExperimentalModifiedFindings", []) or []:
            gone.add((m["Finding"]["VulnerabilityID"], m["Finding"]["PkgName"]))
    return found | gone, gone


def grype(layout, vex_dir, vex_file):
    run = subprocess.run(["docker", "run", "--rm", "-v", "grype-db:/db",
                          "-v", f"{os.path.dirname(layout)}:/imgs:ro", "-v", f"{vex_dir}:/vex:ro",
                          "-e", "GRYPE_DB_CACHE_DIR=/db", "-e", "GRYPE_DB_AUTO_UPDATE=false",
                          "-e", "GRYPE_DB_VALIDATE_AGE=false", "-e", "GRYPE_CHECK_FOR_APP_UPDATE=false",
                          GRYPE, f"oci-dir:/imgs/{os.path.basename(layout)}", "--vex", f"/vex/{vex_file}",
                          "--show-suppressed", "-o", "json", "-q"], capture_output=True, text=True)
    # Grype can print a log line before the JSON.
    d = json.loads(run.stdout[run.stdout.index("{"):])
    pair = lambda m: (m["vulnerability"]["id"], m["artifact"]["name"])
    found = {pair(m) for m in d["matches"]}
    gone = {pair(m) for m in d.get("ignoredMatches", []) if any(
        "vex" in json.dumps(r).lower() for r in m.get("appliedIgnoreRules", []))}
    return found | gone, gone


def main(binary, config, db, out):
    os.makedirs(out, exist_ok=True)
    out = os.path.abspath(out)
    docs = {}
    for fmt in ("vex", "csaf-vex"):
        path = os.path.join(out, f"fleet.{fmt}.json")
        with open(path, "w") as f:
            run = subprocess.run([binary, "scan", "-c", config, "--offline", "--db", db, "-f", fmt, "-q",
                                  "--vex-author", "security@acme.example",
                                  "--vex-timestamp", "2026-11-12T00:00:00Z"], stdout=f, stderr=subprocess.PIPE,
                                 text=True)
        if run.returncode == 2:
            sys.exit(run.stderr[-500:])
        docs[fmt] = path
    with open(docs["vex"]) as f:
        want = expected(json.load(f))
    for repo, layout in images(config):
        mine = {(c, n) for r, c, n in want if r == repo}
        for fmt, path in docs.items():
            for tool, scan in (("trivy", trivy), ("grype", grype)):
                found, gone = scan(layout, out, os.path.basename(path))
                reported = mine & found
                print(f"{repo} {fmt} {tool}: suppressed {len(reported & gone)} of {len(reported)} "
                      f"asserted pairs it reports ({len(mine - found)} it never reports)")
                for c, n in sorted(reported - gone):
                    print(f"  not applied: {c} {n}")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    main(*sys.argv[1:])
