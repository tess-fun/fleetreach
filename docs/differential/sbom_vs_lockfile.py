#!/usr/bin/env python3
"""A Go or Rust repo scanned from its lockfiles and from Syft's and Trivy's SBOMs of it.

usage: sbom_vs_lockfile.py <work dir> <fleetreach> <osv dir> <repo dir>...
A finding the lockfiles give and an SBOM does not is a false clean to explain, the Trivy runs
above all, since Trivy lowercases Go module paths. A difference is only ever a difference in
what the generator listed, so each is checked against the components the SBOM holds.
"""
import collections, json, os, subprocess, sys
from urllib.parse import unquote

ECOSYSTEMS = {"go", "cargo"}


def scan(binary, osv, work, name, repo, extra):
    toml = f"{work}/{name}.toml"
    with open(toml, "w") as f:
        f.write(f'[[repo]]\nid = "r"\npath = "{repo}"\nglob = true\nglob_max_depth = 8\n{extra}')
    out = subprocess.run([binary, "scan", "--config", toml, "--osv-dir", osv, "--max-db-age",
                          "100000d", "--offline", "--format", "json"], capture_output=True, text=True)
    if out.returncode not in (0, 1):
        print("  FAILED", name, out.stderr[-300:])
    doc = json.loads(out.stdout or "{}")
    found = set()
    for v in doc.get("vulnerabilities", []):
        if v.get("ecosystem", "cargo") in ECOSYSTEMS:
            for o in v["occurrences"]:
                found.add((v["advisory_id"], o["package"].lower(), o["installed"]))
    return found


def generate(cmd, path):
    with open(path, "wb") as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL, check=True)


def main():
    work, binary, osv, repos = os.path.abspath(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4:]
    os.makedirs(f"{work}/trivy-cache", exist_ok=True)
    totals = collections.Counter()
    for repo in repos:
        repo = os.path.abspath(repo)
        base = os.path.basename(repo)
        lock = scan(binary, osv, work, f"{base}-lock", repo, "")
        print(f"{repo}: lockfiles {len(lock)}")
        runs = {
            "syft": ["docker", "run", "--rm", "-v", f"{repo}:/src:ro", "anchore/syft:latest",
                     "dir:/src", "-q", "-o", "cyclonedx-json"],
            "trivy": ["docker", "run", "--rm", "-v", f"{repo}:/src:ro", "-v",
                      f"{work}/trivy-cache:/root/.cache", "aquasec/trivy:0.73.0", "fs", "--quiet",
                      "--format", "cyclonedx", "/src"],
        }
        for tool, cmd in runs.items():
            path = f"{work}/{base}-{tool}.cdx.json"
            generate(cmd, path)
            got = scan(binary, osv, work, f"{base}-{tool}", repo, f'sbom = "{path}"\n')
            missing, extra = sorted(lock - got), sorted(got - lock)
            text = unquote(open(path).read()).lower()
            # A package the SBOM never listed at that version is the generator's doing.
            unlisted = [m for m in missing
                        if f"{m[1]}@{m[2]}" not in text and f"{m[1]}@v{m[2]}" not in text]
            print(f"  {tool}: {len(got)} common={len(lock & got)} "
                  f"missing={len(missing)} (unlisted {len(unlisted)}) extra={len(extra)}")
            for m in [m for m in missing if m not in unlisted][:8]:
                print("    MISSING", m)
            for e in extra[:4]:
                print("    extra", e)
            totals["common"] += len(lock & got)
            totals["missing"] += len(missing)
            totals["unexplained"] += len(missing) - len(unlisted)
            totals["extra"] += len(extra)
    print(dict(totals))


if __name__ == "__main__":
    main()
