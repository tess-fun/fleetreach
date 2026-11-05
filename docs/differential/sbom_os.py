#!/usr/bin/env python3
"""OS findings of an image against those of its Syft and Trivy SBOMs, in CycloneDX and SPDX.

usage: sbom_os.py <fleetreach> <osv dir> <advisory db> <pinned.toml> <dir of SBOMs>

The SBOMs are `<syft|trivy>-<image id>.<cdx|spdx>.json`. All are scanned in one run beside the
images they describe, so a difference is what the SBOM lost. Keys are advisory, source package,
installed version and fix state, and the binaries behind each.
"""
import collections, glob, json, os, re, subprocess, sys, tomllib

BINARY, OSV, DB, PINNED, DIR = sys.argv[1:6]
OS = {"deb", "rpm", "apk"}
pinned = tomllib.load(open(PINNED, "rb"))["image"]
sboms = collections.defaultdict(list)
for path in glob.glob(f"{DIR}/*.json"):
    m = re.match(r"(syft|trivy)-(.+)\.(cdx|spdx)\.json$", os.path.basename(path))
    if m:
        sboms[m[2]].append((f"{m[1]}-{m[3]}", path))

fleet = []
for image in pinned:
    if image["id"] not in sboms:
        continue
    fleet.append(f'[[image]]\nid = "{image["id"]}"\nref = "{image["ref"]}"\n')
    for kind, path in sboms[image["id"]]:
        work = f"{DIR}/repos/{image['id']}--{kind}"
        os.makedirs(work, exist_ok=True)
        fleet.append(f'[[repo]]\nid = "{image["id"]}--{kind}"\npath = "{work}"\nsbom = "{os.path.abspath(path)}"\n')
toml = f"{DIR}/fleet.toml"
open(toml, "w").write("\n".join(fleet))
run = subprocess.run([BINARY, "scan", "-c", toml, "--offline", "--osv-dir", OSV, "--db", DB, "-q", "-f", "json"],
                     capture_output=True, text=True)
if not run.stdout:
    sys.exit(run.stderr[-800:])
report = json.loads(run.stdout)

found = collections.defaultdict(dict)
for v in report["vulnerabilities"]:
    if v.get("ecosystem") not in OS:
        continue
    for o in v["occurrences"]:
        path = o.get("dependency_path") or []
        key = (v["advisory_id"], o["package"], o["installed"], bool(o.get("patched")))
        found[o["repo"]][key] = set(path[2].split(", ")) if len(path) > 2 else set()

gaps = collections.defaultdict(list)
for g in report.get("coverage", {}).get("gaps", []) if isinstance(report.get("coverage"), dict) else report.get("coverage", []):
    gaps[g["repo"]].append(g["reason"])
errored = {o["repo"]: o["status"] for o in report["outcomes"] if "Scanned" not in str(o["status"]) and "scanned" not in str(o["status"])}

totals = collections.Counter()
for image in sorted(sboms):
    want = found.get(image, {})
    for kind, _ in sorted(sboms[image]):
        repo = f"{image}--{kind}"
        got = found.get(repo, {})
        lost, extra = want.keys() - got.keys(), got.keys() - want.keys()
        binaries = sum(1 for k in want.keys() & got.keys() if want[k] != got[k])
        totals["same"] += len(want.keys() & got.keys())
        totals["lost"] += len(lost)
        totals["extra"] += len(extra)
        totals["binaries"] += binaries
        flag = "ok  " if not (lost or extra) else "DIFF"
        print(flag, repo[:60].ljust(60), len(want), len(got), f"lost {len(lost)} extra {len(extra)} binaries {binaries}", errored.get(repo, ""))
        for k in sorted(lost)[:2]:
            print("    lost ", k)
        for k in sorted(extra)[:2]:
            print("    extra", k)
        for reason in gaps.get(repo, []):
            if re.search("OS packages|source packages|several|module stream", reason):
                print("    gap  ", reason[:120])
print(dict(totals))
