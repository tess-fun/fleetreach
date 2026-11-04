#!/usr/bin/env python3
"""Go severities from `scan`, against the records themselves and against Trivy and Grype.

usage: go_severity.py <work dir> <fleetreach> <osv dir> <repo dir>...
Each finding's severity is worked out again from Go/all.zip. Trivy and Grype then rate the same
(module, version, CVE) from their own databases. A finding fleetreach rates below either is
the one to explain: it could pass a gate it should fail. An unknown one cannot, as it fails all.
"""
import collections, json, os, subprocess, sys, zipfile

ORDER = {"unknown": 0, "negligible": 1, "low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4}


def records(osv):
    z = zipfile.ZipFile(f"{osv}/Go/all.zip")
    return {r["id"]: r for r in (json.loads(z.read(n)) for n in z.namelist())
            if not r.get("withdrawn")}


def expected(ids, table):
    """The worst GitHub band over the records sharing an id with `ids`."""
    names = set(ids)
    bands = [ORDER[r["database_specific"]["severity"].lower()] for r in table.values()
             if (r.get("database_specific") or {}).get("severity")
             and names & {r["id"], *(r.get("aliases") or [])}]
    return max(bands, default=0)


def ours(binary, osv, work, base, repo):
    toml = f"{work}/{base}.toml"
    with open(toml, "w") as f:
        f.write(f'[[repo]]\nid = "r"\npath = "{repo}"\necosystem = "go"\n')
    out = subprocess.run([binary, "scan", "--config", toml, "--osv-dir", osv, "--max-db-age",
                          "100000d", "--offline", "--format", "json"], capture_output=True, text=True)
    return json.loads(out.stdout)["vulnerabilities"]


def key(package, version, vuln_id):
    return package.lower(), version.lstrip("v").split("+")[0], vuln_id


def trivy(repo, work):
    out = subprocess.run(["docker", "run", "--rm", "-v", f"{repo}:/src:ro", "-v",
                          f"{work}/trivy-cache:/root/.cache", "aquasec/trivy:0.73.0", "fs", "--quiet",
                          "--scanners", "vuln", "--format", "json", "/src"], capture_output=True, text=True)
    table = {}
    for result in json.loads(out.stdout).get("Results") or []:
        if result.get("Type") == "gomod":
            for v in result.get("Vulnerabilities") or []:
                table[key(v["PkgName"], v["InstalledVersion"], v["VulnerabilityID"])] = v["Severity"].lower()
    return table


def grype(repo):
    out = subprocess.run(["docker", "run", "--rm", "-v", f"{repo}:/src:ro", "anchore/grype:v0.121.1",
                          "dir:/src", "-q", "-o", "json"], capture_output=True, text=True)
    table = {}
    for m in json.loads(out.stdout).get("matches", []):
        a, v = m["artifact"], m["vulnerability"]
        if a["type"] == "go-module":
            ids = [v["id"], *[r["id"] for r in m.get("relatedVulnerabilities", [])]]
            for i in ids:
                table[key(a["name"], a["version"], i)] = v["severity"].lower()
    return table


def main():
    work, binary, osv, repos = os.path.abspath(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4:]
    os.makedirs(f"{work}/trivy-cache", exist_ok=True)
    table = records(osv)
    totals = collections.Counter()
    for repo in repos:
        repo = os.path.abspath(repo)
        findings = ours(binary, osv, work, os.path.basename(repo), repo)
        others = {"trivy": trivy(repo, work), "grype": grype(repo)}
        for v in findings:
            mine = ORDER[v.get("severity", "unknown")]
            ids = [v["advisory_id"], *v["aliases"]]
            totals[f"findings {v.get('severity', 'unknown')}"] += 1
            if mine < expected(ids, table):
                totals["below the records"] += 1
                print("BELOW RECORDS", v["advisory_id"], v.get("severity"))
            for o in v["occurrences"]:
                for tool, rated in others.items():
                    hits = {rated[k] for k in (key(o["package"], o["installed"], i) for i in ids) if k in rated}
                    if not hits:
                        continue
                    theirs = max(ORDER[h] for h in hits)
                    totals[f"{tool} compared"] += 1
                    if mine == 0:
                        # Nothing in the export rates it, and unknown fails every gate.
                        totals[f"{tool} ours unknown"] += 1
                    elif mine == theirs:
                        totals[f"{tool} same"] += 1
                    elif mine > theirs:
                        totals[f"{tool} ours higher"] += 1
                    else:
                        totals[f"{tool} ours lower"] += 1
                        print(f"  {tool} higher:", o["package"], o["installed"], v["advisory_id"],
                              v.get("severity"), sorted(hits))
    print(dict(sorted(totals.items())))


if __name__ == "__main__":
    main()
