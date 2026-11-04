#!/usr/bin/env python3
"""Run Trivy and Grype on the OCI layouts fleetreach pulled, so all three read the same bytes.
usage: scan_others.py <fleetreach report.json> [jobs]"""
import json, os, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
IMGS = os.path.expanduser("~/.cache/fleetreach/images")
report = json.load(open(sys.argv[1]))
jobs = int(sys.argv[2]) if len(sys.argv) > 2 else 6
os.makedirs(f"{HERE}/out", exist_ok=True)


def run(cmd, out):
    if os.path.exists(out) and os.path.getsize(out) > 0:
        return True
    with open(out + ".tmp", "w") as f:
        p = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True, timeout=1800)
    if p.returncode != 0:
        print("FAILED", out, p.stderr[-300:], flush=True)
        os.remove(out + ".tmp")
        return False
    os.rename(out + ".tmp", out)
    return True


def scan(image):
    hexd = image["digest"].split(":")[1]
    repo = image["repo"]
    mount = ["-v", f"{IMGS}:/imgs:ro"]
    trivy = ["docker", "run", "--rm", "-v", "trivy-cache:/root/.cache/trivy", *mount,
             "aquasec/trivy:0.73.0", "image", "--skip-db-update", "--skip-java-db-update",
             "--offline-scan", "--cache-backend", "memory", "--list-all-pkgs", "--scanners", "vuln", "-f", "json", "-q",
             "--input", f"/imgs/layouts/{hexd}"]
    grype = ["docker", "run", "--rm", "-v", "grype-db:/db", "-e", "GRYPE_DB_CACHE_DIR=/db",
             "-e", "GRYPE_DB_AUTO_UPDATE=false", "-e", "GRYPE_CHECK_FOR_APP_UPDATE=false", *mount,
             "anchore/grype:v0.121.1", f"oci-dir:/imgs/layouts/{hexd}", "-o", "json", "-q"]
    a = run(trivy, f"{HERE}/out/trivy-{repo}.json")
    b = run(grype, f"{HERE}/out/grype-{repo}.json")
    print("done" if a and b else "partial", repo, flush=True)


with ThreadPoolExecutor(jobs) as pool:
    list(pool.map(scan, report["provenance"]["images"]))
