#!/usr/bin/env python3
"""Write the snapshot of what CentOS Linux shipped (crates/os/data/centos.tsv), which tells a
Red Hat fix CentOS built from one it never did.

Run once: python3 scripts/update-centos.py
CentOS Linux 6, 7 and 8 have reached their end of life and their final repositories in
vault.centos.org no longer change, so the output is fixed; the script records where it came
from. No fleet data is sent anywhere. Each row is the highest build of a binary package in a
release's final repositories: release, package name, module stream (`-` for a package that is
no module build) and epoch:version-release. Builds are compared with rpm's ordering, checked
against crates/os/tests/data/rpm-pairs.tsv (pairs rpm 4.20 ordered) before anything is written.
"""
import gzip, lzma, os, re, subprocess, sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(__file__)
OUT = os.path.join(HERE, "..", "crates", "os", "data", "centos.tsv")
PAIRS = os.path.join(HERE, "..", "crates", "os", "tests", "data", "rpm-pairs.tsv")
UA = "fleetreach-centos-data (https://github.com/tess-fun/fleetreach)"
VAULT = "https://vault.centos.org/"
# Each release's final point release: its base, updates and extras repositories (PowerTools is
# CentOS 8's CRB).
REPOS = {
    "6": ["6.10/os/x86_64", "6.10/updates/x86_64", "6.10/extras/x86_64"],
    "7": ["7.9.2009/os/x86_64", "7.9.2009/updates/x86_64", "7.9.2009/extras/x86_64"],
    "8": [
        "8.5.2111/BaseOS/x86_64/os", "8.5.2111/AppStream/x86_64/os",
        "8.5.2111/PowerTools/x86_64/os", "8.5.2111/extras/x86_64/os",
    ],
}
NS = {"r": "http://linux.duke.edu/metadata/repo", "c": "http://linux.duke.edu/metadata/common"}


def get(url):
    # curl rather than urllib: it uses the system certificate store everywhere.
    return subprocess.run(
        ["curl", "-fsSL", "--max-time", "300", "-A", UA, url], check=True, capture_output=True
    ).stdout


def rpmvercmp(a, b):
    """rpm's rpmvercmp for one field (version or release)."""
    if a == b:
        return 0
    seg = re.compile(r"(~|\^|[0-9]+|[A-Za-z]+)")
    i = j = 0
    while True:
        # Skip separators: anything but alphanumerics, ~ and ^.
        while i < len(a) and not (a[i].isascii() and a[i].isalnum()) and a[i] not in "~^":
            i += 1
        while j < len(b) and not (b[j].isascii() and b[j].isalnum()) and b[j] not in "~^":
            j += 1
        if (i < len(a) and a[i] == "~") or (j < len(b) and b[j] == "~"):
            if i >= len(a) or a[i] != "~":
                return 1
            if j >= len(b) or b[j] != "~":
                return -1
            i, j = i + 1, j + 1
            continue
        if (i < len(a) and a[i] == "^") or (j < len(b) and b[j] == "^"):
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i, j = i + 1, j + 1
            continue
        if i >= len(a) or j >= len(b):
            break
        x = seg.match(a, i).group(0)
        y = seg.match(b, j).group(0)
        if x.isdigit() != y.isdigit():
            return 1 if x.isdigit() else -1
        i, j = i + len(x), j + len(y)
        if x.isdigit():
            x, y = x.lstrip("0"), y.lstrip("0")
            if len(x) != len(y):
                return 1 if len(x) > len(y) else -1
        if x != y:
            return 1 if x > y else -1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def evr(s):
    e, _, vr = s.rpartition(":")
    v, _, r = vr.partition("-")
    return (int(e or 0), v, r)


def compare(a, b):
    (ea, va, ra), (eb, vb, rb) = evr(a), evr(b)
    if ea != eb:
        return 1 if ea > eb else -1
    return rpmvercmp(va, vb) or (rpmvercmp(ra, rb) if ra and rb else 0)


def check():
    bad = 0
    with open(PAIRS) as f:
        for line in f:
            a, b, want = line.rstrip("\n").split("\t")
            got = {1: ">", 0: "=", -1: "<"}[compare(a, b)]
            bad += got != want
    if bad:
        sys.exit(f"comparator disagrees with rpm on {bad} pairs; nothing written")


def modules(raw):
    """NEVRA -> name:stream for each module build a modules.yaml lists."""
    out = {}
    for doc in raw.decode().split("\n---"):
        if "document: modulemd\n" not in doc:
            continue
        name = re.search(r"^  name: (.+)$", doc, re.M).group(1).strip().strip("\"'")
        stream = re.search(r"^  stream: (.+)$", doc, re.M).group(1).strip().strip("\"'")
        for nevra in re.findall(r"^    - (\S+)$", doc, re.M):
            out[nevra] = f"{name}:{stream}"
    return out


def release(paths):
    best = {}
    for path in paths:
        base = VAULT + path + "/"
        primary, streams = None, {}
        for d in ET.fromstring(get(base + "repodata/repomd.xml")).findall("r:data", NS):
            href = d.find("r:location", NS).get("href")
            if d.get("type") == "primary":
                primary = gzip.decompress(get(base + href))
            elif d.get("type") == "modules":
                raw = get(base + href)
                streams.update(modules(lzma.decompress(raw) if href.endswith(".xz") else raw))
        for p in ET.fromstring(primary).findall("c:package", NS):
            arch = p.find("c:arch", NS).text
            if arch == "src":
                continue
            name = p.find("c:name", NS).text
            v = p.find("c:version", NS)
            build = f"{v.get('epoch') or 0}:{v.get('ver')}-{v.get('rel')}"
            key = (name, streams.get(f"{name}-{build}.{arch}", "-"))
            if key not in best or compare(build, best[key]) > 0:
                best[key] = build
    return best


check()
rows = []
for rel, paths in REPOS.items():
    rows += [(rel, n, s, b) for (n, s), b in release(paths).items()]
rows.sort()
with open(OUT, "w") as f:
    f.write("# CentOS Linux final repositories (vault.centos.org), highest build per package\n")
    f.write("# release\tpackage\tmodule stream\tepoch:version-release\n")
    for row in rows:
        f.write("\t".join(row) + "\n")
print(f"{len(rows)} packages -> {os.path.normpath(OUT)}")
