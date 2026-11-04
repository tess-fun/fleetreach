#!/usr/bin/env python3
"""Licenses detected from package text, against ScanCode Toolkit on the same files.

usage: license_text.py <work dir> <license_text example> <count> <package dir>...
Copies the license files of `count` package directories, spread evenly, into <work dir>/pkgs and
runs ScanCode over them (image `scancode:local`: linux/amd64 python:3.12-slim with the release
tarball of 32.5.0 unpacked; `pip install scancode-toolkit` gives a broken plugin set). A package is agreed when both name the same ids, read past what a text cannot
say (`-only`, `-or-later`). `scancode.json` is kept, so a second run only compares.
"""
import collections, json, os, re, shutil, subprocess, sys

NAMES = re.compile(r"^(licen[cs]e|copying|unlicense|copyright|.*-license)", re.I)
EXT = ("", ".txt", ".md", ".markdown", ".rst", ".lesser", ".mit", ".apache", ".bsd", ".gpl", ".lgpl", ".mpl")


def family(i):
    return re.sub(r"(-only|-or-later|\+)$", "", i)


def collect(dirs, count, root):
    os.makedirs(root, exist_ok=True)
    have = []
    for d in filter(os.path.isdir, dirs):
        names = [n for n in os.listdir(d) if NAMES.match(n) and os.path.splitext(n)[1].lower() in EXT
                 and os.path.isfile(os.path.join(d, n))]
        if names:
            have.append((d, names))
    step = max(1, len(have) // count)
    picked = have[::step][:count]
    for i, (d, names) in enumerate(picked):
        target = f"{root}/{i}"
        os.makedirs(target, exist_ok=True)
        for n in names:
            shutil.copy(os.path.join(d, n), target)
    return [p[0] for p in picked]


def scancode(work):
    if os.path.exists(f"{work}/scancode.json"):
        return
    subprocess.run(["docker", "run", "--rm", "--platform", "linux/amd64", "-v", f"{work}:/w",
                    "scancode:local", "scancode",
                    "--license", "-n", "6", "--timeout", "60", "--json", "/w/scancode.json",
                    "/w/pkgs"], check=True, capture_output=True)


def theirs(work):
    out = collections.defaultdict(set)
    doc = json.load(open(f"{work}/scancode.json"))
    for f in doc["files"]:
        parts = f["path"].split("/")
        if f["type"] != "file" or len(parts) < 3:
            continue
        spdx = f.get("detected_license_expression_spdx") or ""
        out[parts[1]].update(re.findall(r"[A-Za-z0-9.+-]+", spdx.replace("(", " ").replace(")", " ")))
    return {k: {family(i) for i in v - {"AND", "OR", "WITH"}} for k, v in out.items()}


def main():
    work, binary, count = os.path.abspath(sys.argv[1]), sys.argv[2], int(sys.argv[3])
    listing = f"{work}/picked.json"
    os.makedirs(work, exist_ok=True)
    if os.path.exists(listing):
        picked = json.load(open(listing))
    else:
        picked = collect(sys.argv[4:], count, f"{work}/pkgs")
        json.dump(picked, open(listing, "w"))
    scancode(work)
    their = theirs(work)
    args = [binary, *[f"{work}/pkgs/{i}" for i in range(len(picked))]]
    totals, pairs = collections.Counter(), collections.Counter()
    samples = {}
    for line in subprocess.run(args, capture_output=True, text=True).stdout.splitlines():
        row = json.loads(line)
        i = os.path.basename(row["dir"])
        mine = {family(x) for x in row["ids"]}
        other = their.get(i, set())
        lic_ref = {x for x in other if x.startswith("LicenseRef-")}
        totals["packages"] += 1
        if mine == other:
            kind = "agreed"
        elif not mine and row["unrecognized"]:
            kind = "unrecognized by us"
        elif mine and other - lic_ref and mine < other:
            kind = "ours a subset"
        elif mine and other > mine:
            kind = "ours a subset"
        elif other and mine > other:
            kind = "theirs a subset"
        elif mine & other:
            kind = "overlap"
        elif not other:
            kind = "nothing from scancode"
        else:
            kind = "DISAGREE"
        totals[kind] += 1
        if kind != "agreed":
            k = (kind, tuple(sorted(mine)), tuple(sorted(other)))
            pairs[k] += 1
            samples.setdefault(k, picked[int(i)])
    for k, n in pairs.most_common(45):
        print(n, k[0], list(k[1]), "|", list(k[2]), os.path.basename(samples[k]))
    print(dict(totals))


if __name__ == "__main__":
    main()
