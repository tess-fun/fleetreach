"""Gradle recall: fleetreach's static read of a Gradle build against what real Gradle resolves.

usage: python3 -I compare.py ORACLE_DIR SBOM_DIR [--misses]

ORACLE_DIR holds run.sh's <repo>.out and <repo>.status; SBOM_DIR holds `fleetreach sbom -f
cyclonedx --maven-fetch` output, <repo>.cdx.json. The oracle set is every external module on
any project's compile, runtime, test-compile or test-runtime classpath. A module counts as found
when fleetreach lists the same group:name at the same version ("exact") or at any version
("name"). Modules Gradle could not resolve are left out of both sides.
"""
import collections
import glob
import json
import os
import sys
import urllib.parse


def oracle(path):
    mods = set()
    for line in open(path, errors="replace"):
        parts = line.split()
        if len(parts) == 4 and parts[0] == "FA":
            g, n, v = parts[3].split(":", 2)
            mods.add((g, n, v))
    return mods


def fleetreach(path):
    mods = set()
    for c in json.load(open(path)).get("components", []):
        purl = c.get("purl", "")
        if not purl.startswith("pkg:maven/"):
            continue
        body = purl[len("pkg:maven/"):].split("?")[0]
        coord, _, version = body.rpartition("@")
        g, _, n = coord.rpartition("/")
        mods.add((urllib.parse.unquote(g), urllib.parse.unquote(n), urllib.parse.unquote(version)))
    return mods


def main():
    odir, sdir = sys.argv[1:3]
    show = "--misses" in sys.argv
    tot = collections.Counter()
    rows = []
    for st in sorted(glob.glob(os.path.join(odir, "*.status"))):
        name = os.path.basename(st)[: -len(".status")]
        if not open(st).read().startswith("ok"):
            tot["failed"] += 1
            continue
        sb = os.path.join(sdir, name + ".cdx.json")
        g = oracle(os.path.join(odir, name + ".out"))
        if not g:
            tot["empty"] += 1
            continue
        f = fleetreach(sb) if os.path.exists(sb) else set()
        fnames = {(a, b) for a, b, _ in f}
        exact = len(g & f)
        named = sum((a, b) in fnames for a, b, _ in g)
        rows.append((name, len(g), exact, named, len(f)))
        tot["repos"] += 1
        tot["oracle"] += len(g)
        tot["exact"] += exact
        tot["named"] += named
        if show:
            for m in sorted(g - f):
                print("MISS", name, ":".join(m), "(other version)" if m[:2] in fnames else "")
    for name, n, e, nm, fr in rows:
        print(f"{name:55s} gradle {n:5d}  exact {e:5d} ({100*e/n:5.1f}%)  name {nm:5d} ({100*nm/n:5.1f}%)  fleetreach {fr}")
    if tot["oracle"]:
        print(f"\n{tot['repos']} repos, {tot['failed']} failed to resolve, {tot['empty']} empty: "
              f"{tot['oracle']} modules, exact {tot['exact']} ({100*tot['exact']/tot['oracle']:.1f}%), "
              f"by name {tot['named']} ({100*tot['named']/tot['oracle']:.1f}%)")


if __name__ == "__main__":
    main()
