#!/usr/bin/env python3
"""Compare `licenses --detect -f json` read from local files with the same run from downloads.

usage: license_download.py <local.json> <downloaded.json>

Run the second with CARGO_HOME, GOMODCACHE and NUGET_PACKAGES pointing at an empty directory,
XDG_CACHE_HOME at a fresh one and --download added. A package read both ways must say the same.
"""
import collections, json, sys


def table(path):
    packages = json.load(open(path))["packages"]
    return {(p["repo"], p["ecosystem"], p["package"], p["version"]): p for p in packages}


def main():
    local, downloaded = table(sys.argv[1]), table(sys.argv[2])
    counts, differ = collections.Counter(), []
    for key, package in downloaded.items():
        ecosystem, read = key[1], local.get(key, {}).get("detected")
        counts[ecosystem, "packages"] += 1
        if package.get("detected"):
            counts[ecosystem, "downloaded"] += 1
        if read:
            counts[ecosystem, "read both ways"] += 1
            if package.get("detected") == read:
                counts[ecosystem, "same"] += 1
            else:
                differ.append((key[1:], read, package.get("detected")))
    for ecosystem in sorted({k[0] for k in counts}):
        print(ecosystem, {k[1]: n for k, n in counts.items() if k[0] == ecosystem})
    print(len(differ), "differ")
    for row in differ[:40]:
        print(" ", row)


if __name__ == "__main__":
    main()
