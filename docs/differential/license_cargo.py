#!/usr/bin/env python3
"""Compare `fleetreach licenses` with `cargo deny list` for Cargo repositories.

usage: license_cargo.py <fleetreach binary> <repo dir>...

Each repo needs a Cargo.lock and its crates in the local registry. Both tools
are asked the same question: which SPDX ids does each crate carry, by name and
version. fleetreach reads with --detect, so a crate with no license field is
filled from its files, which cargo-deny does with askalono.
"""
import json, os, re, subprocess, sys, tempfile

ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")


def ids(expression):
    words = ID.findall(expression or "")
    return {w for w in words if w not in ("AND", "OR", "WITH")}


def deny(repo):
    out = subprocess.run(
        ["cargo", "deny", "--offline", "--all-features", "--manifest-path",
         f"{repo}/Cargo.toml", "list", "-f", "json", "-l", "crate"], capture_output=True, text=True)
    if out.returncode:
        sys.exit(f"{repo}: {out.stderr[-300:]}")
    table = {}
    for key, value in json.loads(out.stdout).items():
        name, version = key.split()[:2]
        # Local crates are the repository's own; an inventory leaves them out.
        if "registry+" in key:
            table[(name, version)] = set().union(set(), *map(ids, value["licenses"]))
    return table


def ours(binary, repo):
    with tempfile.TemporaryDirectory() as work:
        config = f"{work}/fleet.toml"
        with open(config, "w") as f:
            f.write(f'[[repo]]\nid = "r"\npath = "{repo}"\necosystem = "cargo"\n')
        out = subprocess.run([binary, "licenses", "--config", config, "--detect",
                              "--format", "json"], capture_output=True, text=True)
    return {(p["package"], p["version"]): ids(p["license"])
            for p in json.loads(out.stdout)["packages"]}


def main():
    binary, repos = sys.argv[1], sys.argv[2:]
    for repo in repos:
        theirs, mine = deny(repo), ours(binary, os.path.abspath(repo))
        both = sorted(set(theirs) & set(mine))
        same = [k for k in both if theirs[k] == mine[k]]
        print(f"{repo}: deny {len(theirs)}, ours {len(mine)}, both {len(both)}, same {len(same)}")
        for k in both:
            if theirs[k] != mine[k]:
                print("  differ", *k, sorted(mine[k]), "|", sorted(theirs[k]))
        print("  only deny:", len(set(theirs) - set(mine)), "only ours:", len(set(mine) - set(theirs)))
        for k in sorted(set(theirs) - set(mine))[:20]:
            print("  only deny", *k)


if __name__ == "__main__":
    main()
