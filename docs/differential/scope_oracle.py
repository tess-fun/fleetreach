#!/usr/bin/env python3
"""Compare the dev scope in fleetreach SBOMs with what each package manager builds.

usage: scope_oracle.py <fleetreach binary> <osv dir> <work dir> <repo dir>...

Per repo: `cargo tree` for Cargo.lock, `go list` for go.mod, Bundler's own Gemfile evaluation for
Gemfile.lock, and `mix deps` with MIX_ENV=prod for mix.lock, the last two in Docker. A package the tool builds into the
program and fleetreach calls dev is a FALSE DEV, which can hide a finding from a gate, and must
stay at zero. Missed dev packages only cost noise and are counted.
"""
import json, os, pathlib, subprocess, sys


def run(cmd, cwd, env=None):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=900,
                       env={**os.environ, **(env or {})})
    return p.returncode, p.stdout, p.stderr


def ours(binary, osv, work, repo):
    """(name, version) -> dev, per ecosystem, from the CycloneDX `scope`."""
    rid = pathlib.Path(repo).name
    d = pathlib.Path(work) / rid
    d.mkdir(parents=True, exist_ok=True)
    (d / "f.toml").write_text(f'[[repo]]\nid = "{rid}"\npath = "{repo}"\n')
    code, out, err = run([binary, "scan", "-c", str(d / "f.toml"), "--osv-dir", osv, "--offline", "--max-db-age", "100000d",
                          "-f", "json"], d)
    (d / "r.json").write_text(out)
    code, _, err = run([binary, "sbom", "-c", str(d / "f.toml"), "-o", str(d / "o"), "--report",
                        str(d / "r.json")], d)
    # A repo read in part still writes an SBOM, and exits non-zero.
    sbom = json.load(open(d / "o" / f"{rid}.cdx.json"))
    table = {}
    for c in sbom.get("components", []):
        kind = c.get("purl", "").split("/")[0].removeprefix("pkg:")
        table[(kind, c["name"], c.get("version", ""))] = c.get("scope") == "excluded"
    return table


def tree_lines(text):
    out = set()
    for line in text.splitlines():
        bits = line.split()
        if len(bits) >= 2 and bits[1].startswith("v"):
            out.add((bits[0], bits[1][1:]))
    return out


def cargo(repo, table):
    base = ["cargo", "tree", "--locked", "--workspace", "--all-features", "--target", "all",
            "--prefix", "none"]
    code, normal, err = run(base + ["-e", "normal"], repo)
    if code:
        return None
    code, every, err = run(base + ["-e", "normal,dev,build"], repo)
    normal, every = tree_lines(normal), tree_lines(every)
    dev = {(n, v) for (k, n, v), d in table.items() if k == "cargo" and d}
    return dict(tool_normal=len(normal), tool_dev=len(every - normal), ours_dev=len(dev),
                false_dev=sorted(dev & normal), missed=len((every - normal) - dev))


def go(repo, table):
    fmt = "{{with .Module}}{{if not .Main}}{{.Path}}{{end}}{{end}}"
    env = {"GOFLAGS": "-mod=readonly", "GOTOOLCHAIN": "auto"}
    code, normal, err = run(["go", "list", "-e", "-deps", "-f", fmt, "./..."], repo, env)
    if code:
        return None
    code, every, err = run(["go", "list", "-e", "-deps", "-test", "-f", fmt, "./..."], repo, env)
    normal, every = set(normal.split()), set(every.split())
    dev = {n for (k, n, v), d in table.items() if k == "golang" and d}
    return dict(tool_normal=len(normal), tool_dev=len(every - normal), ours_dev=len(dev),
                false_dev=sorted(dev & normal), missed=len((every - normal) - dev))


BUNDLER = """
require 'bundler'; require 'json'
d = Bundler.definition
dev = d.dependencies.select { |x| !x.groups.empty? && (x.groups - [:development, :test]).empty? }
specs = {}
d.locked_gems.specs.each { |s| (specs[s.name] ||= []) << s }
todo = d.locked_gems.dependencies.keys - dev.map(&:name)
seen = {}
until todo.empty?
  name = todo.pop
  next if seen[name]
  seen[name] = true
  (specs[name] || []).each { |s| s.dependencies.each { |x| todo << x.name } }
end
puts JSON.dump(runtime: seen.keys, all: specs.keys)
"""


def bundler(repo, table):
    cmd = ["docker", "run", "--rm", "-v", f"{repo}:/r:ro", "-w", "/r", "-e", "BUNDLE_GEMFILE=/r/Gemfile",
           "-e", "HOME=/tmp", "ruby:3.3-slim", "ruby", "-e", BUNDLER]
    code, out, err = run(cmd, repo)
    if code:
        print(err[-400:])
        return None
    got = json.loads(out.splitlines()[-1])
    normal, every = set(got["runtime"]), set(got["all"])
    dev = {n for (k, n, v), d in table.items() if k == "gem" and d}
    return dict(tool_normal=len(normal), tool_dev=len(every - normal), ours_dev=len(dev),
                false_dev=sorted(dev & normal), missed=len((every - normal) - dev))


MIX = """
cp -r /r /tmp/r && cd /tmp/r && mix local.hex --force >/dev/null && mix local.rebar --force >/dev/null
mix deps.get >/dev/null 2>&1
echo ==all; mix deps 2>/dev/null | grep '^\\* '
echo ==prod; MIX_ENV=prod mix deps 2>/dev/null | grep '^\\* '
"""


def hex_(repo, table):
    cmd = ["docker", "run", "--rm", "-v", f"{repo}:/r:ro", "elixir:1.18", "sh", "-c", MIX]
    code, out, err = run(cmd, repo)
    if "==prod" not in out:
        print(err[-400:])
        return None
    every, normal = out.split("==prod")
    names = lambda text: {l.split()[1] for l in text.splitlines() if l.startswith("* ")}
    normal, every = names(normal), names(every)
    dev = {n for (k, n, v), d in table.items() if k == "hex" and d}
    return dict(tool_normal=len(normal), tool_dev=len(every - normal), ours_dev=len(dev),
                false_dev=sorted(dev & normal), missed=len((every - normal) - dev))


def main():
    binary, osv, work = sys.argv[1:4]
    totals = {}
    for repo in sys.argv[4:]:
        if os.path.exists(os.path.join(repo, "go.mod")):
            run(["go", "mod", "download"], repo, {"GOFLAGS": "-mod=readonly"})
        table = ours(binary, osv, work, repo)
        for name, marker, check in (("cargo", "Cargo.lock", cargo), ("go", "go.mod", go),
                                     ("bundler", "Gemfile.lock", bundler), ("hex", "mix.lock", hex_)):
            if not os.path.exists(os.path.join(repo, marker)):
                continue
            try:
                row = check(repo, table)
            except subprocess.TimeoutExpired:
                row = None
            print(name, pathlib.Path(repo).name, row if row else "tool failed", flush=True)
            if row:
                t = totals.setdefault(name, dict(repos=0, tool_dev=0, ours_dev=0, missed=0, false_dev=0))
                t["repos"] += 1
                for k in ("tool_dev", "ours_dev", "missed"):
                    t[k] += row[k]
                t["false_dev"] += len(row["false_dev"])
    print(totals)


main()
