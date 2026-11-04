#!/usr/bin/env python3
"""Fixture PRs for `diff --base`, one per ecosystem, from real lockfiles and real scans.

Each repo holds a vulnerable package. The base commit has that entry at its fixed version and
the PR commit puts the vulnerable one back; `diff --base` must name the entry. Then the
reverse: a baseline without the finding but no change in git must not gate.

usage: pr_attribution.py <fleetreach> <osv dir> <fixtures.toml> [more fixture dirs...]
Fixture dirs are read as `[[repo]]` paths of the fleet file; synthetic ones are written here.
"""
import json, os, pathlib, re, shutil, subprocess, sys, tempfile, tomllib

FLEETREACH, OSV, FLEET = sys.argv[1], sys.argv[2], sys.argv[3]

LOCKS = re.compile(r"\.lock(file)?$|^(package-lock\.json|pnpm-lock\.yaml|packages\.lock\.json|pylock\.toml|"
                   r"go\.mod|pom\.xml|Manifest\.toml|Package\.resolved)$")

SYNTHETIC = {
    "cargo": {"Cargo.lock": 'version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = [\n "time",\n]\n\n[[package]]\nname = "time"\nversion = "0.1.43"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
              "Cargo.toml": '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\ntime = "0.1"\n'},
    "go": {"go.mod": "module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.0\n"},
    "maven": {"pom.xml": '<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>a</groupId>\n  <artifactId>b</artifactId>\n  <version>1</version>\n  <dependencies>\n    <dependency>\n      <groupId>org.apache.logging.log4j</groupId>\n      <artifactId>log4j-core</artifactId>\n      <version>2.14.1</version>\n    </dependency>\n  </dependencies>\n</project>\n'},
    "swift": {"Package.resolved": '{\n  "pins" : [\n    {\n      "identity" : "vapor",\n      "kind" : "remoteSourceControl",\n      "location" : "https://github.com/vapor/vapor.git",\n      "state" : {\n        "revision" : "aaaa",\n        "version" : "4.40.0"\n      }\n    }\n  ],\n  "version" : 2\n}\n'},
    "actions": {".github/workflows/ci.yml": "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: tj-actions/changed-files@v35\n"},
    "julia": {"Manifest.toml": 'julia_version = "1.10.0"\nmanifest_format = "2.0"\n\n[[deps.HTTP]]\ndeps = ["Base64"]\ngit-tree-sha1 = "abc"\nuuid = "cd3eb016-35fb-5094-929b-558a96fad6f3"\nversion = "1.5.0"\n', "Project.toml": '[deps]\nHTTP = "cd3eb016-35fb-5094-929b-558a96fad6f3"\n'},
}


def sh(cwd, *args):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout


def scan(path, name, out):
    fleet = pathlib.Path(out).with_suffix(".toml")
    fleet.write_text(f'[[repo]]\nid = "{name}"\npath = "{path}"\n')
    with open(out, "w") as f:
        subprocess.run([FLEETREACH, "scan", "-c", str(fleet), "--offline", "--osv-dir", OSV,
                        "--format", "json", "--quiet"], stdout=f, stderr=subprocess.DEVNULL)
    return json.load(open(out))


def findings(report):
    for v in report["vulnerabilities"]:
        for o in v["occurrences"]:
            if o.get("kind") == "in_repo":
                yield v, o


def fixed_version(o):
    for p in o.get("patched") or []:
        m = re.match(r">=\s*v?([0-9][^, ]*)", p)
        if m:
            return m.group(1)


def rewind(root, package, version, fixed):
    """Puts `fixed` where the package's entry holds `version`. Returns the file changed."""
    short = re.split(r"[:/]", package)[-1]
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file() or ".git/" in str(path):
            continue
        if not LOCKS.search(path.name) and ".github/workflows" not in str(path):
            continue
        try:
            lines = path.read_text().split("\n")
        except UnicodeDecodeError:
            continue
        hit = False
        spellings = [version, re.sub(r"(\.0)+$", "", version)]
        for i, line in enumerate(lines):
            if short.lower() not in line.lower():
                continue
            # Every entry: pnpm repeats one under `snapshots`, NuGet under its dependents.
            for j in range(i, min(i + 12, len(lines))):
                said = next((v for v in spellings
                             if re.search(rf"(?<![\w.])v?{re.escape(v)}(?![\w.-])", lines[j])), None)
                if said:
                    lines[j] = lines[j].replace(said, fixed)
                    hit = True
                    break
        if hit:
            path.write_text("\n".join(lines))
            return path.relative_to(root)
    return None


def run(name, source, tmp):
    work = pathlib.Path(tmp) / name
    shutil.copytree(source, work, symlinks=True, ignore=shutil.ignore_patterns(".git", "node_modules"))
    head = scan(work, name, f"{tmp}/{name}-head.json")
    picks = [(v, o) for v, o in findings(head) if fixed_version(o)]
    picks.sort(key=lambda p: (p[1].get("dependency_kind") != "direct", p[0]["advisory_id"]))
    if not picks:
        return name, "SKIP no finding with a fix", None
    for v, o in picks:
        sh(work, "git", "init", "-q", "-b", "main")
        sh(work, "git", "add", "-Af", ".")
        sh(work, "git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "pr", "--allow-empty")
        original = {p: p.read_bytes() for p in work.rglob("*") if p.is_file() and not p.is_symlink() and ".git/" not in str(p) and LOCKS.search(p.name)} | {p: p.read_bytes() for p in work.glob(".github/workflows/*") if p.is_file()}
        changed = rewind(work, o["package"], o["installed"], fixed_version(o))
        if not changed:
            shutil.rmtree(work / ".git")
            continue
        sh(work, "git", "add", "-Af", ".")
        sh(work, "git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base", "--allow-empty")
        sh(work, "git", "branch", "base")
        base = scan(work, name, f"{tmp}/{name}-base.json")
        for p, b in original.items():
            p.write_bytes(b)
        sh(work, "git", "add", "-Af", ".")
        sh(work, "git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "pr2", "--allow-empty")
        diff = subprocess.run([FLEETREACH, "diff", f"{tmp}/{name}-base.json", f"{tmp}/{name}-head.json",
                               "--base", "base", "--checkout", str(work), "--format", "json"],
                              capture_output=True, text=True)
        if diff.returncode == 2 or diff.returncode == 3:
            return name, f"FAIL exit {diff.returncode}: {diff.stderr[:200]}", None
        rows = json.loads(diff.stdout)["attribution"]
        hit = [r for r in rows if r["advisory_id"] == v["advisory_id"] and r["package"] == o["package"]]
        if not hit:
            shutil.rmtree(work / ".git")
            continue  # the fixed version carried the same advisory on: try another finding
        r = hit[0]
        placed = r.get("at", {})
        ok = r["origin"] == "introduced" and placed.get("file") == str(changed) and diff.returncode == 1
        line = ""
        if placed.get("line"):
            line = (work / placed["file"]).read_text().split("\n")[placed["line"] - 1].strip()[:50]
        # The reverse: the same report, no git change since the base.
        sh(work, "git", "branch", "-f", "base", "HEAD")
        rev = subprocess.run([FLEETREACH, "diff", f"{tmp}/{name}-base.json", f"{tmp}/{name}-head.json",
                              "--base", "base", "--checkout", str(work), "--format", "json"],
                             capture_output=True, text=True)
        back = [x for x in json.loads(rev.stdout)["attribution"] if x["advisory_id"] == v["advisory_id"]]
        existing = all(x["origin"] == "existing" for x in back)
        others = [x["origin"] for x in rows if x is not r]
        for x in rows:
            if x["origin"] == "unknown":
                print("  unknown:", x["advisory_id"], x["package"], x["version"])
        # A Maven build without a lockfile names only direct dependencies; a transitive
        # package is in no file, so it stays unknown and gates.
        placed_all = "unknown" not in others or name == "maven"
        status = "ok" if ok and existing and placed_all else "FAIL"
        return name, status, f'{o["package"]}@{o["installed"]} {placed} [{line}] cause={r.get("cause")} rev={[x["origin"] for x in back][:2]} others={len(others)} unknown={others.count("unknown")} rc={diff.returncode}/{rev.returncode}'
    return name, "SKIP no rewindable finding", None


def main():
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        cases = []
        for repo in tomllib.load(open(FLEET, "rb")).get("repo", []):
            base = pathlib.Path(FLEET).parent
            cases.append((repo["id"], base / repo["path"]))
        for name, files in SYNTHETIC.items():
            src = pathlib.Path(tmp) / "src" / name
            for f, text in files.items():
                (src / f).parent.mkdir(parents=True, exist_ok=True)
                (src / f).write_text(text)
            cases.append((name, src))
        for name, source in cases:
            name, status, detail = run(name, source, tmp)
            failed += status.startswith("FAIL")
            print(f"{status:<6} {name}: {detail}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
