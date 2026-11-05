#!/usr/bin/env python3
"""Checks the range checks behind `fix plan` against the real tools.

usage: fix_constraints.py ranges <example> <semver dir> <root with package-lock.json files>
       fix_constraints.py npm <example> <work dir> <root> [cases]
       fix_constraints.py cargo <example> <work dir> <root> [cases]

`ranges` compares the npm range evaluator with npm's bundled `semver` on every range in the
locks, against versions on both sides of each. `npm` and `cargo` take real locks and real
published versions: a lock bump must be what `npm update` or `cargo update --precise` then
does, a manifest bump must work once the range is raised, and a blocked edit must really fail
to move. <example> is the built `fix_constraints` example. Reads registry metadata, runs no
package code.
"""
import concurrent.futures, json, os, random, re, shutil, subprocess, sys, tempfile, urllib.parse


def locks(root, name):
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "target")]
        if name in files:
            yield os.path.join(base, name)


def ranges(example, semver_dir, root):
    found = set()
    for path in locks(root, "package-lock.json"):
        try:
            lock = json.load(open(path))
        except ValueError:
            continue
        for entry in (lock.get("packages") or {}).values():
            for section in ("dependencies", "peerDependencies", "devDependencies"):
                found.update((entry.get(section) or {}).values())
    extra = ["*", "", "x", "1", "1.x", "1.2.x", "~1", "~1.2", "^0", "^0.0", "^0.0.0", "^0.0.1",
             "^1.2.3-rc.1", "~1.2.3-beta.2", ">1", ">1.2", ">=1.2", "<1.2", "<=1.2", "<=1", ">*",
             "<*", "1.2.3 - 2", "1 - 2.3.4", "1.2 - 2.3", ">= 1.2.3 < 2", "> 1, < 2", "=1.2.3",
             "v1.2.3", "=v1.2.3", "~>1.2", "1.2.3+build", "^1.2.3+build", "1.x.3", ">=1.0.0-0",
             ">=1.0.0-rc.1 <2", "1.2.3-alpha || 2", "||", "1 ||", "|| 2", "01.2.3", "1.2.3.4",
             "latest", "next", "a.b.c", "npm:x@1", "git+ssh://x/y", "file:a", "workspace:^"]
    found.update(extra)
    pairs = set()
    rng = random.Random(7)
    for r in sorted(found):
        if "\t" in r or "\n" in r:
            continue
        numbers = [tuple(map(int, m)) for m in re.findall(r"(\d+)\.(\d+)\.(\d+)", r)] or [(1, 2, 3)]
        for a, b, c in numbers[:3]:
            for v in (f"{a}.{b}.{c}", f"{a}.{b}.{c + 1}", f"{a}.{b + 1}.0", f"{a + 1}.0.0",
                      f"{max(a - 1, 0)}.9.9", f"{a}.{b}.{c}-rc.1", f"{a + 1}.0.0-0",
                      f"{a}.{b + 1}.{rng.randrange(9)}"):
                pairs.add((r, v))
    pairs = sorted(pairs)
    text = "".join(f"{r}\t{v}\n" for r, v in pairs)
    ours = subprocess.run([example, "ranges"], input=text, capture_output=True, text=True,
                          check=True).stdout.split()
    script = """
const semver = require(process.argv[1]);
const pairs = require('fs').readFileSync(0, 'utf8').split('\\n').filter(Boolean);
for (const line of pairs) {
  const [r, v] = line.split('\\t');
  console.log(semver.validRange(r) === null ? 'none' : String(semver.satisfies(v, r)));
}"""
    theirs = subprocess.run(["node", "-e", script, semver_dir], input=text, capture_output=True,
                            text=True, check=True).stdout.split()
    assert len(ours) == len(theirs) == len(pairs), (len(ours), len(theirs), len(pairs))
    wrong = [(p, o, t) for p, o, t in zip(pairs, ours, theirs) if o != t]
    print(f"{len(found)} ranges, {len(pairs)} pairs, {len(wrong)} differ")
    shown = {}
    for (r, v), o, t in wrong:
        shown.setdefault(r, (v, o, t))
    for r, (v, o, t) in list(shown.items())[:40]:
        print(f"  {r!r} {v}: ours {o}, semver {t}")
    return 1 if wrong else 0


def edit(ecosystem, package, version, target):
    return {"campaign": "c", "repo": "r", "ecosystem": ecosystem, "package": package,
            "from": [version], "to": target, "advisories": [], "breaking": False,
            "strategy": "lock-bump", "reason": None, "risk": None, "risk_reasons": []}


def plan(example, directory, record):
    run = subprocess.run([example, "plan", directory], input=json.dumps(record),
                         capture_output=True, text=True, check=True)
    return json.loads(run.stdout)


def raise_manifests(example, directory, record):
    subprocess.run([example, "raise", directory], input=json.dumps(record), capture_output=True,
                   text=True, check=True)


def vkey(v):
    return tuple(int(x) for x in re.match(r"(\d+)\.(\d+)\.(\d+)", v).groups())


def stable(v):
    return re.fullmatch(r"\d+\.\d+\.\d+", v) is not None


def targets(version, published):
    """The next release on this minor, on the next minor, and on the next major."""
    newer = [p for p in published if stable(p) and vkey(p) > vkey(version)]
    picks = []
    for same in (lambda p: vkey(p)[:2] == vkey(version)[:2],
                 lambda p: vkey(p)[0] == vkey(version)[0] and vkey(p)[1] > vkey(version)[1],
                 lambda p: vkey(p)[0] > vkey(version)[0]):
        line = sorted((p for p in newer if same(p)), key=vkey)
        if line:
            picks.append(line[0])
    return picks


def npm_view(package):
    run = subprocess.run(["npm", "view", package, "versions", "--json"], capture_output=True,
                         text=True)
    try:
        versions = json.loads(run.stdout)
    except ValueError:
        return []
    return [versions] if isinstance(versions, str) else versions


def copies(lock, package):
    tail = f"node_modules/{package}"
    return {k: e.get("version") for k, e in lock["packages"].items()
            if k == tail or k.endswith("/" + tail)}


NPM_FLAGS = ["--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]


def npm_case(args):
    example, work, source, package, version, target = args
    directory = tempfile.mkdtemp(dir=work)
    for name in ("package.json", "package-lock.json"):
        shutil.copy(os.path.join(source, name), directory)
    record = edit("npm", package, version, target)
    before = json.load(open(os.path.join(directory, "package-lock.json")))
    vulnerable = [k for k, v in copies(before, package).items() if v == version]
    decided = plan(example, directory, record)
    strategy = decided["strategy"]
    if strategy == "manifest-bump":
        raise_manifests(example, directory, record)
        command = ["npm", "install", *NPM_FLAGS]
    else:
        command = ["npm", "update", package, *NPM_FLAGS]
    run = subprocess.run(command, cwd=directory, capture_output=True, text=True)
    lock = json.load(open(os.path.join(directory, "package-lock.json")))
    after = copies(lock, package)
    # A copy the bump only carried along inside its range has not reached the target.
    moved = run.returncode == 0 and version not in after.values() and all(
        vkey(after[k]) >= vkey(target) for k in vulnerable if k in after)
    explained = ""
    if "ERESOLVE" in run.stderr and repo_conflicts(source, directory):
        explained = "the repo's own tree already fails to resolve"
    elif not moved and strategy != "blocked" and deprecated(package, target):
        explained = "npm will not pick a deprecated version over a working one"
    elif moved and strategy == "blocked" and stale(source, directory, vulnerable, package):
        explained = "the lock holds copies its manifest no longer asks for"
    shutil.rmtree(directory, ignore_errors=True)
    ok = moved if strategy != "blocked" else not moved
    return dict(lock=source, package=package, version=version, target=target, strategy=strategy,
                moved=moved, ok=ok or bool(explained), explained=explained,
                reason=decided.get("reason"),
                error="" if run.returncode == 0 else run.stderr[-300:])


def repo_conflicts(source, scratch):
    """Whether a plain install of the untouched repo fails too."""
    for name in ("package.json", "package-lock.json"):
        shutil.copy(os.path.join(source, name), scratch)
    run = subprocess.run(["npm", "install", *NPM_FLAGS], cwd=scratch, capture_output=True,
                         text=True)
    return run.returncode != 0


def stale(source, scratch, vulnerable, package):
    """Whether a plain install of the untouched repo prunes the copies, as npm update did."""
    repo_conflicts(source, scratch)
    lock = json.load(open(os.path.join(scratch, "package-lock.json")))
    return not set(vulnerable) & set(copies(lock, package))


def deprecated(package, version):
    run = subprocess.run(["npm", "view", f"{package}@{version}", "deprecated"],
                         capture_output=True, text=True)
    return bool(run.stdout.strip())


def npm(example, work, root, cases):
    rng = random.Random(11)
    jobs, views = [], {}
    sources = [os.path.dirname(p) for p in sorted(locks(root, "package-lock.json"))]
    sources = [s for s in sources if os.path.exists(os.path.join(s, "package.json"))]
    rng.shuffle(sources)
    per_lock = max(4, cases // max(len(sources), 1) + 1)
    for source in sources:
        try:
            lock = json.load(open(os.path.join(source, "package-lock.json")))
        except ValueError:
            continue
        entries = [(k, e) for k, e in (lock.get("packages") or {}).items()
                   if "node_modules/" in k and not e.get("link") and e.get("version")
                   and stable(e["version"]) and "registry.npmjs.org" in e.get("resolved", "")]
        if not entries or lock.get("lockfileVersion", 1) < 2:
            continue
        rng.shuffle(entries)
        for key, entry in entries[:per_lock]:
            package = key.rsplit("node_modules/", 1)[1]
            if package not in views:
                views[package] = npm_view(package)
            for target in targets(entry["version"], views[package]):
                jobs.append((example, work, source, package, entry["version"], target))
        if len(jobs) >= cases:
            break
    jobs = jobs[:cases]
    with concurrent.futures.ThreadPoolExecutor(6) as pool:
        results = list(pool.map(npm_case, jobs))
    return report(results)


def report(results):
    counts = {}
    for r in results:
        verdict = "explained" if r.get("explained") else "agrees" if r["ok"] else "differs"
        key = (r["strategy"], verdict)
        counts[key] = counts.get(key, 0) + 1
    print(f"{len(results)} cases", sorted(counts.items()))
    for r in [r for r in results if not r["ok"]][:30]:
        print(json.dumps({k: v for k, v in r.items() if k != "ok"}))
    json.dump(results, open(os.environ.get("OUT", os.devnull), "w"), indent=1)
    return 1 if any(not r["ok"] for r in results) else 0


def index_path(name):
    name = name.lower()
    if len(name) <= 2:
        return f"{len(name)}/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def crate_versions(name):
    url = "https://index.crates.io/" + urllib.parse.quote(index_path(name))
    run = subprocess.run(["curl", "-sf", url], capture_output=True, text=True)
    out = []
    for line in run.stdout.splitlines():
        record = json.loads(line)
        if not record.get("yanked"):
            out.append(record["vers"])
    return out


def cargo_case(args):
    example, work, source, package, version, target = args
    directory = tempfile.mkdtemp(dir=work)
    tree = os.path.join(directory, "t")
    shutil.copytree(source, tree, ignore=shutil.ignore_patterns("target", ".git"), symlinks=True)
    record = edit("cargo", package, version, target)
    decided = plan(example, tree, record)
    strategy = decided["strategy"]
    if strategy == "manifest-bump":
        raise_manifests(example, tree, record)
    run = subprocess.run(["cargo", "update", "--quiet", "-p", f"{package}@{version}", "--precise",
                          target], cwd=tree, capture_output=True, text=True)
    moved = run.returncode == 0
    shutil.rmtree(directory, ignore_errors=True)
    ok = moved if strategy != "blocked" else not moved
    explained = ""
    if "failed to load manifest" in run.stderr:
        explained = "a path dependency outside the copied directory"
    elif not moved and strategy != "blocked":
        conflict = re.findall(r"failed to select a version for `([^`]+)`", run.stderr)
        if "does not have that feature" in run.stderr or any(c != package for c in conflict):
            explained = "the target's own requirements, which only the registry knows"
    return dict(lock=source, package=package, version=version, target=target, strategy=strategy,
                moved=moved, ok=ok or bool(explained), explained=explained,
                reason=decided.get("reason"), error="" if moved else run.stderr[-400:])


def cargo(example, work, root, cases):
    rng = random.Random(13)
    jobs, views = [], {}
    sources = [os.path.dirname(p) for p in sorted(locks(root, "Cargo.lock"))]
    rng.shuffle(sources)
    for source in sources:
        fetched = subprocess.run(["cargo", "fetch", "--locked"], cwd=source, capture_output=True)
        if fetched.returncode != 0:
            continue
        text = open(os.path.join(source, "Cargo.lock")).read()
        entries = re.findall(r'name = "([^"]+)"\nversion = "([^"]+)"\nsource = "registry', text)
        rng.shuffle(entries)
        for package, version in entries[:6]:
            if not stable(version):
                continue
            if package not in views:
                views[package] = crate_versions(package)
            for target in targets(version, views[package]):
                jobs.append((example, work, source, package, version, target))
        if len(jobs) >= cases:
            break
    jobs = jobs[:cases]
    with concurrent.futures.ThreadPoolExecutor(4) as pool:
        results = list(pool.map(cargo_case, jobs))
    return report(results)


def main():
    mode, example = sys.argv[1], os.path.abspath(sys.argv[2])
    if mode == "ranges":
        return ranges(example, sys.argv[3], sys.argv[4])
    work, root = sys.argv[3], sys.argv[4]
    os.makedirs(work, exist_ok=True)
    cases = int(sys.argv[5]) if len(sys.argv) > 5 else 200
    return (npm if mode == "npm" else cargo)(example, work, root, cases)


if __name__ == "__main__":
    sys.exit(main())
