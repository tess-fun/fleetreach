#!/usr/bin/env python3
"""Ask pnpm, yarn and bun what a lockfile holds, for comparison with fleetreach.
Runs inside a container: oracle.py <root> <out>. Installs use --ignore-scripts, so no package
code runs. pnpm reads the lockfile alone; yarn v1 and bun list what they installed."""
import json, os, re, shutil, subprocess, sys

ROOT, OUT = sys.argv[1], sys.argv[2]
KEEP = {"package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml", "yarn.lock", "bun.lock", ".yarnrc.yml", ".npmrc"}


def stage(lock_dir):
    """A copy of the manifests and lockfile, without source or node_modules."""
    w = "/w"
    shutil.rmtree(w, ignore_errors=True)
    for dp, dn, fn in os.walk(lock_dir):
        dn[:] = [d for d in dn if d not in ("node_modules", ".git", "target", "dist")]
        rel = os.path.relpath(dp, lock_dir)
        for f in fn:
            if f in KEEP or "/.yarn/releases" in dp or "/.yarn/patches" in dp:
                os.makedirs(os.path.join(w, rel), exist_ok=True)
                shutil.copy(os.path.join(dp, f), os.path.join(w, rel, f))
    return w


def run(cmd, cwd, timeout=900):
    env = dict(os.environ, CI="1", npm_config_manage_package_manager_versions="false", COREPACK_ENABLE_DOWNLOAD_PROMPT="0", YARN_ENABLE_SCRIPTS="0",
               YARN_ENABLE_IMMUTABLE_INSTALLS="false", YARN_IGNORE_PATH="0")
    p = subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True, timeout=timeout, env=env)
    return p.returncode, p.stdout, p.stderr


def walk_pnpm(node, out):
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, d in (node.get(section) or {}).items():
            v = d.get("version", "")
            if not v.startswith(("link:", "file:", "workspace:")):
                out.add(f"{d.get('from', name)}@{v}")
            walk_pnpm(d, out)


def pnpm(w, old):
    if old:
        # Lockfiles older than 9.x need the pnpm of their day, and an install to list.
        pm = "npx -y pnpm@7" if old == 5 else "npx -y pnpm@8"
        rc, o, err = run(f"{pm} install --frozen-lockfile --ignore-scripts", w)
        if rc:
            return None, (err + o)[-300:]
        rc, o, err = run(f"{pm} list -r --json --depth Infinity", w)
    else:
        rc, o, err = run("pnpm list -r --lockfile-only --json --depth Infinity", w)
    if rc:
        return None, err[-300:]
    s = set()
    for project in json.loads(o):
        walk_pnpm(project, s)
    return s, ""


def yarn_v1(w):
    rc, _, err = run("npx -y yarn@1 install --frozen-lockfile --ignore-scripts --ignore-engines --ignore-platform --non-interactive", w)
    if rc:
        return None, err[-300:]
    rc, o, err = run("npx -y yarn@1 list --json --non-interactive", w)
    if rc:
        return None, err[-300:]
    s = set()

    def walk(trees):
        for t in trees:
            # `shadow` rows repeat a requirement (`a@^1.0.0`), not an installed package.
            if not t.get("shadow"):
                s.add(t["name"])
            walk(t.get("children") or [])
    for line in o.splitlines():
        d = json.loads(line)
        if d.get("type") == "tree":
            walk(d["data"]["trees"])
    return s, ""


def yarn_berry(w):
    run("corepack enable", w)
    rc, _, err = run("yarn install --mode=skip-build", w)
    if rc:
        return None, err[-300:]
    rc, o, err = run("yarn info --all --recursive --json", w)
    if rc:
        return None, err[-300:]
    s = set()
    for line in o.splitlines():
        v = json.loads(line).get("value", "")
        m = re.match(r"(.+)@npm:(.+)$", v)
        if m:
            s.add(f"{m[1]}@{m[2]}")
    return s, ""


def bun(w):
    rc, _, err = run("bun install --frozen-lockfile --ignore-scripts", w)
    if rc:
        return None, err[-300:]
    rc, o, err = run("bun pm ls --all", w)
    if rc:
        return None, err[-300:]
    s = set()
    for line in o.splitlines():
        m = re.search(r"[─ ]\s*((?:@[^/ ]+/)?[^@ ]+)@(\S+)", line)
        if m and not m[2].startswith(("workspace:", "link:", "file:")):
            s.add(f"{m[1]}@{m[2]}")
    return s, ""


targets = json.load(open(f"{ROOT}/targets.json"))
tool = sys.argv[3]
for t in targets:
    if t["tool"] != tool:
        continue
    path = f"{OUT}/{t['id']}.json"
    if os.path.exists(path):
        continue
    w = stage(t["dir"].replace("HOME", ROOT))
    try:
        s, err = {"pnpm": lambda: pnpm(w, 0), "pnpm5": lambda: pnpm(w, 5), "pnpm6": lambda: pnpm(w, 6), "yarn1": lambda: yarn_v1(w),
                  "berry": lambda: yarn_berry(w), "bun": lambda: bun(w)}[tool]()
    except Exception as e:  # a timeout or a tool's odd output is a skipped lockfile, reported
        s, err = None, repr(e)[:300]
    json.dump({"packages": sorted(s) if s is not None else None, "error": err}, open(path, "w"))
    print(t["id"], len(s) if s is not None else err[:100], flush=True)
