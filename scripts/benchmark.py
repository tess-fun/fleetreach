#!/usr/bin/env python3
"""Measure scans of a fleet and print a Markdown table for the benchmark page.
usage: benchmark.py <fleetreach binary> <fleet.toml> <work dir> [scan flags...]
Pass the flags that keep the scan offline, like `--offline --db DIR --osv-dir DIR`. It runs
each case three times and reports the median time and the highest peak memory, then checks that
every incremental run printed the same bytes as a plain scan. Exit 1 if one did not."""
import collections, hashlib, json, os, re, shutil, statistics, subprocess, sys, tomllib

ROOT_FILES = {
    "Rust": ["Cargo.lock"],
    "npm": ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"],
    "PyPI": ["uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt"],
    "Go": ["go.mod"],
    "RubyGems": ["Gemfile.lock"],
    "Packagist": ["composer.lock"],
    "Maven": ["pom.xml"],
    "NuGet": ["packages.lock.json"],
}


def timed(binary, fleet, flags, env):
    """Seconds, peak RSS in MB, and the hash of stdout."""
    time_flag = "-l" if sys.platform == "darwin" else "-v"
    command = ["/usr/bin/time", time_flag, binary, "scan", "-c", fleet, "--format", "json", *flags]
    done = subprocess.run(command, env=env, capture_output=True)
    if done.returncode not in (0, 1):
        sys.exit(f"exit {done.returncode}: {done.stderr[-500:]!r}")
    err = done.stderr.decode(errors="replace")
    if sys.platform == "darwin":
        seconds = float(re.findall(r"^\s*([\d.]+) real", err, re.M)[-1])
        rss = int(re.findall(r"^\s*(\d+)\s+maximum resident", err, re.M)[-1]) / 2**20
    else:
        minutes, secs = re.findall(r"Elapsed.*: (\d+):([\d.]+)", err)[-1]
        seconds = int(minutes) * 60 + float(secs)
        rss = int(re.findall(r"Maximum resident.*: (\d+)", err)[-1]) / 2**10
    return seconds, rss, hashlib.sha256(done.stdout).hexdigest(), json.loads(done.stdout)


def case(binary, fleet, flags, env, runs=3):
    results = [timed(binary, fleet, flags, env) for _ in range(runs)]
    seconds = statistics.median(r[0] for r in results)
    return seconds, max(r[1] for r in results), {r[2] for r in results}, results[-1][3]


def measure(binary, fleet, flags, work):
    env = dict(os.environ, SOURCE_DATE_EPOCH="1700000000", XDG_CACHE_HOME=f"{work}/cache")
    shutil.rmtree(f"{work}/cache", ignore_errors=True)
    os.makedirs(f"{work}/cache")
    plain = case(binary, fleet, flags, env)
    first = case(binary, fleet, [*flags, "--incremental"], env, runs=1)
    warm = case(binary, fleet, [*flags, "--incremental"], env)
    same = len(plain[2] | first[2] | warm[2]) == 1
    return plain, first, warm, same


def row(name, repos, plain, first, warm, same):
    findings = plain[3]["summary"]["vuln_count"]
    return (f"| {name} | {repos:,} | {findings:,} | {plain[0]:.2f} s | {plain[1]:,.0f} MB "
            f"| {first[0]:.2f} s | {warm[0]:.2f} s | {warm[1]:,.0f} MB | {'yes' if same else 'NO'} |")


def main():
    binary, fleet, work, *flags = sys.argv[1:]
    fleet = os.path.abspath(fleet)
    os.makedirs(work, exist_ok=True)
    work = os.path.abspath(work)
    repos = tomllib.load(open(fleet, "rb"))["repo"]
    os.chdir(os.path.dirname(fleet))
    print("| Fleet | Repos | Findings | Plain | Peak memory | First incremental | Warm "
          "| Warm memory | Same output |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|:---:|")
    ok = True
    results = measure(binary, fleet, flags, work)
    ok &= results[3]
    print(row("Whole fleet", len(repos), *results), flush=True)
    groups = collections.defaultdict(list)
    for repo in repos:
        for name, files in ROOT_FILES.items():
            if any(os.path.exists(os.path.join(repo["path"], f)) for f in files):
                groups[name].append(repo)
    for name, members in sorted(groups.items(), key=lambda g: -len(g[1])):
        sub = f"{work}/{name}.toml"
        with open(sub, "w") as out:
            for repo in members:
                out.write(f'[[repo]]\nid = "{repo["id"]}"\npath = "{repo["path"]}"\n\n')
        results = measure(binary, sub, flags, work)
        ok &= results[3]
        print(row(f"Repos with {name}", len(members), *results), flush=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
