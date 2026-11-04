#!/usr/bin/env python3
"""Check `scan --health` warnings against each registry, by another route than fleetreach reads.

usage: health_oracle.py <scan report.json> <answers.json from the health cache> [flagged] [clean]

Samples up to `flagged` (200) warnings, spread over the signals, and `clean` (200) packages
with no flag, and asks: `npm view`, `go list -m -json -u -retracted`, PyPI's simple API,
RubyGems v2, the crates.io API, the Packagist package page, Hex's release endpoint, Maven
Central's other host and deps.dev. Any disagreement is printed. Run outside a temp dir that
holds packages: `npm view` and `go list` read their working directory.
"""
import collections, json, os, random, re, subprocess, sys, time, urllib.parse

Q = urllib.parse.quote


def get(url, accept=None):
    cmd = ["curl", "-sS", "-L", "-m", "30", "-A", "fleetreach-health-oracle", "-w", "\n%{http_code}"]
    if accept:
        cmd += ["-H", f"Accept: {accept}"]
    for attempt in range(5):
        out = subprocess.run(cmd + [url], capture_output=True, timeout=60).stdout
        body, _, code = out.rpartition(b"\n")
        if code == b"200":
            return body
        if code == b"404":
            return None
        time.sleep(2 ** attempt * 2)
    raise RuntimeError(url)


def npm(name, version):
    p = subprocess.run(["npm", "view", f"{name}@{version}", "deprecated", "--json"], capture_output=True,
                       text=True, timeout=120)
    return "deprecated" if p.stdout.strip() not in ("", '""') else None


def pypi(name, version):
    doc = json.loads(get(f"https://pypi.org/simple/{Q(name)}/", "application/vnd.pypi.simple.v1+json"))
    norm = re.sub(r"[-_.]+", "_", name).lower()
    files = [f for f in doc["files"]
             if re.sub(r"[-_.]+", "_", f["filename"]).lower().startswith(f"{norm}_{re.sub(r'[-_.]+', '_', version).lower()}_")
             or re.sub(r"[-_.]+", "_", f["filename"]).lower().startswith(f"{norm}_{re.sub(r'[-_.]+', '_', version).lower()}_tar")]
    if not files:
        return "unmatched"
    return "yanked" if all(f.get("yanked") for f in files) else None


def rubygems(name, version):
    number = version.split("-")[0]
    doc = get(f"https://rubygems.org/api/v2/rubygems/{Q(name)}/versions/{Q(number)}.json")
    if doc is not None:
        return None
    # A gem built for one platform only answers under that platform.
    listed = json.loads(get(f"https://rubygems.org/api/v1/versions/{Q(name)}.json"))
    return None if any(v["number"] == number for v in listed) else "yanked"


def cargo(name, version):
    time.sleep(1.1)
    doc = json.loads(get(f"https://crates.io/api/v1/crates/{Q(name)}/{Q(version)}"))
    return "yanked" if doc["version"]["yanked"] else None


def packagist(name, version):
    doc = json.loads(get(f"https://packagist.org/packages/{name.lower()}.json"))
    return "abandoned" if doc["package"].get("abandoned") else None


def hex_(name, version):
    time.sleep(0.7)
    doc = json.loads(get(f"https://hex.pm/api/packages/{Q(name)}/releases/{Q(version)}"))
    return "retired" if doc.get("retirement") else None


def go(name, version):
    env = {**os.environ, "GOFLAGS": "-mod=mod", "GO111MODULE": "on"}
    p = subprocess.run(["go", "list", "-m", "-json", "-u", "-retracted", f"{name}@{version}"],
                       capture_output=True, text=True, timeout=120, env=env, cwd="/")
    doc = json.loads(p.stdout)
    return ["retracted"] * bool(doc.get("Retracted")) + ["deprecated"] * bool(doc.get("Deprecated"))


def maven(name, version):
    group, artifact = name.split(":")
    url = f"https://repo.maven.apache.org/maven2/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.pom"
    return "relocated" if b"<relocation>" in get(url) else None


def nuget(name, version):
    doc = json.loads(get(f"https://api.deps.dev/v3/systems/nuget/packages/{Q(name, safe='')}/versions/{Q(version)}"))
    return "deprecated" if doc.get("isDeprecated") else None


CHECKS = {"npm": npm, "pypi": pypi, "rubygems": rubygems, "cargo": cargo, "packagist": packagist,
          "hex": hex_, "go": go, "maven": maven, "nuget": nuget}


def truth(eco, name, version):
    got = CHECKS[eco](name, version)
    return set(got) if isinstance(got, list) else ({got} if got else set())


def main():
    random.seed(7)
    report = json.load(open(sys.argv[1]))
    cache = json.load(open(sys.argv[2]))
    n_flagged = int(sys.argv[3]) if len(sys.argv) > 3 else 200
    n_clean = int(sys.argv[4]) if len(sys.argv) > 4 else 200
    groups = collections.defaultdict(list)
    for w in report["warnings"]:
        m = re.match(r"fleetreach:(deprecated|yanked|abandoned|retracted|retired|relocated):([^/]+)/(.+)$",
                     w.get("advisory_id") or "")
        if not m:
            continue
        signal, eco, rest = m.groups()
        for o in w["occurrences"][:1]:
            name = o["package"]
            raw = rest[len(name) + 1:] if rest.startswith(name + "@") else None
            groups[(signal, eco)].append((name, raw, w))
    print("flagged", {k: len(v) for k, v in groups.items()})
    picks = []
    share = max(1, n_flagged // max(1, len(groups)))
    spare = []
    for key, rows in sorted(groups.items()):
        random.shuffle(rows)
        picks += [(key, r) for r in rows[:share]]
        spare += [(key, r) for r in rows[share:]]
    random.shuffle(spare)
    picks += spare[:max(0, n_flagged - len(picks))]
    agree, wrong = collections.Counter(), []
    versions = {k: a for k, a in cache["packages"].items()}
    for (signal, eco), (name, version, w) in picks:
        if version is None:
            answer = versions[f"{eco}\x1f{name}"]["versions"]
            version = next(v for v, flags in answer.items() if any(f["signal"] == signal for f in flags))
        try:
            real = truth(eco, name, version)
        except Exception as e:
            wrong.append((signal, eco, name, version, f"oracle failed: {e}"))
            continue
        if "unmatched" in real:
            agree["unmatched"] += 1
        elif signal in real or (eco == "nuget" and signal == "yanked"):
            agree[(signal, eco)] += 1
        else:
            wrong.append((signal, eco, name, version, sorted(real)))
    print("flagged agreed", sum(v for k, v in agree.items() if k != "unmatched"), dict(agree))
    clean = [(k.split("\x1f")[0], k.split("\x1f")[1], v) for k, a in versions.items()
             for v, flags in a.get("versions", {}).items() if not flags]
    per = collections.defaultdict(list)
    for row in clean:
        per[row[0]].append(row)
    sample = []
    for eco, rows in sorted(per.items()):
        random.shuffle(rows)
        sample += rows[:max(1, n_clean // len(per))]
    clean_ok = collections.Counter()
    for eco, name, version in sample:
        if eco not in CHECKS:
            continue
        try:
            real = truth(eco, name, version)
        except Exception as e:
            wrong.append(("clean", eco, name, version, f"oracle failed: {e}"))
            continue
        if real - {"unmatched"}:
            wrong.append(("clean", eco, name, version, sorted(real)))
        else:
            clean_ok[eco] += 1
    print("clean agreed", sum(clean_ok.values()), dict(clean_ok))
    print("disagreements", len(wrong))
    for row in wrong:
        print(" ", row)


main()
