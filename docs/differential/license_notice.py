#!/usr/bin/env python3
"""Compare `fleetreach licenses --notice` with cargo-about or license-checker.

usage: license_notice.py cargo <fleetreach binary> <cargo-about binary> <workspace dir>
       license_notice.py npm   <fleetreach binary> <license-checker bin.js> <project dir>

The question both tools answer: for each runtime package, which license texts
does the attribution carry. A text the other tool took from a file in the
package must appear, whitespace aside, in fleetreach's text for that package
(or among its NOTICE files). Texts the other tool made up are counted apart:
cargo-about's canonical SPDX text for a crate with no file, license-checker's
README fallback. fleetreach lists those packages as having no license file.

cargo-about needs `cargo install cargo-about --features cli`; it runs with
--all-features and dev dependencies left out. license-checker runs with
--production on an installed node_modules.
"""
import json, os, re, subprocess, sys, tempfile

RULE = "=" * 78
NOTICE_NAMES = {"notice", "notice.txt", "notice.md", "notices", "notices.txt", "notices.md"}


def norm(s):
    return re.sub(r"\s+", " ", s).strip()


def parse(text, eco):
    """Group texts, NOTICE files and the missing list, per (name, version).

    A license text can hold a line of `=`, so groups are found by their
    `Used by:` header rather than by splitting on the rule."""
    who = r"  - (\S+) (\S+) \(" + eco + r"\)"
    heads = list(re.finditer(RULE + r"\n([^\n]*)\nUsed by:\n((?:  - [^\n]*\n)+)" + RULE + r"\n\n", text))
    sections = "\n" + RULE + r"\n(Notices|No license file found on this machine)\n" + RULE + "\n"
    tails = list(re.finditer(sections, text))
    end_all = tails[0].start() if tails else len(text)
    groups = {}
    for k, m in enumerate(heads):
        end = heads[k + 1].start() if k + 1 < len(heads) else end_all
        body = norm(text[m.end():end])
        for u in re.findall(who, m[2]):
            groups[u] = body
    notices, missing = {}, set()
    for k, m in enumerate(tails):
        end = tails[k + 1].start() if k + 1 < len(tails) else len(text)
        sec = text[m.end():end]
        if m[1] == "Notices":
            pattern = r"--- (\S+) (\S+) \(" + eco + r"\) (\S+)\n\n(.*?)(?=\n--- |\Z)"
            for n in re.finditer(pattern, sec, re.S):
                notices.setdefault((n[1], n[2]), []).append(norm(n[4]))
        else:
            missing = set(re.findall(who, sec))
    return groups, notices, missing


def ours(fleetreach, repo, eco, work):
    config = os.path.join(work, "fleet.toml")
    with open(config, "w") as f:
        f.write(f'[[repo]]\nid = "repo"\npath = "{repo}"\necosystem = "{eco}"\n')
    out = subprocess.run([fleetreach, "licenses", "-c", config, "-f", "json", "--notice",
                          os.path.join(work, "out")], capture_output=True, text=True)
    if out.returncode == 2:
        sys.exit(out.stderr[-500:])
    runtime = {(p["package"], p["version"]) for p in json.loads(out.stdout)["packages"] if not p["dev"]}
    with open(os.path.join(work, "out", "repo.NOTICE.txt")) as f:
        return runtime, parse(f.read(), "cargo" if eco == "cargo" else eco)


def has(key, text, groups, notices):
    t = norm(text)
    return (key in groups and t in groups[key]) or t in notices.get(key, [])


def cargo(fleetreach, about, repo):
    work = tempfile.mkdtemp()
    conf = os.path.join(work, "about.toml")
    with open(conf, "w") as f:
        f.write('accepted = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-2-Clause", '
                '"BSD-3-Clause", "ISC", "Zlib", "Unicode-3.0", "Unicode-DFS-2016", "MPL-2.0", "CC0-1.0", '
                '"Unlicense", "BSL-1.0", "0BSD", "CDLA-Permissive-2.0", "OpenSSL", "MIT-0", '
                '"bzip2-1.0.6", "LGPL-2.1-or-later", "GPL-3.0-or-later", "NCSA", "WTFPL"]\n'
                "ignore-dev-dependencies = true\n")
    out = subprocess.run([about, "generate", "-c", conf, "--format", "json", "--offline", "--all-features"],
                         cwd=repo, capture_output=True, text=True)
    if out.returncode:
        sys.exit(out.stderr[-500:])
    data = json.loads(out.stdout)
    runtime, (groups, notices, missing) = ours(fleetreach, repo, "cargo", work)
    theirs = {(c["package"]["name"], c["package"]["version"]) for c in data["crates"]
              if c["package"].get("source") is not None}
    print(f"crates: cargo-about {len(theirs)}, fleetreach runtime {len(runtime)}, "
          f"only cargo-about {len(theirs - runtime)}, only fleetreach {len(runtime - theirs)}")
    agree, differ, made_up, listed = 0, [], 0, 0
    for lic in data["licenses"]:
        for u in lic["used_by"]:
            key = (u["crate"]["name"], u["crate"]["version"])
            if key not in runtime:
                continue
            if lic["source_path"] is None:
                made_up += 1
                listed += key in missing
            elif has(key, lic["text"], groups, notices):
                agree += 1
            else:
                differ.append((key, lic["source_path"]))
    print(f"texts from files: {agree} agree, {len(differ)} differ")
    for key, path in differ:
        print("  differ", *key, path)
    print(f"canonical texts for crates with no file: {made_up}, listed as missing by fleetreach: {listed}")


def npm(fleetreach, checker, repo):
    work = tempfile.mkdtemp()
    out = subprocess.run(["node", checker, "--production", "--json"], cwd=repo, capture_output=True, text=True)
    if out.returncode:
        sys.exit(out.stderr[-500:])
    theirs = {}
    for key, value in json.loads(out.stdout).items():
        name, version = key.rsplit("@", 1)
        theirs[(name, version)] = value
    runtime, (groups, notices, missing) = ours(fleetreach, repo, "npm", work)
    both = set(theirs) & runtime
    print(f"packages: license-checker {len(theirs)}, fleetreach runtime {len(runtime)}, both {len(both)}")
    agree, readme, differ, notice_agree, notice_differ = 0, [], [], 0, []
    for key in sorted(both):
        value = theirs[key]
        path = value.get("licenseFile")
        if path:
            with open(path, errors="replace") as f:
                text = f.read()
            if has(key, text, groups, notices):
                agree += 1
            elif os.path.basename(path).lower().startswith("readme"):
                readme.append(key)
            else:
                differ.append((key, path))
        for name in os.listdir(value["path"]):
            if name.lower() in NOTICE_NAMES:
                with open(os.path.join(value["path"], name), errors="replace") as f:
                    if norm(f.read()) in notices.get(key, []):
                        notice_agree += 1
                    else:
                        notice_differ.append((key, name))
    print(f"license files: {agree} agree, {len(differ)} differ, {len(readme)} README fallbacks "
          f"({sum(k in missing for k in readme)} listed as missing by fleetreach)")
    for key, path in differ:
        print("  differ", *key, path)
    print(f"NOTICE files: {notice_agree} agree, {len(notice_differ)} differ")
    for key, name in notice_differ:
        print("  notice differ", *key, name)


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] not in ("cargo", "npm"):
        sys.exit(__doc__)
    (cargo if sys.argv[1] == "cargo" else npm)(*sys.argv[2:])
