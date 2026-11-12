#!/usr/bin/env python3
"""Compare `fleetreach sbom --check-ntia` with sbomqs's NTIA 2021 profile on the same SBOMs.

usage: ntia_sbomqs.py <fleetreach binary> <sbomqs binary> <fleet.toml> <out dir>

Writes the fleet's SBOMs in each format with `--check-ntia`, runs
`sbomqs compliance --ntia-2021 --json` on every file, and compares, per document, the three
document-level elements (author, timestamp, dependencies) and, per component-level element
(name, supplier, version, unique identifier), how many components lack it. fleetreach prints
only what is missing, so an element it does not name counts as present everywhere.

sbomqs v2.1.3 is the reference (`go install github.com/interlynk-io/sbomqs/v2@v2.1.3`).
Its `--ntia` flag is the 2026 profile, which has different elements; this uses `--ntia-2021`.
"""
import json, os, re, subprocess, sys

FORMATS = {"cyclonedx": "cdx.json", "cyclonedx-xml": "cdx.xml", "spdx": "spdx.json", "spdx3": "spdx3.json"}
SECTIONS = {"2.4": "component name", "2.6": "supplier name", "2.7": "version", "2.8": "other unique identifiers"}
DOC = {"2.1": "author of SBOM data", "2.2": "timestamp", "2.3": "dependency relationship"}


def ours(binary, config, fmt, out):
    """repo -> {element: components lacking it, or True for a missing document element}."""
    run = subprocess.run([binary, "sbom", "-c", config, "-f", fmt, "-o", out, "--check-ntia", "-q"],
                         capture_output=True, text=True, env={**os.environ, "SOURCE_DATE_EPOCH": "1762905600"})
    result = {}
    for line in run.stderr.splitlines():
        m = re.match(r"ntia: (.+?): missing (.*)$", line)
        if not m:
            continue
        missing = {}
        for part in m.group(2).split("; "):
            c = re.match(r"(.+) \((\d+) of (\d+) components lack it\)$", part)
            if c:
                missing[c.group(1)] = int(c.group(2))
            else:
                missing[part] = True
        result[m.group(1)] = missing
    return result


def theirs(sbomqs, path):
    run = subprocess.run([sbomqs, "compliance", "--ntia-2021", "--json", path], capture_output=True, text=True)
    try:
        report = json.loads(run.stdout)
    except json.JSONDecodeError:
        return None, (run.stdout + run.stderr).strip()[:200]
    missing = {}
    for s in report.get("sections", []):
        sid = s["section_id"]
        failed = s["score"] < 10
        if sid in DOC and failed:
            missing[DOC[sid]] = True
        elif sid in SECTIONS and failed:
            missing[SECTIONS[sid]] = missing.get(SECTIONS[sid], 0) + 1
    return missing, None


def main(binary, sbomqs, config, out):
    agree = differ = unread = 0
    for fmt, ext in FORMATS.items():
        target = os.path.join(out, fmt)
        os.makedirs(target, exist_ok=True)
        mine = ours(binary, config, fmt, target)
        for name in sorted(os.listdir(target)):
            if not name.endswith("." + ext):
                continue
            repo = name[: -len(ext) - 1]
            theirs_missing, error = theirs(sbomqs, os.path.join(target, name))
            if theirs_missing is None:
                unread += 1
                print(f"{fmt} {repo}: sbomqs could not read it: {error}")
                continue
            m = mine.get(repo, {})
            if m == theirs_missing:
                agree += 1
            else:
                differ += 1
                print(f"{fmt} {repo}: fleetreach {m} sbomqs {theirs_missing}")
    print(f"{agree} agree, {differ} differ, {unread} not read by sbomqs")
    sys.exit(1 if differ else 0)


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    main(*sys.argv[1:])
