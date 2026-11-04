#!/usr/bin/env python3
"""Check that every import chain's first hop points at a real import line.

usage: import_chains.py <chains.jsonl> [repos.lock]

Takes the output of `cargo run --example import_chains -- <repo>...`. Reads each named line and
asks, with patterns of its own rather than the engine's parser, whether it is an import in that
language, and whether what it imports can name the chain's first package. Reports the rest.
"""
import collections, json, re, sys

IMPORT = {
    "rubygems": r"""^\s*(require\s*\(?\s*['"]([^'"]+)['"]|Bundler\.require)""",
    "packagist": r"^\s*use\s+(function\s+|const\s+)?\\?([A-Za-z_][\w\\]*)",
    "nuget": r"^\s*(global\s+)?(using|open|Imports)\s+(static\s+)?(\w+\s*=\s*)?([\w.]+)",
    "maven": r"^\s*import\s+(static\s+)?([\w.]+)",
    "hex": r"^\s*(alias|import|require|use)\s+([A-Z][\w.]*)",
    "swift": r"^\s*(@\w+(\([^)]*\))?\s+|public\s+|internal\s+)*import\s+(\w+\s+)?([A-Za-z_]\w*)",
}


def squash(text):
    return re.sub(r"[^a-z0-9]", "", text.lower())


def plausible(ecosystem, line, package):
    """Whether the line's name shares a word with the package, which no mapping table decides."""
    words = [w for w in re.split(r"[^a-z0-9]+", package.lower().split("/")[-1].split(":")[-1]) if len(w) > 1]
    text = squash(line)
    return "Bundler.require" in line or any(w in text for w in words)


def main():
    rows = [json.loads(line) for line in open(sys.argv[1])]
    counts = collections.Counter()
    repos = collections.defaultdict(set)
    bad, weak = [], []
    cache = {}
    for row in rows:
        ecosystem = row["ecosystem"]
        key = (row["repo"], row["file"])
        if key not in cache:
            cache[key] = open(f"{row['repo']}/{row['file']}", errors="replace").read().split("\n")
        line = cache[key][row["line"] - 1]
        counts[ecosystem, "chains"] += 1
        repos[ecosystem].add(row["repo"])
        counts[ecosystem, "transitive"] += len(row["chain"]) > 1
        if not re.search(IMPORT[ecosystem], line):
            counts[ecosystem, "not an import"] += 1
            bad.append((row["repo"], row["file"], row["line"], line.strip()[:80]))
        elif not plausible(ecosystem, line, row["chain"][0]):
            counts[ecosystem, "no shared word"] += 1
            weak.append((ecosystem, row["chain"][0], line.strip()[:70]))
    for ecosystem in sorted(repos):
        print(ecosystem, len(repos[ecosystem]), "repos", {k[1]: n for k, n in counts.items() if k[0] == ecosystem})
    print(len(bad), "lines that are not imports")
    for row in bad[:30]:
        print(" ", row)
    seen = sorted(set(weak))
    print(len(seen), "distinct imports sharing no word with their package")
    for row in seen[:60]:
        print(" ", row)


if __name__ == "__main__":
    main()
