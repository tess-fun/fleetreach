#!/usr/bin/env python3
"""Check `scan --incremental`'s list of input files against what a scan really opens.
usage: scan_inputs.py <scancache.rs> <repo root prefix>... -- <strace log>...
Run the scan under `strace -f -e trace=openat,open`. Every regular file opened read-only below
a repo root, or relative to the fleet file, must match `is_input`, or a change to it would not invalidate a reused result.
Maven and Gradle files are exempt: those repos are never reused. Exit 1 on anything else."""
import collections, re, sys

EXEMPT = re.compile(r"(^pom\.xml$|\.gradle$|\.kts$|\.pom$|^gradle\.properties$)")


def is_input_from(source):
    body = source[source.index("fn is_input"):]
    body = body[:body.index("\n}\n")]
    first, second = body.split("name.ends_with", 1)
    listed = re.compile(r'^\s+(?:\| )?"([^"]+)"$', re.M)
    extensions = set(listed.findall(first))
    suffixes = re.findall(r'ends_with\("([^"]+)"\)', "name.ends_with" + second)
    names = set(listed.findall(second))

    def is_input(name):
        extension = name.rsplit(".", 1)[1] if "." in name else ""
        return extension in extensions or name in names or any(name.endswith(s) for s in suffixes)

    return is_input


def main():
    split = sys.argv.index("--")
    source, roots, logs = sys.argv[1], tuple(sys.argv[2:split]), sys.argv[split + 1:]
    is_input = is_input_from(open(source).read())
    seen, missed = collections.Counter(), collections.Counter()
    example = {}
    for log in logs:
        for line in open(log, errors="replace"):
            m = re.search(r'open(?:at)?\((?:AT_FDCWD, )?"([^"]+)", ([A-Z_|]+).*\) = \d+', line)
            if not m or "O_DIRECTORY" in m.group(2) or "O_WRONLY" in m.group(2):
                continue
            path = m.group(1)
            if path.startswith("/") and not path.startswith(roots):
                continue
            name = path.rsplit("/", 1)[-1]
            if "/" not in path:
                continue  # the fleet file itself
            seen[name] += 1
            if not is_input(name) and not EXEMPT.search(name):
                missed[name] += 1
                example[name] = path
    print(f"{sum(seen.values())} reads of {len(seen)} names")
    for name, n in missed.most_common(40):
        print(f"NOT AN INPUT {n} {example[name]}")
    sys.exit(1 if missed else 0)


if __name__ == "__main__":
    main()
