#!/usr/bin/env python3
"""One generator run, every format it writes: fleetreach must read the same components from each.

usage: sbom_formats.py <work dir> <sbom_components binary> <repo dir>...
Each repo goes through Syft and Trivy in each of their formats, cdxgen and Microsoft sbom-tool
in their one format, and spdx-tools and cyclonedx-cli convert what has one format into others.
`--github owner/name` adds GitHub's dependency graph. Purls are also counted straight from the
JSON, so a component every reader lost would still show.
"""
import collections, glob, json, os, re, subprocess, sys
from urllib.parse import unquote

SYFT = {"cyclonedx-json": "cdx.json", "cyclonedx-xml": "cdx.xml", "spdx-json": "spdx.json",
        "spdx-tag-value": "spdx"}
TRIVY = {"cyclonedx": "cdx.json", "spdx-json": "spdx.json", "spdx": "spdx"}


def run(cmd, out=None):
    r = subprocess.run(cmd, capture_output=True)
    if r.returncode:
        print("FAILED", " ".join(cmd)[:160], r.stderr[-300:].decode(errors="replace"))
        return False
    if out:
        open(out, "wb").write(r.stdout)
    return True


def docker(mounts, *cmd):
    args = ["docker", "run", "--rm"]
    for host, guest in mounts:
        args += ["-v", f"{host}:{guest}"]
    return args + list(cmd)


def syft(repo, out):
    paths = []
    for fmt, ext in SYFT.items():
        path = f"{out}/syft.{ext}"
        if run(docker([(repo, "/src:ro")], "anchore/syft:latest", "dir:/src", "-q", "-o", fmt), path):
            paths.append(path)
    return paths


def trivy(repo, out):
    paths = []
    for fmt, ext in TRIVY.items():
        path = f"{out}/trivy.{ext}"
        cmd = docker([(repo, "/src:ro"), (f"{out}/../trivy-cache", "/root/.cache")],
                     "aquasec/trivy:0.73.0", "fs", "--quiet", "--format", fmt, "/src")
        if run(cmd, path):
            paths.append(path)
    return paths


def spdx_convert(source, stem):
    """spdx-tools, in a container: the tag-value of a JSON document."""
    target = f"{stem}.spdx"
    d = os.path.dirname(source)
    cmd = docker([(d, "/w")], "python:3.12-slim", "sh", "-c",
                 "pip -q install --root-user-action=ignore spdx-tools 2>/dev/null; "
                 f"pyspdxtools --novalidation -i /w/{os.path.basename(source)} "
                 f"-o /w/{os.path.basename(target)}")
    return [source, target] if run(cmd) and os.path.exists(target) else [source]


def cdx_convert(source, stem):
    target = f"{stem}.cdx.xml"
    d = os.path.dirname(source)
    cmd = docker([(d, "/w")], "cyclonedx/cyclonedx-cli:latest", "convert",
                 "--input-file", f"/w/{os.path.basename(source)}",
                 "--output-file", f"/w/{os.path.basename(target)}", "--output-format", "xml")
    return [source, target] if run(cmd) and os.path.exists(target) else [source]


def cdxgen(repo, out):
    path = f"{out}/cdxgen.cdx.json"
    cmd = docker([(repo, "/src:ro"), (out, "/out")], "ghcr.io/cyclonedx/cdxgen:latest",
                 "--no-install-deps", "-r", "-o", "/out/cdxgen.cdx.json", "/src")
    return cdx_convert(path, f"{out}/cdxgen") if run(cmd) and os.path.exists(path) else []


def sbom_tool(repo, out):
    """Writes its manifest into the drop folder, so it gets a copy of the repo."""
    drop = f"{out}/drop"
    run(["rm", "-rf", drop])
    run(["cp", "-R", repo, drop])
    # Its launcher is one architecture; the DLL runs on whichever dotnet is here.
    store = "~/.dotnet/tools/.store/microsoft.sbom.dotnettool"
    dll = glob.glob(os.path.expanduser(f"{store}/*/*/*/tools/*/any/Microsoft.Sbom.DotNetTool.dll"))
    os.environ["DOTNET_ROLL_FORWARD"] = "Major"
    cmd = ["dotnet", dll[0], "generate", "-b", drop, "-bc", drop, "-pn", "x", "-pv", "1", "-ps", "x",
           "-nsb", "https://example.com", "-V", "Error"]
    if not run(cmd):
        return []
    path = f"{out}/sbomtool.spdx.json"
    run(["cp", f"{drop}/_manifest/spdx_2.2/manifest.spdx.json", path])
    run(["rm", "-rf", drop])
    return spdx_convert(path, f"{out}/sbomtool")


def github(name, out):
    path = f"{out}/github.spdx.json"
    if not run(["gh", "api", f"repos/{name}/dependency-graph/sbom"], f"{out}/wrapped.spdx.json"):
        return []
    # fleetreach reads the wrapper as it comes; spdx-tools needs what is inside.
    doc = json.load(open(f"{out}/wrapped.spdx.json"))
    json.dump(doc["sbom"], open(path, "w"))
    return [f"{out}/wrapped.spdx.json", *spdx_convert(path, f"{out}/github")]


def components(binary, path):
    text = subprocess.run([binary, path], capture_output=True, text=True).stdout
    return sorted(set(text.splitlines()))


ROUTED = {"npm", "pypi", "gem", "composer", "nuget", "maven", "hex", "julia", "swift"}


def norm(text):
    return re.sub(r"[-_.]+", "-", unquote(text).lower())


def json_purls(path):
    """The (name, version) of each purl fleetreach should route, read from a JSON document by
    another route than it reads them. The document's own root is no component."""
    doc = json.load(open(path))
    doc = doc.get("sbom", doc)
    purls = set()

    def walk(items):
        for c in items or []:
            if c.get("purl"):
                purls.add(c["purl"])
            walk(c.get("components"))

    walk(doc.get("components"))
    roots = set(doc.get("documentDescribes") or [])
    for r in doc.get("relationships") or []:
        if r.get("relationshipType") == "DESCRIBES":
            roots.add(r["relatedSpdxElement"])
    for p in doc.get("packages") or []:
        for ref in p.get("externalRefs") or []:
            if ref.get("referenceType") == "purl" and p.get("SPDXID") not in roots:
                purls.add(ref["referenceLocator"])
    wanted = set()
    for purl in purls:
        body = purl.split("?")[0].split("#")[0]
        kind, _, rest = body[len("pkg:"):].partition("/")
        name, _, version = rest.rpartition("@")
        if kind in ROUTED and name and version:
            wanted.add((norm(unquote(name).rsplit("/", 1)[-1]), unquote(version)))
    return wanted


def compare(label, binary, paths, totals):
    sets = {p: components(binary, p) for p in paths}
    first = paths[0]
    for path in paths:
        names = os.path.basename(path)
        lines = sets[path]
        routed = [l for l in lines if not l.startswith(("unrouted ", "error "))]
        errors = [l for l in lines if l.startswith("error ")]
        extra = ""
        if path.endswith(".json"):
            read = {(norm(l.split(" ")[1].rsplit("/", 1)[-1].rsplit(":", 1)[-1]), l.split(" ")[2])
                    for l in routed}
            lost = sorted(json_purls(path) - read)
            extra = f" lost={len(lost)} {lost[:4] or ''}"
            totals["lost"] += len(lost)
        print(f"  {label} {names}: {len(routed)} routed{extra} {errors[:1] or ''}")
        totals["documents"] += 1
        totals["errors"] += bool(errors)
        if lines != sets[first]:
            a, b = set(sets[first]), set(lines)
            print(f"    DIFFERS from {os.path.basename(first)}: "
                  f"-{sorted(a - b)[:6]} +{sorted(b - a)[:6]}")
            totals["differ"] += 1
    totals["components"] += len(sets[first])


def main():
    args = sys.argv[1:]
    names = []
    while "--github" in args:
        i = args.index("--github")
        names.append(args[i + 1])
        del args[i:i + 2]
    work, binary, repos = os.path.abspath(args[0]), args[1], args[2:]
    totals = collections.Counter()
    os.makedirs(f"{work}/trivy-cache", exist_ok=True)
    for repo in repos:
        repo = os.path.abspath(repo)
        out = f"{work}/{os.path.basename(repo)}"
        os.makedirs(out, exist_ok=True)
        print(repo)
        for label, make in (("syft", syft), ("trivy", trivy), ("cdxgen", cdxgen),
                            ("sbom-tool", sbom_tool)):
            paths = make(repo, out)
            if paths:
                compare(label, binary, paths, totals)
    for name in names:
        out = f"{work}/gh-{name.replace('/', '-')}"
        os.makedirs(out, exist_ok=True)
        print(name)
        paths = github(name, out)
        if paths:
            compare("github", binary, paths, totals)
    print(dict(totals))


if __name__ == "__main__":
    main()
