"""Propose NuGet sink records (spec 16, row 13) for the NuGet advisories in an OSV export.

For each advisory: the fixed release of its latest line and the release before it are
fetched from nuget.org, the .dll files of one target framework both share are extracted (by
file name only, nothing else from the package), the fix commits' changed paths are read with
`gh api`, and the `nugetpropose` example writes a `proposed` record. Nothing fetched is run.

usage: python3 -I propose.py OSV_ALL_ZIP WORK_DIR OUT_DIR NUGETPROPOSE [ID ...]
A python.org build of Python on macOS has no CA certificates: every fetch fails with
CERTIFICATE_VERIFY_FAILED and is logged as an error. Run it with SSL_CERT_FILE=/etc/ssl/cert.pem.
Without ids: every HIGH or CRITICAL advisory with a GitHub fix commit, ChakraCore's native
engine left out.
"""
import json, os, re, subprocess, sys, urllib.error, urllib.request, zipfile

FLAT = "https://api.nuget.org/v3-flatcontainer"
TFM_ORDER = ["net8.0", "net9.0", "net10.0", "net7.0", "net6.0", "net5.0", "netcoreapp3.1",
             "netstandard2.1", "netstandard2.0", "netcoreapp2.1", "netstandard1.3", "net472",
             "net462", "net461", "net45", "net40"]
SKIP_PACKAGES = {"Microsoft.ChakraCore"}


def get(url, dest=None):
    req = urllib.request.Request(url, headers={"User-Agent": "fleetreach-sinks-research"})
    with urllib.request.urlopen(req, timeout=60) as r:
        body = r.read()
    if dest:
        with open(dest, "wb") as f:
            f.write(body)
    return body


def vkey(v):
    core, _, pre = v.partition("+")[0].partition("-")
    nums = [int(x) if x.isdigit() else 0 for x in core.split(".")]
    nums += [0] * (4 - len(nums))
    return (nums, 0 if pre else 1, pre)


def pick_releases(record, package, versions):
    """(last vulnerable, first fixed) of the advisory's latest fixed range, or None.

    The vulnerable release is the highest one inside that same range: the highest before the
    fix overall can sit in another line that was already fixed (YARP 1.0.1 against the
    1.1.0-rc fix)."""
    ranges = []
    for a in record.get("affected", []):
        if a["package"]["name"] != package:
            continue
        for r in a.get("ranges", []):
            if r.get("type") != "ECOSYSTEM":
                continue
            intro = next((e["introduced"] for e in r["events"] if "introduced" in e), "0")
            for e in r.get("events", []):
                if "fixed" in e:
                    ranges.append((intro, e["fixed"]))
    published = {v.lower(): v for v in versions}
    ranges = [(i, f) for i, f in ranges if f.lower() in published]
    if not ranges:
        return None
    intro, fixed = max(ranges, key=lambda r: vkey(r[1]))
    before = [v for v in versions
              if vkey(v) < vkey(fixed) and (intro == "0" or vkey(v) >= vkey(intro))]
    stable = [v for v in before if "-" not in v]
    pool = stable or before
    if not pool:
        return None
    return max(pool, key=vkey), published[fixed.lower()]


def siblings(nupkg, package):
    """(id, version) of the dependencies that are parts of the same library: ids under the
    package's own (`HotChocolate.Language` -> `HotChocolate.Language.Utf8`), where split
    libraries keep the code a meta-package only points at."""
    with zipfile.ZipFile(nupkg) as z:
        spec = next((n for n in z.namelist() if n.endswith(".nuspec") and "/" not in n), None)
        text = z.read(spec).decode("utf-8", "replace") if spec else ""
    out = set()
    for dep, ver in re.findall(r'<dependency id="([^"]+)" version="([^"]+)"', text):
        if not dep.lower().startswith(package.lower() + "."):
            continue
        # `1.2.3`, `[1.2.3]`, `[1.2.3, )` or `[1.2.3, 2.0.0)`: the inclusive lower bound, which
        # is the release built alongside this one.
        m = re.fullmatch(r"\[?([0-9A-Za-z.+-]+)(?:\s*,\s*[0-9A-Za-z.+-]*\s*\)|\])?", ver.strip())
        if m:
            out.add((dep, m.group(1)))
    return sorted(out)


def extract(nupkg, dest):
    """The lib/<tfm>/*.dll members, as {tfm: dir}, written by bare file name."""
    out = {}
    with zipfile.ZipFile(nupkg) as z:
        for name in z.namelist():
            parts = name.split("/")
            # lib/<tfm>/x.dll, or lib/x.dll in old packages (no framework folder): "any".
            if len(parts) == 2 and parts[0].lower() == "lib" and parts[1].lower().endswith(".dll"):
                parts = ["lib", "any", parts[1]]
            if len(parts) != 3 or parts[0].lower() != "lib" or not parts[2].lower().endswith(".dll"):
                continue
            tfm, file = parts[1].lower(), os.path.basename(parts[2])
            if not re.fullmatch(r"[A-Za-z0-9._-]+", tfm) or not re.fullmatch(r"[A-Za-z0-9._-]+", file):
                continue
            d = os.path.join(dest, tfm)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, file), "wb") as f:
                f.write(z.read(name))
            out[tfm] = d
    return out


def best_tfm(old, new):
    """(old tfm, new tfm): the preferred framework both share, or, when each release ships one
    framework only (DotNetCasClient lib/ -> lib/net20, Blogifier netcoreapp2.0 -> 3.1), those."""
    common = [t for t in old if t in new]
    if not common:
        if len(old) == 1 and len(new) == 1:
            return next(iter(old)), next(iter(new))
        return None
    for t in TFM_ORDER:
        if t in common:
            return t, t
    return sorted(common)[-1], sorted(common)[-1]


def changed_files(url):
    m = re.match(r"https://github\.com/([^/]+)/([^/]+)/(commit|pull)/([0-9a-fA-F]+|\d+)", url)
    if not m:
        return None
    owner, repo, kind, ref = m.groups()
    if kind == "commit":
        args = ["gh", "api", f"repos/{owner}/{repo}/commits/{ref}", "--jq", ".files[].filename"]
    else:
        args = ["gh", "api", "--paginate", f"repos/{owner}/{repo}/pulls/{ref}/files", "--jq", ".[].filename"]
    r = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return None
    return [l for l in r.stdout.splitlines() if l.strip()]


def prepare(rec, package, work):
    """(releases, {tfm: dir} per release, (old tfm, new tfm)) for one package, or why not."""
    lower = package.lower()
    try:
        versions = json.loads(get(f"{FLAT}/{lower}/index.json"))["versions"]
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        return "no published fixed release"  # listed in the advisory, never on nuget.org
    pair = pick_releases(rec, package, versions)
    if not pair:
        return "no published fixed release"
    dirs = []
    for v in pair:
        d = os.path.join(work, "pkgs", f"{lower}.{v.lower()}")
        nupkg = d + ".nupkg"
        if not os.path.exists(nupkg):
            os.makedirs(os.path.dirname(nupkg), exist_ok=True)
            get(f"{FLAT}/{lower}/{v.lower()}/{lower}.{v.lower()}.nupkg", nupkg)
        got = extract(nupkg, d)
        # Siblings of siblings too: a meta-package can point at another one
        # (Umbraco.Cms -> Umbraco.Cms.Targets -> Umbraco.Cms.Web.Common).
        queue, seen = siblings(nupkg, package), set()
        while queue and len(seen) < 64:
            dep, dv = queue.pop(0)
            if dep.lower() in seen:
                continue
            seen.add(dep.lower())
            dl = dep.lower()
            dn = os.path.join(work, "pkgs", f"{dl}.{dv.lower()}.nupkg")
            if not os.path.exists(dn):
                get(f"{FLAT}/{dl}/{dv.lower()}/{dl}.{dv.lower()}.nupkg", dn)
            got.update(extract(dn, d))
            queue += siblings(dn, package)
        dirs.append(got)
    tfm = best_tfm(*dirs)
    if not tfm:
        return f"no shared lib target framework ({pair[0]} -> {pair[1]})"
    return pair, dirs, tfm


def merge(docs):
    """One draft from the drafts of several packages: every sink once, every note."""
    out = dict(docs[0])
    sinks, keys = [], set()
    for d in docs:
        for s in d.get("sinks", []):
            k = json.dumps(s, sort_keys=True)
            if k not in keys:
                keys.add(k)
                sinks.append(s)
    if sinks:
        out["verdict"], out["sinks"] = "sinks", sinks
    out["note"] = " ".join(d.get("note", "") for d in docs).strip()
    return out


def main():
    osv_zip, work, out_dir, tool = sys.argv[1:5]
    only = set(sys.argv[5:])
    os.makedirs(work, exist_ok=True)
    os.makedirs(out_dir, exist_ok=True)
    z = zipfile.ZipFile(osv_zip)
    log = open(os.path.join(work, "log.tsv"), "a")
    for name in sorted(z.namelist()):
        rec = json.loads(z.read(name))
        rid = rec["id"]
        if rec.get("withdrawn") or (only and rid not in only):
            continue
        packages = sorted({a["package"]["name"] for a in rec.get("affected", [])
                           if a["package"].get("ecosystem") == "NuGet"})
        commits = [r["url"] for r in rec.get("references", [])
                   if re.search(r"github\.com/[^/]+/[^/]+/(commit|pull)/", r["url"])]
        sev = (rec.get("database_specific") or {}).get("severity")
        if not only and (sev not in ("HIGH", "CRITICAL") or not any("/commit/" in c for c in commits)
                         or not packages or set(packages) & SKIP_PACKAGES):
            continue
        if os.path.exists(os.path.join(out_dir, rid + ".json")):
            continue
        try:
            files, read_all = [], True
            for c in commits:
                f = changed_files(c)
                if f is None:
                    read_all = False
                else:
                    files += f
            list_path = os.path.join(work, "files", rid + ".txt")
            os.makedirs(os.path.dirname(list_path), exist_ok=True)
            with open(list_path, "w") as f:
                f.write("\n".join(files if read_all or files else []))
            # The first affected package with library code in both releases (an advisory can
            # list a CLI tool or a meta-package first: NuGet.CommandLine before NuGet.Packaging,
            # Umbraco.Cms before Umbraco.Cms.Core), plus every other affected package whose own
            # folder the fix commits change: NuGet's CVE-2022-41032 fix spans NuGet.Commands and
            # NuGet.Protocol, and CVE-2023-29337's is only in NuGet.Common.
            named = {p for p in packages
                     if any(f"/{p.lower()}/" in "/" + x.lower() for x in files)}
            diffed, why, first = [], "no published fixed release", None
            for package in packages:
                if first is not None and package not in named:
                    continue
                got = prepare(rec, package, work)
                if isinstance(got, str):
                    why = got if got != "no published fixed release" else why
                    continue
                if first is None:
                    first = package
                pair, dirs, tfm = got
                label = tfm[0] if tfm[0] == tfm[1] else f"{tfm[0]} -> {tfm[1]}"
                args = [tool, "--id", rid, "--old", dirs[0][tfm[0]], "--new", dirs[1][tfm[1]],
                        "--releases", f"{package} {pair[0]} -> {pair[1]} ({label})",
                        "--files", list_path]
                for a in rec.get("aliases", []):
                    if re.fullmatch(r"(CVE-\d{4}-\d+|GHSA(-[23456789cfghjmpqrvwx]{4}){3})", a):
                        args += ["--alias", a]
                for p in packages:
                    args += ["--package", p]
                for c in commits:
                    args += ["--commit", c]
                r = subprocess.run(args, capture_output=True, text=True, timeout=600)
                if r.returncode != 0:
                    raise RuntimeError(r.stderr.strip()[:300])
                diffed.append((json.loads(r.stdout), f"{package} {pair[0]} -> {pair[1]} {label}"))
            if not diffed:
                print(f"{rid}\tskip\t{why}", file=log, flush=True)
                continue
            doc = merge([d for d, _ in diffed])
            with open(os.path.join(out_dir, rid + ".json"), "w") as f:
                f.write(json.dumps(doc, indent=2) + "\n" if len(diffed) > 1 else r.stdout)
            print(f"{rid}\t{doc['verdict']}\t{len(doc.get('sinks', []))} sinks\t"
                  + "; ".join(l for _, l in diffed), file=log, flush=True)
        except Exception as e:  # one advisory's failure never stops the run
            print(f"{rid}\terror\t{type(e).__name__}: {e}"[:400], file=log, flush=True)


if __name__ == "__main__":
    main()
