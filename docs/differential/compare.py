#!/usr/bin/env python3
"""Normalize fleetreach, Trivy and Grype findings to (class, package, version, vulnerability).
usage: compare.py <fleetreach report.json> <out.json>"""
import collections, glob, json, os, re, sys
from urllib.parse import unquote

HERE = os.path.dirname(os.path.abspath(__file__))
OS_TYPES = {"deb", "rpm", "apk"}
TRIVY = {"jar": "maven", "pom": "maven", "gradle": "maven", "gemspec": "gem", "bundler": "gem",
         "node-pkg": "npm", "npm": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm",
         "python-pkg": "pypi", "pip": "pypi", "pipenv": "pypi", "poetry": "pypi", "uv": "pypi",
         "composer": "composer", "composer-vendor": "composer", "gobinary": "go",
         "gomod": "go", "rust-binary": "rust", "cargo": "cargo", "dotnet-core": "nuget",
         "nuget": "nuget", "packages-props": "nuget", "conan": "conan", "conda-pkg": "conda",
         "pub": "pub", "hex": "hex", "swift": "swift", "cocoapods": "cocoapods", "julia": "julia"}
GRYPE = {"java-archive": "maven", "jenkins-plugin": "maven", "npm": "npm", "python": "pypi",
         "gem": "gem", "go-module": "go", "rust-crate": "rust",
         "dotnet": "nuget", "php-composer": "composer", "binary": "binary",
         "hex": "hex", "linux-kernel": "os"}
OURS = {"maven": "maven", "npm": "npm", "pypi": "pypi", "rubygems": "gem", "go": "go",
        "cargo": "cargo", "nuget": "nuget", "packagist": "composer", "hex": "hex",
        "swift": "swift", "julia": "julia", "githubactions": "actions"}


def vnorm(v):
    v = re.sub(r"^(v|go)", "", (v or "").lower()).replace("+incompatible", "")
    parts = [t for t in re.split(r"[.\-+_]", v)]
    # guava is 27.0-jre to Trivy and 27.0.0-jre to us: zero parts say nothing.
    return ".".join(p for p in parts if p != "0")


def pname(klass, name):
    n = name.lower()
    if klass == "pypi":
        n = re.sub(r"[-_.]+", "-", n)
    return n


class Rec:
    __slots__ = ("ids", "status", "extra", "all")

    def __init__(self):
        self.ids, self.status, self.extra, self.all = set(), set(), "", set()


def add(table, klass, name, version, ids, status, extra="", every=()):
    key = (klass, pname(klass, name), "" if klass == "os" else vnorm(version))
    for i in ids:
        r = table[key + (i,)] if (key + (i,)) in table else table.setdefault(key + (i,), Rec())
        r.status.add(status)
        r.extra = r.extra or extra
        r.all.update(every)


def ids_of(primary, others):
    cves = [x for x in [primary, *others] if x.startswith("CVE-")]
    return sorted(set(cves)) or [primary]


def trivy(path):
    d = json.load(open(path))
    out, packages = {}, set()
    for r in d.get("Results") or []:
        typ = r.get("Type", "")
        klass = "os" if r.get("Class") == "os-pkgs" else TRIVY.get(typ, "other:" + typ)
        for p in r.get("Packages") or []:
            packages.add((klass, pname(klass, p["Name"]), "" if klass == "os" else vnorm(p.get("Version"))))
        for v in r.get("Vulnerabilities") or []:
            st = "fixed" if v.get("FixedVersion") else "open"
            add(out, klass, v["PkgName"], v["InstalledVersion"], [v["VulnerabilityID"]], st,
                v.get("PkgPath", ""))
    return out, packages, (d.get("Metadata") or {}).get("OS")


def grype(path):
    d = json.load(open(path))
    out = {}
    for m in d.get("matches", []):
        a, v = m["artifact"], m["vulnerability"]
        t = a["type"]
        klass = "os" if t in OS_TYPES else GRYPE.get(t, "other:" + t)
        name = a["name"]
        purl = a.get("purl", "")
        if klass == "maven" and purl.startswith("pkg:maven/"):
            bits = unquote(purl[len("pkg:maven/"):].split("@")[0].split("?")[0]).split("/")
            if len(bits) == 2:
                name = ":".join(bits)
        st = "fixed" if v.get("fix", {}).get("state") == "fixed" else "open"
        related = [r["id"] for r in m.get("relatedVulnerabilities", [])]
        add(out, klass, name, a["version"], ids_of(v["id"], related), st,
            ",".join(l.get("path", "") for l in a.get("locations", [])[:1]))
    return out


def julia_upstream():
    """JLSEC records name the CVE they repackage in `upstream`, which a finding does not carry."""
    import zipfile
    z = zipfile.ZipFile(f"{HERE}/osv/Julia/all.zip")
    out = {}
    for n in z.namelist():
        d = json.loads(z.read(n))
        out[d["id"]] = d.get("upstream") or []
    return out


def ours(report):
    by = collections.defaultdict(dict)
    upstream = julia_upstream()
    for v in report["vulnerabilities"]:
        eco = v.get("ecosystem", "cargo")
        title = v["title"]
        v["aliases"] = [*v["aliases"], *upstream.get(v["advisory_id"], [])]
        for o in v["occurrences"]:
            path = o.get("dependency_path") or []
            if eco in OS_TYPES:
                st = "fixed" if o.get("patched") else "open"
                for b in (path[2].split(", ") if len(path) >= 3 else []):
                    add(by[o["repo"]], "os", b, "", ids_of(v["advisory_id"], v["aliases"]), st, title[:120], [v["advisory_id"], *v["aliases"]])
            else:
                real = o["installed"]
                add(by[o["repo"]], OURS.get(eco, eco), o["package"], real,
                    ids_of(v["advisory_id"], v["aliases"]), "fixed" if o.get("patched") else "open",
                    (path[0] if path else "")[:120], [v["advisory_id"], *v["aliases"]])
    return by


def main():
    report = json.load(open(sys.argv[1]))
    mine = ours(report)
    alias = {}
    rows, totals = [], collections.Counter()
    for image in report["provenance"]["images"]:
        repo = image["repo"]
        tp, gp = f"{HERE}/out/trivy-{repo}.json", f"{HERE}/out/grype-{repo}.json"
        if not (os.path.exists(tp) and os.path.exists(gp)):
            continue
        t, tpk, tos = trivy(tp)
        g = grype(gp)
        o = mine.get(repo, {})
        # A GHSA Trivy lists and a CVE we list are one record when Grype or we alias them.
        row = dict(repo=repo, os=tos, ours=len(o), trivy=len(t), grype=len(g))
        # Any id of a record of ours stands for it: a GHSA the others list, a SUSE-SU.
        known = set(o)
        for k, r in o.items():
            known.update(k[:3] + (i,) for i in r.all)
        def seen(k, table):
            return k in table or any(k[:3] + (i,) in table for i in o[k].all)
        row["only_trivy"] = sorted(k for k in t if k not in known)
        row["only_grype"] = sorted(k for k in g if k not in known)
        row["only_ours"] = sorted(k for k in o if not seen(k, t) and not seen(k, g))
        row["ours_not_trivy"] = sorted(k for k in o if not seen(k, t))
        row["ours_not_grype"] = sorted(k for k in o if not seen(k, g))
        row["status"] = sorted(k for k in o if k in t and ("fixed" in o[k].status) != ("fixed" in t[k].status))
        row["status_g"] = sorted(k for k in o if k in g and ("fixed" in o[k].status) != ("fixed" in g[k].status))
        row["common_trivy"] = sum(1 for k in o if k in t)
        row["common_grype"] = sum(1 for k in o if k in g)
        row["trivy_packages"] = len(tpk)
        rows.append(row)
    json.dump(rows, open(sys.argv[2], "w"))
    agg = collections.Counter()
    for r in rows:
        for k in r["only_trivy"]:
            agg[("only_trivy", k[0])] += 1
        for k in r["only_grype"]:
            agg[("only_grype", k[0])] += 1
        for k in r["ours_not_trivy"]:
            agg[("ours_not_trivy", k[0])] += 1
        for k in r["ours_not_grype"]:
            agg[("ours_not_grype", k[0])] += 1
        for k in ("ours", "trivy", "grype", "common_trivy", "common_grype"):
            totals[k] += r[k]
        totals["status"] += len(r["status"])
        totals["status_g"] += len(r["status_g"])
    print(len(rows), "images", dict(totals))
    for k, n in sorted(agg.items(), key=lambda x: (x[0][0], -x[1])):
        print(" ", k, n)


if __name__ == "__main__":
    main()
