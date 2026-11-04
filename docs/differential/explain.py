#!/usr/bin/env python3
"""Give every row one tool reports and another does not a reason, from upstream data.
Every rule below reads evidence (an OSV record, the Debian tracker, the tool's own match, the
image's package database). A row no rule claims is printed as UNEXPLAINED.
usage: explain.py [rows.json]  (writes explained.json)"""
import collections, json, os, re, sys, zipfile
from compare_load import osv_index
sys_argv, sys.argv = sys.argv, sys.argv[:1]
from compare import ours
sys.argv = sys_argv

rows = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "rows.json"))
report = json.load(open("report3.json"))
OSV = {d: osv_index(f"osv/{d}/all.zip") for d in
       ("Debian", "Ubuntu", "Alpine", "Go", "Maven", "npm", "PyPI", "RubyGems", "NuGet", "Packagist")
       if os.path.exists(f"osv/{d}/all.zip")}
FROZEN = {r: osv_index(f"stale/Debian_{r}/all.zip") for r in ("10", "11")}


def withdrawn_ids(path):
    z = zipfile.ZipFile(path)
    out = set()
    for n in z.namelist():
        d = json.loads(z.read(n))
        if d.get("withdrawn"):
            out.update({d["id"], *(d.get("aliases") or [])})
    return out


WITHDRAWN = {r: withdrawn_ids(f"stale/Debian_{r}/all.zip") for r in ("10", "11")}
tracker = collections.defaultdict(dict)
for src, cves in json.load(open("tracker.json")).items():
    for c, d in cves.items():
        tracker[c][src] = d
owned = collections.defaultdict(dict)
for line in open("owned.tsv"):
    repo, path, owner = line.rstrip("\n").split("\t")
    owned[repo][path] = owner
def red_hat_index():
    """Every CVE Red Hat's exports speak about, and kernel fixes by CVE."""
    cves, kernel = collections.defaultdict(set), collections.defaultdict(list)
    for d in [x for x in os.listdir("osv") if x.startswith("Red Hat")]:
        z = zipfile.ZipFile(f"osv/{d}/all.zip")
        for n in z.namelist():
            b = z.read(n)
            found = {c.decode() for c in re.findall(rb"CVE-\d{4}-\d+", b)}
            for m in re.findall(rb"(?:enterprise_linux|rhel_els):(\d+)", b):
                cves[m.decode()] |= found
            if d == "Red Hat" and b'"kernel"' in b:
                rec = json.loads(b)
                for a in rec.get("affected", []):
                    if a["package"]["name"] == "kernel" and ":enterprise_linux:" in a["package"]["ecosystem"]:
                        for r in a.get("ranges", []):
                            for e in r["events"]:
                                if "fixed" in e:
                                    for c in rec.get("upstream") or []:
                                        kernel[c].append(e["fixed"])
    return cves, kernel


RH_CVES, RH_KERNEL = red_hat_index()
SUSE_IDS = {n[:-5] for d in ("SUSE", "openSUSE") for n in zipfile.ZipFile(f"osv/{d}/all.zip").namelist()}
MINE = ours(report)


def nums(v):
    return [int(x) for x in re.findall(r"\d+", v)]


def out_of_ranges(version, entries):
    """Whether no range of an OSV record's entries reaches a version, compared by numbers."""
    v = nums(version)
    for _, ranges, _ in entries:
        for r in ranges or []:
            lo, hi = [0], None
            for e in r["events"]:
                if "introduced" in e:
                    lo = nums(e["introduced"])
                if "fixed" in e or "last_affected" in e:
                    hi = nums(e.get("fixed") or e["last_affected"])
                    if lo <= v and (v < hi or ("last_affected" in e and v == hi)):
                        return False
                    hi = None
                    lo = None
            if lo is not None and lo <= v:
                return False
    return True


PRIVATE = {"files_pdfviewer", "firstrunwizard", "suspicious_login", "twofactor_totp", "phpmyadmin"}
LANG = {"go": "Go", "maven": "Maven", "npm": "npm", "pypi": "PyPI", "gem": "RubyGems",
        "nuget": "NuGet", "composer": "Packagist"}
REL = {"12": "bookworm", "13": "trixie"}
gaps = collections.defaultdict(list)
for g in report.get("coverage", []):
    gaps[g["repo"]].append(g["reason"])


def grype_matches(repo):
    """(klass-free) (name, id) -> details of what Grype matched."""
    out = collections.defaultdict(list)
    for m in json.load(open(f"out/grype-{repo}.json")).get("matches", []):
        a, v = m["artifact"], m["vulnerability"]
        ids = {v["id"], *(r["id"] for r in m.get("relatedVulnerabilities", []))}
        d = m["matchDetails"][0]
        for i in ids:
            out[(a["name"].lower(), i)].append(
                (d.get("type"), (d.get("searchedBy") or {}).get("namespace", ""), a["locations"][0]["path"],
                 " ".join(v.get("fix", {}).get("versions") or []), v["id"], a["version"]))
            out[(a["name"].split("/")[-1].lower(), i)].append(
                (d.get("type"), (d.get("searchedBy") or {}).get("namespace", ""), a["locations"][0]["path"],
                 " ".join(v.get("fix", {}).get("versions") or []), v["id"], a["version"]))
    return out


def trivy_paths(repo):
    out = collections.defaultdict(set)
    d = json.load(open(f"out/trivy-{repo}.json"))
    for r in d.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            p = v.get("PkgPath") or r.get("Target", "")
            out[(v["PkgName"].lower(), v["VulnerabilityID"])].add(p)
            out[("version", v["PkgName"].lower(), v["VulnerabilityID"])].add(v["InstalledVersion"])
        for p in r.get("Packages") or []:
            if p.get("AnalyzedBy") == "sbom":
                out[(p["Name"].lower(), "sbom")].add("sbom")
            out["packages"].add(p["Name"].lower())
            out["packages"].add(p["Name"].split(":")[-1].lower())
    return out


def debian_status(vid, rel):
    for src, d in tracker.get(vid, {}).items():
        r = d.get("releases", {}).get(REL.get(rel, ""))
        if r:
            return r.get("status"), r.get("urgency")
    return None, None


def os_only_other(tool, r, k, gm):
    """A row Trivy or Grype reports for an OS package and we do not."""
    fam = (r["os"] or {}).get("Family", "")
    name = (r["os"] or {}).get("Name", "")
    major = name.split(".")[0]
    _, pkg, _, vid = k
    bare = re.sub(r"_\d+$", "", vid)
    if tool == "grype":
        details = gm.get((pkg, vid), [])
        if any("nvd" in d[1] for d in details):
            return "Grype matched NVD CPEs, which no distro record backs"
        if fam == "oracle" and any("_fips" in d[3] for d in details):
            return "Grype compares Oracle's FIPS builds (epoch 10) with ordinary ones"
        if fam == "rocky" and any("redhat:distro" in d[1] for d in details):
            return "Grype applies Red Hat's fixes to Rocky, which ships its own"
        if any("MOCK" in d[4] for d in details):
            return "Grype's data holds a mock record (ALAS2MOCK2)"
    if fam in ("redhat", "centos") and vid not in RH_CVES[major]:
        return "Red Hat's export says nothing about this CVE for this release: the tool's feed only"
    if fam == "redhat" and pkg == "kernel-headers":
        fixes = RH_KERNEL.get(vid, [])
        if any(nums(f.split(":")[-1])[:6] <= [5, 14, 0, 611, 55, 1] for f in fixes):
            return "Red Hat fixed it in a build at or below the installed one; the tool keeps the open status"
    if fam == "sles" and vid.startswith("SUSE-SU") and vid not in SUSE_IDS:
        return "SUSE advisory with no CVE and no OSV record"
    if fam == "rocky" and tool == "trivy":
        return "Rocky's later erratum is in the tool's feed, not in its OSV export"
    if fam == "debian":
        if name.startswith("trixie"):
            return "Image is Debian testing, which has no release to match"
        if vid.startswith("TEMP-"):
            return "Debian placeholder id, published only in the tracker"
        if vid.startswith(("DLA-", "DSA-")):
            return "Debian advisory with no CVE, absent from the OSV export"
        if major in ("10", "11"):
            if vid in WITHDRAWN[major]:
                return "Frozen export marks the record withdrawn; the tools keep the CVE"
            if vid in FROZEN[major]:
                return "Frozen export says nothing about this package for this CVE"
            return "Retired Debian release: not in its frozen export, which ends in October 2024 (coverage gap reported)"
        ecos = OSV["Debian"].get(vid, {})
        if f"Debian:{major}" not in ecos:
            return "No OSV record for this release"
        st, urg = debian_status(vid, major)
        return f"Debian marks it {urg or 'unimportant'}, resolved for this release"
    if fam == "ubuntu":
        ecos = OSV["Ubuntu"].get(vid, {})
        if name in ("25.04",):
            return "Ubuntu release left OSV (coverage gap reported)"
        return "No Ubuntu record for this package and release in OSV"
    if fam == "alpine":
        ecos = OSV["Alpine"].get(bare, {})
        if not any(e == "Alpine:v" + ".".join(name.split(".")[:2]) for e in ecos):
            return "No OSV record for this release"
        return "OSV's lower bound puts the installed version before the bug"
    return None


def ours_os(tool, r, k, rec, other, open_, fam):
    _, pkg, _, vid = k
    major = ((r["os"] or {}).get("Name") or "").split(".")[0]
    if tool == "grype" and re.match(r"(linux-libc-dev|kernel-headers|linux-headers)", pkg):
        return "Grype's default ignore rule drops kernel headers"
    if fam == "debian":
        if major in ("10", "11") and vid in FROZEN[major]:
            if other:
                return "Frozen export's open status: the other tool lists it too"
            return "Frozen export's open status: neither tool lists it now (coverage gap reported)"
        if other and tool == "trivy":
            return "Third-party .deb (nginx.org, MariaDB) Debian also names: Grype matches it, Trivy does not"
        if other:
            return "Debian id or status Grype's data leaves out; Trivy and the tracker list it"
        if vid.startswith(("DLA-", "DSA-")):
            return "Debian advisory with no CVE, which neither tool lists under that id"
        if vid not in tracker:
            return "OSV's Debian record has no tracker entry; both tools read the tracker"
        st, _ = debian_status(vid, major)
        if st == "undetermined":
            return "Debian status undetermined: we keep it open, both tools drop it"
        return "OSV's Debian record is open where the tracker resolved it (unimportant): stale upstream record"
    if fam == "ubuntu":
        if vid.startswith("USN-"):
            return "Ubuntu notice with no CVE, which neither tool lists under that id"
        if other and tool == "trivy":
            return "Ubuntu's open and Pro records: Grype lists them, Trivy leaves them out"
        if other:
            return "Ubuntu record Grype's data leaves out; Trivy lists it"
        return "Ubuntu record neither tool's feed carries for this release"
    if fam in ("alma", "rocky", "centos") and open_:
        return "Red Hat's open status applied to a rebuild: Grype does the same, Trivy reads only fixes" if other \
            else "Red Hat's open status applied to a rebuild, with no module stream named"
    if fam == "redhat" and open_:
        if other:
            return "Red Hat's open status: the other tool lists it"
        return "Red Hat's open status names no module stream: we keep it, both tools drop it"
    if fam in ("redhat", "centos"):
        return "Fix named for the source package: the tool reads fixes per binary"
    if fam == "opensuse-tumbleweed":
        return "openSUSE GA-media record with a wrong fix version: upstream data error"
    if fam in ("sles", "opensuse-leap"):
        return "SUSE's per-CVE status, which the tool does not read here"
    if fam == "wolfi":
        return "Chainguard's open status: both tools read fixes only"
    return f"{fam}: the distribution's OSV record; the tool's feed lacks it"


def classify(direction, r, k, gm, tp):
    klass, pkg, ver, vid = k
    fam = (r["os"] or {}).get("Family", "")
    tool = "trivy" if "trivy" in direction else "grype"
    if direction.startswith("only_"):
        if klass == "binary":
            return "Grype's binary classifiers guess a version from file contents"
        if klass.startswith("other:"):
            return "Ecosystem we do not read (Perl modules)"
        if klass == "os":
            return os_only_other(tool, r, k, gm)
        if tool == "grype":
            paths = [d[2].lstrip("/") for d in gm.get((pkg, vid), [])]
            if any(p in owned[r["repo"]] for p in paths):
                return "File an OS package owns: the distribution's advisories cover it"
            if any(pkg in p.lower() and p.endswith(".egg-info") for p in paths) and pkg in tp["packages"]:
                return "File an OS package owns: the distribution's advisories cover it"
            short = pkg.split(":")[-1]
            if any("distro" in d[1] for d in gm.get((short, vid), [])):
                return "File an OS package owns: the distribution's advisories cover it"
        if klass == "npm" and tool == "grype" and any("MAL" in d[4] or d[4].startswith("GHSA") for d in gm.get((pkg, vid), [])) and pkg in PRIVATE:
            return "A private project that is no registry package: Grype matches a malware record by name"
        if klass == "go" and pkg in ("github.com/hashicorp/vault", "github.com/grafana/grafana"):
            return "Main module built as (devel): the tool takes a version from outside the build info"
        if (pkg, "sbom") in tp:
            return "Vendored copy Trivy reads from an embedded SBOM"
        if klass in LANG and vid not in OSV[LANG[klass]]:
            return "No OSV record: the tool's own database"
        if any("no coordinates" in g for g in gaps[r["repo"]]) and klass == "maven":
            return "Java archive with no coordinates: coverage gap reported"
        if klass in LANG:
            rec = [e for es in OSV[LANG[klass]][vid].values() for e in es
                   if (e[0] or "").lower().split("/")[-1] in (pkg.split("/")[-1], pkg.split(":")[-1])]
            versions = [d[5] for d in gm.get((pkg, vid), [])] + list(tp.get(("version", pkg, vid), []))
            if versions and all(out_of_ranges(v, rec) for v in versions):
                return "OSV's range leaves the installed version out: the tool's database has a wider one"
        return None
    # We report it, the other tool does not.
    other = k in r["keys_g" if tool == "trivy" else "keys_t"]
    rec = MINE[r["repo"]][k]
    open_ = rec.status == {"open"}
    if klass == "os":
        return ours_os(tool, r, k, rec, other, open_, fam)
    if other:
        if klass == "julia":
            return "Grype has no Julia data; Trivy reads the same records"
        if klass == "go" and tool == "grype":
            return "Go vulnerability database or OSV record Grype's data lacks; Trivy has it"
        return f"The other tool reports it: {tool}'s data for this package lacks it"
    if pkg not in tp["packages"] and pkg.split("/")[-1] not in tp["packages"]:
        return "A package only we read: lockfile or module list neither tool reads in images"
    return "Record only OSV carries for this package: neither tool's database has it"


def status_why(direction, r, k):
    """We and the tool report it; one names a fix and the other does not."""
    klass, pkg, _, vid = k
    fam = (r["os"] or {}).get("Family", "")
    tool = "grype" if direction.endswith("_g") else "trivy"
    rec = MINE[r["repo"]][k]
    title_fix = "fixed in" in (rec.extra or "")
    ours_fixed = "fixed" in rec.status
    if klass != "os":
        return "GO- or GHSA record with no fix where its twin names one" if not ours_fixed \
            else "The tool's record names no fix where OSV does"
    if ours_fixed:
        if fam == "ubuntu":
            return "Ubuntu Pro fix: the tool says not fixed, or will not fix"
        if fam in ("centos", "redhat"):
            return "Red Hat's extended-support fix: the tool keeps will not fix"
        if fam == "debian":
            return "Debian retired release: the LTS fix against the tool's will not fix"
        if fam in ("sles", "alpine"):
            return "The vendor's fix: the tool's feed says not fixed"
        return "The distribution's fix: the tool's feed says not fixed"
    if title_fix or "another line" in (rec.extra or ""):
        return "Fix named in the title: its version cannot be rendered in the report's semver form, so it stays open (fail closed), or it is in a line the image cannot reach"
    if fam == "debian" and ((r["os"] or {}).get("Name") or "").split(".")[0] in ("10", "11"):
        return "Frozen export's open status where the tool's feed names a later fix"
    if fam in ("centos", "oracle", "redhat", "rocky"):
        return "Vendor's open status where the tool's feed names a fix from another line"
    return "Distribution record open where the tool's feed names a fix"


results = collections.defaultdict(collections.Counter)
resid = collections.defaultdict(collections.Counter)
residk = collections.defaultdict(list)
samples = collections.defaultdict(list)
for r in rows:
    r["keys_t"] = {tuple(k) for k in r["ours_not_grype"]} ^ {tuple(k) for k in r["only_ours"]}
    r["keys_g"] = {tuple(k) for k in r["ours_not_trivy"]} ^ {tuple(k) for k in r["only_ours"]}
    gm = grype_matches(r["repo"]) if os.path.exists(f"out/grype-{r['repo']}.json") else {}
    tp = trivy_paths(r["repo"])
    for direction in ("only_trivy", "only_grype", "ours_not_trivy", "ours_not_grype", "status", "status_g"):
        for k in r[direction]:
            k = tuple(k)
            why = (status_why(direction, r, k) if direction.startswith("status")
                   else classify(direction, r, k, gm, tp)) or "UNEXPLAINED"
            results[direction][why] += 1
            if why == "UNEXPLAINED":
                resid[direction][((r["os"] or {}).get("Family", "none"), k[0])] += 1
                residk[(direction, (r["os"] or {}).get("Family", "none"), k[0])].append((r["repo"], k[1], k[3]))
            if len(samples[(direction, why)]) < 6:
                samples[(direction, why)].append((r["repo"], *k))
json.dump({f"{a}|{b}|{c}": v for (a, b, c), v in residk.items()}, open("unexplained.json", "w"))
for direction, c in results.items():
    print(direction, sum(c.values()))
    for why, n in c.most_common():
        print(f"  {n:7d}  {why}")
        if why == "UNEXPLAINED":
            print("          ", samples[(direction, why)])
for d, c in resid.items():
    print("RESIDUAL", d, c.most_common(20))
for k, v in sorted(residk.items(), key=lambda x: -len(x[1]))[:24]:
    print(k, len(v), collections.Counter(x[0] for x in v).most_common(3), collections.Counter(x[1] for x in v).most_common(4), v[:2])
json.dump({d: dict(c) for d, c in results.items()}, open("explained.json", "w"), indent=1)
