//! Matching installed OS packages against the distro advisories.
//!
//! Each installed source package (binary packages folded into their source) is matched
//! against its release's ecosystem with the family's own comparator. Red Hat and AlmaLinux
//! name binary packages in their advisories, so there each binary is matched on its own.
//! Two rules beyond the plain range match:
//!
//! - **Unfixed is a finding.** A Debian or Ubuntu entry with no `fixed` event means the
//!   distro knows the package is affected and has not shipped a fix; it becomes a finding
//!   with no patched version, never a silent drop. `ignore_unimportant` drops only what the
//!   distro itself rates `unimportant` (Debian) or `negligible` (Ubuntu).
//! - **Overlays win per CVE.** Ubuntu Pro (ESM) and Root publish their own fixes for CVEs
//!   the base release also lists; where an overlay has a record for the same package and
//!   CVE, its verdict replaces the base one. Root's overlay applies only to packages Root
//!   patched (a `root.io` version).

use std::collections::{BTreeMap, BTreeSet};

use fleetreach_core::osv::{
    self, sort_dedup_findings, Match, ParsedRange, TierCFinding, TierCScan,
};
use fleetreach_core::semver::{Prerelease, Version as SemverVersion};
use fleetreach_core::{Ecosystem, RepoId, VulnFinding};

use crate::apkver::ApkVersion;
use crate::db::{Advisory, DistroDb};
use crate::distro::{Distro, Family};
use crate::dpkgver::DebVersion;
use crate::packages::OsPackage;
use crate::rpmver::RpmVersion;

/// Matching options.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanOptions {
    /// Drop advisories the distro rates `unimportant` / `negligible` (Trivy's default;
    /// off here, so nothing the distro tracks is hidden unless asked).
    pub ignore_unimportant: bool,
}

/// The shared model's SemVer rendering of a distro version. **Detection never uses it**;
/// it keeps the order of the common cases (`2.36.1-8+deb12u1 < 2.36.1-8+deb12u2`,
/// `1.0~rc1 < 1.0`, `-r9 < -r10`) by turning the leading numbers into `major.minor.patch`
/// and the rest into pre-release identifiers split at letter/digit boundaries. The epoch
/// is dropped. Where this order disagrees with the real one, [`scan`] drops the patched
/// requirement rather than let the coerced form call a vulnerable package fixed.
pub fn to_semver(raw: &str) -> SemverVersion {
    let body = match raw.split_once(':') {
        Some((e, rest)) if !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()) => rest,
        _ => raw,
    };
    // Only the dotted numbers before the first `-`, `+`, `~` or `_` are the release.
    let cut = body.find(['-', '+', '~', '_', ':']).unwrap_or(body.len());
    let (head, rest) = body.split_at(cut);
    let mut nums: Vec<u64> = Vec::new();
    let mut tail: Vec<String> = Vec::new();
    let mut in_tail = false;
    let tokens = head.split('.').map(|t| (t, true)).chain(
        rest.split(['.', '-', '+', '~', '_', ':'])
            .map(|t| (t, false)),
    );
    for (tok, in_head) in tokens {
        if !in_tail && in_head {
            if let Ok(n) = tok.parse::<u64>() {
                if nums.len() < 3 {
                    nums.push(n);
                    continue;
                }
            }
        }
        in_tail = true;
        // Split at letter/digit boundaries so numbers compare as numbers.
        let mut run = String::new();
        let mut digit = None;
        for c in tok.chars().filter(char::is_ascii_alphanumeric) {
            let d = c.is_ascii_digit();
            if digit.is_some_and(|p| p != d) {
                tail.push(std::mem::take(&mut run));
            }
            digit = Some(d);
            run.push(c);
        }
        if !run.is_empty() {
            tail.push(run);
        }
    }
    let tail: Vec<String> = tail
        .into_iter()
        .map(|t| match t.parse::<u64>() {
            Ok(n) => n.to_string(),
            Err(_) => t,
        })
        .collect();
    let mut v = SemverVersion::new(
        nums.first().copied().unwrap_or(0),
        nums.get(1).copied().unwrap_or(0),
        nums.get(2).copied().unwrap_or(0),
    );
    if !tail.is_empty() {
        if let Ok(p) = Prerelease::new(&tail.join(".")) {
            v.pre = p;
        }
    }
    v
}

/// A source package as installed: its name, version and the binaries built from it.
struct Source<'a> {
    name: &'a str,
    version: &'a str,
    binaries: Vec<&'a str>,
}

/// What to match: source packages with their binaries folded in, or each binary on its own
/// where the advisories name binaries (`binary_names`).
fn sources(packages: &[OsPackage], binary_names: bool) -> Vec<Source<'_>> {
    let mut by: BTreeMap<(&str, &str), Vec<&str>> = BTreeMap::new();
    for p in packages {
        let key = if binary_names {
            (p.name.as_str(), p.version.as_str())
        } else {
            (p.source.as_str(), p.source_version.as_str())
        };
        by.entry(key).or_default().push(p.name.as_str());
    }
    by.into_iter()
        .map(|((name, version), mut binaries)| {
            binaries.sort_unstable();
            binaries.dedup();
            Source {
                name,
                version,
                binaries,
            }
        })
        .collect()
}

/// `introduced: "0"` means from the first version, even one that sorts below `0`.
fn at_or_after<V: Ord + std::fmt::Display>(v: &V, bound: &V) -> bool {
    bound.to_string() == "0" || v >= bound
}

fn affected<V: Ord + Clone + std::fmt::Display>(v: &V, adv: &Advisory<V>) -> Option<Option<V>> {
    match osv::affected_fixed_parsed(v, &adv.ranges, at_or_after) {
        Match::Affected { fixed } => Some(fixed),
        Match::NotAffected if adv.versions.binary_search(v).is_ok() => Some(None),
        Match::NotAffected => None,
    }
}

fn has_fix<V>(ranges: &[ParsedRange<V>]) -> bool {
    ranges
        .iter()
        .filter(|r| r.matchable)
        .any(|r| r.events.iter().any(|e| e.fixed.is_some()))
}

/// Everything a match needs to know about where it happened.
struct Ctx<'a> {
    distro: &'a Distro,
    repo: &'a RepoId,
    opts: ScanOptions,
}

fn finding<V: Ord + Clone + std::fmt::Display>(
    ctx: &Ctx,
    src: &Source,
    v: &V,
    adv: &Advisory<V>,
    fixed: Option<V>,
) -> VulnFinding {
    let installed = to_semver(src.version);
    let mut patched = osv::patched_reqs(&osv::safe_intervals(v, &adv.ranges), |b| {
        to_semver(&b.to_string()).to_string()
    });
    // Fail closed: if the coerced form would read the installed version as fixed, keep the
    // finding vulnerable with no patched range.
    if patched.iter().any(|r| r.matches(&installed)) {
        patched.clear();
    }
    let mut notes = Vec::new();
    if fixed.is_none() {
        notes.push(if has_fix(&adv.ranges) {
            "fixed only in another line".to_string()
        } else {
            "no fix yet".to_string()
        });
    } else if let Some(f) = &fixed {
        notes.push(format!("fixed in {f}"));
    }
    if let Some(u) = &adv.urgency {
        notes.push(format!("{} {u}", ctx.distro.name_of_urgency()));
    }
    let title = format!("{} [{}: {}]", adv.title, ctx.distro.name, notes.join("; "));
    TierCFinding {
        ecosystem: match ctx.distro.family {
            Family::Deb => Ecosystem::Deb,
            Family::Apk => Ecosystem::Apk,
            Family::Rpm => Ecosystem::Rpm,
        },
        advisory_id: adv.id.clone(),
        aliases: adv.aliases.clone(),
        title,
        severity: adv.severity,
        cvss_score: adv.cvss_score,
        cvss_vector: adv.cvss_vector.clone(),
        package: format!("{}/{}", ctx.distro.namespace, src.name),
        installed,
        patched,
        direct: true,
        dev: false,
        // The shared model holds a SemVer rendering, so the real version rides in the path:
        // distro, then the source package at its true version, then its binaries.
        dependency_path: vec![
            ctx.distro.name.clone(),
            format!("{} {}", src.name, src.version),
            src.binaries.join(", "),
        ],
        repo: ctx.repo,
        reach_reason: "OS package (no toolchain): version match only",
    }
    .build()
}

impl Distro {
    fn name_of_urgency(&self) -> &'static str {
        match self.namespace.as_str() {
            "ubuntu" => "priority",
            _ => "urgency",
        }
    }
}

/// Match one source package across the release and its overlays.
fn match_source<'d, V: Ord + Clone + std::fmt::Display + 'd>(
    ctx: &Ctx,
    src: &Source,
    v: &V,
    lookup: impl Fn(&str) -> &'d [Advisory<V>],
    out: &mut Vec<VulnFinding>,
) {
    let applies = |eco: &str| !eco.starts_with("Root:") || src.version.contains("root.io");
    let overlays: Vec<&str> = ctx
        .distro
        .overlays
        .iter()
        .map(String::as_str)
        .filter(|e| applies(e))
        .collect();
    let mut superseded: BTreeSet<&str> = BTreeSet::new();
    for eco in &overlays {
        for adv in lookup(eco) {
            superseded.extend(adv.keys().filter(|k| k.starts_with("CVE-")));
        }
    }
    let base = std::iter::once(&ctx.distro.ecosystem)
        .chain(&ctx.distro.also)
        .flat_map(|e| lookup(e).iter());
    let candidates = base
        .filter(|a| !a.keys().any(|k| superseded.contains(k)))
        .chain(overlays.iter().flat_map(|e| lookup(e).iter()));
    for adv in candidates {
        if ctx.opts.ignore_unimportant && adv.unimportant() {
            continue;
        }
        if let Some(fixed) = affected(v, adv) {
            out.push(finding(ctx, src, v, adv, fixed));
        }
    }
}

/// Match an image's installed packages. `packages` are from [`crate::inventory`].
pub fn scan(
    distro: &Distro,
    packages: &[OsPackage],
    db: &DistroDb,
    repo: &RepoId,
    opts: ScanOptions,
) -> TierCScan {
    let ctx = Ctx { distro, repo, opts };
    let mut out = Vec::new();
    let mut skipped_unparseable = 0u32;
    for src in sources(packages, distro.binary_names) {
        match distro.family {
            Family::Deb => match DebVersion::parse(src.version) {
                Some(v) => match_source(&ctx, &src, &v, |e| db.deb(e, src.name), &mut out),
                None => skipped_unparseable += 1,
            },
            Family::Apk => match ApkVersion::parse(src.version) {
                Some(v) => match_source(&ctx, &src, &v, |e| db.apk(e, src.name), &mut out),
                None => skipped_unparseable += 1,
            },
            Family::Rpm => match RpmVersion::parse(src.version) {
                Some(v) => match_source(&ctx, &src, &v, |e| db.rpm(e, src.name), &mut out),
                None => skipped_unparseable += 1,
            },
        }
    }
    sort_dedup_findings(&mut out);
    TierCScan {
        findings: out,
        skipped_unparseable,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use fleetreach_core::osv::{Event, Range};
    use fleetreach_core::{Occurrence, Severity};

    fn adv<V>(id: &str, events: &[(&str, &str)], parse: fn(&str) -> Option<V>) -> Advisory<V> {
        let range = Range {
            matchable: true,
            events: events
                .iter()
                .map(|(k, v)| Event {
                    introduced: (*k == "introduced").then(|| v.to_string()),
                    fixed: (*k == "fixed").then(|| v.to_string()),
                    last_affected: None,
                })
                .collect(),
        };
        Advisory {
            id: id.into(),
            aliases: vec![format!(
                "CVE-{}",
                id.trim_start_matches(|c: char| !c.is_ascii_digit())
            )],
            title: format!("issue {id}"),
            severity: Severity::High,
            cvss_score: None,
            cvss_vector: None,
            urgency: None,
            ranges: vec![osv::parse_range(&range, parse)],
            versions: vec![],
        }
    }

    #[test]
    fn coercion_keeps_common_order() {
        let lt = |a: &str, b: &str| assert!(to_semver(a) < to_semver(b), "{a} < {b}");
        lt("2.36.1-8+deb12u1", "2.36.1-8+deb12u2");
        lt("1.0~rc1", "1.0");
        lt("3.3.2-r9", "3.3.2-r10");
        lt("1:2.0-1", "1:2.0-2");
        assert_eq!(
            to_semver("3.0.15-1~deb12u1").to_string(),
            "3.0.15-1.deb.12.u.1"
        );
    }

    #[test]
    fn unfixed_debian_entry_is_a_finding_with_no_fix() {
        let distro = crate::distro::explicit("Debian:12", Family::Deb);
        let mut a = adv("CVE-2024-1", &[("introduced", "0")], DebVersion::parse);
        a.urgency = Some("unimportant".into());
        let pkgs = vec![OsPackage {
            name: "libfoo1".into(),
            version: "1.0-1".into(),
            source: "foo".into(),
            source_version: "1.0-1".into(),
            arch: None,
        }];
        let ctx = Ctx {
            distro: &distro,
            repo: &RepoId("img".into()),
            opts: ScanOptions::default(),
        };
        let src = &sources(&pkgs, false)[0];
        let mut out = Vec::new();
        let v = DebVersion::parse("1.0-1").unwrap();
        match_source(&ctx, src, &v, |_| std::slice::from_ref(&a), &mut out);
        assert_eq!(out.len(), 1);
        assert!(out[0].title.contains("no fix yet"), "{}", out[0].title);
        assert!(out[0].title.contains("urgency unimportant"));
        match &out[0].occurrences[0] {
            Occurrence::InRepo {
                package, patched, ..
            } => {
                assert_eq!(package, "debian/foo");
                assert!(patched.is_empty());
            }
            Occurrence::Toolchain { .. } => panic!("expected InRepo"),
        }
        // Opt-in: the distro's own "unimportant" rating drops it.
        let ctx = Ctx {
            opts: ScanOptions {
                ignore_unimportant: true,
            },
            ..ctx
        };
        let mut out = Vec::new();
        match_source(&ctx, src, &v, |_| std::slice::from_ref(&a), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn fixed_version_is_clean_and_tilde_backport_is_not() {
        let distro = crate::distro::explicit("Debian:12", Family::Deb);
        let a = adv(
            "CVE-2024-2",
            &[("introduced", "0"), ("fixed", "3.0.15-1~deb12u1")],
            DebVersion::parse,
        );
        let repo = RepoId("img".into());
        let ctx = Ctx {
            distro: &distro,
            repo: &repo,
            opts: ScanOptions::default(),
        };
        for (installed, hit) in [
            ("3.0.15-1~deb12u1", false),
            ("3.0.14-1~deb12u2", true),
            ("3.0.15-1", false),
        ] {
            let pkgs = vec![OsPackage {
                name: "libssl3".into(),
                version: installed.into(),
                source: "openssl".into(),
                source_version: installed.into(),
                arch: None,
            }];
            let src = &sources(&pkgs, false)[0];
            let mut out = Vec::new();
            let v = DebVersion::parse(installed).unwrap();
            match_source(&ctx, src, &v, |_| std::slice::from_ref(&a), &mut out);
            assert_eq!(!out.is_empty(), hit, "{installed}");
            if hit {
                assert!(out[0].occurrences[0].is_vulnerable());
            }
        }
    }

    #[test]
    fn root_overlay_supersedes_base_for_patched_packages() {
        let mut distro = crate::distro::explicit("Debian:12", Family::Deb);
        distro.namespace = "debian".into();
        distro.overlays = vec!["Root:Debian:12".into()];
        let base = adv(
            "CVE-2024-3",
            &[("introduced", "0"), ("fixed", "1.0-3")],
            DebVersion::parse,
        );
        let mut root = adv(
            "ROOT-OS-DEBIAN-12-CVE-2024-3",
            &[("introduced", "0"), ("fixed", "1.0-2.root.io.1")],
            DebVersion::parse,
        );
        root.aliases = vec!["CVE-2024-3".into()];
        let repo = RepoId("img".into());
        let ctx = Ctx {
            distro: &distro,
            repo: &repo,
            opts: ScanOptions::default(),
        };
        let lookup = |e: &str| -> &[Advisory<DebVersion>] {
            if e == "Root:Debian:12" {
                std::slice::from_ref(&root)
            } else {
                std::slice::from_ref(&base)
            }
        };
        let run = |ver: &str| {
            let pkgs = vec![OsPackage {
                name: "x".into(),
                version: ver.into(),
                source: "x".into(),
                source_version: ver.into(),
                arch: None,
            }];
            let src = &sources(&pkgs, false)[0];
            let mut out = Vec::new();
            match_source(
                &ctx,
                src,
                &DebVersion::parse(ver).unwrap(),
                lookup,
                &mut out,
            );
            out.len()
        };
        // Root patched it: the base record's later fix no longer applies.
        assert_eq!(run("1.0-2.root.io.1"), 0);
        // Not a Root package: the base record decides.
        assert_eq!(run("1.0-2"), 1);
    }

    #[test]
    fn rpm_matches_binaries_or_sources_as_the_distro_names_them() {
        let pkgs = vec![
            OsPackage {
                name: "openssl-libs".into(),
                version: "1:3.0.7-27.el9".into(),
                source: "openssl".into(),
                source_version: "1:3.0.7-27.el9".into(),
                arch: None,
            },
            OsPackage {
                name: "openssl".into(),
                version: "1:3.0.7-27.el9".into(),
                source: "openssl".into(),
                source_version: "1:3.0.7-27.el9".into(),
                arch: None,
            },
        ];
        let fix = |id: &str| {
            adv(
                id,
                &[("introduced", "0"), ("fixed", "1:3.0.7-28.el9_4")],
                RpmVersion::parse,
            )
        };
        let repo = RepoId("img".into());
        // Red Hat names binaries, across its repositories: each binary is its own finding.
        let mut rhel = crate::distro::explicit("Red Hat:enterprise_linux:9::baseos", Family::Rpm);
        rhel.also = vec!["Red Hat:enterprise_linux:9::appstream".into()];
        let mut db = DistroDb::default();
        db.insert_rpm(
            "Red Hat:enterprise_linux:9::baseos",
            "openssl-libs",
            fix("RHSA-1"),
        );
        db.insert_rpm(
            "Red Hat:enterprise_linux:9::appstream",
            "openssl",
            fix("RHSA-1"),
        );
        let s = scan(&rhel, &pkgs, &db, &repo, ScanOptions::default());
        let names: Vec<_> = s.findings.iter().map(|f| f.ecosystem).collect();
        assert_eq!(names, [Ecosystem::Rpm, Ecosystem::Rpm], "{:?}", s.findings);
        // Rocky names sources: one finding for the source, both binaries in its path.
        let rocky = crate::distro::explicit("Rocky Linux:9", Family::Rpm);
        let mut db = DistroDb::default();
        db.insert_rpm("Rocky Linux:9", "openssl", fix("RLSA-1"));
        let s = scan(&rocky, &pkgs, &db, &repo, ScanOptions::default());
        assert_eq!(s.findings.len(), 1);
        assert!(s.findings[0].occurrences[0].is_vulnerable());
        // The epoch counts: 0:3.1 is older than the installed 1:3.0.7.
        let mut db = DistroDb::default();
        db.insert_rpm(
            "Rocky Linux:9",
            "openssl",
            adv(
                "RLSA-2",
                &[("introduced", "0"), ("fixed", "0:3.1.0-1.el9")],
                RpmVersion::parse,
            ),
        );
        assert!(scan(&rocky, &pkgs, &db, &repo, ScanOptions::default())
            .findings
            .is_empty());
    }

    #[test]
    fn apk_scan_end_to_end() {
        let distro = crate::distro::explicit("Alpine:v3.20", Family::Apk);
        let a = adv(
            "CVE-2024-4",
            &[("introduced", "0"), ("fixed", "3.3.2-r1")],
            ApkVersion::parse,
        );
        let mut db = DistroDb::default();
        db.insert_apk("Alpine:v3.20", "openssl", a);
        let pkgs = vec![
            OsPackage {
                name: "libcrypto3".into(),
                version: "3.3.2-r0".into(),
                source: "openssl".into(),
                source_version: "3.3.2-r0".into(),
                arch: None,
            },
            OsPackage {
                name: "libssl3".into(),
                version: "3.3.2-r0".into(),
                source: "openssl".into(),
                source_version: "3.3.2-r0".into(),
                arch: None,
            },
        ];
        let s = scan(
            &distro,
            &pkgs,
            &db,
            &RepoId("img".into()),
            ScanOptions::default(),
        );
        assert_eq!(s.findings.len(), 1, "binaries fold into one source finding");
        let f = &s.findings[0];
        assert_eq!(f.ecosystem, Ecosystem::Apk);
        match &f.occurrences[0] {
            Occurrence::InRepo {
                dependency_path, ..
            } => {
                assert_eq!(dependency_path[2], "libcrypto3, libssl3");
            }
            Occurrence::Toolchain { .. } => panic!("expected InRepo"),
        }
    }
}
