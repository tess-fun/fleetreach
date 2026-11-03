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
use crate::distro::{is_suse_vex, Distro, Family};
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
    /// The source package name (the same as `name` where packages are grouped by source).
    source: &'a str,
    version: &'a str,
    binaries: Vec<&'a str>,
    /// Binaries whose own version differs from the source one (SUSE's `libreadline7`
    /// 7.0 built from `bash` 4.4), with that version.
    other_versions: BTreeMap<&'a str, &'a str>,
    /// The module stream the packages came from, if any.
    module: Option<&'a str>,
}

/// A binary at a version of its own, with that version (see [`Source::other_versions`]).
type OwnVersion<'a> = Option<(&'a str, &'a str)>;

/// What to match: source packages with their binaries folded in, or each binary on its own
/// where the advisories name binaries (`binary_names`).
fn sources(packages: &[OsPackage], binary_names: bool) -> Vec<Source<'_>> {
    /// Name, version and module stream.
    type Key<'a> = (&'a str, &'a str, Option<&'a str>);
    /// The source name, the binaries, and those at a version of their own.
    type Group<'a> = (&'a str, Vec<&'a str>, BTreeMap<&'a str, &'a str>);
    let mut by: BTreeMap<Key<'_>, Group<'_>> = BTreeMap::new();
    for p in packages {
        let module = p.module.as_deref();
        let key = if binary_names {
            (p.name.as_str(), p.version.as_str(), module)
        } else {
            (p.source.as_str(), p.source_version.as_str(), module)
        };
        let entry = by
            .entry(key)
            .or_insert((p.source.as_str(), Vec::new(), BTreeMap::new()));
        entry.1.push(p.name.as_str());
        if p.version != key.1 {
            entry.2.insert(p.name.as_str(), p.version.as_str());
        }
    }
    by.into_iter()
        .map(
            |((name, version, module), (source, mut binaries, other_versions))| {
                binaries.sort_unstable();
                binaries.dedup();
                Source {
                    name,
                    source,
                    version,
                    binaries,
                    other_versions,
                    module,
                }
            },
        )
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
    binary: OwnVersion<'_>,
) -> VulnFinding {
    let installed = to_semver(src.version);
    let mut patched = osv::patched_reqs(&osv::safe_intervals(v, &adv.ranges), |b| {
        to_semver(&b.to_string()).to_string()
    });
    // Fail closed: if the coerced form would read the installed version as fixed, keep the
    // finding vulnerable with no patched range.
    // A binary at its own version: its fix is in that version's terms, not the source's.
    if binary.is_some() || patched.iter().any(|r| r.matches(&installed)) {
        patched.clear();
    }
    let mut notes = Vec::new();
    if let Some((name, version)) = binary {
        notes.push(format!("{name} {version}"));
    }
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
    let mut f = TierCFinding {
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
    .build();
    if adv.url.is_some() {
        f.url.clone_from(&adv.url);
    }
    f
}

impl Distro {
    /// Whether the release's repositories have `fix`, the fix an advisory of its own
    /// ecosystems names for `package`: always, unless the release is matched against the
    /// records of the distribution it rebuilds (see [`Distro::final_builds`]).
    fn shipped<V: std::fmt::Display>(&self, package: &str, adv: &Advisory<V>, fix: &V) -> bool {
        self.final_builds.as_deref().is_none_or(|release| {
            crate::centos::shipped(release, package, adv.module.as_deref(), &fix.to_string())
        })
    }

    fn name_of_urgency(&self) -> &'static str {
        match self.namespace.as_str() {
            "ubuntu" => "priority",
            // The vendors' VEX statuses (Red Hat, SUSE): no other urgency reaches these distros.
            "redhat" | "suse" | "opensuse" => "status",
            // Red Hat's statuses, borrowed by its rebuilds.
            "almalinux" | "rocky-linux" | "centos" => "Red Hat status",
            _ => "urgency",
        }
    }
}

/// Whether a package can be a build of one of the module streams `modules` names
/// (`php:7.4`, or comma-separated `virt:rhel,virt-devel:rhel`), the condition an advisory
/// about those streams' builds carries. A labelled package belongs to its own stream only,
/// and a package that is no module build (no `.module` in its release) to none. An older
/// module build can lack the label; it belongs to the stream the image has enabled for that
/// module, or, with none recorded, possibly to any (so it still matches: an unknown stream
/// never hides a fix).
fn in_stream(distro: &Distro, src: &Source, modules: &str) -> bool {
    modules.split(',').any(|module| {
        if let Some(own) = src.module {
            return own == module;
        }
        if !src.version.contains(".module") {
            return false;
        }
        let (name, stream) = module.split_once(':').unwrap_or((module, ""));
        distro.modules.get(name).is_none_or(|s| s == stream)
    })
}

/// Whether a module build is outside an advisory's reach: the advisory's fixes are all
/// non-module builds. With a module stream enabled, dnf hides the non-module packages of the
/// same name, so such a fix never replaces a module build (Rocky's RLSA-2021:1678 fixes perl
/// 5.26's `5.26.3-419.el8`, which no `perl:5.32` install takes).
fn non_module_fix_for_module_build<V: std::fmt::Display>(src: &Source, adv: &Advisory<V>) -> bool {
    let module_build = src.module.is_some() || src.version.contains(".module");
    let mut fixes = adv
        .ranges
        .iter()
        .filter(|r| r.matchable)
        .flat_map(|r| &r.events)
        .filter_map(|e| e.fixed.as_ref())
        .peekable();
    module_build
        && adv.module.is_none()
        && fixes.peek().is_some()
        && fixes.all(|f| !f.to_string().contains(".module"))
}

/// Match one source package across the release, its overlays and its fallbacks. `lookup`
/// gives an ecosystem's advisories for a package name.
fn match_source<'d, V: Ord + Clone + std::fmt::Display + 'd>(
    ctx: &Ctx,
    src: &Source,
    v: &V,
    parse: impl Fn(&str) -> Option<V>,
    by_name: impl Fn(&str, &str) -> &'d [Advisory<V>],
    out: &mut Vec<VulnFinding>,
) {
    let lookup = |eco: &str| by_name(eco, src.name);
    let applies = |eco: &str| !eco.starts_with("Root:") || src.version.contains("root.io");
    // Whether an advisory can be about this build at all: another module stream's advisory,
    // or a non-module fix for a module build, says nothing about it, so it neither matches
    // nor counts as the release having spoken about the CVE (php:8.0's RHSA must not hide
    // Red Hat's "fix deferred" for php:7.4).
    let reach = |adv: &Advisory<V>| {
        adv.module
            .as_ref()
            .is_none_or(|m| in_stream(ctx.distro, src, m))
            && !non_module_fix_for_module_build(src, adv)
    };
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
    // A fallback speaks only about CVEs the release's own records do not mention for this
    // package (fixed there or not), and names the binary or its source package.
    let known: BTreeSet<&str> = base
        .clone()
        .chain(overlays.iter().flat_map(|e| lookup(e).iter()))
        .filter(|a| reach(a))
        .flat_map(Advisory::keys)
        .filter(|k| k.starts_with("CVE-"))
        .collect();
    // Fallbacks in order: the first that speaks about a CVE for this package is the one
    // that counts. Within one, by binary name first: vendors list fixes and "not affected"
    // per binary package (Red Hat, SUSE). A source package's entry stands for its binaries
    // only where it has no fix (Red Hat lists open issues per source), and never for a CVE
    // a binary's entry speaks about.
    let mut source_names = vec![src.name];
    if src.source != src.name {
        source_names.push(src.source);
    }
    // SUSE's open status is its word that no build fixes the CVE yet, which a release
    // record's fix (one this package already has) does not overrule: SUSE lists CVEs an
    // update did not fix among those it names (SUSE-SU-2025:4092-1 and CVE-2025-1372).
    // Only a release record that finds this package affected speaks first. Red Hat's open
    // entries can be about another stream, so a release fix stays first there.
    let hit: BTreeSet<&str> = base
        .clone()
        .chain(overlays.iter().flat_map(|e| lookup(e).iter()))
        .filter(|a| reach(a) && affected(v, a).is_some())
        .flat_map(Advisory::keys)
        .filter(|k| k.starts_with("CVE-"))
        .collect();
    let is_open = |a: &Advisory<V>| !a.ranges.is_empty() && !has_fix(&a.ranges);
    let mut spoken: BTreeSet<&str> = known.clone();
    let mut spoken_open: BTreeSet<&str> = hit;
    // Each with whether it is borrowed (its fix is not the release's) and the binary it names
    // when that binary's version is not the source's: its entry is in that version's terms.
    let mut fallbacks: Vec<(&Advisory<V>, bool, OwnVersion<'_>)> = Vec::new();
    for eco in &ctx.distro.fallbacks {
        let borrowed = ctx.distro.borrowed.contains(eco);
        let opens_only = ctx.distro.borrowed_opens.contains(eco);
        let mut by_binary: BTreeSet<&str> = BTreeSet::new();
        let mut here: Vec<(&Advisory<V>, OwnVersion<'_>)> = Vec::new();
        for bin in &src.binaries {
            let own = src.other_versions.get(bin).map(|ver| (*bin, *ver));
            for adv in by_name(eco, bin).iter().filter(|a| reach(a)) {
                by_binary.extend(adv.keys().filter(|k| k.starts_with("CVE-")));
                here.push((adv, own));
            }
        }
        for name in source_names.iter().filter(|n| !src.binaries.contains(n)) {
            here.extend(
                by_name(eco, name)
                    .iter()
                    .filter(|a| reach(a))
                    .filter(|a| !has_fix(&a.ranges) && !a.keys().any(|k| by_binary.contains(k)))
                    .map(|a| (a, None)),
            );
        }
        // From a borrowed codestream only its fixes count: an older build is vulnerable, while
        // its open statuses are not the vendor's word about this release.
        let fresh: Vec<(&Advisory<V>, OwnVersion<'_>)> = here
            .into_iter()
            .filter(|(a, _)| {
                let before = if is_suse_vex(eco) && is_open(a) {
                    &spoken_open
                } else {
                    &spoken
                };
                !a.keys().any(|k| before.contains(k))
            })
            .filter(|(a, _)| !borrowed || has_fix(&a.ranges))
            // From the distribution a release rebuilds, the reverse: its open statuses and
            // "not affected" hold for the same sources, its fix versions are its own builds.
            .filter(|(a, _)| !opens_only || !has_fix(&a.ranges))
            .collect();
        for (adv, _) in &fresh {
            spoken.extend(adv.keys().filter(|k| k.starts_with("CVE-")));
            spoken_open.extend(adv.keys().filter(|k| k.starts_with("CVE-")));
        }
        fallbacks.extend(fresh.into_iter().map(|(a, own)| (a, borrowed, own)));
    }
    let wanted =
        |adv: &Advisory<V>| !(ctx.opts.ignore_unimportant && adv.unimportant()) && reach(adv);
    let candidates = base
        .filter(|a| !a.keys().any(|k| superseded.contains(k)))
        .chain(overlays.iter().flat_map(|e| lookup(e).iter()));
    for adv in candidates.filter(|a| wanted(a)) {
        if let Some(fixed) = affected(v, adv) {
            let fixed = fixed.filter(|f| ctx.distro.shipped(src.name, adv, f));
            out.push(finding(ctx, src, v, adv, fixed, None));
        }
    }
    // One finding per fallback advisory, though several binaries may speak about it: open
    // if any affected binary has no fix (upgrading fixes nothing then), else the highest fix
    // in the source's own terms, else one in a binary's own.
    type Chosen<'a, V> = (Option<V>, &'a Advisory<V>, OwnVersion<'a>);
    let rank = |c: &Chosen<'_, V>| match c {
        (None, ..) => 2,
        (Some(_), _, None) => 1,
        (Some(_), _, Some(_)) => 0,
    };
    let mut chosen: BTreeMap<&str, Chosen<'_, V>> = BTreeMap::new();
    for (adv, borrowed, own) in fallbacks.into_iter().filter(|(a, ..)| wanted(a)) {
        // Fail closed: a binary version that does not parse is read as the source's.
        let own_v = own.and_then(|(_, ver)| parse(ver).map(|bv| (own, bv)));
        let (installed, own) = match &own_v {
            Some((own, bv)) => (bv, *own),
            None => (v, None),
        };
        let Some(fixed) = affected(installed, adv) else {
            continue;
        };
        let new = (fixed.filter(|_| !borrowed), adv, own);
        let better = match chosen.get(adv.id.as_str()) {
            None => true,
            Some(old) => match rank(&new).cmp(&rank(old)) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => new.0.as_ref() > old.0.as_ref(),
            },
        };
        if better {
            chosen.insert(adv.id.as_str(), new);
        }
    }
    for (fixed, adv, own) in chosen.into_values() {
        out.push(finding(ctx, src, v, adv, fixed, own));
    }
}

/// Advisories by ecosystem and package name.
type ByName = BTreeMap<(String, String), Vec<Advisory<RpmVersion>>>;

/// For a rebranded CentOS build (`4.2.5-83.el7.centos.2`), the advisories it is matched
/// against with Red Hat's fixes in CentOS's form (`4.2.5-83.el7_9.2` is the same build), so
/// the build CentOS shipped as a fix reads as fixed; see [`crate::centos::rebrand`]. `None`
/// for any other package, which is matched against the records as they are.
fn rebranded(distro: &Distro, db: &DistroDb, src: &Source) -> Option<ByName> {
    if distro.final_builds.is_none() || !src.version.contains(".centos") {
        return None;
    }
    let rebrand = |f: &RpmVersion| {
        crate::centos::rebrand(&f.to_string())
            .and_then(|r| RpmVersion::parse_fix(&r))
            .unwrap_or_else(|| f.clone())
    };
    let mut names = vec![src.name, src.source];
    names.extend(&src.binaries);
    let mut out = BTreeMap::new();
    for eco in distro.ecosystems() {
        for name in &names {
            let advs = db
                .rpm(&eco, name)
                .iter()
                .cloned()
                .map(|mut a| {
                    for e in a.ranges.iter_mut().flat_map(|r| r.events.iter_mut()) {
                        e.fixed = e.fixed.as_ref().map(rebrand);
                        e.last_affected = e.last_affected.as_ref().map(rebrand);
                    }
                    a
                })
                .collect();
            out.insert((eco.clone(), name.to_string()), advs);
        }
    }
    Some(out)
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
                Some(v) => match_source(
                    &ctx,
                    &src,
                    &v,
                    DebVersion::parse,
                    |e, n| db.deb(e, n),
                    &mut out,
                ),
                None => skipped_unparseable += 1,
            },
            Family::Apk => match ApkVersion::parse(src.version) {
                Some(v) => match_source(
                    &ctx,
                    &src,
                    &v,
                    ApkVersion::parse,
                    |e, n| db.apk(e, n),
                    &mut out,
                ),
                None => skipped_unparseable += 1,
            },
            Family::Rpm => match RpmVersion::parse(src.version) {
                Some(v) => {
                    let rebranded = rebranded(distro, db, &src);
                    match_source(
                        &ctx,
                        &src,
                        &v,
                        RpmVersion::parse,
                        |e, n| match &rebranded {
                            Some(own) => own
                                .get(&(e.to_string(), n.to_string()))
                                .map_or(&[][..], Vec::as_slice),
                            None => db.rpm(e, n),
                        },
                        &mut out,
                    );
                }
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
            module: None,
            url: None,
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
            module: None,
        }];
        let ctx = Ctx {
            distro: &distro,
            repo: &RepoId("img".into()),
            opts: ScanOptions::default(),
        };
        let src = &sources(&pkgs, false)[0];
        let mut out = Vec::new();
        let v = DebVersion::parse("1.0-1").unwrap();
        match_source(
            &ctx,
            src,
            &v,
            DebVersion::parse,
            |_, _| std::slice::from_ref(&a),
            &mut out,
        );
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
        match_source(
            &ctx,
            src,
            &v,
            DebVersion::parse,
            |_, _| std::slice::from_ref(&a),
            &mut out,
        );
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
                module: None,
            }];
            let src = &sources(&pkgs, false)[0];
            let mut out = Vec::new();
            let v = DebVersion::parse(installed).unwrap();
            match_source(
                &ctx,
                src,
                &v,
                DebVersion::parse,
                |_, _| std::slice::from_ref(&a),
                &mut out,
            );
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
        let lookup = |e: &str, _: &str| -> &[Advisory<DebVersion>] {
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
                module: None,
            }];
            let src = &sources(&pkgs, false)[0];
            let mut out = Vec::new();
            match_source(
                &ctx,
                src,
                &DebVersion::parse(ver).unwrap(),
                DebVersion::parse,
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
                module: None,
            },
            OsPackage {
                name: "openssl".into(),
                version: "1:3.0.7-27.el9".into(),
                source: "openssl".into(),
                source_version: "1:3.0.7-27.el9".into(),
                arch: None,
                module: None,
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
    fn module_advisories_match_only_their_stream() {
        let pkg = |version: &str, module: Option<&str>| OsPackage {
            name: "php-cli".into(),
            version: version.into(),
            source: "php".into(),
            source_version: version.into(),
            arch: None,
            module: module.map(str::to_string),
        };
        let mut db = DistroDb::default();
        for (id, stream) in [("ELSA-74", "php:7.4"), ("ELSA-80", "php:8.0")] {
            let mut a = adv(
                id,
                &[("introduced", "0"), ("fixed", "0:9.0-1.module+el8")],
                RpmVersion::parse,
            );
            a.module = Some(stream.into());
            db.insert_rpm("Oracle Linux:8", "php-cli", a);
        }
        let mut ol = crate::distro::explicit("Oracle Linux:8", Family::Rpm);
        let repo = RepoId("img".into());
        let ids = |ol: &Distro, p: OsPackage| -> Vec<String> {
            scan(ol, &[p], &db, &repo, ScanOptions::default())
                .findings
                .iter()
                .map(|f| f.advisory_id.clone())
                .collect()
        };
        let modular = "7.4.6-4.module+el8.3.0+7685+72d70b58";
        // Labelled: its own stream only.
        assert_eq!(ids(&ol, pkg(modular, Some("php:7.4"))), ["ELSA-74"]);
        // Not a module build: no module advisory applies.
        assert!(ids(&ol, pkg("7.2.24-1.el8", None)).is_empty());
        // An unlabelled module build: any stream while the image records none (never a
        // false clean), the enabled one once it does.
        assert_eq!(ids(&ol, pkg(modular, None)), ["ELSA-74", "ELSA-80"]);
        ol.modules.insert("php".into(), "7.4".into());
        assert_eq!(ids(&ol, pkg(modular, None)), ["ELSA-74"]);
    }

    #[test]
    fn module_builds_match_only_their_streams_and_module_fixes() {
        let pkg = |name: &str, version: &str, module: &str| OsPackage {
            name: name.into(),
            version: version.into(),
            source: name.into(),
            source_version: version.into(),
            arch: None,
            module: Some(module.into()),
        };
        let pkgs = vec![
            pkg("php", "0:7.4.30-1.module+el8.9.0+1500+aaaaaaaa", "php:7.4"),
            // RHEL 8's perl:5.24 stream is older than its non-modular perl 5.26.
            pkg(
                "perl",
                "4:5.24.4-404.module+el8.1.0+2926+ce7246ad",
                "perl:5.24",
            ),
        ];
        let rocky = crate::distro::explicit("Rocky Linux:8", Family::Rpm);
        let mut db = DistroDb::default();
        let fix = |id: &str, fixed: &str, module: Option<&str>| {
            let mut a = adv(
                id,
                &[("introduced", "0"), ("fixed", fixed)],
                RpmVersion::parse_fix,
            );
            a.module = module.map(str::to_string);
            a
        };
        // Another stream's fix (php:8.0), and a list naming this stream among others.
        db.insert_rpm(
            "Rocky Linux:8",
            "php",
            fix(
                "RLSA-1",
                "0:8.0.30-1.module+el8.8.0+1550+bbbbbbbb",
                Some("php:8.0"),
            ),
        );
        db.insert_rpm(
            "Rocky Linux:8",
            "php",
            fix(
                "RLSA-2",
                "0:7.4.33-1.module+el8.9.0+1600+aaaaaaaa",
                Some("php-devel:7.4,php:7.4"),
            ),
        );
        // A fix built for another module context, same version and release as installed.
        db.insert_rpm(
            "Rocky Linux:8",
            "php",
            fix(
                "RLSA-3",
                "0:7.4.30-1.module+el8.9.0+1700+cccccccc",
                Some("php:7.4"),
            ),
        );
        // Another stream's fix names a CVE that Red Hat leaves open for this stream: the open
        // status still applies (the other stream's advisory says nothing about this build).
        let mut other = fix(
            "RLSA-5",
            "0:8.0.27-1.module+el8.7.0+1+dddddddd",
            Some("php:8.0"),
        );
        other.aliases = vec!["CVE-2022-4900".into()];
        db.insert_rpm("Rocky Linux:8", "php", other);
        let mut deferred = adv(
            "CVE-2022-4900",
            &[("introduced", "0")],
            RpmVersion::parse_fix,
        );
        deferred.aliases = vec!["CVE-2022-4900".into()];
        deferred.urgency = Some("fix deferred".into());
        deferred.module = Some("php:7.4".into());
        db.insert_rpm("Red Hat:enterprise_linux:8::vex", "php", deferred);
        // perl 5.26's non-module fix: dnf never puts it over a perl:5.24 build.
        db.insert_rpm(
            "Rocky Linux:8",
            "perl",
            fix("RLSA-4", "4:5.26.3-419.el8", None),
        );
        let s = scan(
            &rocky,
            &pkgs,
            &db,
            &RepoId("img".into()),
            ScanOptions::default(),
        );
        let ids: Vec<&str> = s.findings.iter().map(|f| f.advisory_id.as_str()).collect();
        assert_eq!(ids, ["CVE-2022-4900", "RLSA-2"]);
    }

    #[test]
    fn centos_takes_red_hat_fixes_only_where_it_shipped_them() {
        let pkg = |name: &str, version: &str| OsPackage {
            name: name.into(),
            version: version.into(),
            source: name.into(),
            source_version: version.into(),
            arch: None,
            module: None,
        };
        let os = crate::distro::parse_os_release("ID=centos\nVERSION_ID=7\n");
        let centos = crate::distro::detect(&os, None, Default::default()).unwrap();
        let eco = "Red Hat:enterprise_linux:7::server";
        let mut db = DistroDb::default();
        let fix = |id: &str, fixed: &str| {
            adv(
                id,
                &[("introduced", "0"), ("fixed", fixed)],
                RpmVersion::parse_fix,
            )
        };
        // CentOS's final openssl is -26: the -26 fix is its own, the -27 one only Red Hat's.
        db.insert_rpm(eco, "openssl", fix("RHSA-1", "1:1.0.2k-26.el7_9"));
        db.insert_rpm(eco, "openssl", fix("RHSA-2", "1:1.0.2k-27.el7_9"));
        // CentOS shipped Red Hat's dhcp -83.el7_9.2 as -83.el7.centos.2: the same build.
        db.insert_rpm(eco, "dhclient", fix("RHSA-3", "12:4.2.5-83.el7_9.2"));
        db.insert_rpm(eco, "dhclient", fix("RHSA-4", "12:4.2.5-83.el7_9.3"));
        let pkgs = vec![
            pkg("openssl", "1:1.0.2k-25.el7_9"),
            pkg("dhclient", "12:4.2.5-83.el7.centos.2"),
        ];
        let s = scan(
            &centos,
            &pkgs,
            &db,
            &RepoId("img".into()),
            ScanOptions::default(),
        );
        let got: Vec<(&str, &str, bool)> = s
            .findings
            .iter()
            .map(|f| {
                (
                    f.advisory_id.as_str(),
                    match &f.occurrences[0] {
                        Occurrence::InRepo { package, .. } => package.as_str(),
                        Occurrence::Toolchain { .. } => panic!("expected InRepo"),
                    },
                    f.title.contains("fixed only in another line"),
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                ("RHSA-1", "centos/openssl", false),
                ("RHSA-2", "centos/openssl", true),
                ("RHSA-4", "centos/dhclient", true),
            ]
        );
        // Rebranded fixes read in CentOS's form.
        assert!(
            s.findings[2].title.contains("CentOS Linux 7"),
            "{}",
            s.findings[2].title
        );
    }

    #[test]
    fn red_hat_vex_statuses_fill_in_only_what_the_release_does_not_say() {
        let pkgs = vec![OsPackage {
            name: "openssl-libs".into(),
            version: "1:3.0.7-27.el9".into(),
            source: "openssl".into(),
            source_version: "1:3.0.7-27.el9".into(),
            arch: None,
            module: None,
        }];
        let rhel = crate::distro::explicit("Red Hat:enterprise_linux:9::baseos", Family::Rpm);
        let vex = "Red Hat:enterprise_linux:9::vex";
        let mut db = DistroDb::default();
        // The release fixed CVE-2026-1 (installed is past the fix): Red Hat's unfixed entry
        // for another stream of the same CVE must not bring it back.
        db.insert_rpm(
            "Red Hat:enterprise_linux:9::baseos",
            "openssl-libs",
            adv(
                "RHSA-2026-1",
                &[("introduced", "0"), ("fixed", "1:3.0.7-20.el9")],
                RpmVersion::parse,
            ),
        );
        let open = |cve: &str, status: &str, module: Option<&str>| {
            let mut a = adv(cve, &[("introduced", "0")], RpmVersion::parse);
            a.aliases = vec![cve.into()];
            a.urgency = Some(status.into());
            a.module = module.map(str::to_string);
            a
        };
        db.insert_rpm(vex, "openssl", open("CVE-2026-1", "affected", None));
        // Named by source package, and by the binary: one finding.
        db.insert_rpm(vex, "openssl", open("CVE-2026-2", "will not fix", None));
        db.insert_rpm(
            vex,
            "openssl-libs",
            open("CVE-2026-2", "will not fix", None),
        );
        // Another module stream's build.
        db.insert_rpm(
            vex,
            "openssl-libs",
            open("CVE-2026-3", "affected", Some("openssl:1.1")),
        );
        // A fix names binaries: the source package's fix says nothing about openssl-libs
        // (Red Hat lists vim fixed and vim-minimal not affected for one CVE).
        db.insert_rpm(
            vex,
            "openssl",
            adv(
                "CVE-2026-4",
                &[("introduced", "0"), ("fixed", "1:3.0.7-30.el9")],
                RpmVersion::parse,
            ),
        );
        // The binary is not affected (no range): the source's open entry does not apply.
        db.insert_rpm(vex, "openssl", open("CVE-2026-5", "affected", None));
        let mut not_affected = adv("CVE-2026-5", &[], RpmVersion::parse);
        not_affected.ranges.clear();
        db.insert_rpm(vex, "openssl-libs", not_affected);
        let s = scan(
            &rhel,
            &pkgs,
            &db,
            &RepoId("img".into()),
            ScanOptions::default(),
        );
        let got: Vec<(&str, &str)> = s
            .findings
            .iter()
            .map(|f| (f.advisory_id.as_str(), f.title.as_str()))
            .collect();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, "CVE-2026-2");
        assert!(
            got[0].1.ends_with("no fix yet; status will not fix]"),
            "{}",
            got[0].1
        );
    }

    #[test]
    fn rebuilds_borrow_red_hat_open_statuses_but_not_its_fixes() {
        let pkgs = vec![OsPackage {
            name: "openssl-libs".into(),
            version: "1:3.0.7-27.el9".into(),
            source: "openssl".into(),
            source_version: "1:3.0.7-27.el9".into(),
            arch: None,
            module: None,
        }];
        let rocky = crate::distro::explicit("Rocky Linux:9", Family::Rpm);
        let vex = "Red Hat:enterprise_linux:9::vex";
        assert_eq!(rocky.borrowed_opens, [vex]);
        let mut db = DistroDb::default();
        let open = |cve: &str, status: &str| {
            let mut a = adv(cve, &[("introduced", "0")], RpmVersion::parse);
            a.aliases = vec![cve.into()];
            a.urgency = Some(status.into());
            a
        };
        db.insert_rpm(vex, "openssl-libs", open("CVE-2026-1", "affected"));
        // Red Hat's fix version is Red Hat's build, not Rocky's: not borrowed.
        db.insert_rpm(
            vex,
            "openssl-libs",
            adv(
                "CVE-2026-2",
                &[("introduced", "0"), ("fixed", "1:3.0.7-30.el9")],
                RpmVersion::parse,
            ),
        );
        // Rocky's own record fixed it (installed is past the fix): Red Hat's open entry
        // does not bring it back.
        let mut own = adv(
            "RLSA-2026:3",
            &[("introduced", "0"), ("fixed", "1:3.0.7-20.el9")],
            RpmVersion::parse,
        );
        own.aliases = vec!["CVE-2026-3".into()];
        db.insert_rpm("Rocky Linux:9", "openssl", own);
        db.insert_rpm(vex, "openssl-libs", open("CVE-2026-3", "affected"));
        // Not affected for the binary holds for the rebuild too.
        db.insert_rpm(vex, "openssl", open("CVE-2026-4", "affected"));
        let mut not_affected = adv("CVE-2026-4", &[], RpmVersion::parse);
        not_affected.ranges.clear();
        db.insert_rpm(vex, "openssl-libs", not_affected);
        let s = scan(
            &rocky,
            &pkgs,
            &db,
            &RepoId("img".into()),
            ScanOptions::default(),
        );
        let got: Vec<(&str, &str)> = s
            .findings
            .iter()
            .map(|f| (f.advisory_id.as_str(), f.title.as_str()))
            .collect();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, "CVE-2026-1");
        assert!(
            got[0].1.ends_with("no fix yet; Red Hat status affected]"),
            "{}",
            got[0].1
        );
    }

    #[test]
    fn suse_vex_entries_name_binaries() {
        // SUSE's osv.dev records name source packages, its VEX names binaries.
        let pkg = |name: &str| OsPackage {
            name: name.into(),
            version: "6.8.2-150600.3.3.1".into(),
            source: "qt6-svg".into(),
            source_version: "6.8.2-150600.3.3.1".into(),
            arch: None,
            module: None,
        };
        let mut compat = pkg("libqt7-compat");
        compat.version = "7.0-150600.3.3.1".into();
        let pkgs = vec![pkg("libQt6Svg6"), pkg("qt6-svg-imports"), compat];
        let leap = crate::distro::explicit("openSUSE:Leap 15.6", Family::Rpm);
        let vex = "openSUSE:Leap 15.6::vex";
        let mut db = DistroDb::default();
        let status = |cve: &str, events: &[(&str, &str)], status: &str| {
            let mut a = adv(cve, events, RpmVersion::parse);
            a.aliases = vec![cve.into()];
            a.urgency = Some(status.to_string()).filter(|s| !s.is_empty());
            if events.is_empty() {
                a.ranges.clear();
            }
            a
        };
        // One binary not affected, the other open: open.
        db.insert_rpm(vex, "libQt6Svg6", status("CVE-2026-1", &[], "not affected"));
        db.insert_rpm(
            vex,
            "qt6-svg-imports",
            status("CVE-2026-1", &[("introduced", "0")], "affected"),
        );
        // Both fixed: the higher fix.
        for (bin, fix) in [
            ("libQt6Svg6", "6.8.2-150600.3.6.1"),
            ("qt6-svg-imports", "6.8.2-150600.3.9.1"),
        ] {
            db.insert_rpm(
                vex,
                bin,
                status("CVE-2026-2", &[("introduced", "0"), ("fixed", fix)], ""),
            );
        }
        // Fixed in osv.dev's own record, which this build has, but SUSE says it is still
        // affected (an update that names CVEs it did not fix): open.
        let mut own = adv(
            "openSUSE-SU-2026:3",
            &[("introduced", "0"), ("fixed", "6.8.2-150600.3.3.1")],
            RpmVersion::parse,
        );
        own.aliases = vec!["CVE-2026-3".into()];
        db.insert_rpm("openSUSE:Leap 15.6", "qt6-svg", own);
        db.insert_rpm(
            vex,
            "libQt6Svg6",
            status("CVE-2026-3", &[("introduced", "0")], "affected"),
        );
        // osv.dev's own record finds the package affected: it speaks, the VEX adds nothing.
        let mut own = adv(
            "openSUSE-SU-2026:5",
            &[("introduced", "0"), ("fixed", "6.8.2-150600.3.4.1")],
            RpmVersion::parse,
        );
        own.aliases = vec!["CVE-2026-5".into()];
        db.insert_rpm("openSUSE:Leap 15.6", "qt6-svg", own);
        db.insert_rpm(
            vex,
            "libQt6Svg6",
            status("CVE-2026-5", &[("introduced", "0")], "affected"),
        );
        // A binary at its own version (SUSE's libreadline7 7.0 from bash 4.4): its fix is
        // compared with that version, not the source's.
        db.insert_rpm(
            vex,
            "libqt7-compat",
            status(
                "CVE-2026-6",
                &[("introduced", "0"), ("fixed", "7.0-150600.3.1.1")],
                "",
            ),
        );
        db.insert_rpm(
            vex,
            "libqt7-compat",
            status(
                "CVE-2026-7",
                &[("introduced", "0"), ("fixed", "7.0-150600.3.5.1")],
                "",
            ),
        );
        // Only "not affected": nothing.
        db.insert_rpm(vex, "libQt6Svg6", status("CVE-2026-4", &[], "not affected"));
        let s = scan(
            &leap,
            &pkgs,
            &db,
            &RepoId("img".into()),
            ScanOptions::default(),
        );
        let got: Vec<(&str, bool)> = s
            .findings
            .iter()
            .map(|f| (f.advisory_id.as_str(), f.title.contains("no fix yet")))
            .collect();
        assert_eq!(
            got,
            vec![
                ("CVE-2026-1", true),
                ("CVE-2026-2", false),
                ("CVE-2026-3", true),
                ("CVE-2026-7", false),
                ("openSUSE-SU-2026:5", false),
            ],
            "{:?}",
            s.findings
        );
        assert!(
            s.findings[3]
                .title
                .contains("libqt7-compat 7.0-150600.3.3.1; fixed in 7.0-150600.3.5.1"),
            "{}",
            s.findings[3].title
        );
        let fixed = format!("{:?}", s.findings[1].occurrences);
        assert!(
            fixed.contains("150600.3.9.1") && !fixed.contains("150600.3.6.1"),
            "{fixed}"
        );
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
                module: None,
            },
            OsPackage {
                name: "libssl3".into(),
                version: "3.3.2-r0".into(),
                source: "openssl".into(),
                source_version: "3.3.2-r0".into(),
                arch: None,
                module: None,
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
