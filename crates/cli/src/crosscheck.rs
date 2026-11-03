//! `fleetreach db crosscheck` (spec 16, row 12): what the CVE 5.x records and vendor CSAF add
//! to, or contradict in, the OSV data, measured on the local copies.
//!
//! - **CVE 5.x vs OSV.** A CVE whose CNA data maps to a package in an ecosystem the OSV
//!   directory holds is *covered* when some live OSV record names the CVE, else a *gap* the CVE
//!   record fills (marked `unreviewed`). For covered CVEs the CNA's fixed versions are compared
//!   with OSV's for the same package, and the CVE's publication date with the earliest OSV
//!   record's (lead time). Live OSV records aliasing a REJECTED CVE, and OSV records with no
//!   severity whose CVE carries a CVSS vector, are counted too.
//! - **Red Hat CSAF vs OSV's Red Hat export.** Every fixed (CVE, platform, component,
//!   version) in OSV's records is looked up in the CSAF data; the CSAF statuses OSV does not
//!   carry (affected, will not fix, fix deferred, out of support, under investigation, not
//!   affected) are counted as what CSAF adds.
//!
//! A package is mapped from the CNA data directly (a purl, or a registry URL and package name),
//! or through its repository: OSV records reference their package's repository, so a CVE
//! naming that repository maps to those packages (`repo`, lower confidence: a repository can
//! hold several packages).

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::csaf::{VendorState, VexRecord};
use crate::cve5::{normalize_name, normalize_version, CveSummary};
use crate::osvrecords::{repo_key, Record};

/// An example row for spot checks.
#[derive(Debug, Clone, Serialize)]
pub struct Example {
    pub id: String,
    pub ecosystem: String,
    pub package: String,
    pub detail: String,
}

/// The CVE 5.x half.
#[derive(Debug, Default, Serialize)]
pub struct CveReport {
    pub records: usize,
    pub published: usize,
    pub rejected: usize,
    /// Published CVEs whose CNA data maps to a package in a loaded ecosystem.
    pub mapped: usize,
    pub mapped_direct: usize,
    pub mapped_by_repo: usize,
    /// Mapped CVEs some live OSV record names.
    pub covered: usize,
    /// Mapped CVEs no live OSV record names: what the CVE record adds.
    pub gaps: usize,
    pub gaps_by_ecosystem: BTreeMap<String, usize>,
    /// Gaps whose CNA data carries a usable version range or exact version.
    pub gaps_with_versions: usize,
    /// Gaps published in the 30 days before the newest CVE in the data (likely awaiting review).
    pub gaps_recent_30d: usize,
    /// Covered (CVE, package) pairs where both sides name fixed versions.
    pub fix_compared: usize,
    pub fix_agree: usize,
    /// Some fixed versions in common, some not.
    pub fix_partial: usize,
    /// No fixed version in common: a contradiction.
    pub fix_disagree: usize,
    pub fix_disagree_by_ecosystem: BTreeMap<String, usize>,
    /// Pairs where OSV names only Go pseudo-versions as fixes, which a CNA's release
    /// number cannot be compared with.
    pub fix_pseudo_only: usize,
    /// A directly mapped package that no OSV record for the CVE names.
    pub package_mismatch: usize,
    /// Covered CVEs with both dates.
    pub lead_pairs: usize,
    /// Of those, the CVE was published more than a day before the first OSV record.
    pub cve_earlier_1d: usize,
    /// Median of (first OSV record published - CVE published), in days.
    pub lead_median_days: Option<f64>,
    /// The same for CVEs published since 2025-01-01.
    pub lead_pairs_since_2025: usize,
    pub cve_earlier_1d_since_2025: usize,
    pub lead_median_days_since_2025: Option<f64>,
    /// Live OSV records aliasing a REJECTED CVE.
    pub rejected_but_aliased: usize,
    /// Live OSV records (in loaded ecosystems, malware `MAL-` records aside, which never
    /// carry a CVSS vector) with no severity.
    pub osv_without_severity: usize,
    /// Of those, records whose CVE carries a CVSS vector from the CNA or an ADP.
    pub severity_fillable: usize,
    pub severity_fillable_by_adp_only: usize,
    /// CVEs each ADP provider enriched.
    pub adp_providers: BTreeMap<String, usize>,
    pub examples: BTreeMap<String, Vec<Example>>,
}

/// The CSAF half, for one provider.
#[derive(Debug, Default, Serialize)]
pub struct CsafReport {
    pub provider: String,
    pub records: usize,
    pub cves: usize,
    pub entries: usize,
    pub entries_by_state: BTreeMap<String, usize>,
    pub purl_types: BTreeMap<String, usize>,
    /// CVEs with no fixed entry at all (only unfixed or not-affected statuses).
    pub cves_without_fix: usize,
    /// OSV Red Hat records read and the CVEs they name.
    pub osv_records: usize,
    pub osv_cves: usize,
    /// CVEs with a CSAF fixed entry that no OSV Red Hat record names.
    pub fixed_cves_missing_in_osv: usize,
    /// CVEs OSV names that the CSAF data does not.
    pub osv_cves_missing_in_csaf: usize,
    /// OSV (CVE, platform, component, fixed version) tuples compared.
    pub osv_fixes: usize,
    /// Found in CSAF as fixed on the same platform, component and version.
    pub fix_exact: usize,
    /// Same CVE and component fixed in CSAF, at another version or on another platform.
    pub fix_component_only: usize,
    /// CSAF has the CVE but not this component as fixed.
    pub fix_missing: usize,
    /// (CVE, platform, component) with an unfixed state: what CSAF adds over OSV.
    pub unfixed_entries: BTreeMap<String, usize>,
    pub examples: BTreeMap<String, Vec<Example>>,
}

fn example(
    examples: &mut BTreeMap<String, Vec<Example>>,
    kind: &str,
    limit: usize,
    ex: impl FnOnce() -> Example,
) {
    let list = examples.entry(kind.to_string()).or_default();
    if list.len() < limit {
        list.push(ex());
    }
}

fn median(mut v: Vec<f64>) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    let mid = v.len() / 2;
    let upper = *v.get(mid)?;
    Some(if v.len().is_multiple_of(2) {
        (v.get(mid - 1)? + upper) / 2.0
    } else {
        upper
    })
}

fn timestamp(s: &str) -> Option<f64> {
    let s = s.trim();
    // CVE dates sometimes lack the zone (`2024-01-02T03:04:05.000`): they are UTC.
    let with_zone = if s.ends_with('Z') || s.get(19..).is_some_and(|t| t.contains(['+', '-'])) {
        s.to_string()
    } else {
        format!("{s}Z")
    };
    time::OffsetDateTime::parse(&with_zone, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp() as f64)
}

/// Compare the CVE summaries with the OSV records. `ecosystems` are the OSV ecosystems
/// whose exports were loaded (a CVE mapped elsewhere cannot be judged covered or not).
#[must_use]
pub fn cve_vs_osv(
    cves: &[CveSummary],
    records: &BTreeMap<String, (String, Record)>,
    ecosystems: &BTreeSet<String>,
    limit: usize,
) -> CveReport {
    let mut r = CveReport::default();
    let live: Vec<&Record> = records
        .values()
        .map(|(_, rec)| rec)
        .filter(|rec| rec.withdrawn.is_none())
        .collect();
    // CVE -> live records naming it.
    let mut by_cve: BTreeMap<&str, Vec<&Record>> = BTreeMap::new();
    for rec in &live {
        let mut seen = BTreeSet::new();
        for cve in rec.cves() {
            if seen.insert(cve) {
                by_cve.entry(cve).or_default().push(rec);
            }
        }
    }
    // Repository -> packages whose records reference it as their package or repository.
    // Only single-package records count: a record for a library and every package that
    // bundles it (jQuery and jquery-rails) references the library's repository for all of
    // them.
    let mut by_repo: BTreeMap<String, BTreeSet<(String, String)>> = BTreeMap::new();
    for rec in &live {
        let packages: BTreeSet<(String, String)> = rec
            .affected
            .iter()
            .filter_map(|a| {
                let eco = a.package.ecosystem.as_deref()?;
                let name = a.package.name.as_deref()?;
                ecosystems
                    .contains(eco)
                    .then(|| (eco.to_string(), normalize_name(eco, name)))
            })
            .collect();
        if packages.len() != 1 {
            continue;
        }
        let repos = rec
            .references
            .iter()
            .filter(|x| matches!(x.kind.as_deref(), Some("PACKAGE" | "REPOSITORY")))
            .filter_map(|x| x.url.as_deref())
            .chain(
                rec.affected
                    .iter()
                    .flat_map(|a| &a.ranges)
                    .filter_map(|g| g.repo.as_deref()),
            )
            .filter_map(repo_key);
        for repo in repos {
            by_repo
                .entry(repo)
                .or_default()
                .extend(packages.iter().cloned());
        }
    }
    let by_id: BTreeMap<&str, &CveSummary> = cves.iter().map(|c| (c.id.as_str(), c)).collect();
    let newest = cves
        .iter()
        .filter_map(|c| c.published.as_deref().and_then(timestamp))
        .fold(f64::MIN, f64::max);
    let since_2025 = timestamp("2025-01-01T00:00:00Z").unwrap_or(0.0);

    let mut leads = Vec::new();
    let mut leads_2025 = Vec::new();
    for cve in cves {
        r.records += 1;
        match cve.state.as_str() {
            "REJECTED" => {
                r.rejected += 1;
                for rec in by_cve.get(cve.id.as_str()).into_iter().flatten() {
                    r.rejected_but_aliased += 1;
                    example(&mut r.examples, "rejected_but_aliased", limit, || Example {
                        id: rec.id.clone(),
                        ecosystem: rec
                            .affected
                            .first()
                            .and_then(|a| a.package.ecosystem.clone())
                            .unwrap_or_default(),
                        package: rec
                            .affected
                            .first()
                            .and_then(|a| a.package.name.clone())
                            .unwrap_or_default(),
                        detail: format!("aliases {}, which is REJECTED", cve.id),
                    });
                }
                continue;
            }
            "PUBLISHED" => r.published += 1,
            _ => continue,
        }
        for adp in &cve.adp {
            *r.adp_providers.entry(adp.clone()).or_default() += 1;
        }
        // (ecosystem, name) -> (direct?, CNA fixes, has versions)
        let mut mapped: BTreeMap<(String, String), (bool, BTreeSet<String>, bool)> =
            BTreeMap::new();
        for pkg in &cve.packages {
            let fixes: BTreeSet<String> = pkg.fixes().map(normalize_version).collect();
            let has_versions = !pkg.ranges.is_empty() || !pkg.exact.is_empty();
            if let (Some(eco), Some(name)) = (&pkg.ecosystem, &pkg.name) {
                if ecosystems.contains(eco) {
                    let slot = mapped.entry((eco.clone(), name.clone())).or_default();
                    slot.0 = true;
                    slot.1.extend(fixes.iter().cloned());
                    slot.2 |= has_versions;
                    continue;
                }
            }
            for key in pkg
                .repo
                .as_ref()
                .and_then(|repo| by_repo.get(repo))
                .into_iter()
                .flatten()
            {
                let slot = mapped.entry(key.clone()).or_default();
                slot.1.extend(fixes.iter().cloned());
                slot.2 |= has_versions;
            }
        }
        if mapped.is_empty() {
            continue;
        }
        r.mapped += 1;
        if mapped.values().any(|m| m.0) {
            r.mapped_direct += 1;
        } else {
            r.mapped_by_repo += 1;
        }
        let Some(osv) = by_cve.get(cve.id.as_str()) else {
            r.gaps += 1;
            let (eco, name) = mapped.keys().next().cloned().unwrap_or_default();
            *r.gaps_by_ecosystem.entry(eco.clone()).or_default() += 1;
            if mapped.values().any(|m| m.2) {
                r.gaps_with_versions += 1;
            }
            let recent = cve
                .published
                .as_deref()
                .and_then(timestamp)
                .is_some_and(|t| newest - t <= 30.0 * 86_400.0);
            if recent {
                r.gaps_recent_30d += 1;
            }
            let how = if mapped.values().any(|m| m.0) {
                "direct"
            } else {
                "repo"
            };
            let fixes: BTreeSet<&String> = mapped.values().flat_map(|m| &m.1).collect();
            example(&mut r.examples, &format!("gap_{how}"), limit, || Example {
                id: cve.id.clone(),
                ecosystem: eco,
                package: name,
                detail: format!(
                    "published {}, {} package(s), fixed {}",
                    cve.published.as_deref().unwrap_or("?"),
                    mapped.len(),
                    fixes
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join("/")
                ),
            });
            continue;
        };
        r.covered += 1;
        // Lead time against the first OSV record.
        let first_osv = osv
            .iter()
            .filter_map(|rec| rec.published.as_deref().and_then(timestamp))
            .fold(f64::MAX, f64::min);
        if let Some(published) = cve.published.as_deref().and_then(timestamp) {
            if first_osv < f64::MAX {
                let days = (first_osv - published) / 86_400.0;
                leads.push(days);
                if days > 1.0 {
                    r.cve_earlier_1d += 1;
                }
                if published >= since_2025 {
                    leads_2025.push(days);
                    if days > 1.0 {
                        r.cve_earlier_1d_since_2025 += 1;
                    }
                }
            }
        }
        let osv_packages: BTreeSet<(String, String)> = osv
            .iter()
            .flat_map(|rec| &rec.affected)
            .filter_map(|a| {
                let eco = a.package.ecosystem.as_deref()?;
                Some((
                    eco.to_string(),
                    normalize_name(eco, a.package.name.as_deref()?),
                ))
            })
            .collect();
        let mut compared: BTreeSet<(String, String)> = BTreeSet::new();
        for ((eco, name), (direct, cna_fixes, _)) in &mapped {
            // Go CNAs name packages (`cmd/go`, `golang.org/x/net/html`), OSV names modules:
            // compare against the OSV module the package lives in.
            let name = &go_module(eco, name, &osv_packages).unwrap_or_else(|| name.clone());
            if !osv_packages.contains(&(eco.clone(), name.clone())) {
                if *direct {
                    r.package_mismatch += 1;
                    example(&mut r.examples, "package_mismatch", limit, || Example {
                        id: cve.id.clone(),
                        ecosystem: eco.clone(),
                        package: name.clone(),
                        detail: format!(
                            "OSV names {}",
                            osv_packages
                                .iter()
                                .map(|(e, n)| format!("{e}/{n}"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    });
                }
                continue;
            }
            let names_it = |rec: &&&Record| {
                rec.affected.iter().any(|a| {
                    a.package.ecosystem.as_deref() == Some(eco.as_str())
                        && a.package
                            .name
                            .as_deref()
                            .map(|n| normalize_name(eco, n))
                            .as_deref()
                            == Some(name.as_str())
                })
            };
            let osv_fixes: BTreeSet<String> = osv
                .iter()
                .filter(names_it)
                .flat_map(|rec| {
                    rec.affected
                        .iter()
                        .filter(|a| {
                            a.package.ecosystem.as_deref() == Some(eco.as_str())
                                && a.package
                                    .name
                                    .as_deref()
                                    .map(|n| normalize_name(eco, n))
                                    .as_deref()
                                    == Some(name.as_str())
                        })
                        .flat_map(|a| &a.ranges)
                        .filter(|g| g.kind.as_deref() != Some("GIT"))
                        .flat_map(|g| &g.events)
                        .filter_map(|e| e.fixed.as_deref())
                        .map(normalize_version)
                })
                .collect();
            // Several CNA packages can map to one OSV module (Go): compare it once.
            if cna_fixes.is_empty()
                || osv_fixes.is_empty()
                || !compared.insert((eco.clone(), name.clone()))
            {
                continue;
            }
            let osv_fixes: BTreeSet<String> = osv_fixes
                .into_iter()
                .filter(|v| !is_pseudo_version(v))
                .collect();
            if osv_fixes.is_empty() {
                r.fix_pseudo_only += 1;
                continue;
            }
            r.fix_compared += 1;
            let common = cna_fixes.intersection(&osv_fixes).count();
            let kind = if common == 0 {
                r.fix_disagree += 1;
                *r.fix_disagree_by_ecosystem.entry(eco.clone()).or_default() += 1;
                "fix_disagree"
            } else if cna_fixes == &osv_fixes {
                r.fix_agree += 1;
                continue;
            } else {
                r.fix_partial += 1;
                "fix_partial"
            };
            example(&mut r.examples, kind, limit, || Example {
                id: cve.id.clone(),
                ecosystem: eco.clone(),
                package: name.clone(),
                detail: format!(
                    "CNA fixed {}; OSV ({}) fixed {}",
                    cna_fixes.iter().cloned().collect::<Vec<_>>().join("/"),
                    osv.iter()
                        .filter(names_it)
                        .map(|x| x.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    osv_fixes.iter().cloned().collect::<Vec<_>>().join("/")
                ),
            });
        }
    }
    r.lead_pairs = leads.len();
    r.lead_median_days = median(leads);
    r.lead_pairs_since_2025 = leads_2025.len();
    r.lead_median_days_since_2025 = median(leads_2025);

    // Severity: OSV records in loaded ecosystems with none, whose CVE has a vector.
    for rec in &live {
        let in_scope = rec.affected.iter().any(|a| {
            a.package
                .ecosystem
                .as_deref()
                .is_some_and(|e| ecosystems.contains(e))
        });
        if !in_scope || rec.has_severity() || rec.id.starts_with("MAL-") {
            continue;
        }
        r.osv_without_severity += 1;
        let sources: Vec<(bool, bool)> = rec
            .cves()
            .filter_map(|c| by_id.get(c))
            .map(|c| (c.cna_cvss.is_some(), c.adp_cvss.is_some()))
            .collect();
        if sources.iter().any(|(cna, adp)| *cna || *adp) {
            r.severity_fillable += 1;
            if !sources.iter().any(|(cna, _)| *cna) {
                r.severity_fillable_by_adp_only += 1;
            }
            example(&mut r.examples, "severity_fillable", limit, || Example {
                id: rec.id.clone(),
                ecosystem: rec
                    .affected
                    .first()
                    .and_then(|a| a.package.ecosystem.clone())
                    .unwrap_or_default(),
                package: rec
                    .affected
                    .first()
                    .and_then(|a| a.package.name.clone())
                    .unwrap_or_default(),
                detail: rec.cves().collect::<Vec<_>>().join(", "),
            });
        }
    }
    r
}

/// A Go pseudo-version (`v0.5.0-alpha.5.0.20200423152442-f4b650b51dc4`): a timestamp and a
/// 12-hex-digit commit at the end.
fn is_pseudo_version(v: &str) -> bool {
    let Some((head, commit)) = v.rsplit_once('-') else {
        return false;
    };
    let stamp = head.rsplit(['.', '-']).next().unwrap_or("");
    commit.len() == 12
        && commit.bytes().all(|b| b.is_ascii_hexdigit())
        && stamp.len() == 14
        && stamp.bytes().all(|b| b.is_ascii_digit())
}

/// The OSV Go module a CNA's package path belongs to (`cmd/go` is the toolchain, other
/// standard-library paths are `stdlib`, a third-party package is its longest module prefix).
fn go_module(eco: &str, name: &str, osv: &BTreeSet<(String, String)>) -> Option<String> {
    if eco != "Go" {
        return None;
    }
    let has = |m: &str| osv.contains(&(eco.to_string(), m.to_string()));
    let first = name.split('/').next().unwrap_or(name);
    if !first.contains('.') {
        let module = if name.starts_with("cmd/") && has("toolchain") {
            "toolchain"
        } else {
            "stdlib"
        };
        return has(module).then(|| module.to_string());
    }
    let mut prefix = name;
    loop {
        if has(prefix) {
            return Some(prefix.to_string());
        }
        prefix = prefix.rsplit_once('/')?.0;
    }
}

/// The OSV ecosystem for a CSAF platform CPE: `cpe:/a:redhat:enterprise_linux:9::appstream`
/// is `Red Hat:enterprise_linux:9::appstream` in OSV's Red Hat export.
fn osv_ecosystem_of_cpe(cpe: &str) -> Option<String> {
    let rest = cpe.strip_prefix("cpe:/")?;
    let rest = rest.get(2..)?.strip_prefix("redhat:")?;
    Some(format!("Red Hat:{rest}"))
}

/// Compare a provider's CSAF records with OSV's Red Hat records. `vex` is consumed as a
/// stream: Red Hat's index holds about 12 million entries, and only the fixed ones are kept.
#[must_use]
pub fn csaf_vs_osv(
    provider: &str,
    vex: impl IntoIterator<Item = VexRecord>,
    records: &BTreeMap<String, (String, Record)>,
    limit: usize,
) -> CsafReport {
    let mut r = CsafReport {
        provider: provider.to_string(),
        ..CsafReport::default()
    };
    // CVE -> fixed (OSV ecosystem or "", component, version), and the fixed components.
    let mut fixed: BTreeMap<String, BTreeSet<(String, String, String)>> = BTreeMap::new();
    let mut fixed_components: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut cves: BTreeSet<String> = BTreeSet::new();
    for rec in vex {
        r.records += 1;
        for e in &rec.entries {
            r.entries += 1;
            *r.entries_by_state
                .entry(e.state.as_str().to_string())
                .or_default() += 1;
            if let Some(kind) = e
                .purl
                .as_deref()
                .and_then(|p| p.strip_prefix("pkg:"))
                .and_then(|p| p.split('/').next())
            {
                *r.purl_types.entry(kind.to_string()).or_default() += 1;
            }
            match e.state {
                VendorState::Fixed => {
                    if let Some(version) = &e.version {
                        let eco = rec
                            .platforms
                            .get(&e.platform)
                            .and_then(|c| osv_ecosystem_of_cpe(c))
                            .unwrap_or_default();
                        fixed.entry(rec.cve.clone()).or_default().insert((
                            eco,
                            e.component.clone(),
                            version.clone(),
                        ));
                    }
                    fixed_components
                        .entry(rec.cve.clone())
                        .or_default()
                        .insert(e.component.clone());
                }
                VendorState::NotAffected => {}
                state => {
                    // One document per CVE, entries deduplicated within it: a plain count.
                    *r.unfixed_entries
                        .entry(state.as_str().to_string())
                        .or_default() += 1;
                    example(
                        &mut r.examples,
                        &format!("unfixed_{}", state.as_str()),
                        limit,
                        || Example {
                            id: rec.cve.clone(),
                            ecosystem: e.platform.clone(),
                            package: e.component.clone(),
                            detail: e.details.clone().unwrap_or_default(),
                        },
                    );
                }
            }
        }
        cves.insert(rec.cve);
    }
    r.cves = cves.len();
    r.cves_without_fix = cves
        .iter()
        .filter(|c| !fixed_components.contains_key(*c))
        .count();

    let mut osv_cves: BTreeSet<&str> = BTreeSet::new();
    for (export, rec) in records.values() {
        if export != "Red Hat" || rec.withdrawn.is_some() {
            continue;
        }
        r.osv_records += 1;
        let rec_cves: Vec<&str> = rec.cves().collect();
        osv_cves.extend(rec_cves.iter().copied());
        for a in &rec.affected {
            let (Some(eco), Some(name)) =
                (a.package.ecosystem.as_deref(), a.package.name.as_deref())
            else {
                continue;
            };
            for version in a
                .ranges
                .iter()
                .flat_map(|g| &g.events)
                .filter_map(|e| e.fixed.as_deref())
            {
                for cve in &rec_cves {
                    r.osv_fixes += 1;
                    let key = (eco.to_string(), name.to_string(), version.to_string());
                    if fixed.get(*cve).is_some_and(|s| s.contains(&key)) {
                        r.fix_exact += 1;
                    } else if fixed_components.get(*cve).is_some_and(|s| s.contains(name)) {
                        r.fix_component_only += 1;
                        example(&mut r.examples, "fix_component_only", limit, || {
                            Example {
                            id: format!("{} / {cve}", rec.id),
                            ecosystem: eco.to_string(),
                            package: name.to_string(),
                            detail: format!("OSV fixed {version}; CSAF fixes this component at another version or platform"),
                        }
                        });
                    } else {
                        r.fix_missing += 1;
                        example(&mut r.examples, "fix_missing", limit, || Example {
                            id: format!("{} / {cve}", rec.id),
                            ecosystem: eco.to_string(),
                            package: name.to_string(),
                            detail: format!(
                                "OSV fixed {version}; CSAF {}",
                                if cves.contains(*cve) {
                                    "has the CVE, not this fix"
                                } else {
                                    "has no document for the CVE"
                                }
                            ),
                        });
                    }
                }
            }
        }
    }
    r.osv_cves = osv_cves.len();
    for cve in fixed_components
        .keys()
        .filter(|c| !osv_cves.contains(c.as_str()))
    {
        r.fixed_cves_missing_in_osv += 1;
        example(&mut r.examples, "fixed_cves_missing_in_osv", limit, || {
            Example {
                id: cve.clone(),
                ecosystem: String::new(),
                package: fixed_components[cve]
                    .iter()
                    .next()
                    .cloned()
                    .unwrap_or_default(),
                detail: format!("{} fixed component(s)", fixed_components[cve].len()),
            }
        });
    }
    r.osv_cves_missing_in_csaf = osv_cves.iter().filter(|c| !cves.contains(**c)).count();
    r
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cve5::summarize;

    fn records(json: &[(&str, &str)]) -> BTreeMap<String, (String, Record)> {
        json.iter()
            .map(|(export, body)| {
                let rec: Record = serde_json::from_str(body).unwrap();
                (rec.id.clone(), ((*export).to_string(), rec))
            })
            .collect()
    }

    #[test]
    fn gaps_coverage_fix_comparison_and_lead_time() {
        let osv = records(&[
            (
                "PyPI",
                r#"{"id":"GHSA-a","aliases":["CVE-2025-1"],"published":"2025-03-10T00:00:00Z",
              "affected":[{"package":{"ecosystem":"PyPI","name":"Django"},
                "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"5.0.14"}]}]}],
              "references":[{"type":"PACKAGE","url":"https://github.com/django/django"}]}"#,
            ),
            (
                "PyPI",
                r#"{"id":"GHSA-b","aliases":["CVE-2025-3"],"published":"2025-01-01T00:00:00Z",
              "affected":[{"package":{"ecosystem":"PyPI","name":"django"},
                "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.2"}]}]}]}"#,
            ),
            (
                "PyPI",
                r#"{"id":"GHSA-c","aliases":["CVE-2020-9"],"affected":[]}"#,
            ),
        ]);
        let cve = |id: &str, state: &str, published: &str, affected: &str| {
            summarize(&format!(
                r#"{{"cveMetadata":{{"cveId":"{id}","state":"{state}","datePublished":"{published}",
                "assignerShortName":"GitHub_M"}},"containers":{{"cna":{{"affected":[{affected}]}}}}}}"#
            ))
            .unwrap()
        };
        let cves = vec![
            // Covered; fix agrees; CVE published 9 days before OSV.
            cve(
                "CVE-2025-1",
                "PUBLISHED",
                "2025-03-01T00:00:00",
                r#"{"vendor":"django","product":"django","versions":[{"version":"< 5.0.14","status":"affected"}]}"#,
            ),
            // A gap, mapped through the repository.
            cve(
                "CVE-2025-2",
                "PUBLISHED",
                "2025-03-05T00:00:00",
                r#"{"vendor":"django","product":"django","versions":[{"version":"< 5.1","status":"affected"}]}"#,
            ),
            // Covered; the fix disagrees.
            cve(
                "CVE-2025-3",
                "PUBLISHED",
                "2025-01-01T00:00:00",
                r#"{"vendor":"django","product":"django","versions":[{"version":"< 4.1","status":"affected"}]}"#,
            ),
            // Rejected but aliased.
            cve("CVE-2020-9", "REJECTED", "2020-01-01T00:00:00", ""),
            // Unrelated product: not mapped.
            cve(
                "CVE-2025-4",
                "PUBLISHED",
                "2025-01-01T00:00:00",
                r#"{"vendor":"acme","product":"app","versions":[]}"#,
            ),
        ];
        let ecos: BTreeSet<String> = ["PyPI".to_string()].into();
        let r = cve_vs_osv(&cves, &osv, &ecos, 5);
        assert_eq!(
            (r.published, r.rejected, r.mapped, r.covered, r.gaps),
            (4, 1, 3, 2, 1)
        );
        assert_eq!(r.mapped_by_repo, 3);
        assert_eq!(r.gaps_with_versions, 1);
        assert_eq!((r.fix_compared, r.fix_agree, r.fix_disagree), (2, 1, 1));
        assert_eq!(r.rejected_but_aliased, 1);
        assert_eq!(r.lead_pairs, 2);
        assert_eq!(r.cve_earlier_1d, 1);
        assert_eq!(r.lead_median_days, Some(4.5));
    }

    #[test]
    fn pseudo_versions_are_recognized() {
        assert!(is_pseudo_version(
            "0.5.0-alpha.5.0.20200423152442-f4b650b51dc4"
        ));
        assert!(is_pseudo_version("0.0.0-20210101000000-abcdefabcdef"));
        assert!(!is_pseudo_version("1.2.3-rc1"));
        assert!(!is_pseudo_version("3.4.10"));
    }

    #[test]
    fn red_hat_fixes_match_by_platform_component_and_version() {
        let vex: Vec<VexRecord> = serde_json::from_str(
            r#"[{"cve":"CVE-2024-1","document":"CVE-2024-1",
              "platforms":{"AppStream-9":"cpe:/a:redhat:enterprise_linux:9::appstream","rhel8":"cpe:/o:redhat:enterprise_linux:8"},
              "entries":[
                {"platform":"AppStream-9","component":"thunderbird","version":"0:115.6.0-1.el9_3","status":"fixed","state":"fixed"},
                {"platform":"rhel8","component":"thunderbird","status":"known_affected","state":"will_not_fix"}]},
             {"cve":"CVE-2024-2","document":"CVE-2024-2","entries":[
                {"platform":"rhel8","component":"x","status":"under_investigation","state":"under_investigation"}]}]"#,
        )
        .unwrap();
        let osv = records(&[(
            "Red Hat",
            r#"{"id":"RHSA-1","upstream":["CVE-2024-1"],"affected":[
              {"package":{"ecosystem":"Red Hat:enterprise_linux:9::appstream","name":"thunderbird"},
               "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0:115.6.0-1.el9_3"}]}]},
              {"package":{"ecosystem":"Red Hat:enterprise_linux:9::baseos","name":"thunderbird"},
               "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0:1-1"}]}]},
              {"package":{"ecosystem":"Red Hat:enterprise_linux:9::appstream","name":"other"},
               "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0:1-1"}]}]}]}"#,
        )]);
        let r = csaf_vs_osv("redhat", vex, &osv, 5);
        assert_eq!((r.cves, r.cves_without_fix), (2, 1));
        assert_eq!(
            (
                r.osv_fixes,
                r.fix_exact,
                r.fix_component_only,
                r.fix_missing
            ),
            (3, 1, 1, 1)
        );
        assert_eq!(r.unfixed_entries.get("will_not_fix"), Some(&1));
        assert_eq!(r.unfixed_entries.get("under_investigation"), Some(&1));
        assert_eq!(
            (
                r.osv_cves,
                r.osv_cves_missing_in_csaf,
                r.fixed_cves_missing_in_osv
            ),
            (1, 0, 0)
        );
    }
}
