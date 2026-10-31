//! Tier-C scan for NuGet: read a repo's `packages.lock.json`, match every installed package
//! against the offline OSV DB, and emit a module-level [`VulnFinding`] per affected package.
//!
//! Like the other Tier-C paths this is the lowest-fidelity tier — package + version matching
//! only, so every finding is `Unknown` reachability (never `NotReachable`). The trade is that
//! it is **safe by construction**: it parses the lockfile and compares versions, never running
//! `dotnet`/`nuget` or any package's build, so it needs no untrusted-build consent and no
//! sandbox.

use std::path::Path;

use fleetreach_core::inventory::{Package, SourceInventory};
use fleetreach_core::osv::{sort_dedup_findings, Match, TierCFinding, TierCScan};
use fleetreach_core::semver::VersionReq;
use fleetreach_core::{Coverage, DepGraph, Ecosystem, RepoId, VulnFinding};

use crate::db::{affected_fixed, Advisory, NuGetDb};
use crate::error::NuGetError;
use crate::lockfile::{dedupe, parse_lockfile, InstalledPackage};
use crate::version::{parse_nuget_version, to_semver, Version};
use crate::{assets, msbuild};

/// Scan the .NET project at `repo_dir` against the preloaded OSV DB, without a .NET
/// toolchain. Reads, in order of preference, `packages.lock.json`, `obj/project.assets.json`
/// (restore output), `packages.config`, or the project files' `PackageReference` items. Emits
/// one module-level [`VulnFinding`] per affected package; output is sorted by `(advisory id,
/// package)` for determinism.
///
/// This drops the coverage labels; [`scan_offline_with_coverage`] keeps them.
///
/// # Errors
///
/// Returns [`NuGetError::Db`] if no recognized source is present or one cannot be read or
/// parsed, failing closed, so an unreadable/absent/corrupt source is an honest gap.
pub fn scan_offline(repo_dir: &Path, db: &NuGetDb, repo: &RepoId) -> Result<TierCScan, NuGetError> {
    scan_offline_with_coverage(repo_dir, db, repo).map(|scan| scan.scan)
}

/// One source read with less than full coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SourceCoverage {
    /// The file, relative to the scanned directory.
    pub source: String,
    pub level: Coverage,
    /// Why coverage is incomplete, naming what was not read.
    pub reason: String,
}

/// A NuGet scan, with the sources it read with less than full coverage.
#[derive(Debug)]
#[non_exhaustive]
pub struct NuGetScan {
    pub scan: TierCScan,
    /// Project files read for their declared dependencies only, a stale
    /// `project.assets.json`, imports that were not followed.
    pub coverage: Vec<SourceCoverage>,
}

/// Whether `dir` holds anything the NuGet feeder reads: `packages.lock.json`,
/// `packages.config`, or a `.csproj` / `.fsproj` / `.vbproj` project file.
#[must_use]
pub fn has_nuget_sources(dir: &Path) -> bool {
    dir.join("packages.lock.json").is_file()
        || dir.join("packages.config").is_file()
        || !msbuild::project_files(dir).is_empty()
}

/// [`scan_offline`], also reporting which sources were read with less than full coverage.
///
/// # Errors
///
/// As [`scan_offline`].
pub fn scan_offline_with_coverage(
    repo_dir: &Path,
    db: &NuGetDb,
    repo: &RepoId,
) -> Result<NuGetScan, NuGetError> {
    let (installed, graph, coverage) = read_sources(repo_dir)?;
    let scan = scan_installed(&installed, &graph, db, repo);
    Ok(NuGetScan { scan, coverage })
}

/// Match packages that were already read (from an SBOM, say) against the DB, exactly as
/// [`scan_offline`] does for the repo's own files; `graph` supplies dependency paths.
pub fn scan_installed(
    installed: &[InstalledPackage],
    graph: &DepGraph,
    db: &NuGetDb,
    repo: &RepoId,
) -> TierCScan {
    let mut out: Vec<VulnFinding> = Vec::new();
    let mut skipped_unparseable = 0u32;
    for pkg in installed {
        let Some(version) = parse_nuget_version(&pkg.version) else {
            // A non-release pin (a project/floating reference that slipped through) has no
            // registry artifact to match. Skipping it does not hide a NuGet advisory.
            skipped_unparseable += 1;
            continue;
        };
        // The representative introducer chain `[root, …, pkg]` (pkg.name is lowercased,
        // matching the graph nodes), computed once per package.
        let dependency_path = graph.chain_to(&pkg.name);
        for adv in db.advisories_for(&pkg.name) {
            if let Some(finding) = match_advisory(adv, pkg, &version, &dependency_path, repo) {
                out.push(finding);
            }
        }
    }
    sort_dedup_findings(&mut out);
    TierCScan {
        findings: out,
        skipped_unparseable,
    }
}

/// Every package the directory's preferred NuGet source declares, for SBOM output: the same
/// source selection as [`scan_offline`], with its coverage.
///
/// # Errors
///
/// As [`scan_offline`].
pub fn inventory(repo_dir: &Path) -> Result<SourceInventory, NuGetError> {
    let (installed, graph, coverage) = read_sources(repo_dir)?;
    let name = if repo_dir.join("packages.lock.json").is_file() {
        "packages.lock.json".to_string()
    } else if repo_dir.join("obj").join("project.assets.json").is_file()
        && !msbuild::project_files(repo_dir).is_empty()
    {
        "obj/project.assets.json".to_string()
    } else if repo_dir.join("packages.config").is_file() {
        "packages.config".to_string()
    } else {
        msbuild::project_files(repo_dir)
            .iter()
            .map(|p| file_name(p))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let packages = installed
        .into_iter()
        .map(|p| Package::new(p.name, p.version, p.direct, false))
        .collect();
    let mut inv = SourceInventory::new(Ecosystem::NuGet, name, packages).with_graph(&graph);
    for gap in coverage {
        inv = inv.with_gap(gap.level, format!("{}: {}", gap.source, gap.reason));
    }
    Ok(inv)
}

type Read = (Vec<InstalledPackage>, DepGraph, Vec<SourceCoverage>);

/// Read the preferred source in `repo_dir`.
fn read_sources(repo_dir: &Path) -> Result<Read, NuGetError> {
    let text = |path: &Path| std::fs::read_to_string(path).map_err(|e| NuGetError::db(path, e));
    let gap = |source: &str, level: Coverage, reason: String| SourceCoverage {
        source: source.to_string(),
        level,
        reason,
    };

    let lock_path = repo_dir.join("packages.lock.json");
    if lock_path.is_file() {
        let (installed, graph) =
            parse_lockfile(&text(&lock_path)?).map_err(|e| NuGetError::db(&lock_path, e))?;
        return Ok((installed, graph, Vec::new()));
    }

    let projects = msbuild::project_files(repo_dir);
    let mut declared = Vec::new();
    for project in &projects {
        let read = msbuild::read_project(project)
            .map_err(|e| NuGetError::db(project, std::io::Error::from(e)))?;
        declared.push((file_name(project), read));
    }
    let mut coverage: Vec<SourceCoverage> = declared
        .iter()
        .flat_map(|(file, d)| d.imports.iter().map(move |i| (file, i)))
        .map(|(file, import)| {
            gap(
                file,
                Coverage::Partial,
                format!("{import} is not followed; packages declared there were not read"),
            )
        })
        .collect();
    coverage.sort_by(|a, b| a.reason.cmp(&b.reason));
    coverage.dedup_by(|a, b| a.reason == b.reason);

    // Restore output: the full resolved graph, if it still matches the project files.
    let assets_path = repo_dir.join("obj").join("project.assets.json");
    if !projects.is_empty() && assets_path.is_file() {
        let restored =
            assets::parse(&text(&assets_path)?).map_err(|e| NuGetError::db(&assets_path, e))?;
        let stale: Vec<String> = declared
            .iter()
            .flat_map(|(_, d)| &d.declared)
            .filter_map(|(name, version)| match restored.requested.get(name) {
                None => Some(format!("{name} (not restored)")),
                Some(range) => {
                    let floor = assets::range_floor(range)?;
                    let same = version.as_deref().is_none_or(|v| {
                        parse_nuget_version(v).is_some()
                            && parse_nuget_version(v) == parse_nuget_version(floor)
                    });
                    (!same).then(|| {
                        format!(
                            "{name} {} (restored {floor})",
                            version.as_deref().unwrap_or("")
                        )
                    })
                }
            })
            .collect();
        if !stale.is_empty() {
            coverage.push(gap(
                "obj/project.assets.json",
                Coverage::Partial,
                format!(
                    "older than the project file(s), which now declare {}; run dotnet restore \
                     before scanning",
                    sample(&stale)
                ),
            ));
        }
        return Ok((restored.packages, restored.graph, coverage));
    }

    let config_path = repo_dir.join("packages.config");
    if config_path.is_file() {
        let installed = msbuild::parse_packages_config(&text(&config_path)?)
            .map_err(|e| NuGetError::db(&config_path, std::io::Error::from(e)))?;
        return Ok((dedupe(installed), DepGraph::default(), coverage));
    }

    if declared.is_empty() {
        return Err(NuGetError::db(
            repo_dir.to_path_buf(),
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no recognized NuGet source (packages.lock.json, obj/project.assets.json, \
                 packages.config or a .csproj/.fsproj/.vbproj)",
            ),
        ));
    }
    let mut installed = Vec::new();
    for (file, d) in declared {
        if d.declared.is_empty() {
            continue; // nothing declared: nothing to miss
        }
        let unresolved = if d.unresolved.is_empty() {
            String::new()
        } else {
            format!(
                "; {} without a single resolvable version were not matched: {}",
                d.unresolved.len(),
                sample(&d.unresolved)
            )
        };
        coverage.push(gap(
            &file,
            Coverage::DirectOnly,
            format!(
                "PackageReference items declare direct dependencies only; transitive \
                 dependencies were not resolved (commit packages.lock.json with \
                 RestorePackagesWithLockFile, or scan after dotnet restore){unresolved}"
            ),
        ));
        installed.extend(d.packages);
    }
    // Every package here is direct, so there is no chain to show.
    Ok((dedupe(installed), DepGraph::default(), coverage))
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// At most five items, then a count of the rest.
fn sample(items: &[String]) -> String {
    let shown: Vec<&str> = items.iter().take(5).map(String::as_str).collect();
    let more = items.len().saturating_sub(shown.len());
    if more == 0 {
        shown.join(", ")
    } else {
        format!("{} and {more} more", shown.join(", "))
    }
}

/// Build a finding if `adv` lists `pkg` as affected at `version` (a NuGet version).
fn match_advisory(
    adv: &Advisory,
    pkg: &InstalledPackage,
    version: &Version,
    dependency_path: &[String],
    repo: &RepoId,
) -> Option<VulnFinding> {
    let fixed = match affected_fixed(version, &adv.ranges) {
        Match::Affected { fixed } => fixed,
        Match::NotAffected if adv.versions.binary_search(version).is_ok() => None,
        Match::NotAffected => return None,
    };
    let patched: Vec<VersionReq> = fixed
        .as_ref()
        .and_then(|f| VersionReq::parse(&format!(">={}", to_semver(f))).ok())
        .into_iter()
        .collect();

    Some(
        TierCFinding {
            ecosystem: Ecosystem::NuGet,
            advisory_id: adv.id.clone(),
            aliases: adv.aliases.clone(),
            title: adv.summary.clone().unwrap_or_else(|| adv.id.clone()),
            severity: adv.severity,
            cvss_score: adv.cvss_score,
            cvss_vector: adv.cvss_vector.clone(),
            package: pkg.name.clone(),
            installed: to_semver(version),
            patched,
            direct: pkg.direct,
            dev: false,
            dependency_path: dependency_path.to_vec(),
            repo,
            reach_reason: "package-level scan (no toolchain): version match only",
        }
        .build(),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use fleetreach_core::osv::{self, Event, Range};
    use fleetreach_core::{DependencyKind, Occurrence, Severity};

    fn adv(id: &str, fixed: &str) -> Advisory {
        let range = Range {
            matchable: true,
            events: vec![
                Event {
                    introduced: Some("0".into()),
                    fixed: None,
                    last_affected: None,
                },
                Event {
                    introduced: None,
                    fixed: Some(fixed.into()),
                    last_affected: None,
                },
            ],
        };
        Advisory {
            id: id.to_string(),
            aliases: vec![],
            summary: Some(format!("bug in {id}")),
            severity: Severity::High,
            cvss_score: Some(7.5),
            cvss_vector: None,
            ranges: vec![osv::parse_range(&range, parse_nuget_version)],
            versions: vec![],
        }
    }

    fn pkg(name: &str, version: &str, direct: bool) -> InstalledPackage {
        InstalledPackage {
            name: name.to_string(),
            version: version.to_string(),
            direct,
        }
    }

    #[test]
    fn affected_package_becomes_a_finding() {
        let a = adv("GHSA-aaaa", "13.0.1");
        let p = pkg("newtonsoft.json", "12.0.3", true);
        let f = match_advisory(
            &a,
            &p,
            &parse_nuget_version("12.0.3").unwrap(),
            &[],
            &RepoId("r".into()),
        )
        .unwrap();
        assert_eq!(f.advisory_id, "GHSA-aaaa");
        assert_eq!(f.ecosystem, Ecosystem::NuGet);
        match &f.occurrences[0] {
            Occurrence::InRepo {
                package,
                dependency_kind,
                installed,
                ..
            } => {
                assert_eq!(package, "newtonsoft.json");
                assert_eq!(installed.to_string(), "12.0.3");
                assert_eq!(*dependency_kind, DependencyKind::Direct);
            }
            _ => panic!("expected InRepo"),
        }
    }

    #[test]
    fn patched_version_is_not_a_finding() {
        let a = adv("GHSA-aaaa", "13.0.1");
        assert!(match_advisory(
            &a,
            &pkg("newtonsoft.json", "13.0.1", true),
            &parse_nuget_version("13.0.1").unwrap(),
            &[],
            &RepoId("r".into())
        )
        .is_none());
    }

    #[test]
    fn version_only_record_matches_via_versions() {
        let a = Advisory {
            id: "GHSA-only".into(),
            aliases: vec![],
            summary: None,
            severity: Severity::Critical,
            cvss_score: None,
            cvss_vector: None,
            ranges: vec![],
            versions: vec![parse_nuget_version("1.1.1.1").unwrap()],
        };
        assert!(match_advisory(
            &a,
            &pkg("p", "1.1.1.1", false),
            &parse_nuget_version("1.1.1.1").unwrap(),
            &[],
            &RepoId("r".into())
        )
        .is_some());
        assert!(match_advisory(
            &a,
            &pkg("p", "1.1.1.2", false),
            &parse_nuget_version("1.1.1.2").unwrap(),
            &[],
            &RepoId("r".into())
        )
        .is_none());
    }
}
