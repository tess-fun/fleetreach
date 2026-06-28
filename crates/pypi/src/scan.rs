//! Tier-C scan for PyPI: detect a repo's Python lockfile, match every installed package
//! against the offline OSV DB, and emit a module-level [`VulnFinding`] per affected
//! package.
//!
//! Like the Go and npm Tier-C paths this is the lowest-fidelity tier — package + version
//! matching only, so every finding is `Unknown` reachability (never `NotReachable`). The
//! trade is that it is **safe by construction**: it parses the lockfile and compares
//! versions, never running `pip`/`poetry`/`uv` or any package's build, so it needs no
//! untrusted-build consent and no sandbox.

use std::path::Path;

use fleetreach_core::osv::{sort_dedup_findings, Match, TierCFinding, TierCScan};
use fleetreach_core::semver::VersionReq;
use fleetreach_core::{Ecosystem, RepoId, VulnFinding};

use crate::db::{affected_fixed, Advisory, PyPiDb};
use crate::error::PyPiError;
use crate::lockfile::{detect, installed_packages, InstalledPackage};
use crate::version::{normalize_name, parse_pypi_version, to_semver};

/// Scan the Python project at `repo_dir` (containing a `uv.lock`, `poetry.lock`, or
/// `Pipfile.lock`) against the preloaded OSV DB, without a Python toolchain. Emits one
/// module-level [`VulnFinding`] per affected package; output is sorted by `(advisory id,
/// package)` for determinism.
///
/// # Errors
///
/// Returns [`PyPiError::Db`] if no recognized lockfile is present or it cannot be parsed
/// — failing closed, so an unreadable/absent lockfile is an honest gap rather than a
/// false-clean scan.
pub fn scan_offline(repo_dir: &Path, db: &PyPiDb, repo: &RepoId) -> Result<TierCScan, PyPiError> {
    let Some((kind, lock_path)) = detect(repo_dir) else {
        return Err(PyPiError::db(
            repo_dir.to_path_buf(),
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no recognized Python lockfile (uv.lock, poetry.lock, or Pipfile.lock)",
            ),
        ));
    };
    let (installed, graph) = installed_packages(kind, &lock_path, repo_dir)?;

    let mut out: Vec<VulnFinding> = Vec::new();
    let mut skipped_unparseable = 0u32;
    for pkg in &installed {
        let Some(version) = parse_pypi_version(&pkg.version) else {
            // A non-PEP-440 resolved version (a VCS/URL/local-path pin) cannot be matched
            // against the registry advisory DB. Skipping it does not hide a PyPI advisory
            // (the artifact is not a registry release), so this is not a soundness gap —
            // the same stance as the npm feeder's non-SemVer pins.
            skipped_unparseable += 1;
            continue;
        };
        // The representative introducer chain `[root, …, pkg]`, computed once per package.
        let dependency_path = graph.chain_to(&pkg.name);
        for adv in db.advisories_for(&normalize_name(&pkg.name)) {
            if let Some(finding) = match_advisory(adv, pkg, &version, &dependency_path, repo) {
                out.push(finding);
            }
        }
    }
    sort_dedup_findings(&mut out);
    Ok(TierCScan {
        findings: out,
        skipped_unparseable,
    })
}

/// Build a finding if `adv` lists `pkg` as affected at `version` (a PEP 440 version).
fn match_advisory(
    adv: &Advisory,
    pkg: &InstalledPackage,
    version: &crate::version::Version,
    dependency_path: &[String],
    repo: &RepoId,
) -> Option<VulnFinding> {
    // A package is affected if a range covers the version OR the record explicitly lists
    // it. PyPI OSV uses version-only records heavily (MAL- malware advisories, many
    // GHSA/PYSEC), which a range-only matcher would false-clean — so the enumerated
    // `versions` are consulted too. The range path supplies the `fixed` hint; a
    // version-only match has no fix metadata.
    // `adv.versions` are PEP 440 versions sorted at load, so membership is a binary search.
    let fixed = match affected_fixed(version, &adv.ranges) {
        Match::Affected { fixed } => fixed,
        Match::NotAffected if adv.versions.binary_search(version).is_ok() => None,
        Match::NotAffected => return None,
    };
    // The fix and installed version are stored in the shared model's SemVer form (see
    // `to_semver`); detection above used the true PEP 440 comparison.
    let patched: Vec<VersionReq> = fixed
        .as_ref()
        .and_then(|f| VersionReq::parse(&format!(">={}", to_semver(f))).ok())
        .into_iter()
        .collect();

    Some(
        TierCFinding {
            ecosystem: Ecosystem::Pypi,
            advisory_id: adv.id.clone(),
            aliases: adv.aliases.clone(),
            title: adv.summary.clone().unwrap_or_else(|| adv.id.clone()),
            severity: adv.severity,
            cvss_score: adv.cvss_score,
            package: pkg.name.clone(),
            installed: to_semver(version),
            patched,
            direct: pkg.direct,
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
    use crate::db::parse_bound;
    use fleetreach_core::osv::{self, Event, Range};
    use fleetreach_core::{DependencyKind, Occurrence, ReachVerdict, Severity};

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
            ranges: vec![osv::parse_range(&range, parse_bound)],
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
        let a = adv("GHSA-aaaa", "2.31.0");
        let p = pkg("Requests", "2.30.0", true);
        let f = match_advisory(
            &a,
            &p,
            &parse_pypi_version("2.30.0").unwrap(),
            &[],
            &RepoId("r".into()),
        )
        .unwrap();
        assert_eq!(f.advisory_id, "GHSA-aaaa");
        assert_eq!(f.ecosystem, Ecosystem::Pypi);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.cvss_score, Some(7.5));
        match &f.occurrences[0] {
            Occurrence::InRepo {
                package,
                dependency_kind,
                patched,
                installed,
                ..
            } => {
                assert_eq!(package, "Requests", "display name kept verbatim");
                assert_eq!(installed.to_string(), "2.30.0");
                assert_eq!(*dependency_kind, DependencyKind::Direct);
                assert!(patched[0].matches(&to_semver(&parse_pypi_version("2.31.0").unwrap())));
            }
            _ => panic!("expected InRepo"),
        }
        assert!(matches!(
            f.reachability.unwrap().verdict,
            ReachVerdict::Unknown { .. }
        ));
    }

    #[test]
    fn version_only_record_with_no_range_is_matched() {
        // PyPI malware/advisory records often enumerate affected versions with no range;
        // a range-only matcher would false-clean them.
        let a = Advisory {
            id: "MAL-2024-1".into(),
            aliases: vec![],
            summary: Some("malware".into()),
            severity: Severity::Critical,
            cvss_score: None,
            ranges: vec![],
            versions: vec![parse_pypi_version("1.0.0").unwrap()],
        };
        let p = pkg("evil", "1.0.0", false);
        let f = match_advisory(
            &a,
            &p,
            &parse_pypi_version("1.0.0").unwrap(),
            &[],
            &RepoId("r".into()),
        )
        .unwrap();
        assert_eq!(f.advisory_id, "MAL-2024-1");
        // No range => no fix metadata.
        match &f.occurrences[0] {
            Occurrence::InRepo { patched, .. } => assert!(patched.is_empty()),
            _ => panic!("expected InRepo"),
        }
        // A different version is not matched by the enumerated list.
        let other = pkg("evil", "1.0.1", false);
        assert!(match_advisory(
            &a,
            &other,
            &parse_pypi_version("1.0.1").unwrap(),
            &[],
            &RepoId("r".into())
        )
        .is_none());
    }

    #[test]
    fn patched_version_is_not_a_finding() {
        let a = adv("GHSA-aaaa", "2.31.0");
        let p = pkg("requests", "2.31.0", true);
        assert!(match_advisory(
            &a,
            &p,
            &parse_pypi_version("2.31.0").unwrap(),
            &[],
            &RepoId("r".into())
        )
        .is_none());
    }

    #[test]
    fn prerelease_in_affected_window_is_flagged() {
        // 1.0a1 is in [0, 1.0): a vulnerable pre-release must be reported, and its stored
        // version must order below the 1.0 fix.
        let a = adv("GHSA-pre", "1.0");
        let p = pkg("x", "1.0a1", false);
        let f = match_advisory(
            &a,
            &p,
            &parse_pypi_version("1.0a1").unwrap(),
            &[],
            &RepoId("r".into()),
        )
        .unwrap();
        match &f.occurrences[0] {
            Occurrence::InRepo {
                installed, patched, ..
            } => {
                assert_eq!(installed.to_string(), "1.0.0-a1");
                // The fix at 1.0 must still read as not-yet-applied for this pre-release.
                assert!(!patched[0].matches(installed));
            }
            _ => panic!("expected InRepo"),
        }
    }
}
