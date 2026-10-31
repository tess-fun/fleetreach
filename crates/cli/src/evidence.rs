//! Fleet evidence for upgrades (spec 13): which versions of each vulnerable package the
//! fleet already runs, in any repo. A repo that is on the new version and still ships is the
//! best sign that an upgrade is survivable, and no single-repo tool can see it.
//!
//! Read from the same inventories `sbom` writes (lockfiles and manifests only, no network),
//! and only for the packages that have findings, so a clean fleet costs nothing.

use std::collections::{BTreeMap, BTreeSet};

use fleetreach_core::semver::Version;
use fleetreach_core::{
    Ecosystem, FleetReport, Occurrence, PackageVersions, RepoId, VersionInFleet,
};

use crate::config::Repo;

/// Fill `report.package_versions` for every package with an in-repo finding.
pub fn annotate(report: &mut FleetReport, repos: &[Repo]) {
    let wanted: BTreeSet<(Ecosystem, String)> = report
        .vulnerabilities
        .iter()
        .flat_map(|v| {
            v.occurrences.iter().filter_map(move |o| match o {
                Occurrence::InRepo { package, .. } => {
                    Some((v.ecosystem, key(v.ecosystem, package)))
                }
                Occurrence::Toolchain { .. } => None,
            })
        })
        .collect();
    if wanted.is_empty() {
        return;
    }
    let found: Vec<(Ecosystem, String, String, Version, RepoId)> = {
        use rayon::prelude::*;
        repos
            .par_iter()
            .flat_map_iter(|repo| {
                let inv = crate::inventory::repo_inventory(repo);
                inv.sources
                    .into_iter()
                    .flat_map(|s| s.packages.into_iter().map(move |p| (s.ecosystem, p)))
                    .filter_map(|(eco, p)| {
                        let k = key(eco, &p.name);
                        if !wanted.contains(&(eco, k.clone())) {
                            return None;
                        }
                        Some((eco, k, p.name, coerce(&p.version)?, repo.id.clone()))
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    };

    // The finding's spelling of the name is the one remediation groups by.
    let spelling: BTreeMap<(Ecosystem, String), &str> = report
        .vulnerabilities
        .iter()
        .flat_map(|v| {
            v.occurrences.iter().filter_map(move |o| match o {
                Occurrence::InRepo { package, .. } => {
                    Some(((v.ecosystem, key(v.ecosystem, package)), package.as_str()))
                }
                Occurrence::Toolchain { .. } => None,
            })
        })
        .collect();
    let mut by_package: BTreeMap<(Ecosystem, String), BTreeMap<Version, BTreeSet<RepoId>>> =
        BTreeMap::new();
    for (eco, k, name, version, repo) in found {
        let package = spelling.get(&(eco, k)).map_or(name, |s| (*s).to_string());
        by_package
            .entry((eco, package))
            .or_default()
            .entry(version)
            .or_default()
            .insert(repo);
    }
    report.package_versions = by_package
        .into_iter()
        .map(|((ecosystem, package), versions)| PackageVersions {
            ecosystem,
            package,
            versions: versions
                .into_iter()
                .map(|(version, repos)| VersionInFleet {
                    version,
                    repos: repos.into_iter().collect(),
                })
                .collect(),
        })
        .collect();
}

/// The name as each registry compares it: PyPI by its normalized form (PEP 503), Composer and
/// NuGet case-insensitively, everything else verbatim.
fn key(ecosystem: Ecosystem, name: &str) -> String {
    match ecosystem {
        Ecosystem::Pypi => name
            .to_ascii_lowercase()
            .split(['-', '_', '.'])
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("-"),
        Ecosystem::Packagist | Ecosystem::NuGet => name.to_ascii_lowercase(),
        _ => name.to_string(),
    }
}

/// A version in SemVer terms, as the findings carry it: `v1.2` and `1.2` become `1.2.0`; a
/// qualifier that is not a valid SemVer pre-release is dropped. `None` when there is no
/// numeric core at all.
fn coerce(version: &str) -> Option<Version> {
    let v = version.trim().trim_start_matches(['v', 'V']);
    if let Ok(parsed) = Version::parse(v) {
        return Some(parsed);
    }
    let end = v
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(v.len());
    let parts: Vec<u64> = v[..end]
        .split('.')
        .filter(|p| !p.is_empty())
        .take(3)
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    let (major, minor, patch) = match parts.as_slice() {
        [] => return None,
        [a] => (*a, 0, 0),
        [a, b] => (*a, *b, 0),
        [a, b, c, ..] => (*a, *b, *c),
    };
    let mut out = Version::new(major, minor, patch);
    let rest = v[end..].trim_start_matches(['-', '.', '+']);
    if !rest.is_empty() {
        if let Ok(pre) = fleetreach_core::semver::Prerelease::new(rest) {
            out.pre = pre;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coerces_common_version_shapes() {
        let v = |s: &str| coerce(s).map(|v| v.to_string());
        assert_eq!(v("1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(v("v1.2").as_deref(), Some("1.2.0"));
        assert_eq!(v("2").as_deref(), Some("2.0.0"));
        assert_eq!(v("1.0.0-beta.1").as_deref(), Some("1.0.0-beta.1"));
        assert_eq!(v("2.4.5-p1").as_deref(), Some("2.4.5-p1"));
        assert_eq!(v("5.3.20.RELEASE").as_deref(), Some("5.3.20-RELEASE"));
        assert_eq!(v("1.2.3.4").as_deref(), Some("1.2.3"));
        assert_eq!(v("latest"), None);
    }

    #[test]
    fn names_compare_the_way_each_registry_does() {
        assert_eq!(key(Ecosystem::Pypi, "Foo_Bar.baz"), "foo-bar-baz");
        assert_eq!(key(Ecosystem::Packagist, "Symfony/HTTP"), "symfony/http");
        assert_eq!(key(Ecosystem::Npm, "React"), "React");
    }
}
