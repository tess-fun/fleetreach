//! Keeps a planned target clear of advisories the fleet has not met yet.
//!
//! The remediation queue picks a target from the findings in the report, so it only knows the
//! advisories some repo already has. A target can carry one that starts above every installed
//! version: `lodash` 4.17.15 is clear of GHSA-f23m-r3pf-42rh, 4.18.0 is not. The re-scan in
//! `fix apply` refuses such a bump as a new finding, so `fix plan` reads the same OSV exports and
//! steps to the lowest `fixed` bound that clears the edit's advisories and adds none, with each
//! ecosystem's own version order.
//!
//! This looks only at the package itself. What a target brings in with it needs the registry,
//! and stays with the re-scan. Without an export the target stands, for the same reason. Go and
//! GitHub Actions keep their advisories in other shapes and are not checked.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::path::{Path, PathBuf};

use fleetreach_core::osv::{self, Match};
use fleetreach_core::semver::Version;
use fleetreach_core::Ecosystem;
use fleetreach_core::{line, Risk};
use fleetreach_maven::MavenDb;
use fleetreach_npm::NpmDb;
use fleetreach_nuget::NuGetDb;
use fleetreach_packagist::PackagistDb;
use fleetreach_pypi::PyPiDb;
use fleetreach_rubygems::RubyGemsDb;
use fleetreach_scan::CratesDb;

use crate::fix::{campaign_id, Edit, Strategy};

/// What the advisories on a package make of a target.
#[derive(Debug, PartialEq, Eq)]
enum Step<V> {
    Clear,
    /// These ids are on the target, and this is the lowest version clear of them.
    To(V, Vec<String>),
    /// These ids are on the target, and nothing published is clear of them.
    Stuck(Vec<String>),
}

fn hits<V: Ord + Clone>(advisory: &osv::Advisory<V>, version: &V) -> bool {
    let ranged = osv::affected_fixed_parsed(version, &advisory.ranges, |v, bound| v >= bound);
    matches!(ranged, Match::Affected { .. }) || advisory.versions.binary_search(version).is_ok()
}

/// Whether a version text names a prerelease, in any ecosystem's spelling: `1.0.0-rc.1`,
/// `1.0rc1`, `1.0.0.beta2`, `1.0-M1`. A fourth number is not one, nor is `.Final` or `-jre`,
/// which is why the SemVer form of a version cannot answer this.
fn prerelease(text: &str) -> bool {
    let words = text.split(|c: char| !c.is_ascii_alphabetic());
    words.map(str::to_ascii_lowercase).any(|word| {
        let names = [
            "a",
            "alpha",
            "b",
            "beta",
            "c",
            "rc",
            "cr",
            "m",
            "milestone",
            "ea",
            "dev",
            "pre",
            "preview",
            "snapshot",
            "nightly",
        ];
        names.contains(&word.as_str())
    })
}

/// A prerelease target is left alone, but a prerelease is not somewhere to send a repo on
/// releases.
fn step<V: Ord + Clone + Display>(
    advisories: &[osv::Advisory<V>],
    from: &[V],
    to: &V,
    targeted: &[String],
) -> Step<V> {
    // An advisory the repo has already and the plan is not fixing is not a new finding.
    let counts = |a: &&osv::Advisory<V>| {
        let named = targeted.contains(&a.id) || a.aliases.iter().any(|x| targeted.contains(x));
        named || !from.iter().any(|version| hits(a, version))
    };
    let counted: Vec<&osv::Advisory<V>> = advisories.iter().filter(counts).collect();
    let ids: BTreeSet<String> = counted
        .iter()
        .filter(|a| hits(a, to))
        .map(|a| a.id.clone())
        .collect();
    if ids.is_empty() {
        return Step::Clear;
    }
    let ids: Vec<String> = ids.into_iter().collect();
    let ranges = advisories.iter().flat_map(|a| &a.ranges);
    let bounds: BTreeSet<&V> = ranges
        .flat_map(|r| &r.events)
        .filter_map(|e| e.fixed.as_ref())
        .filter(|fixed| *fixed > to)
        .filter(|fixed| !prerelease(&fixed.to_string()) || prerelease(&to.to_string()))
        .collect();
    let clear = bounds
        .into_iter()
        .find(|bound| !counted.iter().any(|a| hits(a, bound)));
    match clear {
        Some(version) => Step::To(version.clone(), ids),
        None => Step::Stuck(ids),
    }
}

/// Moves `edit` as `step` says, by the rules a target has from the start: a jump to a new major
/// needs `--allow-breaking`, and the campaign follows the target.
fn settle(edit: &mut Edit, moved: Step<Target>, allow_breaking: bool) -> bool {
    match moved {
        Step::Clear => false,
        Step::Stuck(ids) => {
            edit.strategy = Strategy::Blocked;
            edit.reason = Some(format!(
                "{} has {}, with no fix published",
                edit.to,
                ids.join(", ")
            ));
            true
        }
        Step::To(target, ids) => {
            let old = std::mem::replace(&mut edit.to, target.text);
            let advisories = &edit.advisories;
            edit.campaign = campaign_id(edit.ecosystem, &edit.package, &edit.to, advisories);
            edit.risk_reasons
                .push(format!("{old} has {}", ids.join(", ")));
            let mut installed = edit.from.iter().filter_map(|v| Version::parse(v).ok());
            let crosses = installed.any(|v| line(&v) != line(&target.semver));
            if crosses && !edit.breaking {
                edit.breaking = true;
                edit.risk = Some(Risk::High);
                edit.risk_reasons
                    .insert(0, "breaking (new major)".to_string());
                if !allow_breaking {
                    edit.strategy = Strategy::Blocked;
                    edit.reason = Some(format!(
                        "{old} has {}, and the next clear version, {}, is a breaking upgrade; \
                         pass --allow-breaking to plan it",
                        ids.join(", "),
                        edit.to
                    ));
                }
            }
            true
        }
    }
}

/// A version to move to: as the ecosystem writes it, since a tool has to find it, and in the
/// plan's SemVer form to compare lines.
#[derive(Debug, PartialEq, Eq)]
struct Target {
    text: String,
    semver: Version,
}

/// One ecosystem's view of the advisories, in its own version type.
struct Reader<'a, V> {
    advisories: &'a dyn Fn(&str) -> &'a [osv::Advisory<V>],
    parse: fn(&str) -> Option<V>,
    semver: fn(&V) -> Version,
}

impl<V: Ord + Clone + Display> Reader<'_, V> {
    fn check(&self, edit: &mut Edit, allow_breaking: bool) -> bool {
        let from: Vec<V> = edit.from.iter().filter_map(|v| (self.parse)(v)).collect();
        let Some(to) = (self.parse)(&edit.to) else {
            return false;
        };
        if from.len() != edit.from.len() {
            return false;
        }
        let advisories = (self.advisories)(&edit.package);
        let moved = match step(advisories, &from, &to, &edit.advisories) {
            Step::Clear => Step::Clear,
            Step::Stuck(ids) => Step::Stuck(ids),
            Step::To(version, ids) => {
                let target = Target {
                    text: version.to_string(),
                    semver: (self.semver)(&version),
                };
                Step::To(target, ids)
            }
        };
        settle(edit, moved, allow_breaking)
    }
}

fn semver_of(version: &Version) -> Version {
    version.clone()
}

fn check_all<V: Ord + Clone + Display>(
    reader: &Reader<'_, V>,
    edits: &mut [&mut Edit],
    allow_breaking: bool,
) -> usize {
    let checked = edits.iter_mut().map(|e| reader.check(e, allow_breaking));
    checked.filter(|moved| *moved).count()
}

/// Reads one ecosystem's export and checks its edits; the count of edits it changed.
fn check_ecosystem(
    ecosystem: Ecosystem,
    path: &Path,
    overlay: Option<&Path>,
    edits: &mut [&mut Edit],
    allow_breaking: bool,
) -> Result<usize, String> {
    let keep = allow_breaking;
    Ok(match ecosystem {
        Ecosystem::Npm => {
            let db = NpmDb::load_with_overlay(path, overlay).map_err(|e| e.to_string())?;
            let reader = Reader {
                advisories: &|name| db.advisories_for(name),
                parse: fleetreach_npm::parse_npm_version,
                semver: semver_of,
            };
            check_all(&reader, edits, keep)
        }
        Ecosystem::Cargo => {
            let db = CratesDb::load_with_overlay(path, overlay).map_err(|e| e.to_string())?;
            let reader = Reader {
                advisories: &|name| db.advisories_for(name),
                parse: |text| Version::parse(text).ok(),
                semver: semver_of,
            };
            check_all(&reader, edits, keep)
        }
        Ecosystem::Pypi => {
            let db = PyPiDb::load_with_overlay(path, overlay).map_err(|e| e.to_string())?;
            let key = |name: &str| fleetreach_pypi::normalize_name(name);
            let reader = Reader {
                advisories: &|name| db.advisories_for(&key(name)),
                parse: fleetreach_pypi::parse_pypi_version,
                semver: fleetreach_pypi::to_semver,
            };
            check_all(&reader, edits, keep)
        }
        Ecosystem::RubyGems => {
            let db = RubyGemsDb::load_with_overlay(path, overlay).map_err(|e| e.to_string())?;
            let reader = Reader {
                advisories: &|name| db.advisories_for(name),
                parse: fleetreach_rubygems::parse_rubygems_version,
                semver: fleetreach_rubygems::to_semver,
            };
            check_all(&reader, edits, keep)
        }
        Ecosystem::Packagist => {
            let db = PackagistDb::load_with_overlay(path, overlay).map_err(|e| e.to_string())?;
            let reader = Reader {
                advisories: &|name| db.advisories_for(&name.to_ascii_lowercase()),
                parse: fleetreach_packagist::parse_composer_version,
                semver: fleetreach_packagist::to_semver,
            };
            check_all(&reader, edits, keep)
        }
        Ecosystem::NuGet => {
            let db = NuGetDb::load_with_overlay(path, overlay).map_err(|e| e.to_string())?;
            let reader = Reader {
                advisories: &|name| db.advisories_for(&name.to_ascii_lowercase()),
                parse: fleetreach_nuget::parse_nuget_version,
                semver: fleetreach_nuget::to_semver,
            };
            check_all(&reader, edits, keep)
        }
        Ecosystem::Maven => {
            let db = MavenDb::load_with_overlay(path, overlay).map_err(|e| e.to_string())?;
            let reader = Reader {
                advisories: &|name| db.advisories_for(name),
                parse: fleetreach_maven::parse_maven_version,
                semver: fleetreach_maven::to_semver,
            };
            check_all(&reader, edits, keep)
        }
        _ => 0,
    })
}

const CHECKED: [Ecosystem; 7] = [
    Ecosystem::Npm,
    Ecosystem::Cargo,
    Ecosystem::Pypi,
    Ecosystem::RubyGems,
    Ecosystem::Packagist,
    Ecosystem::NuGet,
    Ecosystem::Maven,
];

/// The ecosystems with a planned bump that this module can check.
pub(crate) fn needed(edits: &[Edit]) -> Vec<Ecosystem> {
    let planned = edits.iter().filter(|e| e.strategy != Strategy::Blocked);
    let wanted: BTreeSet<Ecosystem> = planned.map(|e| e.ecosystem).collect();
    CHECKED.into_iter().filter(|e| wanted.contains(e)).collect()
}

/// Checks every planned bump against `exports`. Returns how many edits changed, and a warning
/// for each ecosystem that could not be read: its targets stand, and the re-scan decides.
pub(crate) fn check(
    edits: &mut [Edit],
    exports: &BTreeMap<Ecosystem, PathBuf>,
    overlay: Option<&Path>,
    allow_breaking: bool,
) -> (usize, Vec<String>) {
    let (mut changed, mut warnings) = (0, Vec::new());
    for ecosystem in needed(edits) {
        let Some(path) = exports.get(&ecosystem) else {
            warnings.push(format!(
                "no advisory export for {ecosystem:?}: its targets were not checked for \
                 advisories of their own"
            ));
            continue;
        };
        let planned = edits.iter_mut().filter(|e| e.ecosystem == ecosystem);
        let mut planned: Vec<&mut Edit> = planned
            .filter(|e| e.strategy != Strategy::Blocked)
            .collect();
        match check_ecosystem(ecosystem, path, overlay, &mut planned, allow_breaking) {
            Ok(count) => changed += count,
            Err(e) => warnings.push(format!("{ecosystem:?} targets were not checked: {e}")),
        }
    }
    (changed, warnings)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use fleetreach_core::osv::{ParsedEvent, ParsedRange};

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    fn advisory(id: &str, introduced: &str, fixed: Option<&str>) -> osv::Advisory<Version> {
        let events = vec![
            ParsedEvent {
                introduced: Some(osv::ParsedBound::Version(v(introduced))),
                fixed: None,
                last_affected: None,
            },
            ParsedEvent {
                introduced: None,
                fixed: fixed.map(v),
                last_affected: None,
            },
        ];
        osv::Advisory {
            id: id.to_string(),
            aliases: vec![format!("{id}-alias")],
            summary: None,
            severity: fleetreach_core::Severity::High,
            cvss_score: None,
            cvss_vector: None,
            ranges: vec![ParsedRange {
                matchable: true,
                events,
            }],
            versions: Vec::new(),
        }
    }

    fn run(advisories: &[osv::Advisory<Version>], from: &str, to: &str) -> Step<Version> {
        let targeted = ["OLD".to_string()];
        step(advisories, &[v(from)], &v(to), &targeted)
    }

    #[test]
    fn a_target_steps_past_what_starts_above_the_installed_version() {
        let advisories = [
            advisory("OLD", "0.0.0", Some("4.18.0")),
            advisory("LATER", "4.17.23", Some("4.18.1")),
        ];
        let moved = run(&advisories, "4.17.15", "4.18.0");
        assert_eq!(moved, Step::To(v("4.18.1"), vec!["LATER".to_string()]));
        assert_eq!(run(&advisories, "4.17.15", "4.18.1"), Step::Clear);
    }

    #[test]
    fn a_step_does_not_land_on_another_advisory() {
        let advisories = [
            advisory("LATER", "2.0.0", Some("2.1.0")),
            advisory("LATER2", "2.1.0", Some("2.2.0")),
        ];
        let moved = run(&advisories, "1.0.0", "2.0.0");
        assert_eq!(moved, Step::To(v("2.2.0"), vec!["LATER".to_string()]));
    }

    #[test]
    fn an_advisory_with_no_fix_leaves_the_target_stuck() {
        let advisories = [advisory("LATER", "2.0.0", None)];
        let moved = run(&advisories, "1.0.0", "2.0.0");
        assert_eq!(moved, Step::Stuck(vec!["LATER".to_string()]));
    }

    #[test]
    fn what_the_repo_already_has_is_not_new() {
        // On the installed version too, and not one the plan fixes: the re-scan will not call
        // it new, so it does not move the target.
        let advisories = [advisory("KNOWN", "0.0.0", None)];
        assert_eq!(run(&advisories, "1.0.0", "2.0.0"), Step::Clear);
    }

    #[test]
    fn an_alias_of_a_targeted_advisory_counts() {
        let advisories = [advisory("OLD2", "0.0.0", Some("3.0.0"))];
        let targeted = ["OLD2-alias".to_string()];
        let moved = step(&advisories, &[v("1.0.0")], &v("2.0.0"), &targeted);
        assert_eq!(moved, Step::To(v("3.0.0"), vec!["OLD2".to_string()]));
    }

    #[test]
    fn a_prerelease_fix_is_no_place_for_a_repo_on_releases() {
        let advisories = [
            advisory("LATER", "2.0.0", Some("3.0.0-rc.1")),
            advisory("LATER2", "2.0.0", Some("3.0.0")),
        ];
        let moved = run(&advisories, "1.0.0", "2.0.0");
        let ids = vec!["LATER".to_string(), "LATER2".to_string()];
        assert_eq!(moved, Step::To(v("3.0.0"), ids));
    }

    fn target(text: &str) -> Target {
        Target {
            text: text.to_string(),
            semver: v(text),
        }
    }

    fn edit(from: &str, to: &str) -> Edit {
        Edit {
            campaign: "old".to_string(),
            repo: "r".to_string(),
            ecosystem: Ecosystem::Npm,
            package: "p".to_string(),
            from: vec![from.to_string()],
            to: to.to_string(),
            advisories: vec!["OLD".to_string()],
            breaking: false,
            strategy: Strategy::LockBump,
            reason: None,
            risk: Some(Risk::Low),
            risk_reasons: vec![],
        }
    }

    #[test]
    fn prereleases_are_told_apart_in_every_spelling() {
        for text in [
            "1.0.0-rc.1",
            "1.0rc1",
            "1.0.0.beta2",
            "1.0-M1",
            "2.0.dev3",
            "1.0-SNAPSHOT",
        ] {
            assert!(prerelease(text), "{text}");
        }
        for text in [
            "1.2.3",
            "3.41.2.2",
            "1.1.10.9",
            "5.0.Final",
            "31.1-jre",
            "1.0.post1",
        ] {
            assert!(!prerelease(text), "{text}");
        }
    }

    #[test]
    fn a_fourth_number_is_a_release() {
        use fleetreach_maven::{parse_maven_version as maven, Advisory};
        let version = |text| maven(text).unwrap();
        let advisories: [Advisory; 1] = [osv::Advisory {
            id: "OLD".to_string(),
            aliases: Vec::new(),
            summary: None,
            severity: fleetreach_core::Severity::High,
            cvss_score: None,
            cvss_vector: None,
            ranges: vec![ParsedRange {
                matchable: true,
                events: vec![ParsedEvent {
                    introduced: None,
                    fixed: Some(version("3.41.2.2")),
                    last_affected: None,
                }],
            }],
            versions: Vec::new(),
        }];
        // The report's SemVer form of 3.41.2.2 is 3.41.2, which is still affected.
        let targeted = ["OLD".to_string()];
        let moved = step(
            &advisories,
            &[version("3.32.3.3")],
            &version("3.41.2"),
            &targeted,
        );
        assert_eq!(
            moved,
            Step::To(version("3.41.2.2"), vec!["OLD".to_string()])
        );
    }

    #[test]
    fn a_step_to_a_new_major_needs_allow_breaking() {
        let moved = || Step::To(target("2.0.0"), vec!["LATER".to_string()]);

        let mut held = edit("1.0.0", "1.5.0");
        assert!(settle(&mut held, moved(), false));
        assert_eq!(held.strategy, Strategy::Blocked);
        assert!(held.breaking);
        assert_eq!(held.risk, Some(Risk::High));
        let reason = held.reason.unwrap();
        assert!(reason.contains("1.5.0 has LATER"), "{reason}");
        assert!(reason.contains("--allow-breaking"), "{reason}");

        let mut allowed = edit("1.0.0", "1.5.0");
        assert!(settle(&mut allowed, moved(), true));
        assert_eq!(allowed.strategy, Strategy::LockBump);
        assert_eq!(allowed.to, "2.0.0");
        assert_ne!(allowed.campaign, "old");
    }

    #[test]
    fn repos_moved_to_one_target_share_a_campaign() {
        let moved = || Step::To(target("1.6.0"), vec!["LATER".to_string()]);
        let (mut one, mut two) = (edit("1.0.0", "1.5.0"), edit("1.1.0", "1.5.0"));
        two.repo = "s".to_string();
        settle(&mut one, moved(), false);
        settle(&mut two, moved(), false);
        assert_eq!(one.campaign, two.campaign);
        assert_eq!(one.strategy, Strategy::LockBump);
        assert_eq!(one.risk_reasons, ["1.5.0 has LATER"]);
    }

    #[test]
    fn a_stuck_target_is_blocked_with_the_reason() {
        let mut stuck = edit("1.0.0", "1.5.0");
        assert!(settle(
            &mut stuck,
            Step::Stuck(vec!["LATER".to_string()]),
            true
        ));
        assert_eq!(stuck.strategy, Strategy::Blocked);
        assert_eq!(
            stuck.reason.unwrap(),
            "1.5.0 has LATER, with no fix published"
        );
    }
}
