//! Tier-C offline fallback: scan a Go module **without** a toolchain or govulncheck,
//! by reading the module set from `go.mod` and matching versions against an OSV
//! vulnerability DB mirror (the same `vuln.go.dev`-format DB govulncheck consumes).
//!
//! This is the lowest-fidelity tier: module + version matching only, so it has no
//! call-graph evidence and every finding is `Unknown` reachability (consistent with
//! the feeder contract: never `NotReachable`). The trade is that it is **safe by
//! construction** — it parses files and computes version comparisons, never compiling
//! or running the module, so unlike govulncheck it needs **no untrusted-build consent
//! and no sandbox**. It is the honest answer to "I have no Go toolchain installed but
//! still want a fleet-wide module-level audit", replacing what would otherwise be an
//! errored gap.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fleetreach_core::osv::{self, Match};
use fleetreach_core::semver::{Version, VersionReq};
use fleetreach_core::{
    Ecosystem, Occurrence, ReachVerdict, Reachability, RepoId, Severity, VulnFinding,
};
use serde::Deserialize;

use crate::{
    dep_kind, direct_set, go_vuln_url, parse_go_version, render_symbols, replace_directives,
    required_modules, GoError, Replace,
};

/// The filesystem path of an offline (`file://`) DB mirror, or `None` for anything
/// else (an `http(s)://` DB is useless to the toolchain-free matcher). `file:///abs`
/// → `/abs`; `file://rel` → `rel`.
///
/// # Examples
///
/// ```
/// use fleetreach_go::offline_db_path;
/// use std::path::PathBuf;
///
/// assert_eq!(offline_db_path("file:///opt/vulndb"), Some(PathBuf::from("/opt/vulndb")));
/// assert_eq!(offline_db_path("https://vuln.go.dev"), None);
/// ```
pub fn offline_db_path(db: &str) -> Option<PathBuf> {
    let rest = db.strip_prefix("file://")?;
    // `file:///abs` leaves a leading `/`; `file://./rel` leaves `./rel`.
    Some(PathBuf::from(rest))
}

/// The vuln.go.dev mirror loaded **once** and held in memory: the module index plus
/// every advisory it references. Built by [`GoDb::load`] and shared read-only across the
/// fleet walk, so the 434 KB `modules.json` index and the matched advisory files are
/// parsed a single time rather than re-read and re-parsed per repo (profiling a 3k-repo
/// Go fleet showed the per-repo re-parse dominated the scan — the same load-once win the
/// npm feeder has).
#[derive(Debug)]
pub struct GoDb {
    /// Module path → the advisory ids that affect it (from `index/modules.json`).
    index: BTreeMap<String, Vec<String>>,
    /// Advisory id → its OSV record. Holds exactly the advisories the index references;
    /// an id whose file is absent is simply omitted (it can never match).
    advisories: BTreeMap<String, Osv>,
}

impl GoDb {
    /// Load the mirror rooted at `db_root`: parse `index/modules.json`, then read and
    /// parse every advisory it references from `ID/<id>.json`.
    ///
    /// # Errors
    ///
    /// Returns [`GoError::Db`] if the index or a referenced advisory file cannot be read
    /// or parsed — failing closed, so a broken mirror is an honest gap rather than a
    /// false-clean scan. An advisory file that is simply *absent* is skipped (it cannot
    /// match anything); only a present-but-malformed file is an error.
    pub fn load(db_root: &Path) -> Result<GoDb, GoError> {
        let index = load_module_index(db_root)?;
        let mut advisories: BTreeMap<String, Osv> = BTreeMap::new();
        for id in index.values().flatten() {
            if advisories.contains_key(id) || !is_safe_advisory_id(id) {
                continue;
            }
            let path = db_root.join("ID").join(format!("{id}.json"));
            // Absent file → the advisory just is not in this mirror (skip). A present file
            // that fails to parse is a corrupt mirror → hard error, never a silent drop.
            if let Ok(body) = std::fs::read_to_string(&path) {
                let osv: Osv = serde_json::from_str(&body).map_err(|e| GoError::db(&path, e))?;
                advisories.insert(id.clone(), osv);
            }
        }
        Ok(GoDb { index, advisories })
    }
}

/// Scan the Go module at `module_dir` against the preloaded [`GoDb`], without a
/// toolchain. Reads `go.mod` for the module set, matches each module version against the
/// DB's SEMVER ranges, and emits a module-level [`VulnFinding`] per affected module.
/// Output is sorted by advisory id for determinism.
///
/// # Errors
///
/// Returns [`GoError::Db`] if `go.mod` cannot be read — failing closed, so an unreadable
/// manifest is an honest gap rather than a false-clean scan. (Advisory I/O happened once
/// in [`GoDb::load`].)
pub fn scan_offline(
    module_dir: &Path,
    db: &GoDb,
    repo: &RepoId,
) -> Result<Vec<VulnFinding>, GoError> {
    let go_mod_path = module_dir.join("go.mod");
    let go_mod = std::fs::read_to_string(&go_mod_path).map_err(|e| GoError::db(go_mod_path, e))?;
    // Parse go.mod once: the full require list drives matching, the direct set drives
    // direct/transitive classification.
    let required = required_modules(&go_mod);
    let direct = direct_set(&required, &go_mod);
    let replaces = replace_directives(&go_mod);

    let mut out: Vec<VulnFinding> = Vec::new();
    for module in &required {
        // Honor `replace`: match the module's *effective* (path, version), so a require
        // pinned to a fixed version (or to a fork) is not a false positive at its
        // original version. A local-path replacement (`=> ../local`) is unmatchable
        // against the published DB and is skipped.
        let Some((eff_path, eff_version)) = apply_replace(&replaces, &module.path, &module.version)
        else {
            continue;
        };
        // A require with an indeterminate version cannot be matched against the OSV
        // ranges: a branch ref (`master`/`latest`/a fork branch), a non-canonical
        // `v1.0`, or a missing version. A real-world corpus shows these are rare
        // but real. Surface each as a gap rather
        // than silently `continue`ing, which would report a possibly-vulnerable module
        // clean — the matcher's contract is to fail loud on what it cannot assess.
        let Some(installed) = parse_go_version(&eff_version) else {
            eprintln!(
                "warning: Go module {} is pinned to an unparseable version {eff_version:?}; \
                 cannot check it against the vulnerability DB (NOT reported clean)",
                module.path
            );
            continue;
        };
        let Some(candidate_ids) = db.index.get(&eff_path) else {
            continue;
        };
        for id in candidate_ids {
            let Some(osv) = db.advisories.get(id) else {
                continue;
            };
            // Match on the effective module; classify direct/transitive on the declared one.
            if let Some(finding) =
                match_module(osv, &eff_path, &installed, &module.path, &direct, repo)
            {
                out.push(finding);
            }
        }
    }
    out.sort_by(|a, b| a.advisory_id.cmp(&b.advisory_id));
    out.dedup_by(|a, b| a.advisory_id == b.advisory_id);
    Ok(out)
}

/// Build a finding if `osv` lists `module` (the *effective* module path after any
/// `replace`) as affected at `installed`. `declared_path` is the original require path,
/// used only to classify direct vs. transitive.
fn match_module(
    osv: &Osv,
    module: &str,
    installed: &Version,
    declared_path: &str,
    direct: &std::collections::BTreeSet<String>,
    repo: &RepoId,
) -> Option<VulnFinding> {
    let affected = osv.affected.iter().find(|a| {
        a.package.ecosystem.as_deref() == Some("Go") && a.package.name.as_deref() == Some(module)
    })?;

    let Match::Affected { fixed } = affected_fixed(installed, &affected.ranges) else {
        return None;
    };
    let patched: Vec<VersionReq> = fixed
        .as_ref()
        .and_then(|f| VersionReq::parse(&format!(">={f}")).ok())
        .into_iter()
        .collect();

    let dependency_kind = dep_kind(direct, declared_path);

    Some(VulnFinding {
        advisory_id: osv.id.clone(),
        aliases: osv.aliases.clone().unwrap_or_default(),
        ecosystem: Ecosystem::Go,
        title: osv.summary.clone().unwrap_or_else(|| osv.id.clone()),
        severity: Severity::Unknown,
        cvss_score: None,
        url: Some(go_vuln_url(&osv.id)),
        occurrences: vec![Occurrence::InRepo {
            repo: repo.clone(),
            package: module.to_string(),
            installed: installed.clone(),
            patched,
            dependency_kind,
            dependency_path: Vec::new(),
            active: None,
            source: Default::default(),
        }],
        affected_functions: affected.symbols(module),
        reachable: None,
        // Module-level only: no call analysis, so Unknown (never NotReachable). The
        // engine/config tag makes the lower fidelity explicit in the report.
        reachability: Some(Reachability {
            verdict: ReachVerdict::Unknown {
                reason: "module-level scan (no toolchain): version match only".into(),
            },
            config: "module-level".to_string(),
            engine: "fleetreach-tier-c".to_string(),
            targets: Vec::new(),
            witness: None,
        }),
        exploit: Default::default(),
    })
}

/// Resolve a module to its effective `(path, version)` after `replace` directives, or
/// `None` if it was replaced by a local filesystem path (`=> ../local`, which has no
/// version and is not a published artifact, so it cannot be matched against the DB).
fn apply_replace(replaces: &[Replace], path: &str, version: &str) -> Option<(String, String)> {
    for r in replaces {
        if r.from_path == path && r.from_version.as_deref().is_none_or(|v| v == version) {
            // A `to` with a version is a module replacement; without one it is a local
            // path → unmatchable (return None to skip).
            return r
                .to_version
                .as_ref()
                .map(|v| (r.to_path.clone(), v.clone()));
        }
    }
    Some((path.to_string(), version.to_string()))
}

/// Evaluate the OSV SEMVER ranges for `version` with Go's bounds (the shared
/// [`osv::affected_fixed`] skeleton + Go's [`parse_bound`] and the pseudo-version-aware
/// [`at_or_after_introduced`]). The serde range shape is mapped into the shared
/// [`osv::Range`] form the matcher consumes.
fn affected_fixed(version: &Version, ranges: &[Range]) -> Match<Version> {
    let ranges: Vec<osv::Range> = ranges
        .iter()
        .map(|r| osv::Range {
            matchable: r.kind.as_deref() == Some("SEMVER"),
            events: r
                .events
                .iter()
                .map(|e| osv::Event {
                    introduced: e.introduced.clone(),
                    fixed: e.fixed.clone(),
                    last_affected: e.last_affected.clone(),
                })
                .collect(),
        })
        .collect();
    osv::affected_fixed(version, &ranges, parse_bound, at_or_after_introduced)
}

/// Parse an OSV range bound. The introduced bound is often the literal `"0"`, which
/// is not valid SemVer, so map it to `0.0.0`; everything else goes through the Go
/// version adapter.
fn parse_bound(raw: &str) -> Option<Version> {
    if raw == "0" {
        return Some(Version::new(0, 0, 0));
    }
    parse_go_version(raw)
}

/// Whether `version` is at or after an `introduced` lower bound.
///
/// The pre-release tag needs case-split handling, because Go pseudo-versions
/// (`v0.0.0-20210101000000-abc`) parse as SemVer *pre-releases*, which order strictly
/// *below* their release (`0.0.0-x < 0.0.0`):
///
/// * **Bound is a plain release** (the near-universal `introduced: "0"` → `0.0.0`, or a
///   real tag like `1.2.0`): compare the **release tuple only**, ignoring `version`'s
///   pre-release tag. A plain `version >= bound` would call every pseudo-versioned
///   module *not-affected* against `introduced: "0"` and silently miss the vuln. The
///   release-tuple compare keeps the lower bound inclusive of pseudo-versions, erring
///   toward "affected" — the correct bias for a security tool.
///
/// * **Bound is itself a pseudo-version / pre-release** (`introduced:
///   0.0.0-20220524220425-…`): every `0.0.0-*` pseudo shares the *same* release tuple
///   `(0,0,0)`, so dropping the pre-release would throw away the timeline ordering and
///   flag versions *earlier* than the bound. Compare the **full** version so the
///   pre-release ordinal decides. (Observed against govulncheck: x/net
///   `…20210520…` (2021) wrongly matched `introduced …20220524…` (2022) under the
///   tuple-only compare — a false positive govulncheck did not make.)
///
/// The upper (`fixed`/`last_affected`) bounds always keep full SemVer ordering, so a
/// real fix still clears the finding.
fn at_or_after_introduced(version: &Version, bound: &Version) -> bool {
    if bound.pre.is_empty() {
        (version.major, version.minor, version.patch) >= (bound.major, bound.minor, bound.patch)
    } else {
        version >= bound
    }
}

/// `index/modules.json` → `module path → [advisory id]`. This is the cheap lookup
/// that bounds how many per-advisory files we read to the modules actually present.
fn load_module_index(db_root: &Path) -> Result<BTreeMap<String, Vec<String>>, GoError> {
    let path = db_root.join("index").join("modules.json");
    let body = std::fs::read_to_string(&path).map_err(|e| GoError::db(&path, e))?;
    let modules: Vec<ModuleIndex> =
        serde_json::from_str(&body).map_err(|e| GoError::db(&path, e))?;
    Ok(modules
        .into_iter()
        .map(|m| (m.path, m.vulns.into_iter().map(|v| v.id).collect()))
        .collect())
}

/// A flat advisory token safe to use as a path component: non-empty, only
/// `[A-Za-z0-9._-]`, and never `..`. Rejects path separators, absolute components,
/// and traversal, so a poisoned DB index cannot escape the `ID/` directory.
fn is_safe_advisory_id(id: &str) -> bool {
    !id.is_empty()
        && id != ".."
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

// --- OSV schema (the subset the matcher reads). ---

#[derive(Debug, Deserialize)]
struct ModuleIndex {
    path: String,
    #[serde(default)]
    vulns: Vec<VulnRef>,
}

#[derive(Debug, Deserialize)]
struct VulnRef {
    id: String,
}

#[derive(Debug, Deserialize)]
struct Osv {
    id: String,
    aliases: Option<Vec<String>>,
    summary: Option<String>,
    #[serde(default)]
    affected: Vec<Affected>,
}

#[derive(Debug, Deserialize)]
struct Affected {
    #[serde(default)]
    package: Package,
    #[serde(default)]
    ranges: Vec<Range>,
    ecosystem_specific: Option<EcoSpecific>,
}

impl Affected {
    /// The vulnerable symbols this advisory names for `module`, as `path.Symbol`,
    /// for the `affects fn` display (mirrors the govulncheck path).
    fn symbols(&self, module: &str) -> Vec<String> {
        render_symbols(
            self.ecosystem_specific
                .as_ref()
                .and_then(|e| e.imports.as_ref())
                .into_iter()
                .flatten()
                .map(|i| {
                    (
                        i.path.as_deref().unwrap_or(module),
                        i.symbols.as_deref().unwrap_or_default(),
                    )
                }),
        )
    }
}

#[derive(Debug, Deserialize, Default)]
struct Package {
    name: Option<String>,
    ecosystem: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Range {
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    events: Vec<Event>,
}

#[derive(Debug, Deserialize)]
struct Event {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EcoSpecific {
    imports: Option<Vec<Import>>,
}

#[derive(Debug, Deserialize)]
struct Import {
    path: Option<String>,
    symbols: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn ranges(events: &[(&str, &str)]) -> Vec<Range> {
        vec![Range {
            kind: Some("SEMVER".into()),
            events: events
                .iter()
                .map(|(k, v)| Event {
                    introduced: (*k == "introduced").then(|| v.to_string()),
                    fixed: (*k == "fixed").then(|| v.to_string()),
                    last_affected: (*k == "last_affected").then(|| v.to_string()),
                })
                .collect(),
        }]
    }

    fn v(s: &str) -> Version {
        parse_go_version(s).unwrap()
    }

    /// `Match::Affected` with a named fix, for concise assertions.
    fn affected(fix: &str) -> Match<Version> {
        Match::Affected {
            fixed: Some(v(fix)),
        }
    }

    #[test]
    fn affected_below_fix_with_patch_reported() {
        let r = ranges(&[("introduced", "0"), ("fixed", "0.3.7")]);
        // 0.3.0 < 0.3.7 -> affected, fix is 0.3.7.
        assert_eq!(affected_fixed(&v("0.3.0"), &r), affected("0.3.7"));
    }

    #[test]
    fn not_affected_at_or_above_fix() {
        let r = ranges(&[("introduced", "0"), ("fixed", "0.3.7")]);
        assert_eq!(affected_fixed(&v("0.3.7"), &r), Match::NotAffected);
        assert_eq!(affected_fixed(&v("1.0.0"), &r), Match::NotAffected);
    }

    #[test]
    fn introduced_above_zero_excludes_older() {
        // Affected only in [1.2.0, 1.2.5).
        let r = ranges(&[("introduced", "1.2.0"), ("fixed", "1.2.5")]);
        assert_eq!(
            affected_fixed(&v("1.1.0"), &r),
            Match::NotAffected,
            "before introduced"
        );
        assert_eq!(
            affected_fixed(&v("1.2.3"), &r),
            affected("1.2.5"),
            "inside the window"
        );
    }

    #[test]
    fn multi_interval_picks_the_right_fix() {
        // Two windows: [0,1.0.1) and [2.0.0,2.0.3).
        let r = ranges(&[
            ("introduced", "0"),
            ("fixed", "1.0.1"),
            ("introduced", "2.0.0"),
            ("fixed", "2.0.3"),
        ]);
        assert_eq!(affected_fixed(&v("0.9.0"), &r), affected("1.0.1"));
        assert_eq!(
            affected_fixed(&v("1.5.0"), &r),
            Match::NotAffected,
            "between windows"
        );
        assert_eq!(affected_fixed(&v("2.0.1"), &r), affected("2.0.3"));
    }

    #[test]
    fn last_affected_without_fix() {
        let r = ranges(&[("introduced", "1.0.0"), ("last_affected", "1.4.0")]);
        assert_eq!(
            affected_fixed(&v("1.3.0"), &r),
            Match::Affected { fixed: None },
            "affected, no fix named"
        );
        assert_eq!(affected_fixed(&v("1.5.0"), &r), Match::NotAffected);
    }

    #[test]
    fn pseudo_versions_and_prereleases_are_matched_not_silently_clean() {
        // Soundness regression: a Go pseudo-version is a SemVer pre-release ordering
        // below 0.0.0, so a naive `>= introduced "0"` would report it CLEAN and miss
        // the vuln. It must be flagged.
        let r = ranges(&[("introduced", "0"), ("fixed", "1.2.5")]);
        assert_eq!(
            affected_fixed(&v("v0.0.0-20210101000000-abcdef"), &r),
            affected("1.2.5"),
            "pseudo-version in [0,1.2.5) must be flagged"
        );
        // A pre-release of the introduced version is included (fail-loud bias).
        let r2 = ranges(&[("introduced", "1.2.0"), ("fixed", "1.2.5")]);
        assert_eq!(
            affected_fixed(&v("v1.2.0-rc.1"), &r2),
            affected("1.2.5"),
            "1.2.0-rc.1 is at/after introduced 1.2.0"
        );
        // The real fix still clears it (upper bound keeps full SemVer ordering).
        assert_eq!(affected_fixed(&v("1.2.5"), &r2), Match::NotAffected);
    }

    #[test]
    fn pseudo_version_introduced_bound_respects_the_timeline() {
        // Differential regression vs govulncheck: when the
        // `introduced` bound is itself a pseudo-version, every 0.0.0-* pseudo shares the
        // release tuple (0,0,0), so the pre-release ordinal (the commit timestamp) must
        // decide. The real false positive Tier-C made and govulncheck did not:
        // golang.org/x/net …20210520… (2021) matched introduced …20220524… (2022).
        let r = ranges(&[
            ("introduced", "0.0.0-20220524220425-1d687d428aca"),
            ("fixed", "0.1.1-0.20221104162952-702349b0e862"),
        ]);
        // 2021 pseudo is BEFORE the 2022 introduced bound -> NOT affected.
        assert_eq!(
            affected_fixed(&v("v0.0.0-20210520170846-37e1c6afe023"), &r),
            Match::NotAffected,
            "a pseudo-version before the introduced pseudo must not be flagged"
        );
        // A pseudo AFTER introduced and before the fix is affected.
        assert_eq!(
            affected_fixed(&v("v0.0.0-20220812000000-abcdef000000"), &r),
            affected("0.1.1-0.20221104162952-702349b0e862"),
            "a pseudo inside the affected window is flagged"
        );
        // The plain `introduced: "0"` case is unchanged: pseudo-versions stay inclusive.
        let zero = ranges(&[("introduced", "0"), ("fixed", "1.2.5")]);
        assert_eq!(
            affected_fixed(&v("v0.0.0-20210520170846-37e1c6afe023"), &zero),
            affected("1.2.5"),
            "introduced \"0\" keeps every pseudo-version inclusive (no regression)"
        );
    }

    #[test]
    fn malformed_introduced_bound_fails_loud_not_clean() {
        // Soundness: a poisoned/malformed advisory must never read CLEAN.
        // Unparseable `introduced` → treat as affected (fail loud).
        let bad = ranges(&[("introduced", "garbage"), ("fixed", "99.0.0")]);
        assert_eq!(
            affected_fixed(&v("1.0.0"), &bad),
            affected("99.0.0"),
            "unparseable introduced must be affected, not silently clean"
        );
        // A SEMVER range with NO introduced event is introduced-at-0 (OSV convention).
        let no_intro = vec![Range {
            kind: Some("SEMVER".into()),
            events: vec![Event {
                introduced: None,
                fixed: Some("2.0.0".into()),
                last_affected: None,
            }],
        }];
        assert_eq!(affected_fixed(&v("1.5.0"), &no_intro), affected("2.0.0"));
        assert_eq!(
            affected_fixed(&v("2.0.0"), &no_intro),
            Match::NotAffected,
            "at/above fix is clean"
        );
    }

    #[test]
    fn rejects_unsafe_advisory_ids_for_path_safety() {
        assert!(is_safe_advisory_id("GO-2021-0113"));
        assert!(is_safe_advisory_id("CVE-2021-38561"));
        assert!(is_safe_advisory_id("GHSA-ppp9-7jff-5vj2"));
        // Traversal / absolute / separators / empty are rejected.
        assert!(!is_safe_advisory_id("../../etc/hosts"));
        assert!(!is_safe_advisory_id("/etc/hosts"));
        assert!(!is_safe_advisory_id(".."));
        assert!(!is_safe_advisory_id("a/b"));
        assert!(!is_safe_advisory_id("a\\b"));
        assert!(!is_safe_advisory_id(""));
    }

    #[test]
    fn offline_db_path_only_file_urls() {
        assert_eq!(
            offline_db_path("file:///opt/vulndb"),
            Some(PathBuf::from("/opt/vulndb"))
        );
        assert_eq!(offline_db_path("https://vuln.go.dev"), None);
        assert_eq!(offline_db_path("/bare/path"), None);
    }
}
