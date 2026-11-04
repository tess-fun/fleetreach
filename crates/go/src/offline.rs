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

use fleetreach_core::osv::{
    self, cvss_vector_in, severity_from, DatabaseSpecific, Match, SeverityEntry,
};
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
    /// Lowercased module path → the module paths in `index` it may stand for.
    folded: BTreeMap<String, Vec<String>>,
    /// Advisory id → how bad it is, for those any record rates.
    ratings: BTreeMap<String, Rating>,
}

/// How bad an advisory is.
#[derive(Debug, Clone, PartialEq)]
struct Rating {
    severity: Severity,
    score: Option<f32>,
    vector: Option<String>,
}

/// Rates every advisory. The Go team's `GO-` records carry no severity, so each takes GitHub's
/// from the records sharing an id with it, and where those disagree the worst of them: a finding
/// no record rates stays `Unknown`, which always trips a gate.
fn ratings(advisories: &BTreeMap<String, Osv>) -> BTreeMap<String, Rating> {
    let own: BTreeMap<&str, Rating> = advisories
        .iter()
        .filter_map(|(id, osv)| {
            let (severity, score) = severity_from(&osv.severity, osv.database_specific.as_ref());
            let vector = cvss_vector_in(&osv.severity);
            (severity != Severity::Unknown).then_some((
                id.as_str(),
                Rating {
                    severity,
                    score,
                    vector,
                },
            ))
        })
        .collect();
    let mut by_name: BTreeMap<&str, Vec<&Rating>> = BTreeMap::new();
    for (id, rating) in &own {
        let aliases = advisories[*id].aliases.iter().flatten();
        for name in aliases.map(String::as_str).chain([*id]) {
            by_name.entry(name).or_default().push(rating);
        }
    }
    let mut out = BTreeMap::new();
    for (id, osv) in advisories {
        if let Some(rating) = own.get(id.as_str()) {
            out.insert(id.clone(), rating.clone());
            continue;
        }
        let aliases = osv.aliases.iter().flatten().map(String::as_str);
        let twins = aliases.chain([id.as_str()]).filter_map(|n| by_name.get(n));
        let worst = twins.flatten().max_by(|a, b| {
            let score = |r: &Rating| r.score.unwrap_or(0.0);
            a.severity
                .cmp(&b.severity)
                .then_with(|| score(a).total_cmp(&score(b)))
                .then_with(|| b.vector.cmp(&a.vector))
        });
        if let Some(rating) = worst {
            out.insert(id.clone(), (*rating).clone());
        }
    }
    out
}

/// Indexes the module paths of `index` by their lowercase form.
fn folded(index: &BTreeMap<String, Vec<String>>) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for module in index.keys() {
        out.entry(module.to_lowercase())
            .or_default()
            .push(module.clone());
    }
    out
}

impl GoDb {
    /// The module paths a package URL's name may stand for. Module paths are case-sensitive,
    /// but Trivy lowercases its purls, so a lowercase name is every module it could have been:
    /// `github.com/azure/go-ntlmssp` must still reach `github.com/Azure/go-ntlmssp`'s
    /// advisories. A name with capitals kept them, and stands for itself.
    #[must_use]
    pub fn modules_named(&self, name: &str) -> Vec<String> {
        if name.chars().any(char::is_uppercase) {
            return vec![name.to_string()];
        }
        match self.folded.get(name) {
            Some(modules) => modules.clone(),
            None => vec![name.to_string()],
        }
    }

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
        // A missing path keeps the mirror's error (it names `index/modules.json`).
        if db_root.is_file() || (db_root.is_dir() && !db_root.join("index").exists()) {
            return Self::load_osv_export(db_root);
        }
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
                // A withdrawn advisory is a retraction and must never match.
                if osv.withdrawn.is_none() {
                    advisories.insert(id.clone(), osv);
                }
            }
        }
        let folded = folded(&index);
        let ratings = ratings(&advisories);
        Ok(GoDb {
            index,
            advisories,
            folded,
            ratings,
        })
    }
}

impl GoDb {
    /// Load the osv.dev `Go` export: its `all.zip`, or the directory it unzips to. Beside what
    /// vuln.go.dev serves it holds GitHub's records, which reach further: some have no `GO-`
    /// twin, and some of a twin's ranges stop short (GHSA-4vq8-7jfc-9cvp for
    /// `github.com/docker/docker`). Twins that both match collapse into one finding. Withdrawn
    /// records never match.
    ///
    /// # Errors
    ///
    /// Returns [`GoError::Db`] if the export cannot be read or a record is not valid JSON,
    /// failing closed.
    pub fn load_osv_export(root: &Path) -> Result<GoDb, GoError> {
        let mut bodies: Vec<String> = Vec::new();
        if root.is_dir() {
            let mut paths: Vec<PathBuf> = std::fs::read_dir(root)
                .map_err(|e| GoError::db(root, e))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
                .collect();
            paths.sort();
            for path in paths {
                bodies.push(std::fs::read_to_string(&path).map_err(|e| GoError::db(&path, e))?);
            }
        } else {
            use std::io::Read;
            let file = std::fs::File::open(root).map_err(|e| GoError::db(root, e))?;
            let mut archive = zip::ZipArchive::new(file).map_err(|e| GoError::db(root, e))?;
            for i in 0..archive.len() {
                let mut entry = archive.by_index(i).map_err(|e| GoError::db(root, e))?;
                let name = entry.name().map_err(|e| GoError::db(root, e))?;
                if !name.ends_with(".json") {
                    continue;
                }
                let mut body = String::new();
                entry
                    .read_to_string(&mut body)
                    .map_err(|e| GoError::db(root, e))?;
                bodies.push(body);
            }
        }
        if bodies.is_empty() {
            return Err(GoError::Db {
                path: root.to_path_buf(),
                source: crate::DbError::Empty,
            });
        }
        let mut index: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut advisories: BTreeMap<String, Osv> = BTreeMap::new();
        for body in bodies {
            let osv: Osv = serde_json::from_str(&body).map_err(|e| GoError::db(root, e))?;
            if osv.withdrawn.is_some() {
                continue;
            }
            for affected in &osv.affected {
                let (Some(name), Some("Go")) = (
                    &affected.package.name,
                    affected.package.ecosystem.as_deref(),
                ) else {
                    continue;
                };
                let ids = index.entry(name.clone()).or_default();
                if !ids.contains(&osv.id) {
                    ids.push(osv.id.clone());
                }
            }
            advisories.insert(osv.id.clone(), osv);
        }
        let folded = folded(&index);
        let ratings = ratings(&advisories);
        Ok(GoDb {
            index,
            advisories,
            folded,
            ratings,
        })
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
                match_module(db, osv, &eff_path, &installed, &module.path, &direct, repo)
            {
                out.push(finding);
            }
        }
    }
    // One finding per (advisory, module, version): an advisory naming several modules (pgx/v4
    // and pgproto3/v2) needs each of them fixed.
    osv::sort_dedup_findings(&mut out);
    Ok(out)
}

/// Match the modules linked into built binaries: `(binary path, module, version)`. There is
/// no manifest to read, so every module is transitive, and the path says which binary holds it.
/// Returns the findings and how many versions could not be read.
#[must_use]
pub fn scan_built(
    modules: &[(String, String, String)],
    db: &GoDb,
    repo: &RepoId,
) -> (Vec<VulnFinding>, u32) {
    let direct = std::collections::BTreeSet::new();
    let mut out: Vec<VulnFinding> = Vec::new();
    let mut unreadable = 0;
    for (binary, module, version) in modules {
        let Some(installed) = parse_go_version(version) else {
            unreadable += 1;
            continue;
        };
        for id in db.index.get(module).into_iter().flatten() {
            let Some(osv) = db.advisories.get(id) else {
                continue;
            };
            if let Some(mut finding) =
                match_module(db, osv, module, &installed, module, &direct, repo)
            {
                for occurrence in &mut finding.occurrences {
                    if let Occurrence::InRepo {
                        dependency_path, ..
                    } = occurrence
                    {
                        *dependency_path = vec![binary.clone()];
                    }
                }
                out.push(finding);
            }
        }
    }
    osv::sort_dedup_findings(&mut out);
    (out, unreadable)
}

/// Build a finding if `osv` lists `module` (the *effective* module path after any
/// `replace`) as affected at `installed`. `declared_path` is the original require path,
/// used only to classify direct vs. transitive.
fn match_module(
    db: &GoDb,
    osv: &Osv,
    module: &str,
    installed: &Version,
    declared_path: &str,
    direct: &std::collections::BTreeSet<String>,
    repo: &RepoId,
) -> Option<VulnFinding> {
    // A record can list a module in several entries, one per release line (go-redis/v9 in
    // GO-2025-3540): the version is affected when any of them says so.
    let entries: Vec<&Affected> = osv
        .affected
        .iter()
        .filter(|a| {
            a.package.ecosystem.as_deref() == Some("Go")
                && a.package.name.as_deref() == Some(module)
        })
        .collect();
    if entries.is_empty() {
        return None;
    }
    let ranges: Vec<osv::Range> = entries.iter().flat_map(|a| osv_ranges(&a.ranges)).collect();

    let bare = compatible(installed.clone());
    let Match::Affected { .. } = affected_fixed(&bare, &ranges) else {
        return None;
    };
    // Every safe interval above the installed version, so a fix that a later release branch
    // re-breaks (grpc GO-2026-6443) is never taken for safe.
    let parsed: Vec<osv::ParsedRange<Version>> = ranges
        .iter()
        .map(|r| osv::parse_range(r, parse_bound))
        .collect();
    let patched: Vec<VersionReq> =
        osv::patched_reqs(&osv::safe_intervals(&bare, &parsed), ToString::to_string);

    let dependency_kind = dep_kind(direct, declared_path);
    let rating = db.ratings.get(&osv.id);

    Some(VulnFinding {
        advisory_id: osv.id.clone(),
        aliases: osv.aliases.clone().unwrap_or_default(),
        ecosystem: Ecosystem::Go,
        title: osv.summary.clone().unwrap_or_else(|| osv.id.clone()),
        severity: rating.map_or(Severity::Unknown, |r| r.severity),
        cvss_score: rating.and_then(|r| r.score),
        cvss_vector: rating.and_then(|r| r.vector.clone()),
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
            scope: Default::default(),
            layer: None,
        }],
        affected_functions: {
            let mut symbols: Vec<String> = entries.iter().flat_map(|a| a.symbols(module)).collect();
            symbols.sort();
            symbols.dedup();
            symbols
        },
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
            import_site: None,
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
/// [`at_or_after_introduced`]), over ranges already in the shared [`osv::Range`] form (see
/// [`osv_ranges`]).
fn affected_fixed(version: &Version, ranges: &[osv::Range]) -> Match<Version> {
    osv::affected_fixed(version, ranges, parse_bound, at_or_after_introduced)
}

/// The advisory's ranges in the shared shape; only `SEMVER` ranges are evaluated.
fn osv_ranges(ranges: &[Range]) -> Vec<osv::Range> {
    ranges
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
        .collect()
}

/// Parse an OSV range bound. The introduced bound is often the literal `"0"`, which
/// is not valid SemVer, so map it to `0.0.0`; everything else goes through the Go
/// version adapter.
fn parse_bound(raw: &str) -> Option<Version> {
    if raw == "0" {
        return Some(Version::new(0, 0, 0));
    }
    parse_go_version(raw).map(compatible)
}

/// `version` without `+incompatible`, which marks a module with no `go.mod` and not a different
/// release: `v2.8.3+incompatible` is the `2.8.3` a `last_affected` bound names. Other build
/// metadata stays, because Grafana's `11.2.2+security-01` is a later release than `11.2.2`.
fn compatible(mut version: Version) -> Version {
    if version.build.as_str() == "incompatible" {
        version.build = fleetreach_core::semver::BuildMetadata::EMPTY;
    }
    version
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
///   toward "affected" — the correct bias for a security tool. (It also flags a
///   pre-release of the introducing release, such as etcd `3.5.0-alpha.0` against
///   `introduced: 3.5.0`, which govulncheck does not: a deliberate extra alert rather
///   than a possible miss.)
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
    withdrawn: Option<String>,
    #[serde(default)]
    affected: Vec<Affected>,
    #[serde(default)]
    severity: Vec<SeverityEntry>,
    database_specific: Option<DatabaseSpecific>,
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

    fn record(id: &str, aliases: &[&str], band: Option<&str>, vector: Option<&str>) -> Osv {
        let text = serde_json::json!({
            "id": id,
            "aliases": aliases,
            "database_specific": {"severity": band},
            "severity": vector.map_or(Vec::new(), |v| vec![serde_json::json!({"type": "CVSS_V3", "score": v})]),
        });
        serde_json::from_value(text).unwrap()
    }

    #[test]
    fn a_go_record_takes_the_worst_severity_of_its_twins() {
        const HIGH: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
        let records = [
            record("GO-1", &["CVE-1", "GHSA-a"], None, None),
            record("GHSA-a", &["CVE-1"], Some("MODERATE"), None),
            // Names the same CVE, and the GO record only through that.
            record("GHSA-b", &["CVE-1"], Some("HIGH"), Some(HIGH)),
            // Only GitHub's record names the Go one.
            record("GO-2", &[], None, None),
            record("GHSA-c", &["GO-2"], Some("LOW"), None),
            record("GO-3", &["CVE-3"], None, None),
        ];
        let advisories: BTreeMap<String, Osv> =
            records.into_iter().map(|r| (r.id.clone(), r)).collect();
        let got = ratings(&advisories);
        assert_eq!(got["GO-1"].severity, Severity::High);
        assert_eq!(got["GO-1"].score, Some(7.5));
        assert_eq!(got["GO-1"].vector.as_deref(), Some(HIGH));
        assert_eq!(got["GHSA-a"].severity, Severity::Medium, "its own stands");
        assert_eq!(got["GO-2"].severity, Severity::Low);
        assert!(
            !got.contains_key("GO-3"),
            "nothing rates it: it stays unknown"
        );
    }

    #[test]
    fn a_lowercased_purl_reaches_the_module_it_stands_for() {
        let index: BTreeMap<String, Vec<String>> = [
            "github.com/Azure/go-ntlmssp",
            "github.com/Sirupsen/logrus",
            "github.com/sirupsen/logrus",
        ]
        .iter()
        .map(|m| (m.to_string(), Vec::new()))
        .collect();
        let db = GoDb {
            folded: folded(&index),
            index,
            advisories: BTreeMap::new(),
            ratings: BTreeMap::new(),
        };
        let named = |name| db.modules_named(name);
        assert_eq!(
            named("github.com/azure/go-ntlmssp"),
            vec!["github.com/Azure/go-ntlmssp"]
        );
        assert_eq!(
            named("github.com/sirupsen/logrus"),
            vec!["github.com/Sirupsen/logrus", "github.com/sirupsen/logrus"]
        );
        assert_eq!(
            named("github.com/Sirupsen/logrus"),
            vec!["github.com/Sirupsen/logrus"]
        );
        assert_eq!(named("example.com/none"), vec!["example.com/none"]);
    }

    #[test]
    fn affected_below_fix_with_patch_reported() {
        let r = ranges(&[("introduced", "0"), ("fixed", "0.3.7")]);
        // 0.3.0 < 0.3.7 -> affected, fix is 0.3.7.
        assert_eq!(
            affected_fixed(&v("0.3.0"), &osv_ranges(&r)),
            affected("0.3.7")
        );
    }

    #[test]
    fn not_affected_at_or_above_fix() {
        let r = ranges(&[("introduced", "0"), ("fixed", "0.3.7")]);
        assert_eq!(
            affected_fixed(&v("0.3.7"), &osv_ranges(&r)),
            Match::NotAffected
        );
        assert_eq!(
            affected_fixed(&v("1.0.0"), &osv_ranges(&r)),
            Match::NotAffected
        );
    }

    #[test]
    fn introduced_above_zero_excludes_older() {
        // Affected only in [1.2.0, 1.2.5).
        let r = ranges(&[("introduced", "1.2.0"), ("fixed", "1.2.5")]);
        assert_eq!(
            affected_fixed(&v("1.1.0"), &osv_ranges(&r)),
            Match::NotAffected,
            "before introduced"
        );
        assert_eq!(
            affected_fixed(&v("1.2.3"), &osv_ranges(&r)),
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
        assert_eq!(
            affected_fixed(&v("0.9.0"), &osv_ranges(&r)),
            affected("1.0.1")
        );
        assert_eq!(
            affected_fixed(&v("1.5.0"), &osv_ranges(&r)),
            Match::NotAffected,
            "between windows"
        );
        assert_eq!(
            affected_fixed(&v("2.0.1"), &osv_ranges(&r)),
            affected("2.0.3")
        );
    }

    #[test]
    fn last_affected_without_fix() {
        let r = ranges(&[("introduced", "1.0.0"), ("last_affected", "1.4.0")]);
        assert_eq!(
            affected_fixed(&v("1.3.0"), &osv_ranges(&r)),
            Match::Affected { fixed: None },
            "affected, no fix named"
        );
        assert_eq!(
            affected_fixed(&v("1.5.0"), &osv_ranges(&r)),
            Match::NotAffected
        );
    }

    #[test]
    fn pseudo_versions_and_prereleases_are_matched_not_silently_clean() {
        // Soundness regression: a Go pseudo-version is a SemVer pre-release ordering
        // below 0.0.0, so a naive `>= introduced "0"` would report it CLEAN and miss
        // the vuln. It must be flagged.
        let r = ranges(&[("introduced", "0"), ("fixed", "1.2.5")]);
        assert_eq!(
            affected_fixed(&v("v0.0.0-20210101000000-abcdef"), &osv_ranges(&r)),
            affected("1.2.5"),
            "pseudo-version in [0,1.2.5) must be flagged"
        );
        // A pre-release of the introduced version is included (fail-loud bias).
        let r2 = ranges(&[("introduced", "1.2.0"), ("fixed", "1.2.5")]);
        assert_eq!(
            affected_fixed(&v("v1.2.0-rc.1"), &osv_ranges(&r2)),
            affected("1.2.5"),
            "1.2.0-rc.1 is at/after introduced 1.2.0"
        );
        // The real fix still clears it (upper bound keeps full SemVer ordering).
        assert_eq!(
            affected_fixed(&v("1.2.5"), &osv_ranges(&r2)),
            Match::NotAffected
        );
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
            affected_fixed(&v("v0.0.0-20210520170846-37e1c6afe023"), &osv_ranges(&r)),
            Match::NotAffected,
            "a pseudo-version before the introduced pseudo must not be flagged"
        );
        // A pseudo AFTER introduced and before the fix is affected.
        assert_eq!(
            affected_fixed(&v("v0.0.0-20220812000000-abcdef000000"), &osv_ranges(&r)),
            affected("0.1.1-0.20221104162952-702349b0e862"),
            "a pseudo inside the affected window is flagged"
        );
        // The plain `introduced: "0"` case is unchanged: pseudo-versions stay inclusive.
        let zero = ranges(&[("introduced", "0"), ("fixed", "1.2.5")]);
        assert_eq!(
            affected_fixed(&v("v0.0.0-20210520170846-37e1c6afe023"), &osv_ranges(&zero)),
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
            affected_fixed(&v("1.0.0"), &osv_ranges(&bad)),
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
        assert_eq!(
            affected_fixed(&v("1.5.0"), &osv_ranges(&no_intro)),
            affected("2.0.0")
        );
        assert_eq!(
            affected_fixed(&v("2.0.0"), &osv_ranges(&no_intro)),
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
