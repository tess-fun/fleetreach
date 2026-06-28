//! OSV advisory version-range matching plus the shared toolchain-free feeder scaffolding
//! (wire schema, parallel dir/zip loader, by-package index, severity), used by every
//! ecosystem Tier-C feeder. The per-ecosystem knobs are passed in via [`Spec`]; this matcher
//! is the algorithmic core.
//!
//! The event-walking skeleton — a matchable range with no `introduced` is affected from
//! 0, an unparseable `introduced` fails **loud** (treated as affected, never silently
//! clean), the reported fix is the *smallest* `fixed` above the version, and a
//! `last_affected` closes an open interval — is identical across ecosystems. It is also
//! exactly the logic where a missed case is a *false-clean*, the worst bug, so it lives
//! here once rather than copied per feeder where the two could drift apart.
//!
//! What differs per ecosystem is only the version type and its handling, both passed in:
//! the matcher is generic over the version type `V` (SemVer for Go/npm, PEP 440 for
//! PyPI), and the bound handling comes in as closures — how a raw bound string parses
//! (Go's pseudo-versions vs plain SemVer vs PEP 440, and each ecosystem's `"0"`
//! lower-bound convention) and whether a version is at/after an `introduced` bound (Go
//! pseudo-versions order below their release, so they need a release-tuple compare; the
//! others just use `>=`). The `fixed`/`last_affected` upper bounds always use `V`'s own
//! ordering.

/// One advisory range reduced to what the matcher needs: whether its `type` is one this
/// ecosystem evaluates (`matchable` — `SEMVER` for Go/npm, `ECOSYSTEM` for PyPI; other
/// types are skipped) and its events.
#[derive(Debug, Clone)]
pub struct Range {
    pub matchable: bool,
    pub events: Vec<Event>,
}

/// One OSV range event: at most one of the three bounds is set.
#[derive(Debug, Clone)]
pub struct Event {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
}

/// A bound parsed once at DB-load time. `Version` holds the parsed bound; `Unparseable`
/// records that a bound string was present but the ecosystem's version parser rejected it
/// (a malformed / poisoned DB) so the matcher can fail **loud** — exactly the case the
/// string-based [`affected_fixed`] handles by treating an unparseable `introduced` as
/// affected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedBound<V> {
    /// A bound that parsed to this version.
    Version(V),
    /// A bound string that was present but could not be parsed.
    Unparseable,
}

/// One OSV range event with its bounds pre-parsed into the version type `V`. Built once at
/// DB load (see [`parse_range`]) so the per-scan matcher never re-parses a bound string.
#[derive(Debug, Clone)]
pub struct ParsedEvent<V> {
    /// `None` = no `introduced` event; `Some(_)` = an `introduced` bound (parsed or not).
    pub introduced: Option<ParsedBound<V>>,
    /// A parseable `fixed` bound, or `None` (absent OR unparseable — both simply skip, the
    /// same as the string matcher's `and_then(parse)`).
    pub fixed: Option<V>,
    /// A parseable `last_affected` bound, or `None` (absent OR unparseable).
    pub last_affected: Option<V>,
}

/// An advisory range with its event bounds pre-parsed (see [`ParsedEvent`]).
#[derive(Debug, Clone)]
pub struct ParsedRange<V> {
    pub matchable: bool,
    pub events: Vec<ParsedEvent<V>>,
}

/// Pre-parse a string-bound [`Range`] into a [`ParsedRange`] once, using the ecosystem's
/// bound parser (the same `parse_bound` closure the string matcher takes, including its
/// `"0"` convention). Do this at DB load so a popular advisory's bounds are parsed once per
/// load rather than once per repo scanned.
pub fn parse_range<V>(range: &Range, parse_bound: impl Fn(&str) -> Option<V>) -> ParsedRange<V> {
    ParsedRange {
        matchable: range.matchable,
        events: range
            .events
            .iter()
            .map(|e| ParsedEvent {
                introduced: e.introduced.as_deref().map(|raw| {
                    parse_bound(raw).map_or(ParsedBound::Unparseable, ParsedBound::Version)
                }),
                fixed: e.fixed.as_deref().and_then(&parse_bound),
                last_affected: e.last_affected.as_deref().and_then(&parse_bound),
            })
            .collect(),
    }
}

/// The pre-parsed counterpart of [`affected_fixed`]: identical semantics, but the bounds
/// were parsed once at DB load (see [`parse_range`]) so this hot per-scan path does no
/// string parsing. `at_or_after_introduced` is unchanged (plain `>=` for SemVer/PEP 440, a
/// pseudo-version-aware compare for Go).
pub fn affected_fixed_parsed<V: Ord + Clone>(
    version: &V,
    ranges: &[ParsedRange<V>],
    at_or_after_introduced: impl Fn(&V, &V) -> bool,
) -> Match<V> {
    for range in ranges {
        if !range.matchable {
            continue;
        }
        // OSV convention: a matchable range with no `introduced` event is affected from 0.
        let mut affected = !range.events.iter().any(|e| e.introduced.is_some());
        let mut patch: Option<V> = None;
        for event in &range.events {
            match &event.introduced {
                Some(ParsedBound::Version(v)) if at_or_after_introduced(version, v) => {
                    affected = true
                }
                Some(ParsedBound::Version(_)) => {}
                // A present-but-unparseable lower bound must fail LOUD — treat as affected.
                Some(ParsedBound::Unparseable) => affected = true,
                None => {}
            }
            if let Some(v) = &event.fixed {
                if version >= v {
                    affected = false;
                } else {
                    patch = Some(patch.map_or_else(|| v.clone(), |p| p.min(v.clone())));
                }
            }
            if let Some(v) = &event.last_affected {
                if version > v {
                    affected = false;
                }
            }
        }
        if affected {
            return Match::Affected { fixed: patch };
        }
    }
    Match::NotAffected
}

/// Whether an installed version is covered by an advisory's ranges. Generic over the
/// version type `V` so it carries back a SemVer or PEP 440 fix verbatim.
#[derive(Debug, PartialEq, Eq)]
pub enum Match<V> {
    /// The version falls in no affected range.
    NotAffected,
    /// The version is affected. `fixed` is the patch that closes its interval, if the
    /// DB names one (`None` for an open `last_affected`-only range, or no fix yet).
    Affected { fixed: Option<V> },
}

/// Evaluate the matchable `ranges` for `version`. Ranges whose `type` this ecosystem does
/// not evaluate (`matchable == false`) are skipped.
///
/// Generic over the version type `V`: `parse_bound` parses a raw bound string with the
/// ecosystem's version adapter (and its `"0"` convention), and `at_or_after_introduced`
/// decides whether `version` is at/after an `introduced` lower bound — plain `>=` for
/// SemVer/PEP 440, a pseudo-version-aware compare for Go. Both are called many times, so
/// they are taken by reference internally.
pub fn affected_fixed<V: Ord + Clone>(
    version: &V,
    ranges: &[Range],
    parse_bound: impl Fn(&str) -> Option<V>,
    at_or_after_introduced: impl Fn(&V, &V) -> bool,
) -> Match<V> {
    for range in ranges {
        if !range.matchable {
            continue;
        }
        // OSV convention: a matchable range with no `introduced` event is introduced at 0,
        // i.e. affected from the start. Defaulting to `false` would make such a range
        // (and a poisoned advisory that simply omits `introduced`) silently read clean.
        let mut affected = !range.events.iter().any(|e| e.introduced.is_some());
        let mut patch: Option<V> = None;
        for event in &range.events {
            if let Some(raw) = event.introduced.as_deref() {
                match parse_bound(raw) {
                    Some(v) if at_or_after_introduced(version, &v) => affected = true,
                    Some(_) => {}
                    // An unparseable lower bound (malformed / poisoned DB) must fail
                    // LOUD — treat as affected — never silently clean.
                    None => affected = true,
                }
            }
            if let Some(v) = event.fixed.as_deref().and_then(&parse_bound) {
                if *version >= v {
                    affected = false;
                } else {
                    // The patch is the *smallest* fixed above `version` (the fix that
                    // closes its interval), not merely the last fixed event seen — a
                    // later interval's fix must not overwrite an earlier one.
                    patch = Some(patch.map_or(v.clone(), |p| p.min(v)));
                }
            }
            if let Some(v) = event.last_affected.as_deref().and_then(&parse_bound) {
                if *version > v {
                    affected = false;
                }
            }
        }
        if affected {
            return Match::Affected { fixed: patch };
        }
    }
    Match::NotAffected
}

// =============================================================================
// Shared toolchain-free OSV feeder scaffolding
// =============================================================================
//
// Every ecosystem Tier-C feeder (npm, PyPI, RubyGems, Packagist, NuGet, Julia, Swift, Hex,
// GitHub Actions, Maven) reads the same osv.dev export shape — a directory of OSV JSON
// records, or the `all.zip` — and indexes it by package name. The only per-ecosystem
// differences are captured in [`Spec`]: the version type, how a bound/version string parses,
// how a package name normalizes, which OSV `ecosystem`/range `type` strings this feeder
// consumes, whether enumerated `versions` are used, and how severity is derived. The load,
// the wire schema, the parallel dir/zip reader, the by-package index, and the parse-once
// range building all live here, once — the place where a missed case is a false-clean.

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read as _};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use rayon::prelude::*;
use serde::Deserialize;
use thiserror::Error;

use crate::semver::{Version, VersionReq};
use crate::{DependencyKind, Ecosystem, Occurrence, Reachability, RepoId, Severity, VulnFinding};

/// One advisory's facts for a single affected package, version type `V`. The range bounds
/// and enumerated `versions` are parsed once at load (see [`load`]).
#[derive(Debug, Clone)]
pub struct Advisory<V> {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub severity: Severity,
    /// A CVSS base score when the record carries a parseable CVSS_V3 vector (always `None`
    /// for feeders whose [`Spec::severity`] does not extract one, e.g. npm).
    pub cvss_score: Option<f32>,
    /// `matchable` ranges with bounds pre-parsed (see [`parse_range`]).
    pub ranges: Vec<ParsedRange<V>>,
    /// Enumerated affected versions, sorted+deduped for `binary_search` (empty when
    /// [`Spec::use_versions`] is false).
    pub versions: Vec<V>,
}

/// The offline OSV DB: `normalized package name -> advisories`, built once at load.
#[derive(Debug)]
pub struct OsvDb<V> {
    by_package: BTreeMap<String, Vec<Advisory<V>>>,
}

impl<V> Default for OsvDb<V> {
    fn default() -> Self {
        OsvDb {
            by_package: BTreeMap::new(),
        }
    }
}

impl<V> OsvDb<V> {
    /// The advisories indexed under `key` (a name already run through
    /// [`Spec::normalize_name`]), or an empty slice if none.
    pub fn advisories_for(&self, key: &str) -> &[Advisory<V>] {
        self.by_package.get(key).map_or(&[], Vec::as_slice)
    }
    /// Total advisory-package index entries — for diagnostics/tests.
    pub fn len(&self) -> usize {
        self.by_package.values().map(Vec::len).sum()
    }
    /// Whether the DB indexed no advisories at all.
    pub fn is_empty(&self) -> bool {
        self.by_package.is_empty()
    }
}

/// The per-ecosystem knobs the generic [`load`]/[`advisories_from`] need. Everything else
/// (wire schema, parallel reader, indexing, parse-once) is shared.
pub struct Spec<V: 'static> {
    /// The OSV `affected[].package.ecosystem` string this feeder consumes (e.g. `"Maven"`).
    pub ecosystem: &'static str,
    /// The OSV range `type` this feeder evaluates (`"ECOSYSTEM"` or `"SEMVER"`); other types
    /// are not `matchable`.
    pub range_type: &'static str,
    /// Parse a bound/version string with this ecosystem's version adapter (incl. its `"0"`
    /// convention). Used at load to pre-parse range bounds and the enumerated `versions`.
    pub parse_version: fn(&str) -> Option<V>,
    /// Normalize a package name into the index key (identity, lowercase, PEP 503, URL, ...).
    pub normalize_name: fn(&str) -> String,
    /// Whether to collect the enumerated `versions` list (false for npm, which is range-only).
    pub use_versions: bool,
    /// Derive `(severity, cvss_score)` from a record. [`default_severity`] suits every feeder
    /// whose records carry the GHSA band / CVSS_V3 vector; npm passes its own.
    pub severity: fn(&OsvRecord) -> (Severity, Option<f32>),
}

/// Why an OSV mirror file could not be read or parsed — shared by every feeder's error type.
/// A present-but-broken input fails **closed** (an honest gap, never a false-clean).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DbError {
    /// The file could not be read.
    #[error("read failed: {0}")]
    Read(#[from] io::Error),
    /// An OSV record was not valid JSON.
    #[error("invalid JSON: {0}")]
    Parse(#[from] serde_json::Error),
    /// The OSV mirror `.zip` could not be opened or decompressed.
    #[error("invalid zip archive: {0}")]
    Archive(String),
}

impl From<zip::result::ZipError> for DbError {
    fn from(e: zip::result::ZipError) -> Self {
        match e {
            zip::result::ZipError::Io(io) => DbError::Read(io),
            other => DbError::Archive(other.to_string()),
        }
    }
}

/// A load failure carrying the offending `path` and its cause, so a feeder can wrap it into
/// its own `Db { path, source }` error verbatim.
#[derive(Debug)]
pub struct LoadError {
    pub path: PathBuf,
    pub source: DbError,
}

impl LoadError {
    fn new(path: impl Into<PathBuf>, source: impl Into<DbError>) -> Self {
        LoadError {
            path: path.into(),
            source: source.into(),
        }
    }
}

/// Load the OSV mirror at `root` — a directory of `*.json` records (what the osv.dev
/// `<Ecosystem>/all.zip` unzips to) or the `.zip` itself — into an indexed [`OsvDb`],
/// parsing every range bound and enumerated version once.
///
/// # Errors
///
/// Returns [`LoadError`] if `root` cannot be read, the archive cannot be decompressed, or a
/// record is not valid JSON — failing closed.
pub fn load<V>(root: &Path, spec: &Spec<V>) -> Result<OsvDb<V>, LoadError>
where
    V: Ord + Clone + Send,
{
    if root.is_dir() {
        load_dir(root, spec)
    } else {
        load_zip(root, spec)
    }
}

fn load_dir<V>(root: &Path, spec: &Spec<V>) -> Result<OsvDb<V>, LoadError>
where
    V: Ord + Clone + Send,
{
    let mut paths: Vec<PathBuf> = std::fs::read_dir(root)
        .map_err(|e| LoadError::new(root, e))?
        .map(|entry| entry.map(|e| e.path()).map_err(|e| LoadError::new(root, e)))
        .collect::<Result<_, _>>()?;
    paths.retain(|p| p.extension().and_then(|e| e.to_str()) == Some("json"));
    paths.sort();

    let per_file: Vec<Vec<(String, Advisory<V>)>> = paths
        .par_iter()
        .map(|path| {
            let body = std::fs::read_to_string(path).map_err(|e| LoadError::new(path, e))?;
            let osv: OsvRecord =
                serde_json::from_str(&body).map_err(|e| LoadError::new(path, e))?;
            Ok(advisories_from(osv, spec))
        })
        .collect::<Result<_, LoadError>>()?;

    Ok(OsvDb {
        by_package: merge(per_file),
    })
}

fn load_zip<V>(path: &Path, spec: &Spec<V>) -> Result<OsvDb<V>, LoadError>
where
    V: Ord + Clone + Send,
{
    let bytes: Arc<[u8]> = std::fs::read(path)
        .map_err(|e| LoadError::new(path, e))?
        .into();
    let archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| LoadError::new(path, e))?;

    let per_entry: Vec<Vec<(String, Advisory<V>)>> = (0..archive.len())
        .into_par_iter()
        .map_init(
            || archive.clone(),
            |archive, i| {
                let mut entry = archive.by_index(i).map_err(|e| LoadError::new(path, e))?;
                if !entry.name().ends_with(".json") {
                    return Ok(Vec::new());
                }
                let mut body = String::new();
                entry
                    .read_to_string(&mut body)
                    .map_err(|e| LoadError::new(path, e))?;
                let osv: OsvRecord =
                    serde_json::from_str(&body).map_err(|e| LoadError::new(path, e))?;
                Ok(advisories_from(osv, spec))
            },
        )
        .collect::<Result<_, LoadError>>()?;

    Ok(OsvDb {
        by_package: merge(per_entry),
    })
}

/// Fold per-record advisory lists (in their original `affected[]` order) into the by-package
/// index.
fn merge<V>(per_file: Vec<Vec<(String, Advisory<V>)>>) -> BTreeMap<String, Vec<Advisory<V>>> {
    let mut by_package: BTreeMap<String, Vec<Advisory<V>>> = BTreeMap::new();
    for record in per_file {
        for (name, advisory) in record {
            by_package.entry(name).or_default().push(advisory);
        }
    }
    by_package
}

/// The `(normalized name, advisory)` pairs one OSV record contributes: one per `affected[]`
/// entry whose `package.ecosystem` matches [`Spec::ecosystem`]. Bounds and versions are
/// parsed once here. Exposed for feeder unit tests.
pub fn advisories_from<V>(osv: OsvRecord, spec: &Spec<V>) -> Vec<(String, Advisory<V>)>
where
    V: Ord + Clone,
{
    let (severity, cvss_score) = (spec.severity)(&osv);
    osv.affected
        .iter()
        .filter(|a| a.package.ecosystem.as_deref() == Some(spec.ecosystem))
        .filter_map(|affected| {
            let name = (spec.normalize_name)(affected.package.name.as_deref()?);
            let ranges = affected
                .ranges
                .iter()
                .map(|r| {
                    let range = Range {
                        matchable: r.kind.as_deref() == Some(spec.range_type),
                        events: r
                            .events
                            .iter()
                            .map(|e| Event {
                                introduced: e.introduced.clone(),
                                fixed: e.fixed.clone(),
                                last_affected: e.last_affected.clone(),
                            })
                            .collect(),
                    };
                    parse_range(&range, spec.parse_version)
                })
                .collect();
            let mut versions: Vec<V> = if spec.use_versions {
                affected
                    .versions
                    .iter()
                    .flatten()
                    .filter_map(|v| (spec.parse_version)(v))
                    .collect()
            } else {
                Vec::new()
            };
            versions.sort();
            versions.dedup();
            Some((
                name,
                Advisory {
                    id: osv.id.clone(),
                    aliases: osv.aliases.clone().unwrap_or_default(),
                    summary: osv.summary.clone(),
                    severity,
                    cvss_score,
                    ranges,
                    versions,
                },
            ))
        })
        .collect()
}

/// The default `(severity, cvss_score)` derivation: prefer the curated GHSA band
/// (`database_specific.severity`), and take the best CVSS_V3 base score across the record's
/// `severity[]` vectors (deriving the band from it when no GHSA band is present).
pub fn default_severity(osv: &OsvRecord) -> (Severity, Option<f32>) {
    let band = osv
        .database_specific
        .as_ref()
        .and_then(|d| d.severity.as_deref())
        .map(band_from_label)
        .unwrap_or(Severity::Unknown);

    let scored: Option<(Severity, f32)> = osv
        .severity
        .iter()
        .filter(|s| s.kind.as_deref() == Some("CVSS_V3"))
        .filter_map(|s| cvss::v3::Base::from_str(s.score.as_deref()?).ok())
        .map(|base| {
            let score = base.score();
            (band_from_cvss(score.severity()), score.value() as f32)
        })
        .max_by(|a, b| a.1.total_cmp(&b.1));

    let cvss_score = scored.map(|(_, v)| v);
    let severity = if band != Severity::Unknown {
        band
    } else {
        scored.map(|(b, _)| b).unwrap_or(Severity::Unknown)
    };
    (severity, cvss_score)
}

/// Map a GHSA/OSV severity band string onto [`Severity`].
pub fn band_from_label(label: &str) -> Severity {
    match label.to_ascii_uppercase().as_str() {
        "LOW" => Severity::Low,
        "MODERATE" | "MEDIUM" => Severity::Medium,
        "HIGH" => Severity::High,
        "CRITICAL" => Severity::Critical,
        _ => Severity::Unknown,
    }
}

/// Map a parsed CVSS v3 severity band onto [`Severity`].
fn band_from_cvss(sev: cvss::Severity) -> Severity {
    match sev {
        cvss::Severity::None => Severity::Unknown,
        cvss::Severity::Low => Severity::Low,
        cvss::Severity::Medium => Severity::Medium,
        cvss::Severity::High => Severity::High,
        cvss::Severity::Critical => Severity::Critical,
    }
}

// --- Shared Tier-C finding construction ---
//
// Every toolchain-free feeder turns an "this advisory affects this installed package at this
// version" decision into the same `VulnFinding` shape, then sorts and dedups the same way.
// Only the *decision* (range vs versions-list match, the per-ecosystem version type and its
// coercion to the stored SemVer form) differs per feeder; the construction does not. Owning it
// here keeps the finding contract — the `osv.dev` URL, the per-occurrence skeleton, the
// `(advisory, package)` sort/dedup — in one place instead of copy-pasted ten times, where a
// field added in one feeder and forgotten in another would be a silent inconsistency.

/// The outcome of a toolchain-free `scan_offline`: the findings, plus how many installed
/// packages were skipped because their version string did not parse.
///
/// A skip is benign for a non-registry pin (a VCS/URL/path-pinned dependency has no registry
/// release, so no registry advisory can apply). But surfacing the *count* keeps the skip
/// visible rather than silent — so a malformed-but-real version the parser wrongly rejects is
/// not indistinguishable from a clean result. The orchestrator sums these and reports a nonzero
/// total; it is never an error (the scan is still as complete as the lockfile allows).
#[derive(Debug, Default, Clone)]
pub struct TierCScan {
    /// The deduplicated, sorted findings.
    pub findings: Vec<VulnFinding>,
    /// Count of installed packages skipped because their version did not parse.
    pub skipped_unparseable: u32,
}

/// The canonical advisory URL on `osv.dev` — every id (GHSA, CVE, PYSEC, MAL, …) resolves there.
#[must_use]
pub fn advisory_url(id: &str) -> String {
    format!("https://osv.dev/vulnerability/{id}")
}

/// The package name of a finding's first occurrence, the sort/dedup key alongside the advisory
/// id. Tier-C findings always carry exactly one `InRepo` occurrence.
#[must_use]
pub fn occ_package(v: &VulnFinding) -> &str {
    match v.occurrences.first() {
        Some(Occurrence::InRepo { package, .. }) => package,
        _ => "",
    }
}

/// Sort by `(advisory id, package)` and dedup on that pair — the deterministic ordering every
/// feeder emits. The same package+version can resolve many times in a lockfile, but a
/// multi-package advisory legitimately yields one finding per *distinct* package, so the dedup
/// key is the pair, not the advisory alone.
pub fn sort_dedup_findings(out: &mut Vec<VulnFinding>) {
    out.sort_by(|a, b| {
        a.advisory_id
            .cmp(&b.advisory_id)
            .then_with(|| occ_package(a).cmp(occ_package(b)))
    });
    out.dedup_by(|a, b| a.advisory_id == b.advisory_id && occ_package(a) == occ_package(b));
}

/// The inputs a feeder supplies to build one Tier-C [`VulnFinding`]. The version-matching
/// decision (and any `to_semver` coercion of the installed/patched versions) happens in the
/// feeder; everything here is already in the shared model's types.
pub struct TierCFinding<'a> {
    /// The ecosystem this finding came from.
    pub ecosystem: Ecosystem,
    /// The advisory id (the `osv.dev` URL is derived from it).
    pub advisory_id: String,
    /// CVE/GHSA/… cross-reference aliases.
    pub aliases: Vec<String>,
    /// Display title — typically the advisory summary, falling back to the id.
    pub title: String,
    /// Severity band.
    pub severity: Severity,
    /// CVSS base score when the advisory carries one (`None` where the feeder does not
    /// extract it).
    pub cvss_score: Option<f32>,
    /// The affected package name.
    pub package: String,
    /// The installed version, in the shared SemVer model (already coerced by the feeder).
    pub installed: Version,
    /// Versions that fix the advisory; empty means "no fix available".
    pub patched: Vec<VersionReq>,
    /// Whether the package is a direct dependency.
    pub direct: bool,
    /// A representative introducer chain `[root, …, package]`; empty when the feeder cannot
    /// compute a dependency graph.
    pub dependency_path: Vec<String>,
    /// The repo the package was found in.
    pub repo: &'a RepoId,
    /// The reason string for the Tier-C `Unknown` reachability verdict (the feeder names the
    /// fidelity, e.g. "package-level scan (no toolchain): version match only").
    pub reach_reason: &'static str,
}

impl TierCFinding<'_> {
    /// Assemble the [`VulnFinding`]. Package-level only: `affected_functions` is empty,
    /// `reachable` is `None`, and reachability is the Tier-C `Unknown` contract (never
    /// `NotReachable` — see [`Reachability::tier_c_unknown`]).
    #[must_use]
    pub fn build(self) -> VulnFinding {
        VulnFinding {
            advisory_id: self.advisory_id.clone(),
            aliases: self.aliases,
            ecosystem: self.ecosystem,
            title: self.title,
            severity: self.severity,
            cvss_score: self.cvss_score,
            url: Some(advisory_url(&self.advisory_id)),
            occurrences: vec![Occurrence::InRepo {
                repo: self.repo.clone(),
                package: self.package,
                installed: self.installed,
                patched: self.patched,
                dependency_kind: if self.direct {
                    DependencyKind::Direct
                } else {
                    DependencyKind::Transitive
                },
                dependency_path: self.dependency_path,
                active: None,
                source: Default::default(),
            }],
            affected_functions: Vec::new(),
            reachable: None,
            reachability: Some(Reachability::tier_c_unknown(self.reach_reason)),
            exploit: Default::default(),
        }
    }
}

// --- OSV wire schema (the subset every feeder reads). ---

/// One OSV advisory record, deserialized from a single `*.json` export file.
#[derive(Debug, Deserialize)]
pub struct OsvRecord {
    pub id: String,
    pub aliases: Option<Vec<String>>,
    pub summary: Option<String>,
    #[serde(default)]
    pub affected: Vec<Affected>,
    #[serde(default)]
    pub severity: Vec<SeverityEntry>,
    pub database_specific: Option<DatabaseSpecific>,
}

/// One `severity[]` vector (e.g. a `CVSS_V3` base-score string).
#[derive(Debug, Deserialize)]
pub struct SeverityEntry {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub score: Option<String>,
}

/// The `database_specific` block, read for its curated GHSA severity band.
#[derive(Debug, Deserialize)]
pub struct DatabaseSpecific {
    pub severity: Option<String>,
}

/// One `affected[]` entry: a package, its ranges, and any enumerated versions.
#[derive(Debug, Deserialize)]
pub struct Affected {
    #[serde(default)]
    pub package: Package,
    #[serde(default)]
    pub ranges: Vec<RawRange>,
    pub versions: Option<Vec<String>>,
}

/// The `affected[].package` identity.
#[derive(Debug, Deserialize, Default)]
pub struct Package {
    pub name: Option<String>,
    pub ecosystem: Option<String>,
}

/// One `affected[].ranges[]` entry (raw string bounds; parsed once by [`advisories_from`]).
#[derive(Debug, Deserialize)]
pub struct RawRange {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub events: Vec<RawEvent>,
}

/// One `ranges[].events[]` entry: at most one bound set.
#[derive(Debug, Deserialize)]
pub struct RawEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use semver::Version;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    // Plain-SemVer bounds, the simplest instantiation (the npm shape).
    fn plain(version: &Version, ranges: &[Range]) -> Match<Version> {
        affected_fixed(
            version,
            ranges,
            |raw| {
                if raw == "0" {
                    Some(Version::new(0, 0, 0))
                } else {
                    Version::parse(raw).ok()
                }
            },
            |ver, bound| ver >= bound,
        )
    }

    fn range(events: &[(&str, &str)]) -> Range {
        Range {
            matchable: true,
            events: events
                .iter()
                .map(|(k, val)| Event {
                    introduced: (*k == "introduced").then(|| val.to_string()),
                    fixed: (*k == "fixed").then(|| val.to_string()),
                    last_affected: (*k == "last_affected").then(|| val.to_string()),
                })
                .collect(),
        }
    }

    #[test]
    fn affected_below_fix_reports_smallest_patch() {
        let r = [
            range(&[("introduced", "0"), ("fixed", "1.0.1")]),
            range(&[("introduced", "2.0.0"), ("fixed", "2.0.3")]),
        ];
        // 0.9.0 is in [0,1.0.1): fix is 1.0.1, not 2.0.3.
        assert_eq!(
            plain(&v("0.9.0"), &r),
            Match::Affected {
                fixed: Some(v("1.0.1"))
            }
        );
        assert_eq!(
            plain(&v("1.5.0"), &r),
            Match::NotAffected,
            "between windows"
        );
    }

    #[test]
    fn no_introduced_event_is_affected_from_zero() {
        let r = [Range {
            matchable: true,
            events: vec![Event {
                introduced: None,
                fixed: Some("2.0.0".into()),
                last_affected: None,
            }],
        }];
        assert_eq!(
            plain(&v("1.5.0"), &r),
            Match::Affected {
                fixed: Some(v("2.0.0"))
            }
        );
        assert_eq!(plain(&v("2.0.0"), &r), Match::NotAffected);
    }

    #[test]
    fn unparseable_introduced_fails_loud() {
        let r = [range(&[("introduced", "garbage"), ("fixed", "99.0.0")])];
        assert_eq!(
            plain(&v("1.0.0"), &r),
            Match::Affected {
                fixed: Some(v("99.0.0"))
            },
            "a malformed lower bound must read affected, never clean"
        );
    }

    #[test]
    fn non_semver_ranges_are_skipped() {
        let r = [Range {
            matchable: false,
            events: vec![Event {
                introduced: Some("0".into()),
                fixed: None,
                last_affected: None,
            }],
        }];
        assert_eq!(plain(&v("1.0.0"), &r), Match::NotAffected);
    }

    #[test]
    fn last_affected_closes_an_open_interval() {
        let r = [range(&[
            ("introduced", "1.0.0"),
            ("last_affected", "1.4.0"),
        ])];
        assert_eq!(plain(&v("1.3.0"), &r), Match::Affected { fixed: None });
        assert_eq!(plain(&v("1.5.0"), &r), Match::NotAffected);
    }

    // The pre-parsed matcher must agree with the string matcher on every shape: that is the
    // whole safety contract of the parse-once optimization (a divergence = a false-clean).
    #[test]
    fn parsed_matcher_agrees_with_string_matcher() {
        let parse = |raw: &str| {
            if raw == "0" {
                Some(Version::new(0, 0, 0))
            } else {
                Version::parse(raw).ok()
            }
        };
        let ranges = [
            range(&[("introduced", "0"), ("fixed", "1.0.1")]),
            range(&[("introduced", "2.0.0"), ("fixed", "2.0.3")]),
            range(&[("introduced", "1.0.0"), ("last_affected", "1.4.0")]),
            range(&[("introduced", "garbage"), ("fixed", "99.0.0")]),
            Range {
                matchable: false,
                events: vec![Event {
                    introduced: Some("0".into()),
                    fixed: None,
                    last_affected: None,
                }],
            },
        ];
        let parsed: Vec<ParsedRange<Version>> =
            ranges.iter().map(|r| parse_range(r, parse)).collect();
        for s in [
            "0.0.1", "0.9.0", "1.0.0", "1.0.1", "1.3.0", "1.5.0", "2.0.0", "2.0.3", "5.0.0",
        ] {
            let ver = v(s);
            let want = plain(&ver, &ranges);
            let got = affected_fixed_parsed(&ver, &parsed, |a, b| a >= b);
            assert_eq!(want, got, "disagreement at {s}");
        }
    }

    #[test]
    fn custom_introduced_comparator_is_honored() {
        // A comparator that treats nothing as at/after `introduced` ⇒ never affected
        // via an introduced bound (proves the closure actually drives the decision).
        let r = [range(&[("introduced", "1.0.0"), ("fixed", "2.0.0")])];
        let never = affected_fixed(
            &v("1.5.0"),
            &r,
            |raw| Version::parse(raw).ok(),
            |_, _| false,
        );
        assert_eq!(never, Match::NotAffected);
    }
}
