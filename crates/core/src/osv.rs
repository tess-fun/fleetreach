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

/// The versions above `version` that no range leaves affected, as `[from, until)` pairs: each
/// starts at a `fixed` bound that every range leaves safe and runs up to the next bound where
/// some range is affected again (`None` = never). Every range counts, not only the one that
/// matched: a branch fixed per release (grpc's GO-2026-6443: fixed 1.82.2, re-introduced
/// 1.83.0, fixed 1.83.2) or a record with one `affected` entry per line (js-yaml's
/// GHSA-2883: 3.x fixed in 3.15.2, 4.x in 4.3.2) is not safe from its first fix on, and a bare
/// `>=fix` would let a planner pick 1.83.1 or 4.1.1. Empty when `version` is not affected or
/// no fix is published.
pub fn safe_intervals<V: Ord + Clone>(
    version: &V,
    ranges: &[ParsedRange<V>],
) -> Vec<(V, Option<V>)> {
    let affected = |v: &V| {
        matches!(
            affected_fixed_parsed(v, ranges, |v, b| v >= b),
            Match::Affected { .. }
        )
    };
    if !affected(version) {
        return Vec::new();
    }
    // Every bound above `version`, in order; `true` when some range is fixed there.
    let mut bounds: BTreeMap<&V, bool> = BTreeMap::new();
    for range in ranges.iter().filter(|r| r.matchable) {
        for e in &range.events {
            if let Some(ParsedBound::Version(v)) = &e.introduced {
                bounds.entry(v).or_insert(false);
            }
            if let Some(v) = &e.fixed {
                bounds.insert(v, true);
            }
        }
    }
    let mut out = Vec::new();
    let mut open: Option<&V> = None;
    for (v, is_fixed) in bounds.range::<V, _>((
        std::ops::Bound::Excluded(version),
        std::ops::Bound::Unbounded,
    )) {
        match open {
            None if *is_fixed && !affected(v) => open = Some(v),
            Some(from) if affected(v) => {
                out.push((from.clone(), Some((*v).clone())));
                open = None;
            }
            _ => {}
        }
    }
    if let Some(from) = open {
        out.push((from.clone(), None));
    }
    out
}

/// The safe intervals as the model's SemVer requirements (`>=from, <until`), with `show`
/// rendering a version in SemVer form. An interval whose bounds do not form a valid SemVer
/// requirement keeps its lower bound alone, as before.
pub fn patched_reqs<V>(
    intervals: &[(V, Option<V>)],
    show: impl Fn(&V) -> String,
) -> Vec<semver::VersionReq> {
    intervals
        .iter()
        .filter_map(|(from, until)| {
            let lower = format!(">={}", show(from));
            until
                .as_ref()
                .and_then(|u| semver::VersionReq::parse(&format!("{lower}, <{}", show(u))).ok())
                .or_else(|| semver::VersionReq::parse(&lower).ok())
        })
        .collect()
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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::semver::{Version, VersionReq};
use crate::{
    DepScope, DependencyKind, Ecosystem, Occurrence, Reachability, RepoId, Severity, VulnFinding,
};

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
    /// The record's CVSS vector string (a `CVSS_V3` entry, else `CVSS_V4`), for decisions
    /// that read individual metrics, such as SSVC Automatable.
    pub cvss_vector: Option<String>,
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
    /// Set by [`load_names`]: the keys kept, and whether anything else was asked for.
    kept: Option<Kept>,
}

#[derive(Debug)]
struct Kept {
    keys: HashSet<String>,
    missed: AtomicBool,
}

impl<V> Default for OsvDb<V> {
    fn default() -> Self {
        OsvDb {
            by_package: BTreeMap::new(),
            kept: None,
        }
    }
}

impl<V> OsvDb<V> {
    /// The advisories indexed under `key` (a name already run through
    /// [`Spec::normalize_name`]), or an empty slice if none.
    pub fn advisories_for(&self, key: &str) -> &[Advisory<V>] {
        if let Some(kept) = &self.kept {
            if !kept.keys.contains(key) {
                kept.missed.store(true, Ordering::Relaxed);
            }
        }
        self.by_package.get(key).map_or(&[], Vec::as_slice)
    }
    /// Whether a DB from [`load_names`] was asked for a package it did not keep: its answers
    /// may then be incomplete, and the caller must load the full DB and ask again.
    pub fn missed(&self) -> bool {
        self.kept
            .as_ref()
            .is_some_and(|k| k.missed.load(Ordering::Relaxed))
    }
    /// Total advisory-package index entries — for diagnostics/tests.
    pub fn len(&self) -> usize {
        self.by_package.values().map(Vec::len).sum()
    }
    /// Every `(index key, advisory)` pair, in key order (for data-quality checks).
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Advisory<V>)> {
        self.by_package
            .iter()
            .flat_map(|(key, advs)| advs.iter().map(move |a| (key.as_str(), a)))
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
    /// The OSV range `type` this feeder evaluates (`"ECOSYSTEM"`, `"SEMVER"`, or both as
    /// `"SEMVER|ECOSYSTEM"`); other types are not `matchable`.
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

/// A `zipdir` failure: malformed data is an archive error, anything else a read error.
pub fn zip_error(e: io::Error) -> DbError {
    if e.kind() == io::ErrorKind::InvalidData {
        DbError::Archive(e.to_string())
    } else {
        DbError::Read(e)
    }
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
    load_skipping(root, spec, &BTreeSet::new())
}

/// [`load`] with an organization's own OSV records layered on top (`overlay`, a directory
/// searched recursively for `*.json`). An overlay record whose `id` matches an upstream record
/// **replaces** it, in every ecosystem; one with a new id is an addition; one with
/// `withdrawn` set retracts the upstream record of that id (withdrawn records never match).
/// Overlay records are indexed after the upstream ones.
///
/// # Errors
///
/// As [`load`], plus an unreadable overlay directory or an overlay record that is not valid
/// OSV JSON: a broken correction fails closed rather than being dropped.
pub fn load_with_overlay<V>(
    root: &Path,
    overlay: Option<&Path>,
    spec: &Spec<V>,
) -> Result<OsvDb<V>, LoadError>
where
    V: Ord + Clone + Send,
{
    let Some(overlay) = overlay else {
        return load(root, spec);
    };
    let records = read_overlay(overlay)?;
    let replaced: BTreeSet<String> = records.iter().map(|r| r.id.clone()).collect();
    let mut db = load_skipping(root, spec, &replaced)?;
    for record in records {
        for (name, advisory) in advisories_from(record, spec) {
            db.by_package.entry(name).or_default().push(advisory);
        }
    }
    Ok(db)
}

/// Which packages to keep, by their index key (the name after [`Spec::normalize_name`]).
pub type Keep<'a> = &'a (dyn Fn(&str) -> bool + Sync);

/// [`load_with_overlay`], keeping only the advisories of packages `keep` accepts. A record
/// none of whose packages is kept is read only as far as its package names, so a caller
/// asking about a few packages (`whatif`, `fix plan`) does not hold a whole export.
///
/// # Errors
///
/// As [`load_with_overlay`].
pub fn load_only<V>(
    root: &Path,
    overlay: Option<&Path>,
    spec: &Spec<V>,
    keep: Keep<'_>,
) -> Result<OsvDb<V>, LoadError>
where
    V: Ord + Clone + Send,
{
    let records = match overlay {
        Some(dir) => read_overlay(dir)?,
        None => Vec::new(),
    };
    let replaced: BTreeSet<String> = records.iter().map(|r| r.id.clone()).collect();
    let mut db = load_filtered(root, spec, &replaced, Some(keep))?;
    for record in records {
        for (name, advisory) in advisories_from(record, spec) {
            if keep(&name) {
                db.by_package.entry(name).or_default().push(advisory);
            }
        }
    }
    Ok(db)
}

/// [`load_only`] for the packages `names` (as installed; normalized here with the spec), which
/// also remembers the kept keys: a lookup of any other key marks the DB [`OsvDb::missed`], so
/// a caller that guessed the names wrong learns it instead of reporting clean.
///
/// # Errors
///
/// As [`load_only`].
pub fn load_names<'n, V>(
    root: &Path,
    overlay: Option<&Path>,
    spec: &Spec<V>,
    names: impl IntoIterator<Item = &'n str>,
) -> Result<OsvDb<V>, LoadError>
where
    V: Ord + Clone + Send,
{
    let keys: HashSet<String> = names.into_iter().map(spec.normalize_name).collect();
    let mut db = load_only(root, overlay, spec, &|key: &str| keys.contains(key))?;
    db.kept = Some(Kept {
        keys,
        missed: AtomicBool::new(false),
    });
    Ok(db)
}

/// Every `*.json` OSV record under `dir` (recursively, in path order, hidden entries
/// skipped), as layered by [`load_with_overlay`].
///
/// # Errors
///
/// A directory that cannot be read or a record that is not valid OSV JSON.
pub fn read_overlay(dir: &Path) -> Result<Vec<OsvRecord>, LoadError> {
    let mut paths = Vec::new();
    collect_json(dir, &mut paths)?;
    paths.sort();
    paths
        .iter()
        .map(|path| {
            let body = std::fs::read_to_string(path).map_err(|e| LoadError::new(path, e))?;
            serde_json::from_str(&body).map_err(|e| LoadError::new(path, e))
        })
        .collect()
}

fn collect_json(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), LoadError> {
    for entry in std::fs::read_dir(dir).map_err(|e| LoadError::new(dir, e))? {
        let entry = entry.map_err(|e| LoadError::new(dir, e))?;
        let path = entry.path();
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let kind = entry.file_type().map_err(|e| LoadError::new(&path, e))?;
        if kind.is_dir() {
            collect_json(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
            out.push(path);
        }
    }
    Ok(())
}

fn load_skipping<V>(
    root: &Path,
    spec: &Spec<V>,
    skip: &BTreeSet<String>,
) -> Result<OsvDb<V>, LoadError>
where
    V: Ord + Clone + Send,
{
    load_filtered(root, spec, skip, None)
}

fn load_filtered<V>(
    root: &Path,
    spec: &Spec<V>,
    skip: &BTreeSet<String>,
    keep: Option<Keep<'_>>,
) -> Result<OsvDb<V>, LoadError>
where
    V: Ord + Clone + Send,
{
    if root.is_dir() {
        load_dir(root, spec, skip, keep)
    } else {
        load_zip(root, spec, skip, keep)
    }
}

/// Just enough of a record to know its packages.
#[derive(Deserialize)]
struct Names<'a> {
    #[serde(default, borrow)]
    affected: Vec<NameEntry<'a>>,
}

#[derive(Deserialize)]
struct NameEntry<'a> {
    #[serde(default, borrow)]
    package: NamePackage<'a>,
}

#[derive(Deserialize, Default)]
struct NamePackage<'a> {
    #[serde(default, borrow)]
    ecosystem: Option<std::borrow::Cow<'a, str>>,
    #[serde(default, borrow)]
    name: Option<std::borrow::Cow<'a, str>>,
}

/// One record's text to its advisories: none when an overlay replaces its id, and only kept
/// packages' when there is a filter. A record no kept package is in is not parsed in full.
fn record_advisories<V: Ord + Clone>(
    body: &str,
    spec: &Spec<V>,
    skip: &BTreeSet<String>,
    keep: Option<Keep<'_>>,
) -> Result<Vec<(String, Advisory<V>)>, serde_json::Error> {
    if let Some(keep) = keep {
        let names: Names<'_> = serde_json::from_str(body)?;
        let wanted = names.affected.iter().any(|a| {
            a.package.ecosystem.as_deref() == Some(spec.ecosystem)
                && a.package
                    .name
                    .as_deref()
                    .is_some_and(|n| keep(&(spec.normalize_name)(n)))
        });
        if !wanted {
            return Ok(Vec::new());
        }
    }
    let osv: OsvRecord = serde_json::from_str(body)?;
    if skip.contains(&osv.id) {
        return Ok(Vec::new());
    }
    let mut out = advisories_from(osv, spec);
    if let Some(keep) = keep {
        out.retain(|(name, _)| keep(name));
    }
    Ok(out)
}

/// A record's `(ecosystem, name)` pairs as written, and the advisories it gives.
type Named<V> = (Vec<(String, String)>, Vec<(String, Advisory<V>)>);

/// [`record_advisories`] with a filter, also giving the record's `(ecosystem, name)` pairs
/// as written, for the [`NamesIndex`].
fn record_advisories_naming<V: Ord + Clone>(
    body: &str,
    spec: &Spec<V>,
    skip: &BTreeSet<String>,
    keep: Keep<'_>,
) -> Result<Named<V>, serde_json::Error> {
    let names: Names<'_> = serde_json::from_str(body)?;
    let pairs: Vec<(String, String)> = names
        .affected
        .iter()
        .filter_map(|a| {
            Some((
                a.package.ecosystem.as_deref()?.to_string(),
                a.package.name.as_deref()?.to_string(),
            ))
        })
        .collect();
    let wanted = pairs
        .iter()
        .any(|(e, n)| e == spec.ecosystem && keep(&(spec.normalize_name)(n)));
    if !wanted {
        return Ok((pairs, Vec::new()));
    }
    let out = record_advisories(body, spec, skip, Some(keep))?;
    Ok((pairs, out))
}

fn load_dir<V>(
    root: &Path,
    spec: &Spec<V>,
    skip: &BTreeSet<String>,
    keep: Option<Keep<'_>>,
) -> Result<OsvDb<V>, LoadError>
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
            record_advisories(&body, spec, skip, keep).map_err(|e| LoadError::new(path, e))
        })
        .collect::<Result<_, LoadError>>()?;

    Ok(OsvDb {
        kept: None,
        by_package: merge(per_file),
    })
}

fn load_zip<V>(
    path: &Path,
    spec: &Spec<V>,
    skip: &BTreeSet<String>,
    keep: Option<Keep<'_>>,
) -> Result<OsvDb<V>, LoadError>
where
    V: Ord + Clone + Send,
{
    let archive = crate::zipdir::Archive::open(path, |name| name.ends_with(".json"))
        .map_err(|e| LoadError::new(path, zip_error(e)))?;
    let text = |body: std::io::Result<Vec<u8>>| {
        body.and_then(|b| String::from_utf8(b).map_err(|_| crate::zipdir::not_utf8()))
            .map_err(|e| LoadError::new(path, zip_error(e)))
    };

    let per_entry: Vec<Vec<(String, Advisory<V>)>> = match keep {
        None => archive
            .par_read(|body| {
                record_advisories(&text(body)?, spec, skip, None)
                    .map_err(|e| LoadError::new(path, e))
            })
            .into_iter()
            .collect::<Result<_, LoadError>>()?,
        Some(keep) => match NamesIndex::read(path, &archive) {
            // Only the records naming a kept package are read at all.
            Some(index) => {
                let wanted = index.members_naming(spec, keep);
                archive
                    .par_read_some(wanted, |body| {
                        record_advisories(&text(body)?, spec, skip, Some(keep))
                            .map_err(|e| LoadError::new(path, e))
                    })
                    .into_iter()
                    .map(|(_, r)| r)
                    .collect::<Result<_, LoadError>>()?
            }
            // Every record is read as far as its names, which are saved for the next load.
            None => {
                let read: Vec<Named<V>> = archive
                    .par_read(|body| {
                        record_advisories_naming(&text(body)?, spec, skip, keep)
                            .map_err(|e| LoadError::new(path, e))
                    })
                    .into_iter()
                    .collect::<Result<_, LoadError>>()?;
                let (names, per_entry): (Vec<_>, Vec<_>) = read.into_iter().unzip();
                NamesIndex::build(&archive, names).write(path);
                per_entry
            }
        },
    };

    Ok(OsvDb {
        kept: None,
        by_package: merge(per_entry),
    })
}

/// `all.zip.names.json`: the `(ecosystem, name)` pairs of every record of an `all.zip`, as
/// written (not normalized), in member order, tied to the zip by its central directory. With
/// it a load that keeps a few packages reads only their records; any other zip, or a file
/// that does not parse, and the load reads every record as before.
#[derive(Serialize, Deserialize)]
struct NamesIndex {
    schema: u32,
    fingerprint: String,
    /// Every ecosystem and name, once.
    strings: Vec<String>,
    /// Per member, its pairs as indices into `strings`.
    members: Vec<Vec<(u32, u32)>>,
}

const NAMES_SCHEMA: u32 = 1;

impl NamesIndex {
    fn path(zip: &Path) -> PathBuf {
        let mut name = zip.file_name().unwrap_or_default().to_os_string();
        name.push(".names.json");
        zip.with_file_name(name)
    }

    fn read(zip: &Path, archive: &crate::zipdir::Archive) -> Option<NamesIndex> {
        let body = std::fs::read(Self::path(zip)).ok()?;
        let index: NamesIndex = serde_json::from_slice(&body).ok()?;
        let fits = index.schema == NAMES_SCHEMA
            && index.fingerprint == archive.fingerprint()
            && index.members.len() == archive.len()
            && index.members.iter().flatten().all(|&(e, n)| {
                (e as usize) < index.strings.len() && (n as usize) < index.strings.len()
            });
        fits.then_some(index)
    }

    fn build(archive: &crate::zipdir::Archive, names: Vec<Vec<(String, String)>>) -> NamesIndex {
        let mut strings: Vec<String> = Vec::new();
        let mut at: HashMap<String, u32> = HashMap::new();
        let mut id = |s: String| -> u32 {
            if let Some(&i) = at.get(&s) {
                return i;
            }
            let i = u32::try_from(strings.len()).unwrap_or(u32::MAX);
            strings.push(s.clone());
            at.insert(s, i);
            i
        };
        let members = names
            .into_iter()
            .map(|pairs| pairs.into_iter().map(|(e, n)| (id(e), id(n))).collect())
            .collect();
        NamesIndex {
            schema: NAMES_SCHEMA,
            fingerprint: archive.fingerprint().to_string(),
            strings,
            members,
        }
    }

    /// Saved next to the zip when the directory takes it; a load never fails over it.
    fn write(&self, zip: &Path) {
        if u32::try_from(self.strings.len()).is_err() {
            return;
        }
        let Ok(body) = serde_json::to_vec(self) else {
            return;
        };
        let path = Self::path(zip);
        let mut tmp = path.clone().into_os_string();
        tmp.push(format!(".{}.partial", std::process::id()));
        let tmp = PathBuf::from(tmp);
        if std::fs::write(&tmp, body).is_ok() && std::fs::rename(&tmp, &path).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }

    /// The members a record of which names a package `keep` accepts in `spec`'s ecosystem:
    /// the records [`record_advisories`] would not pass over.
    fn members_naming<V>(&self, spec: &Spec<V>, keep: Keep<'_>) -> Vec<usize> {
        let mut wanted_string = vec![None::<bool>; self.strings.len()];
        let mut wanted = |n: u32| -> bool {
            let slot = &mut wanted_string[n as usize];
            *slot.get_or_insert_with(|| keep(&(spec.normalize_name)(&self.strings[n as usize])))
        };
        self.members
            .iter()
            .enumerate()
            .filter(|(_, pairs)| {
                pairs
                    .iter()
                    .any(|&(e, n)| self.strings[e as usize] == spec.ecosystem && wanted(n))
            })
            .map(|(i, _)| i)
            .collect()
    }
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

/// The `(normalized name, advisory)` pairs one OSV record contributes: one per package among
/// its `affected[]` entries whose `package.ecosystem` matches [`Spec::ecosystem`], with the
/// ranges and versions of every entry for that package (GHSA writes one entry per release
/// line, and the safe versions of one line depend on the others). Bounds and versions are
/// parsed once here. Exposed for feeder unit tests.
pub fn advisories_from<V>(osv: OsvRecord, spec: &Spec<V>) -> Vec<(String, Advisory<V>)>
where
    V: Ord + Clone,
{
    // A withdrawn record is a retraction: OSV keeps it in the export so consumers can drop
    // what they already reported, but it must never match. Only the rustsec path checked this
    // before, so every OSV feeder reported retracted advisories.
    if osv.withdrawn.is_some() {
        return Vec::new();
    }
    let (severity, cvss_score) = (spec.severity)(&osv);
    let cvss_vector = cvss_vector_of(&osv);
    let entries: Vec<(String, Advisory<V>)> = osv
        .affected
        .iter()
        .filter(|a| a.package.ecosystem.as_deref() == Some(spec.ecosystem))
        .filter_map(|affected| {
            let name = (spec.normalize_name)(affected.package.name.as_deref()?);
            let ranges = affected
                .ranges
                .iter()
                .map(|r| {
                    let range = Range {
                        matchable: r
                            .kind
                            .as_deref()
                            .is_some_and(|k| spec.range_type.split('|').any(|t| t == k)),
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
                    cvss_vector: cvss_vector.clone(),
                    ranges,
                    versions,
                },
            ))
        })
        .collect();
    let mut merged: Vec<(String, Advisory<V>)> = Vec::new();
    for (name, adv) in entries {
        match merged.iter_mut().find(|(n, _)| *n == name) {
            Some((_, into)) => {
                into.ranges.extend(adv.ranges);
                into.versions.extend(adv.versions);
                into.versions.sort();
                into.versions.dedup();
            }
            None => merged.push((name, adv)),
        }
    }
    merged
}

/// The record's CVSS vector: the first `CVSS_V3` entry, else the first `CVSS_V4`.
pub fn cvss_vector_of(osv: &OsvRecord) -> Option<String> {
    cvss_vector_in(&osv.severity)
}

/// [`cvss_vector_of`], from a record's `severity[]`.
pub fn cvss_vector_in(entries: &[SeverityEntry]) -> Option<String> {
    ["CVSS_V3", "CVSS_V4"].iter().find_map(|kind| {
        entries
            .iter()
            .find(|s| s.kind.as_deref() == Some(kind))
            .and_then(|s| s.score.clone())
    })
}

/// The default `(severity, cvss_score)` derivation: prefer the curated GHSA band
/// (`database_specific.severity`), and take the best CVSS_V3 base score across the record's
/// `severity[]` vectors (deriving the band from it when no GHSA band is present).
pub fn default_severity(osv: &OsvRecord) -> (Severity, Option<f32>) {
    severity_from(&osv.severity, osv.database_specific.as_ref())
}

/// [`default_severity`], from the two parts of a record it reads.
pub fn severity_from(
    entries: &[SeverityEntry],
    database_specific: Option<&DatabaseSpecific>,
) -> (Severity, Option<f32>) {
    let band = database_specific
        .and_then(|d| d.severity.as_deref())
        .map(band_from_label)
        .unwrap_or(Severity::Unknown);

    let scored: Option<(Severity, f32)> = entries
        .iter()
        .filter(|s| s.kind.as_deref() == Some("CVSS_V3"))
        .filter_map(|s| cvss::v3::Vector::from_str(s.score.as_deref()?).ok())
        .map(|vector| {
            let score = vector.base_score();
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
    occ_key(v).0
}

/// The `(package, installed version)` of a finding's first occurrence.
fn occ_key(v: &VulnFinding) -> (&str, Option<&Version>) {
    match v.occurrences.first() {
        Some(Occurrence::InRepo {
            package, installed, ..
        }) => (package, Some(installed)),
        _ => ("", None),
    }
}

/// Sort by `(advisory id, package, installed version)` and dedup on that triple — the
/// deterministic ordering every feeder emits. The same package+version can resolve many times
/// in a lockfile, but a multi-package advisory legitimately yields one finding per *distinct*
/// package, and a lockfile can hold the same package at several versions (npm nests a
/// conflicting copy under its dependent), each of which needs its own fix, so the version is
/// part of the key. Advisories that are the same vulnerability under different ids are then
/// collapsed by [`collapse_alias_duplicates`].
pub fn sort_dedup_findings(out: &mut Vec<VulnFinding>) {
    out.sort_by(|a, b| {
        a.advisory_id
            .cmp(&b.advisory_id)
            .then_with(|| occ_key(a).cmp(&occ_key(b)))
    });
    out.dedup_by(|a, b| a.advisory_id == b.advisory_id && occ_key(a) == occ_key(b));
    collapse_alias_duplicates(out);
}

/// Merge findings on the same package+version that are one vulnerability published under
/// several ids. osv.dev carries, e.g., both a `PYSEC-` and a `GHSA-` record for most PyPI
/// vulnerabilities, each listing the other (or a shared CVE) in `aliases`; reporting both
/// double-counts. Findings whose `{id} + aliases` sets overlap (transitively) are one cluster.
/// The kept id is chosen from the records alone (`representative_rank`) so every repo picks
/// the same one; the others' ids move into its `aliases` (so ignores and VEX naming any of them
/// still apply) and it takes the cluster's worst severity and highest CVSS score.
pub fn collapse_alias_duplicates(out: &mut Vec<VulnFinding>) {
    let mut groups: BTreeMap<(&str, Option<&Version>), Vec<usize>> = BTreeMap::new();
    for (i, finding) in out.iter().enumerate() {
        groups.entry(occ_key(finding)).or_default().push(i);
    }

    // (kept index, absorbed indices) per multi-member cluster.
    let mut merges: Vec<(usize, Vec<usize>)> = Vec::new();
    for members in groups.values().filter(|m| m.len() > 1) {
        let ids: Vec<BTreeSet<&str>> = members
            .iter()
            .map(|&i| {
                std::iter::once(out[i].advisory_id.as_str())
                    .chain(out[i].aliases.iter().map(String::as_str))
                    .collect()
            })
            .collect();
        let mut parent: Vec<usize> = (0..members.len()).collect();
        for a in 0..members.len() {
            for b in a + 1..members.len() {
                if !ids[a].is_disjoint(&ids[b]) {
                    let (ra, rb) = (find_root(&mut parent, a), find_root(&mut parent, b));
                    if ra != rb {
                        parent[rb] = ra;
                    }
                }
            }
        }
        let mut clusters: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (a, &member) in members.iter().enumerate() {
            clusters
                .entry(find_root(&mut parent, a))
                .or_default()
                .push(member);
        }
        for cluster in clusters.into_values().filter(|c| c.len() > 1) {
            let Some(&kept) = cluster
                .iter()
                .min_by(|&&x, &&y| representative_rank(&out[x]).cmp(&representative_rank(&out[y])))
            else {
                continue;
            };
            merges.push((kept, cluster.into_iter().filter(|&i| i != kept).collect()));
        }
    }

    let mut absorbed = vec![false; out.len()];
    for (kept, others) in merges {
        let mut aliases: BTreeSet<String> = out[kept].aliases.iter().cloned().collect();
        let (mut severity, mut cvss) = (out[kept].severity, out[kept].cvss_score);
        let mut vector = out[kept].cvss_vector.clone();
        for &i in &others {
            absorbed[i] = true;
            aliases.insert(out[i].advisory_id.clone());
            aliases.extend(out[i].aliases.iter().cloned());
            severity = severity.max(out[i].severity);
            if vector.is_none() {
                vector = out[i].cvss_vector.clone();
            }
            cvss = match (cvss, out[i].cvss_score) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
        }
        aliases.remove(&out[kept].advisory_id);
        let finding = &mut out[kept];
        finding.aliases = aliases.into_iter().collect();
        finding.severity = severity;
        finding.cvss_score = cvss;
        finding.cvss_vector = vector;
    }
    let mut i = 0;
    out.retain(|_| {
        let keep = !absorbed[i];
        i += 1;
        keep
    });
}

/// Which id of an alias cluster is reported (lowest wins): a `GO-` record, then a GHSA (the
/// curated record with a severity band and summary) over any other id, and anything over a
/// GitHub "Duplicate Advisory" record; ties go to the smaller id, so the choice is deterministic.
fn representative_rank(v: &VulnFinding) -> (u8, &str) {
    let duplicate = v.title.starts_with("Duplicate Advisory");
    // A `GO-` record names the affected symbols, which its GitHub twin does not.
    let rank = match (duplicate, v.advisory_id.split('-').next()) {
        (true, _) => 3,
        (false, Some("GO")) => 0,
        (false, Some("GHSA")) => 1,
        (false, _) => 2,
    };
    (rank, v.advisory_id.as_str())
}

/// Union-find root with path halving.
fn find_root(parent: &mut [usize], mut x: usize) -> usize {
    while parent[x] != x {
        parent[x] = parent[parent[x]];
        x = parent[x];
    }
    x
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
    /// The advisory's CVSS vector string, when it carries one.
    pub cvss_vector: Option<String>,
    /// The affected package name.
    pub package: String,
    /// The installed version, in the shared SemVer model (already coerced by the feeder).
    pub installed: Version,
    /// Versions that fix the advisory; empty means "no fix available".
    pub patched: Vec<VersionReq>,
    /// Whether the package is a direct dependency.
    pub direct: bool,
    /// Whether the package is reachable only through dev/build dependency groups; `false`
    /// where the feeder's lockfile does not record scope (the conservative default).
    pub dev: bool,
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
            // Some summaries carry stray spaces (` cowlib cow_http_te module: ...`).
            title: self.title.split_whitespace().collect::<Vec<_>>().join(" "),
            severity: self.severity,
            cvss_score: self.cvss_score,
            cvss_vector: self.cvss_vector,
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
                scope: if self.dev {
                    DepScope::Dev
                } else {
                    DepScope::Runtime
                },
                layer: None,
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
    /// Set (to the retraction timestamp) when the advisory was withdrawn.
    pub withdrawn: Option<String>,
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

    fn parsed(events: &[(&str, &str)]) -> Vec<ParsedRange<Version>> {
        let range = Range {
            matchable: true,
            events: events
                .iter()
                .map(|(k, val)| Event {
                    introduced: (*k == "introduced").then(|| val.to_string()),
                    fixed: (*k == "fixed").then(|| val.to_string()),
                    last_affected: (*k == "last_affected").then(|| val.to_string()),
                })
                .collect(),
        };
        vec![parse_range(&range, |raw| {
            if raw == "0" {
                Some(Version::new(0, 0, 0))
            } else {
                Version::parse(raw).ok()
            }
        })]
    }

    #[test]
    fn safe_intervals_stop_where_a_later_branch_reintroduces_the_bug() {
        // grpc GO-2026-6443: fixed 1.82.2, re-introduced 1.83.0, fixed 1.83.2.
        let r = parsed(&[
            ("introduced", "0"),
            ("fixed", "1.82.2"),
            ("introduced", "1.83.0"),
            ("fixed", "1.83.2"),
        ]);
        let safe = safe_intervals(&v("1.46.0"), &r);
        assert_eq!(
            safe,
            [(v("1.82.2"), Some(v("1.83.0"))), (v("1.83.2"), None)]
        );
        let reqs = patched_reqs(&safe, ToString::to_string);
        let ok = |s: &str| reqs.iter().any(|r| r.matches(&v(s)));
        assert!(ok("1.82.5") && ok("1.83.2") && ok("1.90.0"));
        assert!(!ok("1.83.1"), "re-introduced");
        // From inside the second interval only the later fix is safe.
        assert_eq!(safe_intervals(&v("1.83.0"), &r), [(v("1.83.2"), None)]);
        // Not affected, or no fix: nothing.
        assert!(safe_intervals(&v("1.82.3"), &r).is_empty());
        let open = parsed(&[("introduced", "0"), ("last_affected", "2.0.0")]);
        assert!(safe_intervals(&v("1.0.0"), &open).is_empty());
    }

    #[test]
    fn safe_intervals_see_every_range_not_only_the_matching_one() {
        // js-yaml GHSA-2883: one range per line, 3.x fixed in 3.15.2 and 4.x in 4.3.2.
        let mut r = parsed(&[("introduced", "4.0.0"), ("fixed", "4.3.2")]);
        r.extend(parsed(&[("introduced", "3.0.0"), ("fixed", "3.15.2")]));
        assert_eq!(
            safe_intervals(&v("3.14.1"), &r),
            [(v("3.15.2"), Some(v("4.0.0"))), (v("4.3.2"), None)]
        );
        assert_eq!(safe_intervals(&v("4.1.0"), &r), [(v("4.3.2"), None)]);
        // A fix inside another range's affected span is not a safe start.
        let mut r = parsed(&[("introduced", "0"), ("fixed", "2.0.0")]);
        r.extend(parsed(&[("introduced", "1.5.0"), ("fixed", "2.1.0")]));
        assert_eq!(safe_intervals(&v("1.0.0"), &r), [(v("2.1.0"), None)]);
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

    fn finding(
        id: &str,
        aliases: &[&str],
        title: &str,
        severity: Severity,
        package: &str,
        installed: &str,
    ) -> VulnFinding {
        let repo = RepoId("r".into());
        TierCFinding {
            ecosystem: Ecosystem::Npm,
            advisory_id: id.into(),
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
            title: title.into(),
            severity,
            cvss_score: None,
            cvss_vector: None,
            package: package.into(),
            installed: v(installed),
            patched: Vec::new(),
            direct: false,
            dependency_path: Vec::new(),
            repo: &repo,
            reach_reason: "test",
            dev: false,
        }
        .build()
    }

    fn keys(out: &[VulnFinding]) -> Vec<(String, String)> {
        out.iter()
            .map(|f| match f.occurrences.first() {
                Some(Occurrence::InRepo { installed, .. }) => {
                    (f.advisory_id.clone(), installed.to_string())
                }
                _ => (f.advisory_id.clone(), String::new()),
            })
            .collect()
    }

    #[test]
    fn dedup_keeps_each_vulnerable_version() {
        // npm nests a conflicting copy (`resources/node_modules/core@2.5.1`) beside the
        // top-level `core@1.30.1`; both are vulnerable and need separate fixes.
        let mut out = vec![
            finding("GHSA-a", &[], "t", Severity::High, "core", "2.5.1"),
            finding("GHSA-a", &[], "t", Severity::High, "core", "1.30.1"),
            finding("GHSA-a", &[], "t", Severity::High, "core", "2.5.1"),
        ];
        sort_dedup_findings(&mut out);
        assert_eq!(
            keys(&out),
            vec![
                ("GHSA-a".to_string(), "1.30.1".to_string()),
                ("GHSA-a".to_string(), "2.5.1".to_string()),
            ]
        );
    }

    #[test]
    fn alias_duplicates_collapse_to_one_finding() {
        // The PyPI shape: a PYSEC and a GHSA record for one bug, linked through aliases (here
        // transitively, via a shared CVE and a GitHub "Duplicate Advisory").
        let mut out = vec![
            finding(
                "PYSEC-2026-1",
                &["CVE-2026-1", "GHSA-b"],
                "PYSEC-2026-1",
                Severity::Unknown,
                "pillow",
                "12.3.0",
            ),
            finding(
                "GHSA-b",
                &["CVE-2026-1"],
                "Heap overflow",
                Severity::High,
                "pillow",
                "12.3.0",
            ),
            finding(
                "GHSA-a",
                &["CVE-2026-1"],
                "Duplicate Advisory: Heap overflow",
                Severity::Critical,
                "pillow",
                "12.3.0",
            ),
            finding(
                "GHSA-z",
                &["CVE-2026-9"],
                "Unrelated",
                Severity::Low,
                "pillow",
                "12.3.0",
            ),
        ];
        sort_dedup_findings(&mut out);
        assert_eq!(
            keys(&out),
            vec![
                ("GHSA-b".to_string(), "12.3.0".to_string()),
                ("GHSA-z".to_string(), "12.3.0".to_string()),
            ]
        );
        let kept = &out[0];
        assert_eq!(kept.aliases, vec!["CVE-2026-1", "GHSA-a", "PYSEC-2026-1"]);
        assert_eq!(
            kept.severity,
            Severity::Critical,
            "takes the cluster's worst band"
        );
        assert_eq!(kept.title, "Heap overflow");
    }

    #[test]
    fn alias_collapse_is_per_package_version() {
        // The same pair on two different installed versions stays two findings each: the
        // collapse never merges across versions or packages.
        let mut out = vec![
            finding("PYSEC-1", &["GHSA-x"], "p", Severity::High, "a", "1.0.0"),
            finding("GHSA-x", &["PYSEC-1"], "g", Severity::High, "a", "1.0.0"),
            finding("GHSA-x", &["PYSEC-1"], "g", Severity::High, "a", "2.0.0"),
            finding("PYSEC-1", &["GHSA-x"], "p", Severity::High, "b", "1.0.0"),
        ];
        sort_dedup_findings(&mut out);
        assert_eq!(
            keys(&out),
            vec![
                ("GHSA-x".to_string(), "1.0.0".to_string()),
                ("GHSA-x".to_string(), "2.0.0".to_string()),
                ("PYSEC-1".to_string(), "1.0.0".to_string()),
            ]
        );
    }

    fn semver_spec() -> Spec<Version> {
        Spec {
            ecosystem: "npm",
            range_type: "SEMVER",
            parse_version: |s| Version::parse(if s == "0" { "0.0.0" } else { s }).ok(),
            normalize_name: |n| n.to_string(),
            use_versions: false,
            severity: default_severity,
        }
    }

    fn record(id: &str, name: &str, fixed: &str, extra: &str) -> String {
        format!(
            r#"{{"id":"{id}"{extra},"affected":[{{"package":{{"ecosystem":"npm","name":"{name}"}},
            "ranges":[{{"type":"SEMVER","events":[{{"introduced":"0"}},{{"fixed":"{fixed}"}}]}}]}}]}}"#
        )
    }

    #[test]
    fn a_db_loaded_for_named_packages_notices_any_other_lookup() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("GHSA-1.json"),
            record("GHSA-1", "a", "1.0.0", ""),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("GHSA-2.json"),
            record("GHSA-2", "b", "2.0.0", ""),
        )
        .unwrap();
        let db = load_names(dir.path(), None, &semver_spec(), ["a"]).unwrap();
        assert_eq!(db.advisories_for("a").len(), 1);
        assert!(!db.missed(), "a kept name is no miss");
        assert!(db.advisories_for("b").is_empty(), "b was not loaded");
        assert!(db.missed(), "asking for b must be noticed");
        let full = load(dir.path(), &semver_spec()).unwrap();
        assert_eq!(full.advisories_for("b").len(), 1);
        assert!(!full.missed(), "a full DB never misses");
    }

    fn write_zip(path: &Path, records: &[(&str, String)]) {
        use std::io::Write;
        let mut out = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in records {
            out.start_file(*name, options).unwrap();
            out.write_all(body.as_bytes()).unwrap();
        }
        out.finish().unwrap();
    }

    fn ids(db: &OsvDb<Version>, name: &str) -> Vec<String> {
        db.advisories_for(name)
            .iter()
            .map(|a| a.id.clone())
            .collect()
    }

    #[test]
    fn a_names_index_reads_only_the_records_it_needs_and_follows_the_zip() {
        let dir = tempfile::tempdir().unwrap();
        let zip = dir.path().join("all.zip");
        let sidecar = dir.path().join("all.zip.names.json");
        write_zip(
            &zip,
            &[
                ("GHSA-1.json", record("GHSA-1", "a", "1.0.0", "")),
                ("GHSA-2.json", record("GHSA-2", "b", "2.0.0", "")),
                ("GHSA-3.json", record("GHSA-3", "a", "3.0.0", "")),
            ],
        );
        let spec = semver_spec();
        let first = load_names(&zip, None, &spec, ["a"]).unwrap();
        assert_eq!(ids(&first, "a"), ["GHSA-1", "GHSA-3"]);
        assert!(sidecar.is_file(), "the first filtered load saves the names");
        let index: NamesIndex = serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
        let archive = crate::zipdir::Archive::open(&zip, |n| n.ends_with(".json")).unwrap();
        assert_eq!(index.members_naming(&spec, &|k: &str| k == "b"), [1]);
        assert_eq!(
            ids(&load_names(&zip, None, &spec, ["a"]).unwrap(), "a"),
            ["GHSA-1", "GHSA-3"]
        );

        // A record now naming `a` too, at the same size: the zip changed, so the index is
        // read again rather than trusted, and the record is not missed.
        write_zip(
            &zip,
            &[
                ("GHSA-1.json", record("GHSA-1", "a", "1.0.0", "")),
                ("GHSA-2.json", record("GHSA-2", "a", "2.0.0", "")),
                ("GHSA-3.json", record("GHSA-3", "a", "3.0.0", "")),
            ],
        );
        assert_ne!(
            crate::zipdir::Archive::open(&zip, |n| n.ends_with(".json"))
                .unwrap()
                .fingerprint(),
            archive.fingerprint()
        );
        let changed = load_names(&zip, None, &spec, ["a"]).unwrap();
        assert_eq!(ids(&changed, "a"), ["GHSA-1", "GHSA-2", "GHSA-3"]);

        // An index of another zip, or one that does not parse, is passed over.
        let other = dir.path().join("other.zip");
        write_zip(
            &other,
            &[("GHSA-9.json", record("GHSA-9", "z", "1.0.0", ""))],
        );
        load_names(&other, None, &spec, ["z"]).unwrap();
        std::fs::copy(dir.path().join("other.zip.names.json"), &sidecar).unwrap();
        assert_eq!(
            ids(&load_names(&zip, None, &spec, ["a"]).unwrap(), "a").len(),
            3
        );
        std::fs::write(&sidecar, b"{not json").unwrap();
        assert_eq!(
            ids(&load_names(&zip, None, &spec, ["a"]).unwrap(), "a").len(),
            3
        );
        // And a full load never needs it.
        assert_eq!(ids(&load(&zip, &spec).unwrap(), "a").len(), 3);
    }

    #[test]
    fn a_names_index_never_hides_a_broken_record_it_has_not_seen() {
        let dir = tempfile::tempdir().unwrap();
        let zip = dir.path().join("all.zip");
        write_zip(
            &zip,
            &[
                ("GHSA-1.json", record("GHSA-1", "a", "1.0.0", "")),
                ("GHSA-2.json", "{broken".to_string()),
            ],
        );
        assert!(load_names(&zip, None, &semver_spec(), ["a"]).is_err());
        assert!(
            !dir.path().join("all.zip.names.json").exists(),
            "no index of a zip that does not read in full"
        );
    }

    #[test]
    fn overlay_replaces_adds_and_retracts() {
        let root = std::env::temp_dir().join(format!("fr-core-overlay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (up, ov) = (root.join("npm"), root.join("advisories"));
        std::fs::create_dir_all(&up).unwrap();
        std::fs::create_dir_all(ov.join("nested")).unwrap();
        std::fs::write(up.join("GHSA-1.json"), record("GHSA-1", "a", "1.0.0", "")).unwrap();
        std::fs::write(up.join("GHSA-2.json"), record("GHSA-2", "b", "2.0.0", "")).unwrap();
        std::fs::write(up.join("GHSA-3.json"), record("GHSA-3", "c", "3.0.0", "")).unwrap();
        // Correct GHSA-1's fix, retract GHSA-2, add ORG-1 (in a subdirectory).
        std::fs::write(ov.join("GHSA-1.json"), record("GHSA-1", "a", "1.5.0", "")).unwrap();
        std::fs::write(
            ov.join("GHSA-2.json"),
            record(
                "GHSA-2",
                "b",
                "2.0.0",
                r#","withdrawn":"2025-01-01T00:00:00Z""#,
            ),
        )
        .unwrap();
        std::fs::write(
            ov.join("nested/ORG-1.json"),
            record("ORG-1", "d", "4.0.0", ""),
        )
        .unwrap();
        std::fs::write(ov.join(".hidden.json"), "not json").unwrap();

        let spec = semver_spec();
        let plain = load(&up, &spec).unwrap();
        assert_eq!(plain.len(), 3);
        let db = load_with_overlay(&up, Some(&ov), &spec).unwrap();
        let fixes = |key: &str| -> Vec<String> {
            db.advisories_for(key)
                .iter()
                .flat_map(|a| &a.ranges)
                .flat_map(|r| &r.events)
                .filter_map(|e| e.fixed.as_ref().map(ToString::to_string))
                .collect()
        };
        assert_eq!(fixes("a"), ["1.5.0"], "replaced, not duplicated");
        assert!(db.advisories_for("b").is_empty(), "retracted");
        assert_eq!(fixes("c"), ["3.0.0"], "untouched");
        assert_eq!(fixes("d"), ["4.0.0"], "added");
        assert_eq!(db.iter().count(), 3);
        assert!(load_with_overlay(&up, None, &spec).unwrap().len() == 3);

        // A broken overlay record fails the load rather than being skipped.
        std::fs::write(ov.join("bad.json"), "{").unwrap();
        let err = load_with_overlay(&up, Some(&ov), &spec).unwrap_err();
        assert!(err.path.ends_with("bad.json"));
        assert!(load_with_overlay(&up, Some(&root.join("missing")), &spec).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
