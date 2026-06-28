//! The only fleetreach crate that touches `rustsec`: load the advisory DB, scan a
//! lockfile, and map the engine's types onto `fleetreach-core`.
//!
//! `fleetreach-scan` wraps the audited `rustsec` engine (the library `cargo-audit`
//! is built on). No `rustsec` type appears in this crate's public API, so the
//! engine stays a quarantined dependency and callers see only `core` types. It
//! scans one `Cargo.lock` (and optionally the toolchain), recording one
//! occurrence per finding; cross-repo grouping lives in `fleetreach-correlate`.
//!
//! # Usage
//!
//! ```sh
//! cargo add fleetreach-scan
//! ```
//!
//! ```no_run
//! use std::path::Path;
//!
//! use fleetreach_core::RepoId;
//! use fleetreach_scan::{scan_lockfile, AdvisoryDb};
//!
//! // Open a local advisory-db clone (always available). With the `network`
//! // feature, `AdvisoryDb::fetch()` clones the default DB from GitHub instead.
//! let db = AdvisoryDb::open(Path::new("advisory-db"))?;
//! let scan = scan_lockfile(&db, &RepoId("app".into()), Path::new("Cargo.lock"))?;
//! for vuln in &scan.vulnerabilities {
//!     println!("{}  {}", vuln.advisory_id, vuln.title);
//! }
//! # Ok::<(), fleetreach_scan::ScanError>(())
//! ```
//!
//! # Minimum supported Rust version
//!
//! 1.89. An MSRV increase is treated as a minor-version bump.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::path::Path;

use fleetreach_core::semver::Version;
use fleetreach_core::{
    DepSource, DependencyKind, Occurrence, RepoId, Severity, VulnFinding, WarnFinding, WarnKind,
};
use rustsec::advisory::Informational;
use rustsec::cargo_lock::dependency::graph::{EdgeDirection, NodeIndex};
use rustsec::cargo_lock::dependency::tree::Tree;
use rustsec::cargo_lock::dependency::Dependency;
use rustsec::cargo_lock::Package;
use rustsec::database::Query;
use rustsec::report::{Report, Settings};
// `DatabaseInfo` exposes the DB's git commit/timestamp, so it lives behind the git
// (`network`) feature; the pure-Rust build reports no DB provenance.
#[cfg(feature = "network")]
use rustsec::report::DatabaseInfo;
#[cfg(feature = "network")]
use rustsec::Repository;
use rustsec::{Collection, Database, Lockfile};

/// The exact `rustsec` engine version this build links, recorded in provenance.
pub const RUSTSEC_VERSION: &str = "0.33.0";

/// Errors surfaced while scanning. Engine errors are flattened to strings so no
/// `rustsec` error type leaks across the API boundary — but the *kind* is
/// preserved as a variant so callers can branch (e.g. suggest going online on a
/// cache miss) without string-matching.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// The advisory database could not be fetched or opened.
    #[error("failed to load advisory database: {0}")]
    DatabaseLoad(String),
    /// `--offline` was requested but no local advisory-db cache exists yet.
    #[error("no advisory-db cache at {path} (run once online, or pass --db)")]
    CacheMissing { path: String },
    /// A `Cargo.lock` could not be read or parsed.
    #[error("failed to read lockfile `{path}`: {message}")]
    Lockfile { path: String, message: String },
    /// An advisory id passed to `--explain` was not well-formed.
    #[error("malformed advisory id `{id}`")]
    MalformedAdvisoryId { id: String },
}

/// Advisory-DB provenance as plain strings, ready for `core::Provenance`.
/// Both fields are `None` for a DB opened from a non-git directory.
#[derive(Debug, Clone, Default)]
pub struct DatabaseMeta {
    /// git sha of the advisory-db commit used.
    pub commit: Option<String>,
    /// RFC3339 timestamp of that commit — the freshness signal.
    pub timestamp: Option<String>,
}

/// A loaded advisory database. Wraps the engine type so it never escapes.
pub struct AdvisoryDb {
    inner: Database,
}

impl AdvisoryDb {
    /// Fetch the default RustSec advisory DB from GitHub (performs network I/O).
    /// Requires the `network` feature; without it, the build is pure-Rust and the
    /// caller must supply a local DB via [`open`](Self::open).
    #[cfg(feature = "network")]
    pub fn fetch() -> Result<Self, ScanError> {
        Database::fetch()
            .map(|inner| Self { inner })
            .map_err(|e| ScanError::DatabaseLoad(e.to_string()))
    }

    /// Open a local advisory-db directory (offline). The directory must hold the
    /// RustSec layout: `<collection>/<crate>/RUSTSEC-*.md`.
    pub fn open(path: &Path) -> Result<Self, ScanError> {
        Database::open(path)
            .map(|inner| Self { inner })
            .map_err(|e| ScanError::DatabaseLoad(e.to_string()))
    }

    /// Open the default advisory-db cache without fetching (for `--offline`). The
    /// default cache path is the git-clone location, so this needs the `network`
    /// feature; a pure-Rust build passes an explicit `--db` to [`open`](Self::open).
    /// Errors if the cache has never been populated.
    #[cfg(feature = "network")]
    pub fn open_default_cache() -> Result<Self, ScanError> {
        let path = Repository::default_path();
        if !path.exists() {
            return Err(ScanError::CacheMissing {
                path: path.display().to_string(),
            });
        }
        Self::open(&path)
    }

    /// Age of the DB in whole seconds (now − last commit), or `None` if the DB
    /// has no commit metadata (e.g. opened from a non-git directory).
    #[cfg(feature = "network")]
    pub fn age_seconds(&self) -> Option<i64> {
        DatabaseInfo::new(&self.inner)
            .last_updated
            .map(|updated| (time::OffsetDateTime::now_utc() - updated).whole_seconds())
    }

    /// Without the `network` feature there is no git metadata to derive an age from.
    #[cfg(not(feature = "network"))]
    pub fn age_seconds(&self) -> Option<i64> {
        None
    }

    /// Render the full detail of a single advisory by id (for `--explain`).
    /// `Ok(None)` means the id parsed but is absent from the DB; `Err` means the
    /// id was malformed.
    pub fn explain(&self, advisory_id: &str) -> Result<Option<String>, ScanError> {
        let id = advisory_id.parse::<rustsec::advisory::Id>().map_err(|_| {
            ScanError::MalformedAdvisoryId {
                id: advisory_id.to_string(),
            }
        })?;
        Ok(self.inner.get(&id).map(format_advisory))
    }

    /// Commit sha + RFC3339 timestamp of the DB, for the report's provenance.
    #[cfg(feature = "network")]
    pub fn meta(&self) -> DatabaseMeta {
        let info = DatabaseInfo::new(&self.inner);
        DatabaseMeta {
            commit: info.last_commit,
            timestamp: info.last_updated.and_then(|t| {
                t.format(&time::format_description::well_known::Rfc3339)
                    .ok()
            }),
        }
    }

    /// A pure-Rust build has no git backend, so it reports no DB provenance.
    #[cfg(not(feature = "network"))]
    pub fn meta(&self) -> DatabaseMeta {
        DatabaseMeta::default()
    }
}

/// The result of scanning a single lockfile. Each finding carries exactly **one**
/// occurrence (this lockfile); fleet-wide grouping happens in `correlate`.
#[derive(Debug, Clone, Default)]
pub struct RepoScan {
    pub vulnerabilities: Vec<VulnFinding>,
    pub warnings: Vec<WarnFinding>,
}

/// Scan one `Cargo.lock` against the advisory database, returning both the
/// vulnerability and warning streams mapped to `core` types.
pub fn scan_lockfile(
    db: &AdvisoryDb,
    repo: &RepoId,
    lockfile_path: &Path,
) -> Result<RepoScan, ScanError> {
    let lockfile = Lockfile::load(lockfile_path).map_err(|e| ScanError::Lockfile {
        path: lockfile_path.display().to_string(),
        message: e.to_string(),
    })?;

    // We do NOT pass `ignore` here — ignore handling (with stale-ignore hygiene)
    // is applied downstream so we can report suppressions that matched nothing.
    // Warnings are opt-in: an empty `informational_warnings` yields zero warnings.
    let settings = Settings {
        informational_warnings: vec![
            Informational::Notice,
            Informational::Unmaintained,
            Informational::Unsound,
        ],
        ..Settings::default()
    };

    let report = Report::generate(&db.inner, &lockfile, &settings);

    // Best-effort dependency graph for provenance (who pulls each package in).
    // If it cannot be built, findings simply carry no path.
    let tree = lockfile.dependency_tree().ok();

    let vulnerabilities = report
        .vulnerabilities
        .list
        .iter()
        .map(|v| map_vulnerability(repo, v, tree.as_ref()))
        .collect();

    let warnings = report
        .warnings
        .values()
        .flatten()
        .map(|w| map_warning(repo, w, tree.as_ref()))
        .collect();

    Ok(RepoScan {
        vulnerabilities,
        warnings,
    })
}

/// The toolchain advisory streams (`Collection::Rust`). These are global — a
/// `std`/`rustc` soundness issue is not tied to any repo — so each finding's
/// occurrence is [`Occurrence::Toolchain`].
#[derive(Debug, Clone, Default)]
pub struct ToolchainScan {
    pub vulnerabilities: Vec<VulnFinding>,
    pub warnings: Vec<WarnFinding>,
}

/// Match the advisory DB's `rust` collection against an installed toolchain
/// version. `channel` is a human label for the toolchain (e.g. `"stable 1.96.0"`).
pub fn scan_toolchain(db: &AdvisoryDb, channel: &str, installed: &Version) -> ToolchainScan {
    let mut scan = ToolchainScan::default();

    // No package filter: collect every rust-collection advisory, then decide
    // applicability ourselves via the advisory's own version ranges.
    for advisory in db.inner.query(&Query::new().collection(Collection::Rust)) {
        let meta = &advisory.metadata;
        if meta.withdrawn.is_some() || !advisory.versions.is_vulnerable(installed) {
            continue;
        }

        let occurrence = Occurrence::Toolchain {
            channel: channel.to_string(),
            installed: Some(installed.clone()),
            patched: advisory.versions.patched().to_vec(),
        };

        match &meta.informational {
            Some(info) => {
                if let Some(kind) = info.warning_kind() {
                    scan.warnings.push(warn_finding(
                        Some(meta.id.to_string()),
                        meta.title.clone(),
                        map_warn_kind(kind),
                        occurrence,
                    ));
                }
            }
            // Toolchain advisories: no per-repo source to check, so no functions.
            None => scan
                .vulnerabilities
                .push(vuln_finding(meta, occurrence, Vec::new())),
        }
    }

    scan
}

fn map_vulnerability(
    repo: &RepoId,
    vuln: &rustsec::Vulnerability,
    tree: Option<&Tree>,
) -> VulnFinding {
    let (dependency_path, dependency_kind) = provenance(tree, &vuln.package);
    let occurrence = Occurrence::InRepo {
        repo: repo.clone(),
        package: vuln.package.name.as_str().to_string(),
        installed: vuln.package.version.clone(),
        patched: vuln.versions.patched().to_vec(),
        dependency_kind,
        dependency_path,
        active: None,
        source: dep_source(&vuln.package),
    };
    // Functions/types the advisory marks vulnerable at this installed version.
    let affected_functions = vuln
        .affected_functions()
        .unwrap_or_default()
        .iter()
        .map(ToString::to_string)
        .collect();
    vuln_finding(&vuln.advisory, occurrence, affected_functions)
}

fn map_warning(repo: &RepoId, warning: &rustsec::Warning, tree: Option<&Tree>) -> WarnFinding {
    let (dependency_path, dependency_kind) = provenance(tree, &warning.package);
    let occurrence = Occurrence::InRepo {
        repo: repo.clone(),
        package: warning.package.name.as_str().to_string(),
        installed: warning.package.version.clone(),
        patched: warning
            .versions
            .as_ref()
            .map(|v| v.patched().to_vec())
            .unwrap_or_default(),
        dependency_kind,
        dependency_path,
        active: None,
        source: dep_source(&warning.package),
    };
    warn_finding(
        warning.advisory.as_ref().map(|m| m.id.to_string()),
        warning
            .advisory
            .as_ref()
            .map(|m| m.title.clone())
            .unwrap_or_default(),
        map_warn_kind(warning.kind),
        occurrence,
    )
}

/// A way a package enters a repo's dependency tree (for `--why`).
#[derive(Debug, Clone)]
pub struct Route {
    pub version: String,
    /// Chain of package names from a root crate to the package.
    pub path: Vec<String>,
    pub direct: bool,
}

/// Every route by which a package (by name, any version) is pulled into a
/// lockfile's dependency tree — one shortest path per matching version.
pub fn routes_to(lockfile_path: &Path, package_name: &str) -> Result<Vec<Route>, ScanError> {
    let lockfile = Lockfile::load(lockfile_path).map_err(|e| ScanError::Lockfile {
        path: lockfile_path.display().to_string(),
        message: e.to_string(),
    })?;
    let tree = lockfile
        .dependency_tree()
        .map_err(|e| ScanError::Lockfile {
            path: lockfile_path.display().to_string(),
            message: e.to_string(),
        })?;

    let graph = tree.graph();
    let mut routes: Vec<Route> = tree
        .nodes()
        .iter()
        .filter(|(dep, _)| dep.name.as_str() == package_name)
        .filter_map(|(_, &idx)| {
            shortest_path_names(&tree, idx).map(|path| Route {
                version: graph[idx].version.to_string(),
                direct: path.len() <= 2,
                path,
            })
        })
        .collect();
    routes.sort_by(|a, b| a.version.cmp(&b.version));
    Ok(routes)
}

/// Map a package's lockfile source to the [`DepSource`] the VEX PURL needs (§4.1).
/// A lockfile entry with no `source` is a path/workspace-local crate; otherwise we
/// classify the `SourceId` (crates.io default registry, git remote + locked rev,
/// path, or another registry). Unknown future kinds fall through to the registry
/// arm (its URL is still the most useful identity).
fn dep_source(package: &Package) -> DepSource {
    match &package.source {
        None => DepSource::Path,
        Some(src) if src.is_default_registry() => DepSource::CratesIo,
        Some(src) if src.is_git() => DepSource::Git {
            url: src.url().to_string(),
            rev: src.precise().map(str::to_string),
        },
        Some(src) if src.is_path() => DepSource::Path,
        Some(src) => DepSource::OtherRegistry {
            url: src.url().to_string(),
        },
    }
}

/// Compute the dependency provenance of a flagged package from the lockfile's
/// graph: a shortest chain of package names from a root crate down to the
/// package, plus a Direct/Transitive classification. Returns an empty path and
/// `Transitive` when the graph is unavailable or the package is unreachable.
fn provenance(tree: Option<&Tree>, package: &Package) -> (Vec<String>, DependencyKind) {
    let Some(tree) = tree else {
        return (Vec::new(), DependencyKind::Transitive);
    };
    let Some(&target) = tree.nodes().get(&Dependency::from(package)) else {
        return (Vec::new(), DependencyKind::Transitive);
    };
    match shortest_path_names(tree, target) {
        // Direct: the package is a root, or a root depends on it directly
        // (path is [root, package]).
        Some(names) if names.len() <= 2 => (names, DependencyKind::Direct),
        Some(names) => (names, DependencyKind::Transitive),
        None => (Vec::new(), DependencyKind::Transitive),
    }
}

/// Shortest path (as package names) from any root to `target`, via a multi-source
/// BFS along dependent → dependency edges. `None` if `target` is unreachable.
fn shortest_path_names(tree: &Tree, target: NodeIndex) -> Option<Vec<String>> {
    let graph = tree.graph();
    let mut predecessor: BTreeMap<NodeIndex, NodeIndex> = BTreeMap::new();
    let mut visited: BTreeSet<NodeIndex> = tree.roots().into_iter().collect();
    let mut queue: VecDeque<NodeIndex> = visited.iter().copied().collect();
    while let Some(node) = queue.pop_front() {
        if node == target {
            break;
        }
        for neighbor in graph.neighbors_directed(node, EdgeDirection::Outgoing) {
            if visited.insert(neighbor) {
                predecessor.insert(neighbor, node);
                queue.push_back(neighbor);
            }
        }
    }
    if !visited.contains(&target) {
        return None;
    }

    let mut path = vec![target];
    let mut cursor = target;
    while let Some(&parent) = predecessor.get(&cursor) {
        path.push(parent);
        cursor = parent;
    }
    path.reverse();
    Some(
        path.iter()
            .map(|&idx| graph[idx].name.as_str().to_string())
            .collect(),
    )
}

/// Build a [`VulnFinding`] (one occurrence) from advisory metadata.
fn vuln_finding(
    meta: &rustsec::advisory::Metadata,
    occurrence: Occurrence,
    affected_functions: Vec<String>,
) -> VulnFinding {
    VulnFinding {
        advisory_id: meta.id.to_string(),
        aliases: meta.aliases.iter().map(ToString::to_string).collect(),
        ecosystem: fleetreach_core::Ecosystem::Cargo,
        affected_functions,
        reachable: None,
        reachability: None,
        exploit: Default::default(),
        title: meta.title.clone(),
        severity: map_severity(meta.cvss.as_ref().map(|cvss| cvss.severity())),
        cvss_score: meta.cvss.as_ref().map(|cvss| cvss.score() as f32),
        url: meta.url.as_ref().map(ToString::to_string),
        occurrences: vec![occurrence],
    }
}

fn warn_finding(
    advisory_id: Option<String>,
    title: String,
    kind: WarnKind,
    occurrence: Occurrence,
) -> WarnFinding {
    WarnFinding {
        kind,
        advisory_id,
        title,
        occurrences: vec![occurrence],
    }
}

/// Map CVSS qualitative severity to `core::Severity`. An absent score (or an
/// explicit CVSS "None"/0.0) becomes `Unknown`.
fn map_severity(severity: Option<rustsec::advisory::Severity>) -> Severity {
    use rustsec::advisory::Severity as Cvss;
    match severity {
        Some(Cvss::Low) => Severity::Low,
        Some(Cvss::Medium) => Severity::Medium,
        Some(Cvss::High) => Severity::High,
        Some(Cvss::Critical) => Severity::Critical,
        Some(Cvss::None) | None => Severity::Unknown,
    }
}

fn format_advisory(advisory: &rustsec::advisory::Advisory) -> String {
    let meta = &advisory.metadata;
    let mut out = String::new();
    let _ = writeln!(out, "{}  {}", meta.id, meta.title);
    if let Some(severity) = advisory.severity() {
        let _ = writeln!(out, "severity:  {severity:?}");
    }
    let _ = writeln!(out, "date:      {}", meta.date);
    if let Some(url) = &meta.url {
        let _ = writeln!(out, "url:       {url}");
    }
    if !meta.aliases.is_empty() {
        let aliases = meta
            .aliases
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let _ = writeln!(out, "aliases:   {}", aliases.join(", "));
    }
    let patched = advisory.versions.patched();
    if !patched.is_empty() {
        let patched = patched.iter().map(ToString::to_string).collect::<Vec<_>>();
        let _ = writeln!(out, "patched:   {}", patched.join(", "));
    }
    if let Some(affected) = &advisory.affected {
        if !affected.functions.is_empty() {
            let functions = affected
                .functions
                .keys()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            let _ = writeln!(out, "functions: {}", functions.join(", "));
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", meta.description.trim());
    out
}

fn map_warn_kind(kind: rustsec::WarningKind) -> WarnKind {
    match kind {
        rustsec::WarningKind::Notice => WarnKind::Notice,
        rustsec::WarningKind::Unmaintained => WarnKind::Unmaintained,
        rustsec::WarningKind::Unsound => WarnKind::Unsound,
        rustsec::WarningKind::Yanked => WarnKind::Yanked,
        // `WarningKind` is #[non_exhaustive]; treat any future kind as a generic
        // notice rather than dropping it silently.
        _ => WarnKind::Notice,
    }
}
