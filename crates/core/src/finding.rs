use std::fmt;

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};

use crate::Severity;

/// The package ecosystem a finding belongs to: a crate, a Go module, an npm package, a PyPI
/// distribution, a gem, a Composer package ([`Packagist`]), or a [`NuGet`] (.NET) package,
/// so a mixed fleet keeps the namespaces apart (the same name can exist in several). Each is
/// fed by its own `fleetreach-<ecosystem>` crate. Ordered so it can key a grouping map.
///
/// [`Cargo`]: Ecosystem::Cargo
/// [`Go`]: Ecosystem::Go
/// [`Npm`]: Ecosystem::Npm
/// [`Pypi`]: Ecosystem::Pypi
/// [`RubyGems`]: Ecosystem::RubyGems
/// [`Packagist`]: Ecosystem::Packagist
/// [`NuGet`]: Ecosystem::NuGet
/// [`Julia`]: Ecosystem::Julia
/// [`Swift`]: Ecosystem::Swift
/// [`Hex`]: Ecosystem::Hex
/// [`GitHubActions`]: Ecosystem::GitHubActions
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    #[default]
    Cargo,
    Go,
    Npm,
    Pypi,
    RubyGems,
    Packagist,
    NuGet,
    Julia,
    Swift,
    Hex,
    Maven,
    /// GitHub Actions (`owner/repo@ref` in workflow files).
    #[serde(rename = "github-actions")]
    GitHubActions,
}

impl Ecosystem {
    /// Whether this is the default crates.io ecosystem — used to omit the field
    /// from JSON for every existing Rust finding, keeping `schema_version: 1`
    /// output byte-identical.
    pub fn is_cargo(&self) -> bool {
        matches!(self, Ecosystem::Cargo)
    }
}

/// Stable identifier for a repository, taken verbatim from `fleet.toml` — a
/// logical id, **never** a filesystem path. Paths move; ids are the group key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RepoId(pub String);

impl fmt::Display for RepoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How a package enters a repo's dependency graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DependencyKind {
    Direct,
    Transitive,
}

/// Where a vulnerable package resolves *from* — which registry, git remote, or
/// local path. This is the identity a VEX subcomponent PURL must carry (spec
/// §4.1): a crates.io dep is the bare `pkg:cargo/<name>@<ver>` PURL, but a git or
/// alternate-registry dep needs a qualifier so a downstream scanner matches the
/// exact artifact. Captured here so the PURL can be derived without re-reading the
/// lockfile. Additive — defaults to [`CratesIo`](DepSource::CratesIo) so a report
/// written before this field existed keeps the crates.io assumption it shipped with.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepSource {
    /// The default crates.io registry — the overwhelmingly common case.
    #[default]
    CratesIo,
    /// A git dependency: the remote URL and the locked commit, when known.
    Git {
        /// The git remote URL (without the `git+` scheme prefix or commit fragment).
        url: String,
        /// The locked commit hash (`SourceId::precise`), when the lock pins one.
        rev: Option<String>,
    },
    /// A local path dependency or workspace member — not a published artifact.
    Path,
    /// Another registry (alternate / sparse / local): its index URL.
    OtherRegistry {
        /// The registry index URL.
        url: String,
    },
}

impl DepSource {
    /// Whether this is the default crates.io source — used to omit the field from
    /// JSON in the common case, keeping `schema_version: 1` output byte-identical.
    pub fn is_crates_io(&self) -> bool {
        matches!(self, DepSource::CratesIo)
    }
}

/// A single location/version where an advisory applies.
///
/// The advisory groups occurrences, but the **verdict is per-occurrence**: the
/// same crate at different versions across repos may differ (one patched, one
/// not). A toolchain advisory (`rustsec::Collection::Rust`) has no repo to pin,
/// so it is a distinct variant rather than a sentinel repo.
///
/// Serializes internally-tagged on `kind` (`"in_repo"` / `"toolchain"`), with
/// the variant's fields inlined alongside.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Occurrence {
    InRepo {
        /// Stable id from `fleet.toml`.
        repo: RepoId,
        package: String,
        installed: Version,
        /// Versions that fix the advisory; empty means "no fix available".
        patched: Vec<VersionReq>,
        dependency_kind: DependencyKind,
        /// A shortest chain of package names from a root crate down to this
        /// package (`["my-app", "jiff", "defmt", …]`) — the answer to "who pulls
        /// this in". There may be other paths; this is one representative. Empty
        /// when the dependency graph could not be computed. Additive field —
        /// omitted from JSON when empty, so `schema_version: 1` is unaffected.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        dependency_path: Vec<String>,
        /// Whether this package is actually compiled in the host's default build
        /// (feature-resolved). `None` unless `--resolve-features` ran; `Some(false)`
        /// flags a `Cargo.lock`-only optional dep that is never built. Additive —
        /// omitted from JSON when `None`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        active: Option<bool>,
        /// Where this package resolves from (registry / git / path), for the VEX
        /// subcomponent PURL (§4.1). Additive — omitted from JSON for the common
        /// crates.io case, so `schema_version: 1` output is unaffected.
        #[serde(default, skip_serializing_if = "DepSource::is_crates_io")]
        source: DepSource,
    },
    Toolchain {
        /// e.g. `"stable 1.xx"` — there is no repo to pin a toolchain advisory to.
        channel: String,
        installed: Option<Version>,
        patched: Vec<VersionReq>,
    },
}

impl Occurrence {
    /// The per-occurrence verdict: is the *installed* version actually
    /// vulnerable? An occurrence is vulnerable when its installed version is
    /// covered by none of the advisory's patched requirements. This is computed
    /// per occurrence precisely because the same advisory can apply to different
    /// versions across the fleet — one already patched, one not.
    ///
    /// Fail-closed: an empty patched set (no fix published) or an unknown
    /// installed version counts as vulnerable.
    ///
    /// ```
    /// use fleetreach_core::{DependencyKind, Occurrence, RepoId};
    /// use fleetreach_core::semver::{Version, VersionReq};
    ///
    /// let at = |major, minor, patch| Occurrence::InRepo {
    ///     repo: RepoId("app".into()),
    ///     package: "foo".into(),
    ///     installed: Version::new(major, minor, patch),
    ///     patched: vec![VersionReq::parse(">=1.2.0").unwrap()],
    ///     dependency_kind: DependencyKind::Transitive,
    ///     dependency_path: vec![],
    ///     active: None,
    ///     source: Default::default(),
    /// };
    /// assert!(at(1, 1, 9).is_vulnerable());  // below the fix
    /// assert!(!at(1, 2, 0).is_vulnerable()); // at the fix
    /// ```
    pub fn is_vulnerable(&self) -> bool {
        match self {
            Occurrence::InRepo {
                installed, patched, ..
            } => !patched.iter().any(|req| req.matches(installed)),
            Occurrence::Toolchain {
                installed, patched, ..
            } => match installed {
                Some(version) => !patched.iter().any(|req| req.matches(version)),
                None => true,
            },
        }
    }
}

/// Exploit-risk enrichment for an advisory, from CISA KEV + FIRST EPSS (added by
/// `--enrich`). Additive — its fields are flattened onto the vulnerability and
/// omitted when absent, so `schema_version: 1` consumers are unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct Exploitability {
    /// In CISA's Known Exploited Vulnerabilities catalog — actively exploited.
    #[serde(default, skip_serializing_if = "is_false")]
    pub kev: bool,
    /// EPSS probability of exploitation in the next 30 days (0.0–1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss: Option<f32>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// A vulnerability (a real CVE-class advisory), correlated across the fleet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VulnFinding {
    /// Canonical `RUSTSEC-YYYY-NNNN` — the group key.
    pub advisory_id: String,
    /// CVE/GHSA ids — metadata for cross-reference, **never** the key.
    pub aliases: Vec<String>,
    /// Which ecosystem this finding came from. Additive — omitted from JSON for the
    /// common Cargo case, so `schema_version: 1` output is unaffected; the
    /// `fleetreach-go` feeder sets [`Ecosystem::Go`] so a mixed fleet groups crates
    /// and Go modules separately.
    #[serde(default, skip_serializing_if = "Ecosystem::is_cargo")]
    pub ecosystem: Ecosystem,
    pub title: String,
    pub severity: Severity,
    /// CVSS base score (0.0–10.0) behind `severity`, when one is known — from the
    /// advisory's own CVSS, or backfilled from NVD by `--enrich`. Additive;
    /// omitted from JSON when absent (advisories with no CVSS at all).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f32>,
    pub url: Option<String>,
    /// At least one; the same advisory may surface in many repos/versions.
    pub occurrences: Vec<Occurrence>,
    /// Canonical paths to the specific functions/types the advisory marks
    /// vulnerable *at the installed version* (`time::Time::from_hms_nano`, …),
    /// when the advisory scopes itself that way — so you can check whether you
    /// call any of them. Empty when the advisory affects the whole crate.
    /// Additive; omitted from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_functions: Vec<String>,
    /// A *heuristic* (`--reachability`): does an affected function name appear in
    /// the affected repos' own source? `Some(true)` = yes, `Some(false)` = not
    /// found in your source (it could still be reached through a dependency —
    /// this only scans your code), `None` = not checked or the advisory names no
    /// functions. Never proves absence; never auto-suppresses by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachable: Option<bool>,
    /// *Static* reachability (`--reachability=static`): a sound call-graph verdict
    /// over the compiled crate closure, with a witness chain when reachable. Far
    /// stronger than `reachable` (the grep heuristic) — a `NotReachable` here is
    /// trusted enough to suppress. Additive; absent unless the static engine ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachability: Option<Reachability>,
    /// Exploit-risk enrichment; default (empty) until `--enrich` runs.
    #[serde(flatten)]
    pub exploit: Exploitability,
}

/// A static-reachability verdict for a finding's affected functions, scoped to
/// the toolchain + feature/target config it was computed under (spec §7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reachability {
    /// The reachability outcome for the finding's affected functions.
    pub verdict: ReachVerdict,
    /// The config the verdict is scoped to (toolchain + features/target).
    pub config: String,
    /// The engine that produced it, e.g. `static-mir-rta@<ver>`.
    pub engine: String,
    /// The target triple(s) the verdict was computed for (spec §7 edge 3): a
    /// function unreachable on one target may be reachable behind a `cfg` on
    /// another, so a `NotReachable` names its targets. Additive; omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    /// A content-addressed witness for a `NotReachable` verdict (spec §9.2): a
    /// hash binding the verdict to the exact inputs that produced it (lockfile,
    /// source, toolchain, features, sinks). `fleetreach vex verify` re-derives
    /// against current source and fails if the verdict no longer holds. Additive;
    /// `None` for `Reachable`/`Unknown` and when caching was impossible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<String>,
}

/// The reachability outcome. The acceptable error direction is over-reporting
/// (`Reachable`/`Unknown` when in fact dead) — `NotReachable` is sound: there is
/// genuinely no path from a root to the sink under the analyzed config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReachVerdict {
    /// A concrete call chain exists; `witness` is `root -> … -> sink`.
    Reachable { witness: Vec<String> },
    /// Sound: no path under the analyzed config.
    NotReachable,
    /// Could not be decided soundly (build failed, sink unresolved, an opaque
    /// boundary on every candidate path, …).
    Unknown { reason: String },
}

impl Reachability {
    /// The reachability verdict shared by every toolchain-free (Tier-C) feeder: a
    /// package/version match with no call-graph analysis. It is **always** `Unknown`
    /// (never `NotReachable` — Tier-C must not claim a soundness it did not compute),
    /// with a fixed `config`/`engine` so the report renders the tier consistently
    /// across all ecosystems. `reason` names the lower fidelity for the report.
    ///
    /// Centralizing this here keeps the Tier-C contract in one place instead of
    /// copy-pasted into each feeder's `scan.rs`, where a divergence would be a
    /// silent per-ecosystem inconsistency the compiler could not catch.
    pub fn tier_c_unknown(reason: impl Into<String>) -> Self {
        Reachability {
            verdict: ReachVerdict::Unknown {
                reason: reason.into(),
            },
            config: "package-level".to_string(),
            engine: "fleetreach-tier-c".to_string(),
            targets: Vec::new(),
            witness: None,
        }
    }

    /// Map onto the legacy heuristic `reachable: Option<bool>` for back-compat
    /// (spec §7): `Reachable -> Some(true)`, `NotReachable -> Some(false)`,
    /// `Unknown -> None`.
    pub fn as_legacy_bool(&self) -> Option<bool> {
        match self.verdict {
            ReachVerdict::Reachable { .. } => Some(true),
            ReachVerdict::NotReachable => Some(false),
            ReachVerdict::Unknown { .. } => None,
        }
    }
}

/// The class of a supply-chain warning — informational, **not** a CVE. Kept in a
/// stream separate from vulnerabilities so warnings never inflate the vuln count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WarnKind {
    Unmaintained,
    Yanked,
    Unsound,
    Notice,
}

/// A supply-chain warning, correlated across the fleet by `(kind, id)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WarnFinding {
    pub kind: WarnKind,
    /// Some warnings (e.g. a plain yank) may not carry a RUSTSEC id.
    pub advisory_id: Option<String>,
    pub title: String,
    pub occurrences: Vec<Occurrence>,
}
