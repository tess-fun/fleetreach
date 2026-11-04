//! `fleet.toml` parsing and validation.
//!
//! Trust boundary (§3): every table uses `deny_unknown_fields`, every repo path
//! is validated to exist and be a directory **before** any scanning, and every
//! `ignore` requires a non-empty `reason`. A bad config is a hard error
//! (exit `2`) surfaced up front, never a mid-run surprise.

use std::path::{Path, PathBuf};

use fleetreach_core::ssvc::{Exposure, MissionImpact, SafetyImpact};
use fleetreach_core::{Ecosystem, RepoId, Severity};
use fleetreach_report::VexScope;

use crate::assemble::DevGate;
use serde::Deserialize;

/// Default depth bound for `glob = true` lockfile discovery (§6).
pub const DEFAULT_GLOB_MAX_DEPTH: usize = 3;

/// A configuration error. All are fatal (exit `2`).
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config `{path}`: {message}")]
    Read { path: String, message: String },
    #[error("failed to parse config `{path}`: {message}")]
    Parse { path: String, message: String },
    #[error("repo `{repo}`: path `{path}` does not exist")]
    PathMissing { repo: String, path: String },
    #[error("repo `{repo}`: path `{path}` is not a directory")]
    PathNotDir { repo: String, path: String },
    #[error("image `{image}`: path `{path}` does not exist")]
    ImageMissing { image: String, path: String },
    #[error("image `{image}`: {message}")]
    InvalidImage { image: String, message: String },
    #[error("repo id `{0}` is declared more than once")]
    DuplicateRepoId(String),
    #[error("ignore `{0}` must have a non-empty `reason`")]
    EmptyIgnoreReason(String),
    #[error("ignore `{id}`: `expires` `{day}` is not a YYYY-MM-DD date")]
    InvalidIgnoreExpiry { id: String, day: String },
    #[error("settings.vex.scope `{0}` is not one of `runtime`, `build`")]
    InvalidVexScope(String),
    #[error("vex_assertion `{0}` must have a non-empty `reason`")]
    EmptyAssertionReason(String),
    #[error("vex_assertion `{0}` (a not_affected statement) must have a non-empty `approved_by`")]
    EmptyAssertionApprover(String),
    #[error("vex_assertion `{id}`: justification `{justification}` is not a VEX WG label")]
    InvalidVexJustification { id: String, justification: String },
    #[error("settings.osv.refresh: {0}")]
    InvalidOsvRefresh(String),
    #[error("source #{index}: {message}")]
    InvalidSource { index: usize, message: String },
    #[error("settings.licenses: {0}")]
    InvalidLicenses(String),
    #[error("settings.ssvc: {0}")]
    InvalidSsvc(String),
    #[error("settings.sla: {0}")]
    InvalidSla(String),
    #[error(
        "settings.gate.scope.dev `{0}` is not one of `low`, `medium`, `high`, `critical`, `never`"
    )]
    BadGateScope(String),
    #[error("settings.history: {0}")]
    InvalidHistory(String),
}

/// The five CISA VEX Working Group `not_affected` justification labels; a
/// `vex_assertion.justification`, when present, must be one of these (§5, §6).
pub const VEX_JUSTIFICATIONS: [&str; 5] = [
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
];

// ---- Raw, untrusted shapes (deny_unknown_fields everywhere) ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    fleet: FleetTable,
    #[serde(default)]
    repo: Vec<RawRepo>,
    #[serde(default)]
    image: Vec<RawImage>,
    #[serde(default)]
    source: Vec<RawSource>,
    #[serde(default)]
    settings: SettingsTable,
}

/// A `[[source]]` entry (spec 06): repos discovered from a forge or listed by URL.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSource {
    kind: String,
    org: Option<String>,
    api_url: Option<String>,
    #[serde(default)]
    urls: Vec<String>,
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    topics: Vec<String>,
    #[serde(default)]
    archived: bool,
    #[serde(default)]
    forks: bool,
    checkout: Option<String>,
    glob: Option<bool>,
    glob_max_depth: Option<usize>,
    token_env: Option<String>,
    // Context (spec 08) for every discovered repo; inline for `deny_unknown_fields`.
    exposure: Option<Exposure>,
    mission_impact: Option<MissionImpact>,
    safety_impact: Option<SafetyImpact>,
    owner: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

/// The `[fleet]` table carries no fields yet; `deny_unknown_fields` rejects
/// stray keys so typos surface instead of being silently ignored.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FleetTable {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRepo {
    id: String,
    path: String,
    #[serde(default)]
    glob: bool,
    glob_max_depth: Option<usize>,
    /// Optional explicit product `@id` for `-f vex` (§4.3 step 1). An IRI/PURL.
    vex_product_id: Option<String>,
    /// An SBOM (CycloneDX or SPDX JSON) to scan instead of the repo's lockfiles, relative to
    /// the config file.
    sbom: Option<String>,
    /// Optional ecosystem override (`cargo`/`rust`/`go`/`npm`/`pypi`/`rubygems`/`packagist`/
    /// `nuget`/`julia`/`swift`/`hex`/`maven`/`githubactions`).
    /// Absent = auto-detect from the repo's manifests at scan time.
    ecosystem: Option<RawEcosystem>,
    // Exposure and impact context (spec 08). Inline rather than a flattened `RawContext`,
    // because serde's `flatten` silently disables `deny_unknown_fields`.
    exposure: Option<Exposure>,
    mission_impact: Option<MissionImpact>,
    safety_impact: Option<SafetyImpact>,
    owner: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

/// An `[[image]]` entry: a container image scanned for its OS and language packages.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawImage {
    id: String,
    /// A `docker save` or OCI-layout tarball, an OCI-layout directory, or a root filesystem
    /// (a directory, or a tarball of one), relative to the config file.
    path: Option<String>,
    /// Or an image in a registry (`ghcr.io/org/app@sha256:...`), pulled for the scan.
    #[serde(rename = "ref")]
    reference: Option<String>,
    /// Which image of a multi-platform OCI index to scan (`linux/arm64`).
    platform: Option<String>,
    /// The osv.dev ecosystem to match against (`Debian:12`), instead of `/etc/os-release`.
    distro: Option<String>,
    exposure: Option<Exposure>,
    mission_impact: Option<MissionImpact>,
    safety_impact: Option<SafetyImpact>,
    owner: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

/// Exposure and impact context (spec 08), on a `[[repo]]` or as
/// `[settings.context.defaults]`. Values use SSVC's own names.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawContext {
    exposure: Option<Exposure>,
    mission_impact: Option<MissionImpact>,
    safety_impact: Option<SafetyImpact>,
    owner: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

impl From<RawContext> for ContextFields {
    fn from(raw: RawContext) -> Self {
        ContextFields {
            exposure: raw.exposure,
            mission_impact: raw.mission_impact,
            safety_impact: raw.safety_impact,
            owner: raw.owner.filter(|o| !o.trim().is_empty()),
            tags: raw.tags,
        }
    }
}

/// The `[settings.context]` block (spec 08).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawContextSettings {
    defaults: Option<RawContext>,
    #[serde(default)]
    tag_rules: Vec<RawTagRule>,
}

/// One `[[settings.context.tag_rules]]`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTagRule {
    name: Option<String>,
    tags: Vec<String>,
    exposure: Option<Exposure>,
    mission_impact: Option<MissionImpact>,
    safety_impact: Option<SafetyImpact>,
}

/// The `[settings.ssvc]` block (spec 08).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSsvc {
    /// EPSS at or above this counts as Exploitation `public-poc`. Off by default.
    poc_epss: Option<f32>,
    /// A custom decision table (CSV), relative to the config file.
    table: Option<String>,
    /// How much a repo at each outcome counts in the fleet views' weighted reach.
    weights: Option<RawWeights>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawWeights {
    immediate: u32,
    out_of_cycle: u32,
    scheduled: u32,
    defer: u32,
}

/// The accepted `ecosystem = "..."` strings, mapped onto [`Ecosystem`]. `rust` is
/// an alias for `cargo` since that is what users call the ecosystem; `python` is an
/// alias for `pypi`; `ruby` is an alias for `rubygems`; `composer` and `php` are aliases
/// for `packagist`; `dotnet` is an alias for `nuget`; `elixir` aliases `hex`; `actions` and
/// `gha` alias `githubactions`.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawEcosystem {
    Cargo,
    Rust,
    Go,
    Npm,
    Pypi,
    Python,
    Rubygems,
    Ruby,
    Packagist,
    Composer,
    Php,
    Nuget,
    Dotnet,
    Julia,
    Swift,
    Hex,
    Elixir,
    Githubactions,
    Actions,
    Gha,
    Maven,
    Gradle,
    Java,
}

impl From<RawEcosystem> for Ecosystem {
    fn from(raw: RawEcosystem) -> Self {
        match raw {
            RawEcosystem::Cargo | RawEcosystem::Rust => Ecosystem::Cargo,
            RawEcosystem::Go => Ecosystem::Go,
            RawEcosystem::Npm => Ecosystem::Npm,
            RawEcosystem::Pypi | RawEcosystem::Python => Ecosystem::Pypi,
            RawEcosystem::Rubygems | RawEcosystem::Ruby => Ecosystem::RubyGems,
            RawEcosystem::Packagist | RawEcosystem::Composer | RawEcosystem::Php => {
                Ecosystem::Packagist
            }
            RawEcosystem::Nuget | RawEcosystem::Dotnet => Ecosystem::NuGet,
            RawEcosystem::Julia => Ecosystem::Julia,
            RawEcosystem::Swift => Ecosystem::Swift,
            RawEcosystem::Hex | RawEcosystem::Elixir => Ecosystem::Hex,
            RawEcosystem::Githubactions | RawEcosystem::Actions | RawEcosystem::Gha => {
                Ecosystem::GitHubActions
            }
            RawEcosystem::Maven | RawEcosystem::Gradle | RawEcosystem::Java => Ecosystem::Maven,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsTable {
    #[serde(default)]
    ignore: Vec<RawIgnore>,
    #[serde(default)]
    vex: RawVex,
    #[serde(default)]
    vex_assertion: Vec<RawVexAssertion>,
    #[serde(default)]
    osv: RawOsv,
    #[serde(default)]
    advisories: RawAdvisories,
    #[serde(default)]
    triage: RawTriage,
    licenses: Option<RawLicenses>,
    #[serde(default)]
    signals: RawSignals,
    #[serde(default)]
    context: RawContextSettings,
    #[serde(default)]
    ssvc: RawSsvc,
    /// `[settings.sla]`: an SSVC outcome or a severity to a duration (`7d`).
    #[serde(default)]
    sla: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    history: RawHistory,
    #[serde(default)]
    gate: RawGate,
}

/// The `[settings.gate]` block (spec 16, row 17).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGate {
    #[serde(default)]
    scope: RawGateScope,
}

/// `[settings.gate.scope]`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGateScope {
    /// The floor for dev and build-only packages, or `never`.
    dev: Option<String>,
}

/// The `[settings.history]` block (spec 09).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHistory {
    /// Drop snapshots older than this (`180d`); the index keeps their findings.
    keep: Option<String>,
}

/// The `[settings.signals]` block (spec 10).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignals {
    /// Registry hosts (and path prefixes) allowed besides the public ones, e.g. a company
    /// npm mirror `npm.example.com`.
    #[serde(default)]
    registries: Vec<String>,
}

/// The `[settings.licenses]` policy (spec 11).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLicenses {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
    /// `category = "allow" | "warn" | "deny"`.
    #[serde(default)]
    categories: std::collections::BTreeMap<String, String>,
    unknown: Option<String>,
    /// `"runtime"` leaves dev-only packages out of the policy; `"all"` (default) includes them.
    scope: Option<String>,
    #[serde(default)]
    exception: Vec<RawLicenseException>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLicenseException {
    package: String,
    allow: Vec<String>,
    reason: String,
}

/// The `[settings.osv]` block (spec 01): where the osv.dev exports live and how often the
/// default cache is re-checked upstream.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOsv {
    /// A directory laid out like the osv.dev bucket (`<dir>/<Ecosystem>/all.zip`).
    dir: Option<String>,
    /// e.g. `6h`; how stale a cached export may get before a sync re-checks it.
    refresh: Option<String>,
}

/// The `[settings.triage]` block (spec 16, row 6).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTriage {
    dir: Option<PathBuf>,
}

/// The `[settings.advisories]` block (spec 16, row 12): the organization's own OSV records,
/// layered over the upstream exports.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAdvisories {
    /// A directory of OSV JSON records (searched recursively), versioned with the config.
    dir: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIgnore {
    id: String,
    reason: String,
    expires: Option<String>,
    owner: Option<String>,
}

/// A `[[settings.vex_assertion]]` entry (§6): a richer `ignore` with an optional
/// justification label and a required approver.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVexAssertion {
    id: String,
    /// Omit = fleet-wide; else scope the assertion to one repo id.
    repo: Option<String>,
    /// One of [`VEX_JUSTIFICATIONS`]; falls back to a free-text `impact_statement`.
    justification: Option<String>,
    reason: String,
    approved_by: String,
}

/// The `[settings.vex]` block (§12); all fields optional, the rest from `--vex-*`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVex {
    author: Option<String>,
    role: Option<String>,
    scope: Option<String>,
    product_id_base: Option<String>,
    /// Read OpenVEX attached to images in registries.
    #[serde(default)]
    oci: bool,
    /// Public keys whose signatures on attached VEX are accepted.
    #[serde(default)]
    oci_keys: Vec<PathBuf>,
    /// Accept attached VEX that no key signed.
    #[serde(default)]
    oci_unsigned: bool,
}

// ---- Validated, trusted shapes ----

#[derive(Debug, Clone)]
pub struct Config {
    pub repos: Vec<Repo>,
    pub ignores: Vec<Ignore>,
    pub triage: TriageSettings,
    pub vex: VexConfig,
    pub vex_assertions: Vec<VexAssertion>,
    pub osv: OsvSettings,
    /// `[[source]]` entries; expanded into repos by [`crate::sources`] at scan time.
    pub sources: Vec<crate::sources::Source>,
    /// `[settings.licenses]`, when present.
    pub licenses: Option<crate::licenses::Policy>,
    /// `[settings.signals] registries`: hosts allowed besides the public registries.
    pub signal_registries: Vec<String>,
    /// `[[image]]` entries (and `scan --image`): container images, scanned apart from repos.
    pub images: Vec<Image>,
    /// `[[repo]] sbom`: repos scanned from an SBOM instead of their lockfiles.
    pub sboms: std::collections::BTreeMap<RepoId, PathBuf>,
    /// Per-repo exposure and impact context (spec 08), for repos that set any.
    pub context: std::collections::BTreeMap<RepoId, ContextFields>,
    /// `[settings.context.defaults]`, applied where a repo sets nothing.
    pub context_defaults: Option<ContextFields>,
    /// `[[settings.context.tag_rules]]` in file order: between a repo's own values and the
    /// defaults.
    pub tag_rules: Vec<TagRule>,
    /// `[settings.ssvc] poc_epss`.
    pub ssvc_poc_epss: Option<f32>,
    /// `[settings.ssvc] table`, else the published deployer table.
    pub ssvc_table: fleetreach_core::ssvc::DecisionTable,
    /// `[settings.ssvc] weights`, else the spec's 8 / 4 / 2 / 0.
    pub ssvc_weights: std::collections::BTreeMap<fleetreach_core::ssvc::Outcome, u32>,
    /// `[settings.sla]` (spec 09).
    pub sla: crate::history::SlaPolicy,
    /// `[settings.history] keep`, in seconds.
    pub history_keep: Option<i64>,
    /// `[settings.gate.scope] dev`.
    pub gate_dev: crate::assemble::DevGate,
}

/// A rule that turns a repo's tags or forge topics into decision points. For each decision
/// point the first matching rule that sets it wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagRule {
    /// `name`, or the rule's place in the file.
    pub name: String,
    /// Globs; any one matching any of the repo's tags applies the rule.
    pub tags: Vec<String>,
    pub exposure: Option<Exposure>,
    pub mission_impact: Option<MissionImpact>,
    pub safety_impact: Option<SafetyImpact>,
}

fn tag_rules(raw: Vec<RawTagRule>) -> Result<Vec<TagRule>, ConfigError> {
    raw.into_iter()
        .enumerate()
        .map(|(index, rule)| {
            let name = rule.name.unwrap_or_else(|| format!("tag_rules[{index}]"));
            if rule.tags.is_empty() {
                return Err(ConfigError::InvalidSsvc(format!("{name}: `tags` is empty")));
            }
            if rule.exposure.is_none()
                && rule.mission_impact.is_none()
                && rule.safety_impact.is_none()
            {
                return Err(ConfigError::InvalidSsvc(format!(
                    "{name}: sets none of `exposure`, `mission_impact`, `safety_impact`"
                )));
            }
            Ok(TagRule {
                name,
                tags: rule.tags,
                exposure: rule.exposure,
                mission_impact: rule.mission_impact,
                safety_impact: rule.safety_impact,
            })
        })
        .collect()
}

/// Validated exposure and impact context (spec 08).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextFields {
    pub exposure: Option<Exposure>,
    pub mission_impact: Option<MissionImpact>,
    pub safety_impact: Option<SafetyImpact>,
    pub owner: Option<String>,
    pub tags: Vec<String>,
}

impl ContextFields {
    /// Whether any SSVC decision point is set (an owner or tags alone do not turn SSVC on).
    #[must_use]
    pub fn has_decision_points(&self) -> bool {
        self.exposure.is_some() || self.mission_impact.is_some() || self.safety_impact.is_some()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == ContextFields::default()
    }
}

/// Validated `[settings.osv]` (spec 01).
#[derive(Debug, Clone, Default)]
pub struct OsvSettings {
    /// Resolved against the config file's directory. Not required to exist: an absent
    /// ecosystem directory just falls through to the default cache.
    pub dir: Option<PathBuf>,
    pub refresh: Option<std::time::Duration>,
    /// `[settings.advisories] dir`: local OSV records that replace (same id), add to, or
    /// retract (`withdrawn`) upstream records. Resolved against the config file's directory;
    /// a scan refuses to run when it is set but missing.
    pub advisories: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Repo {
    pub id: RepoId,
    /// Resolved against the config file's directory; validated to be a directory.
    pub path: PathBuf,
    pub glob: bool,
    pub glob_max_depth: usize,
    /// Explicit product `@id` for `-f vex` (§4.3 step 1).
    pub vex_product_id: Option<String>,
    /// Explicit ecosystem override; `None` = auto-detect from manifests.
    pub ecosystem: Option<Ecosystem>,
}

/// A validated `[[image]]`.
#[derive(Debug, Clone)]
pub struct Image {
    /// Shares the repo id namespace: findings and outcomes carry it as their repo.
    pub id: RepoId,
    /// Resolved against the config file's directory; validated to exist. Empty for `reference`.
    pub path: PathBuf,
    /// An image in a registry, pulled for the scan.
    pub reference: Option<String>,
    pub platform: Option<String>,
    pub distro: Option<String>,
}

/// Where the fleet's triage files live.
#[derive(Debug, Clone)]
pub struct TriageSettings {
    /// `[settings.triage] dir`, else `triage/`, beside the config file.
    pub dir: PathBuf,
    /// Set in the config, so a scan refuses to run when it is missing.
    pub explicit: bool,
}

#[derive(Debug, Clone)]
pub struct Ignore {
    pub id: String,
    pub reason: String,
    /// The last day it holds, `YYYY-MM-DD`. After that it fails the scan while its finding is
    /// open.
    pub expires: Option<String>,
    /// Who to ask about it.
    pub owner: Option<String>,
}

/// Validated `[settings.vex]` (§12); resolved against `--vex-*` flags at `-f vex`.
#[derive(Debug, Clone, Default)]
pub struct VexConfig {
    pub author: Option<String>,
    pub role: Option<String>,
    pub scope: Option<VexScope>,
    pub product_id_base: Option<String>,
    /// Read OpenVEX attached to images in registries.
    pub oci: bool,
    /// Keys whose signatures on attached VEX are accepted, relative to the config file.
    pub oci_keys: Vec<PathBuf>,
    /// Accept attached VEX that no key signed.
    pub oci_unsigned: bool,
}

/// A validated `[[settings.vex_assertion]]` (§6, §7.2): `approved_by` + `reason`
/// non-empty and `justification` a known label, all enforced at parse (fail-closed).
#[derive(Debug, Clone)]
pub struct VexAssertion {
    pub id: String,
    /// `None` = fleet-wide; else scoped to this repo id.
    pub repo: Option<RepoId>,
    pub justification: Option<String>,
    pub reason: String,
    pub approved_by: String,
}

/// Validate `[settings.licenses]`: every id must be an SPDX license id, every verdict
/// `allow`/`warn`/`deny`, every exception must say why.
fn license_policy(raw: RawLicenses) -> Result<crate::licenses::Policy, ConfigError> {
    use crate::licenses::{Category, Policy, Verdict};
    let bad = |m: String| ConfigError::InvalidLicenses(m);
    let ids = |list: Vec<String>,
               field: &str|
     -> Result<std::collections::BTreeSet<String>, ConfigError> {
        list.into_iter()
            .map(|id| match spdx::license_id(&id) {
                Some(l) => Ok(l.name.to_string()),
                None if id.starts_with("LicenseRef-") => Ok(id),
                None => Err(bad(format!("{field}: `{id}` is not an SPDX license id"))),
            })
            .collect()
    };
    let verdict = |v: &str, field: &str| {
        Verdict::parse(v).ok_or_else(|| {
            bad(format!(
                "{field} `{v}` is not one of `allow`, `warn`, `deny`"
            ))
        })
    };
    let mut categories = Policy::default_categories();
    for (name, v) in &raw.categories {
        let category = Category::parse(name).ok_or_else(|| {
            bad(format!(
                "category `{name}` is not one of forbidden, restricted, reciprocal, notice, unencumbered"
            ))
        })?;
        categories.insert(category, verdict(v, &format!("categories.{name}"))?);
    }
    let unknown = match raw.unknown.as_deref() {
        Some(v) => verdict(v, "unknown")?,
        None => Verdict::Deny,
    };
    let runtime_only = match raw.scope.as_deref() {
        None | Some("all") => false,
        Some("runtime") => true,
        Some(other) => {
            return Err(bad(format!(
                "scope `{other}` is not one of `all`, `runtime`"
            )))
        }
    };
    let mut exceptions = std::collections::BTreeMap::new();
    for e in raw.exception {
        if e.reason.trim().is_empty() {
            return Err(bad(format!(
                "exception for `{}` must have a non-empty `reason`",
                e.package
            )));
        }
        let allowed = ids(e.allow, &format!("exception `{}`", e.package))?;
        exceptions.insert(e.package, (allowed, e.reason));
    }
    Ok(Policy {
        allow: ids(raw.allow, "allow")?,
        deny: ids(raw.deny, "deny")?,
        categories,
        unknown,
        runtime_only,
        exceptions,
    })
}

impl Config {
    /// Read and validate a `fleet.toml` from disk. Repo paths are resolved
    /// relative to the config file's directory.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        Self::from_str(&text, base_dir, &path.display().to_string())
    }

    /// A one-repo fleet for `dir` with every default, as if a `fleet.toml` held only
    /// `[[repo]] path = "."` with `glob = true` so nested lockfiles are found. The repo id is
    /// the directory's name.
    pub fn single_repo(dir: &Path) -> Result<Self, ConfigError> {
        let dir = std::fs::canonicalize(dir).map_err(|e| ConfigError::PathMissing {
            repo: dir.display().to_string(),
            path: format!("{} ({e})", dir.display()),
        })?;
        let id = dir
            .file_name()
            .map_or_else(|| "repo".to_string(), |n| n.to_string_lossy().into_owned());
        let text = format!(
            "[[repo]]\nid = {}\npath = \".\"\nglob = true\n",
            toml::Value::String(id)
        );
        Self::from_str(&text, &dir, &dir.display().to_string())
    }

    /// Parse and validate config text with an explicit base directory for
    /// resolving repo paths. Split out from [`Config::load`] for testing.
    pub fn from_str(text: &str, base_dir: &Path, label: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(text).map_err(|e| ConfigError::Parse {
            path: label.to_string(),
            message: e.to_string(),
        })?;
        let FleetTable {} = raw.fleet; // touch the field so it is not dead

        let mut repos = Vec::with_capacity(raw.repo.len());
        let mut sboms = std::collections::BTreeMap::new();
        let mut context = std::collections::BTreeMap::new();
        let mut seen = std::collections::BTreeSet::new();
        for r in raw.repo {
            if !seen.insert(r.id.clone()) {
                return Err(ConfigError::DuplicateRepoId(r.id));
            }
            let resolved = base_dir.join(&r.path);
            if !resolved.exists() {
                return Err(ConfigError::PathMissing {
                    repo: r.id,
                    path: resolved.display().to_string(),
                });
            }
            if !resolved.is_dir() {
                return Err(ConfigError::PathNotDir {
                    repo: r.id,
                    path: resolved.display().to_string(),
                });
            }
            if let Some(sbom) = &r.sbom {
                sboms.insert(RepoId(r.id.clone()), base_dir.join(sbom));
            }
            let fields = ContextFields::from(RawContext {
                exposure: r.exposure,
                mission_impact: r.mission_impact,
                safety_impact: r.safety_impact,
                owner: r.owner,
                tags: r.tags,
            });
            if !fields.is_empty() {
                context.insert(RepoId(r.id.clone()), fields);
            }
            repos.push(Repo {
                id: RepoId(r.id),
                path: resolved,
                glob: r.glob,
                glob_max_depth: r.glob_max_depth.unwrap_or(DEFAULT_GLOB_MAX_DEPTH),
                vex_product_id: r.vex_product_id,
                ecosystem: r.ecosystem.map(Ecosystem::from),
            });
        }

        let mut images = Vec::with_capacity(raw.image.len());
        for i in raw.image {
            if !seen.insert(i.id.clone()) {
                return Err(ConfigError::DuplicateRepoId(i.id));
            }
            let resolved = match (&i.path, &i.reference) {
                (Some(path), None) => {
                    let resolved = base_dir.join(path);
                    if !resolved.exists() {
                        return Err(ConfigError::ImageMissing {
                            image: i.id,
                            path: resolved.display().to_string(),
                        });
                    }
                    resolved
                }
                (None, Some(reference)) => {
                    if let Err(message) = crate::registry::Reference::parse(reference) {
                        return Err(ConfigError::InvalidImage {
                            image: i.id,
                            message,
                        });
                    }
                    PathBuf::new()
                }
                _ => {
                    return Err(ConfigError::InvalidImage {
                        image: i.id,
                        message: "give exactly one of `path` and `ref`".to_string(),
                    })
                }
            };
            if let Some(platform) = &i.platform {
                if platform.split('/').count() < 2 || platform.split('/').any(str::is_empty) {
                    return Err(ConfigError::InvalidImage {
                        image: i.id,
                        message: format!("platform `{platform}` is not like `linux/amd64`"),
                    });
                }
            }
            if let Some(distro) = &i.distro {
                if !fleetreach_os::distro::known_ecosystem(distro) {
                    return Err(ConfigError::InvalidImage {
                        image: i.id,
                        message: format!(
                            "distro `{distro}` is not an osv.dev distro ecosystem fleetreach \
                             matches (like `Debian:12`, `Ubuntu:24.04:LTS`, `Alpine:v3.20`, \
                             `Wolfi`)"
                        ),
                    });
                }
            }
            let fields = ContextFields::from(RawContext {
                exposure: i.exposure,
                mission_impact: i.mission_impact,
                safety_impact: i.safety_impact,
                owner: i.owner,
                tags: i.tags,
            });
            if !fields.is_empty() {
                context.insert(RepoId(i.id.clone()), fields);
            }
            images.push(Image {
                id: RepoId(i.id),
                path: resolved,
                reference: i.reference,
                platform: i.platform,
                distro: i.distro,
            });
        }

        let mut ignores = Vec::with_capacity(raw.settings.ignore.len());
        for ig in raw.settings.ignore {
            if ig.reason.trim().is_empty() {
                return Err(ConfigError::EmptyIgnoreReason(ig.id));
            }
            if let Some(day) = ig.expires.as_deref() {
                if crate::triage::parse_day(day).is_none() {
                    return Err(ConfigError::InvalidIgnoreExpiry {
                        id: ig.id,
                        day: day.to_string(),
                    });
                }
            }
            ignores.push(Ignore {
                id: ig.id,
                reason: ig.reason,
                expires: ig.expires,
                owner: ig.owner,
            });
        }

        let scope = match raw.settings.vex.scope {
            Some(s) => Some(VexScope::parse(&s).ok_or(ConfigError::InvalidVexScope(s))?),
            None => None,
        };
        let vex = VexConfig {
            author: raw.settings.vex.author,
            role: raw.settings.vex.role,
            scope,
            product_id_base: raw.settings.vex.product_id_base,
            oci: raw.settings.vex.oci,
            oci_keys: raw
                .settings
                .vex
                .oci_keys
                .iter()
                .map(|key| base_dir.join(key))
                .collect(),
            oci_unsigned: raw.settings.vex.oci_unsigned,
        };

        let mut vex_assertions = Vec::with_capacity(raw.settings.vex_assertion.len());
        for a in raw.settings.vex_assertion {
            if a.reason.trim().is_empty() {
                return Err(ConfigError::EmptyAssertionReason(a.id));
            }
            // A human `not_affected` must name an approver (§7) — fail closed.
            if a.approved_by.trim().is_empty() {
                return Err(ConfigError::EmptyAssertionApprover(a.id));
            }
            if let Some(j) = &a.justification {
                if !VEX_JUSTIFICATIONS.contains(&j.as_str()) {
                    return Err(ConfigError::InvalidVexJustification {
                        id: a.id,
                        justification: j.clone(),
                    });
                }
            }
            vex_assertions.push(VexAssertion {
                id: a.id,
                repo: a.repo.map(RepoId),
                justification: a.justification,
                reason: a.reason,
                approved_by: a.approved_by,
            });
        }

        let refresh = match raw.settings.osv.refresh {
            Some(spec) => {
                let secs = crate::db::parse_duration_secs(&spec)
                    .map_err(ConfigError::InvalidOsvRefresh)?;
                let secs = u64::try_from(secs)
                    .map_err(|_| ConfigError::InvalidOsvRefresh(format!("`{spec}` is negative")))?;
                Some(std::time::Duration::from_secs(secs))
            }
            None => None,
        };
        let osv = OsvSettings {
            dir: raw.settings.osv.dir.map(|d| base_dir.join(d)),
            refresh,
            advisories: raw.settings.advisories.dir.map(|d| base_dir.join(d)),
        };

        let mut sources = Vec::with_capacity(raw.source.len());
        for (index, src) in raw.source.into_iter().enumerate() {
            let invalid = |message: String| ConfigError::InvalidSource {
                index: index + 1,
                message,
            };
            let kind = match src.kind.as_str() {
                "github" => crate::sources::SourceKind::GitHub,
                "gitlab" => crate::sources::SourceKind::GitLab,
                "gitea" => crate::sources::SourceKind::Gitea,
                "forgejo" => crate::sources::SourceKind::Forgejo,
                "bitbucket" => crate::sources::SourceKind::Bitbucket,
                "bitbucket-server" => crate::sources::SourceKind::BitbucketServer,
                "azure" => crate::sources::SourceKind::Azure,
                "git" => crate::sources::SourceKind::Git,
                other => {
                    return Err(invalid(format!(
                        "kind `{other}` is not one of `github`, `gitlab`, `gitea`, `forgejo`, \
                         `bitbucket`, `bitbucket-server`, `azure`, `git`"
                    )))
                }
            };
            let checkout = match src.checkout.as_deref().unwrap_or("lockfiles") {
                "lockfiles" => crate::sources::Checkout::Lockfiles,
                "full" => crate::sources::Checkout::Full,
                other => {
                    return Err(invalid(format!(
                        "checkout `{other}` is not one of `lockfiles`, `full`"
                    )))
                }
            };
            match kind {
                crate::sources::SourceKind::GitHub if src.org.is_none() => {
                    return Err(invalid("kind `github` needs `org`".to_string()))
                }
                crate::sources::SourceKind::GitLab if src.org.is_none() => {
                    return Err(invalid(
                        "kind `gitlab` needs `org` (a group, subgroup or user path)".to_string(),
                    ))
                }
                crate::sources::SourceKind::Git if src.urls.is_empty() => {
                    return Err(invalid("kind `git` needs `urls`".to_string()))
                }
                crate::sources::SourceKind::Git => {}
                other if src.org.is_none() => {
                    return Err(invalid(format!(
                        "kind `{}` needs `org` ({})",
                        other.name(),
                        match other {
                            crate::sources::SourceKind::Bitbucket => "a workspace",
                            crate::sources::SourceKind::BitbucketServer =>
                                "a project key, or `~user`",
                            crate::sources::SourceKind::Azure =>
                                "an organization, or `organization/project`",
                            _ => "an organization or user",
                        }
                    )))
                }
                other if other.needs_api_url() && src.api_url.is_none() => {
                    return Err(invalid(format!(
                        "kind `{}` needs `api_url`, the server's API root",
                        other.name()
                    )))
                }
                _ => {}
            }
            // On a forge without topics the filter would match nothing and empty the fleet.
            if !kind.has_topics() && !src.topics.is_empty() {
                return Err(invalid(format!(
                    "kind `{}` has no repo topics, so `topics` cannot apply",
                    kind.name()
                )));
            }
            if let Some(url) = src.urls.iter().find(|u| !u.starts_with("https://")) {
                return Err(invalid(format!("url `{url}` must be https://")));
            }
            if let Some(api) = src
                .api_url
                .as_deref()
                .filter(|u| !u.starts_with("https://"))
            {
                return Err(invalid(format!("api_url `{api}` must be https://")));
            }
            sources.push(crate::sources::Source {
                kind,
                org: src.org,
                api_url: src.api_url,
                urls: src.urls,
                include: src.include,
                exclude: src.exclude,
                topics: src.topics,
                archived: src.archived,
                forks: src.forks,
                checkout,
                glob: src.glob.unwrap_or(true),
                glob_max_depth: src.glob_max_depth.unwrap_or(DEFAULT_GLOB_MAX_DEPTH),
                token_env: src.token_env,
                context: ContextFields::from(RawContext {
                    exposure: src.exposure,
                    mission_impact: src.mission_impact,
                    safety_impact: src.safety_impact,
                    owner: src.owner,
                    tags: src.tags,
                }),
            });
        }

        let licenses = raw.settings.licenses.map(license_policy).transpose()?;
        let ssvc_poc_epss = match raw.settings.ssvc.poc_epss {
            Some(p) if !(0.0..=1.0).contains(&p) => {
                return Err(ConfigError::InvalidSsvc(format!(
                    "poc_epss `{p}` must be between 0 and 1"
                )))
            }
            p => p,
        };
        let ssvc_table = match &raw.settings.ssvc.table {
            None => fleetreach_core::ssvc::DecisionTable::deployer(),
            Some(rel) => {
                use sha2::{Digest, Sha256};
                let path = base_dir.join(rel);
                let text = std::fs::read_to_string(&path).map_err(|e| {
                    ConfigError::InvalidSsvc(format!("table `{}`: {e}", path.display()))
                })?;
                let digest: String = Sha256::digest(text.as_bytes())
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                fleetreach_core::ssvc::DecisionTable::from_csv(&text, format!("custom:{digest}"))
                    .map_err(|e| ConfigError::InvalidSsvc(format!("table `{rel}`: {e}")))?
            }
        };
        let ssvc_weights = {
            use fleetreach_core::ssvc::Outcome;
            let w = raw.settings.ssvc.weights.unwrap_or(RawWeights {
                immediate: 8,
                out_of_cycle: 4,
                scheduled: 2,
                defer: 0,
            });
            [
                (Outcome::Immediate, w.immediate),
                (Outcome::OutOfCycle, w.out_of_cycle),
                (Outcome::Scheduled, w.scheduled),
                (Outcome::Defer, w.defer),
            ]
            .into_iter()
            .collect()
        };

        let mut sla = crate::history::SlaPolicy::default();
        for (key, value) in &raw.settings.sla {
            let seconds = crate::db::parse_duration_secs(value)
                .ok()
                .filter(|s| *s > 0)
                .ok_or_else(|| {
                    ConfigError::InvalidSla(format!("`{key}`: `{value}` is not a duration like 7d"))
                })?;
            if let Some(outcome) = fleetreach_core::ssvc::Outcome::parse(key) {
                sla.by_outcome.insert(outcome, seconds);
            } else if let Some(severity) = severity_named(key) {
                sla.by_severity.insert(severity, seconds);
            } else {
                return Err(ConfigError::InvalidSla(format!(
                    "`{key}` is neither an SSVC outcome (immediate, out-of-cycle, scheduled, \
                     defer) nor a severity (critical, high, medium, low, unknown)"
                )));
            }
        }
        let gate_dev = match raw.settings.gate.scope.dev.as_deref() {
            None => DevGate::Same,
            Some("low") => DevGate::At(Severity::Low),
            Some("medium") => DevGate::At(Severity::Medium),
            Some("high") => DevGate::At(Severity::High),
            Some("critical") => DevGate::At(Severity::Critical),
            Some("never") => DevGate::Never,
            Some(other) => return Err(ConfigError::BadGateScope(other.to_string())),
        };
        let history_keep = match &raw.settings.history.keep {
            None => None,
            Some(v) => Some(
                crate::db::parse_duration_secs(v)
                    .ok()
                    .filter(|s| *s > 0)
                    .ok_or_else(|| {
                        ConfigError::InvalidHistory(format!(
                            "keep `{v}` is not a duration like 180d"
                        ))
                    })?,
            ),
        };

        let triage = TriageSettings {
            explicit: raw.settings.triage.dir.is_some(),
            dir: base_dir.join(raw.settings.triage.dir.unwrap_or_else(|| "triage".into())),
        };

        Ok(Config {
            repos,
            ignores,
            triage,
            vex,
            vex_assertions,
            osv,
            sources,
            licenses,
            signal_registries: raw.settings.signals.registries,
            images,
            sboms,
            context,
            context_defaults: raw.settings.context.defaults.map(ContextFields::from),
            tag_rules: tag_rules(raw.settings.context.tag_rules)?,
            ssvc_poc_epss,
            ssvc_table,
            ssvc_weights,
            sla,
            history_keep,
            gate_dev,
        })
    }
}

fn severity_named(name: &str) -> Option<fleetreach_core::Severity> {
    use fleetreach_core::Severity;
    Some(match name {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "unknown" => Severity::Unknown,
        _ => return None,
    })
}
