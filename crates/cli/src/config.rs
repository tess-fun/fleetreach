//! `fleet.toml` parsing and validation.
//!
//! Trust boundary (§3): every table uses `deny_unknown_fields`, every repo path
//! is validated to exist and be a directory **before** any scanning, and every
//! `ignore` requires a non-empty `reason`. A bad config is a hard error
//! (exit `2`) surfaced up front, never a mid-run surprise.

use std::path::{Path, PathBuf};

use fleetreach_core::{Ecosystem, RepoId};
use fleetreach_report::VexScope;
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
    #[error("repo id `{0}` is declared more than once")]
    DuplicateRepoId(String),
    #[error("ignore `{0}` must have a non-empty `reason`")]
    EmptyIgnoreReason(String),
    #[error("settings.vex.scope `{0}` is not one of `runtime`, `build`")]
    InvalidVexScope(String),
    #[error("vex_assertion `{0}` must have a non-empty `reason`")]
    EmptyAssertionReason(String),
    #[error("vex_assertion `{0}` (a not_affected statement) must have a non-empty `approved_by`")]
    EmptyAssertionApprover(String),
    #[error("vex_assertion `{id}`: justification `{justification}` is not a VEX WG label")]
    InvalidVexJustification { id: String, justification: String },
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
    settings: SettingsTable,
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
    /// Optional ecosystem override (`cargo`/`rust`/`go`/`npm`/`pypi`/`rubygems`/`packagist`/
    /// `nuget`/`julia`/`swift`/`hex`/`maven`/`githubactions`).
    /// Absent = auto-detect from the repo's manifests at scan time.
    ecosystem: Option<RawEcosystem>,
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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIgnore {
    id: String,
    reason: String,
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
}

// ---- Validated, trusted shapes ----

#[derive(Debug, Clone)]
pub struct Config {
    pub repos: Vec<Repo>,
    pub ignores: Vec<Ignore>,
    pub vex: VexConfig,
    pub vex_assertions: Vec<VexAssertion>,
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

#[derive(Debug, Clone)]
pub struct Ignore {
    pub id: String,
    pub reason: String,
}

/// Validated `[settings.vex]` (§12); resolved against `--vex-*` flags at `-f vex`.
#[derive(Debug, Clone, Default)]
pub struct VexConfig {
    pub author: Option<String>,
    pub role: Option<String>,
    pub scope: Option<VexScope>,
    pub product_id_base: Option<String>,
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

    /// Parse and validate config text with an explicit base directory for
    /// resolving repo paths. Split out from [`Config::load`] for testing.
    pub fn from_str(text: &str, base_dir: &Path, label: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(text).map_err(|e| ConfigError::Parse {
            path: label.to_string(),
            message: e.to_string(),
        })?;
        let FleetTable {} = raw.fleet; // touch the field so it is not dead

        let mut repos = Vec::with_capacity(raw.repo.len());
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
            repos.push(Repo {
                id: RepoId(r.id),
                path: resolved,
                glob: r.glob,
                glob_max_depth: r.glob_max_depth.unwrap_or(DEFAULT_GLOB_MAX_DEPTH),
                vex_product_id: r.vex_product_id,
                ecosystem: r.ecosystem.map(Ecosystem::from),
            });
        }

        let mut ignores = Vec::with_capacity(raw.settings.ignore.len());
        for ig in raw.settings.ignore {
            if ig.reason.trim().is_empty() {
                return Err(ConfigError::EmptyIgnoreReason(ig.id));
            }
            ignores.push(Ignore {
                id: ig.id,
                reason: ig.reason,
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

        Ok(Config {
            repos,
            ignores,
            vex,
            vex_assertions,
        })
    }
}
