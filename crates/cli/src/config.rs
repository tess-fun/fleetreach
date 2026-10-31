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
    #[error("settings.osv.refresh: {0}")]
    InvalidOsvRefresh(String),
    #[error("source #{index}: {message}")]
    InvalidSource { index: usize, message: String },
    #[error("settings.licenses: {0}")]
    InvalidLicenses(String),
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
    #[serde(default)]
    osv: RawOsv,
    licenses: Option<RawLicenses>,
    #[serde(default)]
    signals: RawSignals,
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
    pub osv: OsvSettings,
    /// `[[source]]` entries; expanded into repos by [`crate::sources`] at scan time.
    pub sources: Vec<crate::sources::Source>,
    /// `[settings.licenses]`, when present.
    pub licenses: Option<crate::licenses::Policy>,
    /// `[settings.signals] registries`: hosts allowed besides the public registries.
    pub signal_registries: Vec<String>,
}

/// Validated `[settings.osv]` (spec 01).
#[derive(Debug, Clone, Default)]
pub struct OsvSettings {
    /// Resolved against the config file's directory. Not required to exist: an absent
    /// ecosystem directory just falls through to the default cache.
    pub dir: Option<PathBuf>,
    pub refresh: Option<std::time::Duration>,
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
                "git" => crate::sources::SourceKind::Git,
                other => {
                    return Err(invalid(format!(
                        "kind `{other}` is not one of `github`, `gitlab`, `git`"
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
                _ => {}
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
            });
        }

        let licenses = raw.settings.licenses.map(license_policy).transpose()?;

        Ok(Config {
            repos,
            ignores,
            vex,
            vex_assertions,
            osv,
            sources,
            licenses,
            signal_registries: raw.settings.signals.registries,
        })
    }
}
