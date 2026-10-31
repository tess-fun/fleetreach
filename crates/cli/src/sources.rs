//! Fleet sources (spec 06): repos discovered from a forge (`kind = "github"`) or listed by URL
//! (`kind = "git"`), materialized as cheap checkouts under `~/.cache/fleetreach/checkouts/`.
//!
//! A `lockfiles` checkout is a shallow, blob-less, sparse clone that fetches only the files
//! the feeders read, so hundreds of repos cost little more than their lockfiles. A `full`
//! checkout is a normal shallow clone (needed by reachability and `--resolve-features`).
//!
//! Fail-closed: a listing that fails stops the run (a partial org listing is never the
//! fleet), and a repo that cannot be cloned or refreshed becomes an errored gap. `git` runs
//! hardened: no hooks, no submodules, no `file://` transport, no prompts, and the token
//! travels in an environment-supplied header, never in argv or the stored remote URL.

use std::path::{Path, PathBuf};
use std::process::Command;

use fleetreach_core::{RepoId, RepoSource};
use serde::{Deserialize, Serialize};

use crate::config::{Config, Repo};
use crate::osvdb::{create_private_dir, private_subdir};

/// The files the feeders read (plus their sibling manifests), checked out sparsely in
/// `lockfiles` mode. Keep in step with the feeders' lockfile detection.
pub const SPARSE_PATTERNS: &[&str] = &[
    "**/Cargo.lock",
    "**/Cargo.toml",
    "**/go.mod",
    "**/go.sum",
    "**/package-lock.json",
    "**/pnpm-lock.yaml",
    "**/yarn.lock",
    "**/bun.lock",
    "**/bun.lockb",
    "**/package.json",
    "**/uv.lock",
    "**/poetry.lock",
    "**/Pipfile.lock",
    "**/pylock.toml",
    "**/pylock.*.toml",
    // Requirements files and what they usually include; an include under another name is
    // reported as a coverage gap, not silently skipped.
    "**/requirements*.txt",
    "**/*requirements.txt",
    "**/requirements/*.txt",
    "**/constraints*.txt",
    "**/pyproject.toml",
    "**/Gemfile.lock",
    "**/composer.lock",
    "**/composer.json",
    "**/packages.lock.json",
    "**/packages.config",
    "**/*.csproj",
    "**/*.fsproj",
    "**/*.vbproj",
    "**/Directory.Packages.props",
    "**/Directory.Build.props",
    "**/Manifest.toml",
    "**/Project.toml",
    "**/Package.resolved",
    "**/Package.swift",
    "**/mix.lock",
    "**/gradle.lockfile",
    "**/pom.xml",
    "/.github/workflows/",
    "/action.yml",
    "/action.yaml",
];

/// How a `[[source]]` finds its repos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SourceKind {
    GitHub,
    GitLab,
    Git,
}

/// How much of each repo to fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Checkout {
    Lockfiles,
    Full,
}

/// A validated `[[source]]`.
#[derive(Debug, Clone, Serialize)]
pub struct Source {
    pub kind: SourceKind,
    pub org: Option<String>,
    pub api_url: Option<String>,
    pub urls: Vec<String>,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub topics: Vec<String>,
    pub archived: bool,
    pub forks: bool,
    pub checkout: Checkout,
    pub glob: bool,
    pub glob_max_depth: usize,
    pub token_env: Option<String>,
    /// Exposure and impact context (spec 08) for every repo this source discovers; a
    /// `[[repo]]` with the same id is explicit and keeps its own. Not part of the listing
    /// cache key: context does not change which repos are listed.
    #[serde(skip)]
    pub context: crate::config::ContextFields,
}

impl Source {
    fn label(&self) -> String {
        match self.kind {
            SourceKind::GitHub => format!("github:{}", self.org.as_deref().unwrap_or_default()),
            SourceKind::GitLab => format!("gitlab:{}", self.org.as_deref().unwrap_or_default()),
            SourceKind::Git => format!("git:{} url(s)", self.urls.len()),
        }
    }

    /// The token for this source: `token_env`, else `GITHUB_TOKEN` / `GH_TOKEN` for GitHub and
    /// `GITLAB_TOKEN` for GitLab.
    fn token(&self) -> Option<String> {
        let names: Vec<&str> = match (&self.token_env, self.kind) {
            (Some(name), _) => vec![name.as_str()],
            (None, SourceKind::GitHub) => vec!["GITHUB_TOKEN", "GH_TOKEN"],
            (None, SourceKind::GitLab) => vec!["GITLAB_TOKEN"],
            (None, SourceKind::Git) => Vec::new(),
        };
        names
            .into_iter()
            .find_map(|n| std::env::var(n).ok().filter(|v| !v.is_empty()))
    }

    /// Whether a listed repo passes this source's filters.
    fn keeps(&self, repo: &Listed) -> bool {
        if (repo.archived && !self.archived) || (repo.fork && !self.forks) {
            return false;
        }
        if !self
            .topics
            .iter()
            .all(|t| repo.topics.iter().any(|r| r == t))
        {
            return false;
        }
        let name = repo.id.rsplit('/').next().unwrap_or(&repo.id);
        let included = self.include.is_empty() || self.include.iter().any(|p| glob_match(p, name));
        included && !self.exclude.iter().any(|p| glob_match(p, name))
    }
}

/// One repo a source lists.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Listed {
    /// `owner/name`, the repo id in the report.
    pub id: String,
    pub clone_url: String,
    pub default_branch: Option<String>,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub fork: bool,
    #[serde(default)]
    pub topics: Vec<String>,
}

/// The repos all sources resolved to, plus the ones that could not be checked out.
#[derive(Debug, Default)]
pub struct Materialized {
    pub repos: Vec<Repo>,
    /// Repos that exist in a listing but could not be cloned/refreshed: errored gaps.
    pub failed: Vec<(RepoId, String)>,
    pub provenance: Vec<RepoSource>,
    /// The source's context for each discovered repo, when the source sets any.
    pub context: Vec<(RepoId, crate::config::ContextFields)>,
}

/// Case-insensitive glob with `*` (any run) and `?` (one character), as Renovate's
/// `autodiscoverFilter` matches repo names.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        match p.get(pi) {
            Some('*') => {
                star = Some(pi);
                mark = ti;
                pi += 1;
            }
            Some(&c) if c == '?' || Some(&c) == t.get(ti) => {
                pi += 1;
                ti += 1;
            }
            _ => match star {
                Some(s) => {
                    pi = s + 1;
                    mark += 1;
                    ti = mark;
                }
                None => return false,
            },
        }
    }
    p.get(pi..)
        .is_some_and(|rest| rest.iter().all(|&c| c == '*'))
}

/// `owner/name` from an https clone URL (`https://host/owner/name(.git)`).
pub fn id_from_url(url: &str) -> Option<String> {
    let path = url.strip_prefix("https://")?.split_once('/')?.1;
    let path = path.trim_end_matches('/').trim_end_matches(".git");
    let parts: Vec<&str> = path.split('/').collect();
    let ok = |s: &&str| {
        !s.is_empty()
            && *s != "."
            && *s != ".."
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    // `owner/name`, or a GitLab namespace path `group/subgroup/name` kept whole, so two
    // projects of the same name in different subgroups never share an id or a checkout.
    (parts.len() >= 2 && parts.iter().all(ok)).then(|| parts.join("/"))
}

fn host_of(url: &str) -> Option<&str> {
    url.strip_prefix("https://")?.split('/').next()
}

/// The repos a source lists, fresh from the forge (`refresh`) or from the listing cache.
pub fn list(source: &Source, refresh: bool) -> Result<Vec<Listed>, String> {
    match source.kind {
        SourceKind::Git => source
            .urls
            .iter()
            .map(|url| {
                Ok(Listed {
                    id: id_from_url(url)
                        .ok_or_else(|| format!("cannot name a repo from `{url}`"))?,
                    clone_url: url.clone(),
                    default_branch: None,
                    archived: false,
                    fork: false,
                    topics: Vec::new(),
                })
            })
            .collect(),
        SourceKind::GitHub | SourceKind::GitLab => {
            let cache = listing_cache_path(source)?;
            if !refresh {
                let text = std::fs::read_to_string(&cache).map_err(|_| {
                    format!(
                        "{} has not been listed yet; run `fleetreach fleet sync` (or scan --sync)",
                        source.label()
                    )
                })?;
                let all: Vec<Listed> = serde_json::from_str(&text)
                    .map_err(|e| format!("listing cache {}: {e}", cache.display()))?;
                return Ok(all.into_iter().filter(|r| source.keeps(r)).collect());
            }
            let all = if source.kind == SourceKind::GitLab {
                gitlab::list(source)?
            } else {
                github::list(source)?
            };
            if let Some(dir) = cache.parent() {
                create_private_dir(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
            }
            let json = serde_json::to_string(&all).map_err(|e| e.to_string())?;
            std::fs::write(&cache, json)
                .map_err(|e| format!("writing {}: {e}", cache.display()))?;
            Ok(all.into_iter().filter(|r| source.keeps(r)).collect())
        }
    }
}

fn listing_cache_path(source: &Source) -> Result<PathBuf, String> {
    use sha2::{Digest, Sha256};
    let root = private_subdir("sources").ok_or("no usable cache directory for source listings")?;
    let key = format!(
        "{:?}|{}|{}",
        source.kind,
        source.org.as_deref().unwrap_or_default(),
        source.api_url.as_deref().unwrap_or_default()
    );
    let hash: String = Sha256::digest(key.as_bytes())
        .iter()
        .take(12)
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(root.join(format!("{hash}.json")))
}

/// Expand every `[[source]]` into repos. With `sync`, list afresh and clone or refresh each
/// checkout; without, use the cached listing and existing checkouts only. Explicit
/// `[[repo]]` entries win over a discovered repo with the same id.
///
/// # Errors
///
/// A source whose listing fails, or has never been listed when not syncing: the fleet is
/// unknown, so the run must not go on as if it were complete.
pub fn materialize(config: &Config, sync: bool, quiet: bool) -> Result<Materialized, String> {
    let mut out = Materialized::default();
    if config.sources.is_empty() {
        return Ok(out);
    }
    let checkouts = private_subdir("checkouts").ok_or("no usable cache directory for checkouts")?;
    let explicit: std::collections::BTreeSet<&str> =
        config.repos.iter().map(|r| r.id.0.as_str()).collect();
    for source in &config.sources {
        let listed = list(source, sync)?;
        if !quiet {
            eprintln!("{}: {} repo(s)", source.label(), listed.len());
        }
        let token = source.token();
        let work: Vec<&Listed> = listed
            .iter()
            .filter(|r| !explicit.contains(r.id.as_str()))
            .collect();
        let results: Vec<(&Listed, CheckoutResult)> = {
            use rayon::prelude::*;
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(8)
                .build()
                .map_err(|e| e.to_string())?;
            pool.install(|| {
                work.par_iter()
                    .map(|r| (*r, checkout(&checkouts, r, source, token.as_deref(), sync)))
                    .collect()
            })
        };
        for (listed, result) in results {
            let id = RepoId(listed.id.clone());
            match result {
                Ok((path, commit)) => {
                    out.provenance.push(RepoSource {
                        repo: id.clone(),
                        url: listed.clone_url.clone(),
                        commit,
                    });
                    if !source.context.is_empty() {
                        out.context.push((id.clone(), source.context.clone()));
                    }
                    out.repos.push(Repo {
                        id,
                        path,
                        glob: source.glob,
                        glob_max_depth: source.glob_max_depth,
                        vex_product_id: None,
                        ecosystem: None,
                    });
                }
                Err(reason) => out.failed.push((id, reason)),
            }
        }
    }
    Ok(out)
}

/// A checkout's path and commit, or why it failed.
type CheckoutResult = Result<(PathBuf, String), String>;

/// Clone or refresh one repo; returns its checkout path and commit.
fn checkout(
    root: &Path,
    repo: &Listed,
    source: &Source,
    token: Option<&str>,
    sync: bool,
) -> Result<(PathBuf, String), String> {
    let host = host_of(&repo.clone_url).ok_or("clone URL is not https")?;
    let id = id_from_url(&format!("https://{host}/{}", repo.id)).ok_or("unsafe repo id")?;
    let dir = root.join(host).join(&id);
    let git = Git {
        dir: &dir,
        host,
        token,
    };
    let exists = dir.join(".git").is_dir();
    if !sync {
        if !exists {
            return Err("not checked out yet; run `fleetreach fleet sync` (or scan --sync)".into());
        }
        return git.head().map(|commit| (dir.clone(), commit));
    }
    if let Some(parent) = dir.parent() {
        create_private_dir(parent).map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    if exists {
        git.run(&["fetch", "--depth", "1", "--no-tags", "origin"])?;
        git.sparse(source.checkout)?;
        git.run(&["reset", "--hard", "--quiet", "FETCH_HEAD"])?;
    } else {
        let mut args = vec![
            "clone",
            "--quiet",
            "--no-checkout",
            "--depth",
            "1",
            "--single-branch",
            "--no-tags",
        ];
        if source.checkout == Checkout::Lockfiles {
            args.push("--filter=blob:none");
        }
        if let Some(branch) = repo.default_branch.as_deref() {
            args.extend(["--branch", branch]);
        }
        let dir_str = dir.to_str().ok_or("checkout path is not UTF-8")?;
        args.extend(["--", repo.clone_url.as_str(), dir_str]);
        let cloned = Git {
            dir: root,
            host,
            token,
        }
        .run(&args);
        if let Err(e) = cloned {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }
        git.sparse(source.checkout)?;
        git.run(&["checkout", "--quiet"])?;
    }
    git.head().map(|commit| (dir.clone(), commit))
}

struct Git<'a> {
    dir: &'a Path,
    host: &'a str,
    token: Option<&'a str>,
}

impl Git<'_> {
    fn run(&self, args: &[&str]) -> Result<String, String> {
        let mut cmd = Command::new("git");
        cmd.current_dir(self.dir)
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "protocol.file.allow=never",
                "-c",
                "protocol.ext.allow=never",
                "-c",
                "submodule.recurse=false",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "advice.detachedHead=false",
            ])
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE");
        if let Some(token) = self.token {
            // HTTP Basic with the token as password, the form GitHub and GitLab accept for
            // git over HTTPS; scoped to this host only.
            let header = format!(
                "Authorization: Basic {}",
                base64(&format!("x-access-token:{token}"))
            );
            cmd.env("GIT_CONFIG_COUNT", "1")
                .env(
                    "GIT_CONFIG_KEY_0",
                    format!("http.https://{}/.extraheader", self.host),
                )
                .env("GIT_CONFIG_VALUE_0", header);
        }
        let output = cmd.output().map_err(|e| format!("running git: {e}"))?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let first = stderr
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("failed");
            Err(format!(
                "git {}: {}",
                args.first().copied().unwrap_or_default(),
                first.trim()
            ))
        }
    }

    fn sparse(&self, mode: Checkout) -> Result<(), String> {
        match mode {
            Checkout::Lockfiles => {
                let mut args = vec!["sparse-checkout", "set", "--no-cone"];
                args.extend(SPARSE_PATTERNS);
                self.run(&args).map(drop)
            }
            Checkout::Full => self.run(&["sparse-checkout", "disable"]).map(drop),
        }
    }

    fn head(&self) -> Result<String, String> {
        self.run(&["rev-parse", "HEAD"])
    }
}

fn base64(input: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].iter().enumerate() {
            if i <= chunk.len() {
                let idx = usize::try_from((n >> shift) & 63).unwrap_or(0);
                out.push(char::from(TABLE.get(idx).copied().unwrap_or(b'A')));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(feature = "network")]
mod github {
    use std::time::Duration;

    use super::{Listed, Source};

    const DEFAULT_API: &str = "https://api.github.com";

    pub(super) fn list(source: &Source) -> Result<Vec<Listed>, String> {
        let org = source.org.as_deref().ok_or("github source without org")?;
        let api = source
            .api_url
            .as_deref()
            .unwrap_or(DEFAULT_API)
            .trim_end_matches('/');
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .https_only(true)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(60)))
            .build()
            .into();
        let token = source.token();
        let mut all = Vec::new();
        // Organizations first; a 404 means `org` is a user account.
        for owner_kind in ["orgs", "users"] {
            let mut page = 1u32;
            loop {
                let url =
                    format!("{api}/{owner_kind}/{org}/repos?type=all&per_page=100&page={page}");
                let mut req = agent
                    .get(&url)
                    .header("Accept", "application/vnd.github+json")
                    .header(
                        "User-Agent",
                        concat!("fleetreach/", env!("CARGO_PKG_VERSION")),
                    )
                    .header("X-GitHub-Api-Version", "2022-11-28");
                if let Some(t) = &token {
                    req = req.header("Authorization", format!("Bearer {t}"));
                }
                let mut resp = req.call().map_err(|e| format!("GET {url}: {e}"))?;
                let status = resp.status().as_u16();
                if status == 404 && owner_kind == "orgs" && page == 1 {
                    break;
                }
                if status != 200 {
                    let remaining = resp
                        .headers()
                        .get("x-ratelimit-remaining")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    let hint = if remaining == "0" {
                        " (rate limit exhausted; set GITHUB_TOKEN)"
                    } else {
                        ""
                    };
                    return Err(format!("GET {url}: HTTP {status}{hint}"));
                }
                let body = resp
                    .body_mut()
                    .with_config()
                    .limit(64 * 1024 * 1024)
                    .read_to_string()
                    .map_err(|e| format!("reading {url}: {e}"))?;
                let items: Vec<serde_json::Value> =
                    serde_json::from_str(&body).map_err(|e| format!("{url}: {e}"))?;
                let n = items.len();
                for item in items {
                    let text = |k: &str| item.get(k).and_then(|v| v.as_str()).map(str::to_string);
                    let (Some(id), Some(clone_url)) = (text("full_name"), text("clone_url")) else {
                        continue;
                    };
                    all.push(Listed {
                        id,
                        clone_url,
                        default_branch: text("default_branch"),
                        archived: item.get("archived").and_then(|v| v.as_bool()) == Some(true),
                        fork: item.get("fork").and_then(|v| v.as_bool()) == Some(true),
                        topics: item
                            .get("topics")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|t| t.as_str().map(str::to_string))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    });
                }
                if n < 100 {
                    return Ok(all);
                }
                page += 1;
            }
        }
        Err(format!("GitHub has no organization or user `{org}`"))
    }
}

#[cfg(not(feature = "network"))]
mod github {
    use super::{Listed, Source};

    pub(super) fn list(_source: &Source) -> Result<Vec<Listed>, String> {
        Err("listing a GitHub source needs a network build (`--features network`)".to_string())
    }
}

/// GitLab project listing: `GET /groups/:group/projects` (subgroups included, shared
/// projects excluded), falling back to `/users/:user/projects` for a personal namespace.
// The parsers are used by the network client (and the tests) only.
#[cfg_attr(not(feature = "network"), allow(dead_code))]
mod gitlab {
    use super::Listed;

    #[cfg(feature = "network")]
    const DEFAULT_API: &str = "https://gitlab.com/api/v4";

    /// One page of `GET .../projects`: the repos it lists. Empty repositories are left out
    /// (there is nothing to clone or scan).
    pub(super) fn parse_projects(body: &str) -> Result<Vec<Listed>, String> {
        let items: Vec<serde_json::Value> =
            serde_json::from_str(body).map_err(|e| format!("GitLab projects: {e}"))?;
        Ok(items
            .iter()
            .filter(|p| p.get("empty_repo").and_then(serde_json::Value::as_bool) != Some(true))
            .filter_map(|p| {
                let text = |k: &str| p.get(k).and_then(|v| v.as_str()).map(str::to_string);
                let topics = p
                    .get("topics")
                    .or_else(|| p.get("tag_list"))
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|t| t.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                Some(Listed {
                    id: text("path_with_namespace")?,
                    clone_url: text("http_url_to_repo")?,
                    default_branch: text("default_branch"),
                    archived: p.get("archived").and_then(serde_json::Value::as_bool) == Some(true),
                    fork: p.get("forked_from_project").is_some_and(|f| !f.is_null()),
                    topics,
                })
            })
            .collect())
    }

    /// The group or user path as one URL path segment (`group/sub` -> `group%2Fsub`).
    pub(super) fn encode_namespace(namespace: &str) -> String {
        namespace
            .trim_matches('/')
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    }

    #[cfg(feature = "network")]
    pub(super) fn list(source: &super::Source) -> Result<Vec<Listed>, String> {
        use std::time::Duration;
        let namespace = source.org.as_deref().ok_or("gitlab source without org")?;
        let api = source
            .api_url
            .as_deref()
            .unwrap_or(DEFAULT_API)
            .trim_end_matches('/');
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .https_only(true)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(60)))
            .build()
            .into();
        let token = source.token();
        let encoded = encode_namespace(namespace);
        let mut all = Vec::new();
        // Groups first (subgroups included); a 404 means `org` is a user namespace.
        for (kind, query) in [
            ("groups", "include_subgroups=true&with_shared=false&"),
            ("users", ""),
        ] {
            let mut page = 1u32;
            loop {
                let url = format!(
                    "{api}/{kind}/{encoded}/projects?{query}per_page=100&page={page}&order_by=id&sort=asc"
                );
                let mut req = agent.get(&url).header(
                    "User-Agent",
                    concat!("fleetreach/", env!("CARGO_PKG_VERSION")),
                );
                if let Some(t) = &token {
                    req = req.header("PRIVATE-TOKEN", t);
                }
                let mut resp = req.call().map_err(|e| format!("GET {url}: {e}"))?;
                let status = resp.status().as_u16();
                if status == 404 && kind == "groups" && page == 1 {
                    break;
                }
                if status != 200 {
                    let hint = match status {
                        401 | 403 => " (set GITLAB_TOKEN to a token with read_api scope)",
                        429 => " (rate limited; set GITLAB_TOKEN or retry later)",
                        _ => "",
                    };
                    return Err(format!("GET {url}: HTTP {status}{hint}"));
                }
                let next = resp
                    .headers()
                    .get("x-next-page")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let body = resp
                    .body_mut()
                    .with_config()
                    .limit(64 * 1024 * 1024)
                    .read_to_string()
                    .map_err(|e| format!("reading {url}: {e}"))?;
                let items = parse_projects(&body)?;
                let raw_count = serde_json::from_str::<Vec<serde_json::Value>>(&body)
                    .map(|v| v.len())
                    .unwrap_or(0);
                all.extend(items);
                // GitLab omits `x-next-page` (or leaves it empty) on the last page; a short
                // page ends it too.
                if next.is_empty() || raw_count < 100 {
                    return Ok(all);
                }
                page += 1;
            }
        }
        Err(format!("GitLab has no group or user `{namespace}`"))
    }

    #[cfg(not(feature = "network"))]
    pub(super) fn list(_source: &super::Source) -> Result<Vec<Listed>, String> {
        Err("listing a GitLab source needs a network build (`--features network`)".to_string())
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::unwrap_used)]
        use super::*;

        #[test]
        fn projects_page_maps_to_listed_repos() {
            let body = r#"[
              {"path_with_namespace": "acme/platform/api", "http_url_to_repo": "https://gitlab.com/acme/platform/api.git",
               "default_branch": "main", "archived": false, "topics": ["production"], "forked_from_project": null},
              {"path_with_namespace": "acme/old", "http_url_to_repo": "https://gitlab.com/acme/old.git",
               "default_branch": "master", "archived": true, "tag_list": ["legacy"]},
              {"path_with_namespace": "acme/fork", "http_url_to_repo": "https://gitlab.com/acme/fork.git",
               "forked_from_project": {"id": 1}},
              {"path_with_namespace": "acme/empty", "http_url_to_repo": "https://gitlab.com/acme/empty.git",
               "empty_repo": true},
              {"name": "no path"}
            ]"#;
            let listed = parse_projects(body).unwrap();
            let ids: Vec<&str> = listed.iter().map(|r| r.id.as_str()).collect();
            assert_eq!(ids, vec!["acme/platform/api", "acme/old", "acme/fork"]);
            assert_eq!(listed[0].topics, vec!["production"]);
            assert_eq!(listed[0].default_branch.as_deref(), Some("main"));
            assert!(!listed[0].fork && !listed[0].archived);
            assert!(listed[1].archived);
            assert_eq!(listed[1].topics, vec!["legacy"]);
            assert!(listed[2].fork);
            assert!(parse_projects("{\"message\": \"404\"}").is_err());
        }

        #[test]
        fn namespaces_are_one_path_segment() {
            assert_eq!(encode_namespace("acme"), "acme");
            assert_eq!(encode_namespace("acme/platform"), "acme%2Fplatform");
            assert_eq!(encode_namespace("/a b/"), "a%20b");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn globs_match_like_renovate_filters() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("svc-*", "SVC-payments"));
        assert!(glob_match("*-sandbox", "team-sandbox"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("legacy-*", "new-legacy"));
        assert!(glob_match("*mid*", "has-mid-part"));
    }

    #[test]
    fn ids_from_urls_keep_the_namespace_and_reject_traversal() {
        assert_eq!(
            id_from_url("https://github.com/acme/api.git").as_deref(),
            Some("acme/api")
        );
        assert_eq!(
            id_from_url("https://gitlab.example.com/group/sub/svc.git").as_deref(),
            Some("group/sub/svc")
        );
        assert_eq!(id_from_url("https://github.com/acme").as_deref(), None);
        assert_eq!(id_from_url("https://gitlab.com/g/../svc").as_deref(), None);
        assert_eq!(id_from_url("https://github.com/acme/..").as_deref(), None);
        assert_eq!(id_from_url("http://github.com/acme/api"), None);
        assert_eq!(id_from_url("https://github.com/acme/a b"), None);
    }

    #[test]
    fn filters_drop_archived_forks_topics_and_excluded() {
        let source = Source {
            kind: SourceKind::GitHub,
            org: Some("acme".into()),
            api_url: None,
            urls: vec![],
            include: vec![],
            exclude: vec!["*-sandbox".into()],
            topics: vec!["production".into()],
            archived: false,
            forks: false,
            checkout: Checkout::Lockfiles,
            glob: true,
            glob_max_depth: 3,
            token_env: None,
            context: Default::default(),
        };
        let repo = |id: &str, archived: bool, fork: bool, topics: &[&str]| Listed {
            id: id.into(),
            clone_url: format!("https://github.com/{id}.git"),
            default_branch: None,
            archived,
            fork,
            topics: topics.iter().map(|t| t.to_string()).collect(),
        };
        assert!(source.keeps(&repo("acme/api", false, false, &["production", "x"])));
        assert!(!source.keeps(&repo("acme/old", true, false, &["production"])));
        assert!(!source.keeps(&repo("acme/fork", false, true, &["production"])));
        assert!(!source.keeps(&repo("acme/untagged", false, false, &[])));
        assert!(!source.keeps(&repo("acme/team-sandbox", false, false, &["production"])));
    }

    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(base64(""), "");
        assert_eq!(base64("f"), "Zg==");
        assert_eq!(base64("fo"), "Zm8=");
        assert_eq!(base64("foo"), "Zm9v");
        assert_eq!(base64("foobar"), "Zm9vYmFy");
    }
}
