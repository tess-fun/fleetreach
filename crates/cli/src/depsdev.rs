//! The deps.dev client shared by `licenses --fetch` and `scan --release-age`: one call per
//! package version returns its licenses and when it was published. Answers are cached for
//! good under the user cache (a published version does not change); a failed lookup is not
//! cached. Every call sends the package's ecosystem, name and version to deps.dev (Google),
//! so callers only use it behind an explicit flag.

use std::collections::{BTreeMap, BTreeSet};

use fleetreach_core::Ecosystem;
use serde::{Deserialize, Serialize};

/// `(system, name, version)`.
pub type Key = (String, String, String);

/// What deps.dev knows about one package version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionInfo {
    pub licenses: Vec<String>,
    /// RFC 3339 publish time.
    pub published: Option<String>,
}

/// The deps.dev system name of an ecosystem it covers.
pub fn system(ecosystem: Ecosystem) -> Option<&'static str> {
    Some(match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::Pypi => "pypi",
        Ecosystem::Cargo => "cargo",
        Ecosystem::Go => "go",
        Ecosystem::Maven => "maven",
        Ecosystem::NuGet => "nuget",
        Ecosystem::RubyGems => "rubygems",
        _ => return None,
    })
}

/// Look every key up, from the cache or deps.dev. `None` in the map: deps.dev does not know
/// the version. Returns the answers and how many lookups failed (those keys are absent).
///
/// # Errors
///
/// When no cache directory is usable, or (without the `network` feature) when anything is
/// not cached.
pub fn infos(keys: &BTreeSet<Key>) -> Result<(BTreeMap<Key, Option<VersionInfo>>, usize), String> {
    let dir = crate::osvdb::private_subdir("depsdev").ok_or("no usable cache directory")?;
    crate::osvdb::create_private_dir(&dir)
        .map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let path = dir.join("versions.json");
    let flat = |k: &Key| format!("{}\u{1f}{}\u{1f}{}", k.0, k.1, k.2);
    let mut cache: BTreeMap<String, Option<VersionInfo>> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let todo: Vec<&Key> = keys
        .iter()
        .filter(|k| !cache.contains_key(&flat(k)))
        .collect();
    let mut failed = 0usize;
    if !todo.is_empty() {
        for (k, result) in todo.iter().zip(client::lookup_all(&todo)?) {
            match result {
                Ok(info) => {
                    cache.insert(flat(k), info);
                }
                Err(_) => failed += 1,
            }
        }
        let written = serde_json::to_string(&cache)
            .map_err(|e| e.to_string())
            .and_then(|json| std::fs::write(&path, json).map_err(|e| e.to_string()));
        if let Err(e) = written {
            eprintln!(
                "warning: could not save the deps.dev cache {}: {e}",
                path.display()
            );
        }
    }
    let out = keys
        .iter()
        .filter_map(|k| cache.get(&flat(k)).map(|v| (k.clone(), v.clone())))
        .collect();
    Ok((out, failed))
}

#[cfg(feature = "network")]
mod client {
    use std::time::Duration;

    use super::{Key, VersionInfo};

    /// Look each key up, 16 at a time.
    pub(super) fn lookup_all(
        keys: &[&Key],
    ) -> Result<Vec<Result<Option<VersionInfo>, String>>, String> {
        use rayon::prelude::*;
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .https_only(true)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(16)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(pool.install(|| keys.par_iter().map(|k| lookup(&agent, k)).collect()))
    }

    fn lookup(
        agent: &ureq::Agent,
        (system, name, version): &Key,
    ) -> Result<Option<VersionInfo>, String> {
        let url = format!(
            "https://api.deps.dev/v3/systems/{system}/packages/{}/versions/{}",
            encode(name),
            encode(version)
        );
        let mut resp = agent
            .get(&url)
            .header(
                "User-Agent",
                concat!("fleetreach/", env!("CARGO_PKG_VERSION")),
            )
            .call()
            .map_err(|e| e.to_string())?;
        match resp.status().as_u16() {
            200 => {}
            404 => return Ok(None),
            other => return Err(format!("HTTP {other}")),
        }
        let body = resp
            .body_mut()
            .with_config()
            .limit(4 * 1024 * 1024)
            .read_to_string()
            .map_err(|e| e.to_string())?;
        let value: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        Ok(Some(VersionInfo {
            licenses: value
                .get("licenses")
                .and_then(|l| l.as_array())
                .into_iter()
                .flatten()
                .filter_map(|l| l.as_str().map(str::to_string))
                .collect(),
            published: value
                .get("publishedAt")
                .and_then(|p| p.as_str())
                .map(str::to_string),
        }))
    }

    fn encode(s: &str) -> String {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    }
}

#[cfg(not(feature = "network"))]
mod client {
    use super::{Key, VersionInfo};

    pub(super) fn lookup_all(
        _keys: &[&Key],
    ) -> Result<Vec<Result<Option<VersionInfo>, String>>, String> {
        Err("deps.dev lookups need a network build (`--features network`)".to_string())
    }
}
