//! Where the Maven resolver finds POMs: the local Maven repository (`~/.m2/repository`, or
//! `$MAVEN_REPO_LOCAL`), fleetreach's own POM cache, and, only with `--maven-fetch`, Maven
//! Central. Fetching sends each artifact's coordinates to Maven Central, so it is opt-in;
//! fetched POMs and listings are kept in the cache (release POMs never change).

use std::path::PathBuf;

use fleetreach_maven::{LocalRepositories, PomSource};

const CENTRAL: &str = "https://repo.maven.apache.org/maven2";

/// The local repositories, in lookup order.
pub fn local() -> LocalRepositories {
    let mut roots = Vec::new();
    if let Some(dir) = std::env::var_os("MAVEN_REPO_LOCAL") {
        roots.push(PathBuf::from(dir));
    }
    if let Some(home) = std::env::var_os("HOME") {
        roots.push(PathBuf::from(home).join(".m2").join("repository"));
    }
    if let Some(cache) = cache_root() {
        roots.push(cache);
    }
    LocalRepositories { roots }
}

fn cache_root() -> Option<PathBuf> {
    crate::osvdb::private_subdir("maven")
}

fn layout(group: &str, artifact: &str) -> String {
    format!("{}/{artifact}", group.replace('.', "/"))
}

/// Maven Central, writing what it fetches into the cache.
pub struct Central;

impl Central {
    fn get(path: &str) -> Option<String> {
        let body = fetch(&format!("{CENTRAL}/{path}"))?;
        if let Some(root) = cache_root() {
            let file = root.join(path);
            if let Some(dir) = file.parent() {
                if crate::osvdb::create_private_dir(&root).is_ok()
                    && std::fs::create_dir_all(dir).is_ok()
                {
                    let _ = std::fs::write(&file, &body);
                }
            }
        }
        Some(body)
    }
}

impl PomSource for Central {
    fn pom(&self, group: &str, artifact: &str, version: &str) -> Option<String> {
        if !safe(group) || !safe(artifact) || !safe(version) {
            return None;
        }
        Self::get(&format!(
            "{}/{version}/{artifact}-{version}.pom",
            layout(group, artifact)
        ))
    }

    fn metadata(&self, group: &str, artifact: &str) -> Option<String> {
        if !safe(group) || !safe(artifact) {
            return None;
        }
        Self::get(&format!("{}/maven-metadata.xml", layout(group, artifact)))
    }
}

/// Coordinates from untrusted POMs become URL and file path segments: no separators or
/// traversal.
fn safe(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
}

#[cfg(feature = "network")]
fn fetch(url: &str) -> Option<String> {
    use std::sync::OnceLock;
    use std::time::Duration;
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    let agent = AGENT.get_or_init(|| {
        ureq::Agent::config_builder()
            .https_only(true)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into()
    });
    let mut resp = agent
        .get(url)
        .header(
            "User-Agent",
            concat!("fleetreach/", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .ok()?;
    if resp.status().as_u16() != 200 {
        return None;
    }
    resp.body_mut()
        .with_config()
        .limit(8 * 1024 * 1024)
        .read_to_string()
        .ok()
}

#[cfg(not(feature = "network"))]
fn fetch(_url: &str) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinates_cannot_traverse() {
        assert!(safe("org.apache.logging.log4j"));
        assert!(safe("2.17.1"));
        assert!(!safe("../etc"));
        assert!(!safe("a/b"));
        assert!(!safe(".."));
        assert_eq!(layout("org.slf4j", "slf4j-api"), "org/slf4j/slf4j-api");
    }
}
