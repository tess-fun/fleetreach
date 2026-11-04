//! Where the Maven resolver finds POMs: the local Maven repository (`~/.m2/repository`, or
//! `$MAVEN_REPO_LOCAL`), fleetreach's own POM cache, and, only with `--maven-fetch`, a remote
//! repository: the mirror of Maven Central that `settings.xml` names, or Maven Central itself.
//! Fetching sends each artifact's coordinates to that repository, so it is opt-in; fetched POMs
//! and listings are kept in the cache (release POMs never change).
//!
//! Fail-closed: when `settings.xml` mirrors Central but the mirror cannot be used (plain HTTP,
//! an encrypted password, an unset `${env.VAR}`), the scan stops instead of falling back to
//! Central, which a network that requires the mirror may forbid.

use std::path::{Path, PathBuf};

use fleetreach_maven::{LocalRepositories, PomSource};

const CENTRAL: &str = "https://repo.maven.apache.org/maven2";

/// `--maven-fetch` and `--maven-settings`, shared by the commands that resolve `pom.xml`.
#[derive(clap::Args, Debug, Default, Clone)]
pub struct FetchArgs {
    #[arg(
        long,
        help = "resolve pom.xml and Gradle builds with POMs fetched when they are not in ~/.m2, from the mirror of Maven Central that settings.xml names, else Maven Central (sends each artifact's coordinates there); without it, only local repositories are used"
    )]
    pub maven_fetch: bool,
    #[arg(
        long,
        value_name = "FILE",
        requires = "maven_fetch",
        help = "the Maven settings.xml whose mirror --maven-fetch uses (default: ~/.m2/settings.xml when present)"
    )]
    pub maven_settings: Option<PathBuf>,
}

impl FetchArgs {
    /// The remote to fetch from, read once, or `None` without `--maven-fetch`. A mirror that
    /// is configured but unusable is an error rather than a fallback to Maven Central.
    ///
    /// # Errors
    ///
    /// As [`Remote::configured`], prefixed with the flag.
    pub fn remote(&self, verbose: bool) -> Result<Option<Remote>, String> {
        if !self.maven_fetch {
            return Ok(None);
        }
        let remote = Remote::configured(self.maven_settings.as_deref())
            .map_err(|e| format!("--maven-fetch: {e}"))?;
        if verbose {
            match &remote.mirror {
                Some(id) => eprintln!("maven: fetching through mirror `{id}` ({})", remote.host()),
                None => eprintln!("maven: fetching from Maven Central"),
            }
        }
        Ok(Some(remote))
    }
}

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

/// The remote repository POMs are fetched from, writing what it fetches into the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    /// Base URL, without a trailing slash.
    pub url: String,
    /// The mirror id from `settings.xml`, or `None` for Maven Central itself.
    pub mirror: Option<String>,
    /// `Basic` credentials from the mirror's `<server>` entry.
    auth: Option<(String, String)>,
}

impl Remote {
    pub fn central() -> Remote {
        Remote {
            url: CENTRAL.to_string(),
            mirror: None,
            auth: None,
        }
    }

    /// The remote to fetch from: `settings` when given (it must exist), else
    /// `~/.m2/settings.xml` when present, else Maven Central.
    ///
    /// # Errors
    ///
    /// When the settings file cannot be read or parsed, or names a mirror of Central that
    /// cannot be used.
    pub fn configured(settings: Option<&Path>) -> Result<Remote, String> {
        let path = match settings {
            Some(p) => p.to_path_buf(),
            None => match std::env::var_os("HOME") {
                Some(home) => {
                    let p = PathBuf::from(home).join(".m2").join("settings.xml");
                    if !p.is_file() {
                        return Ok(Remote::central());
                    }
                    p
                }
                None => return Ok(Remote::central()),
            },
        };
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        from_settings(&text, &|name| std::env::var(name).ok())
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The URL without credentials or path, for messages.
    pub fn host(&self) -> &str {
        let rest = self
            .url
            .split_once("://")
            .map_or(self.url.as_str(), |(_, r)| r);
        rest.split('/').next().unwrap_or(rest)
    }

    fn get(&self, path: &str) -> Option<String> {
        let body = fetch(&format!("{}/{path}", self.url), self.auth.as_ref())?;
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

impl PomSource for Remote {
    fn pom(&self, group: &str, artifact: &str, version: &str) -> Option<String> {
        if !safe(group) || !safe(artifact) || !safe(version) {
            return None;
        }
        self.get(&format!(
            "{}/{version}/{artifact}-{version}.pom",
            layout(group, artifact)
        ))
    }

    fn metadata(&self, group: &str, artifact: &str) -> Option<String> {
        if !safe(group) || !safe(artifact) {
            return None;
        }
        self.get(&format!("{}/maven-metadata.xml", layout(group, artifact)))
    }
}

/// Whether a `<mirrorOf>` value covers Maven Central (repository id `central`, an external
/// HTTPS repository), with Maven's rules: comma lists, `*`, `external:*`, and `!id`
/// exclusions, which win.
fn mirrors_central(mirror_of: &str) -> bool {
    let items: Vec<&str> = mirror_of.split(',').map(str::trim).collect();
    if items.contains(&"!central") {
        return false;
    }
    items
        .iter()
        .any(|i| matches!(*i, "central" | "*" | "external:*" | "external:https:*"))
}

fn child_text<'a>(node: roxmltree::Node<'a, 'a>, name: &str) -> Option<&'a str> {
    node.children()
        .find(|c| c.has_tag_name(name))
        .and_then(|c| c.text())
        .map(str::trim)
}

/// Expand `${env.NAME}` (Maven's settings interpolation); an unset variable is an error,
/// never an empty credential.
fn expand(value: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let end = rest[start..]
            .find('}')
            .ok_or_else(|| format!("unterminated `${{` in `{value}`"))?;
        let expr = &rest[start + 2..start + end];
        let name = expr
            .strip_prefix("env.")
            .ok_or_else(|| format!("only `${{env.NAME}}` is expanded, not `${{{expr}}}`"))?;
        out.push_str(&env(name).ok_or_else(|| format!("environment variable {name} is not set"))?);
        rest = &rest[start + end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The remote a `settings.xml` makes Maven use for Central.
fn from_settings(text: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Remote, String> {
    let doc = roxmltree::Document::parse(text).map_err(|e| e.to_string())?;
    let root = doc.root_element();
    let section = |name: &str| root.children().find(|c| c.has_tag_name(name));
    let mirrors: Vec<roxmltree::Node> = section("mirrors")
        .map(|m| m.children().filter(|c| c.has_tag_name("mirror")).collect())
        .unwrap_or_default();
    // Maven prefers a mirror naming the repository exactly over a pattern.
    let exact = mirrors.iter().find(|m| {
        child_text(**m, "mirrorOf").is_some_and(|o| o.split(',').any(|i| i.trim() == "central"))
    });
    let chosen = exact.or_else(|| {
        mirrors
            .iter()
            .find(|m| child_text(**m, "mirrorOf").is_some_and(mirrors_central))
    });
    let Some(mirror) = chosen else {
        return Ok(Remote::central());
    };
    let id = child_text(*mirror, "id").unwrap_or("").to_string();
    let url = expand(
        child_text(*mirror, "url").ok_or_else(|| format!("mirror `{id}` has no <url>"))?,
        env,
    )?;
    if !url.starts_with("https://") {
        return Err(format!(
            "mirror `{id}` is not HTTPS ({}); fleetreach fetches over HTTPS only and will not fall \
             back to Maven Central",
            url.split("://").next().unwrap_or("no scheme")
        ));
    }
    let server = section("servers").and_then(|s| {
        s.children()
            .filter(|c| c.has_tag_name("server"))
            .find(|c| child_text(*c, "id") == Some(id.as_str()))
    });
    let auth = match server {
        Some(server) => {
            let user = child_text(server, "username")
                .map(|u| expand(u, env))
                .transpose()?;
            let password = child_text(server, "password")
                .map(|p| expand(p, env))
                .transpose()?;
            if password
                .as_deref()
                .is_some_and(|p| p.starts_with('{') && p.ends_with('}'))
            {
                return Err(format!(
                    "the password for server `{id}` is encrypted (settings-security.xml), which \
                     fleetreach does not decrypt; use `${{env.NAME}}` instead"
                ));
            }
            user.map(|u| (u, password.unwrap_or_default()))
        }
        None => None,
    };
    Ok(Remote {
        url: url.trim_end_matches('/').to_string(),
        mirror: Some(id),
        auth,
    })
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
fn fetch(url: &str, auth: Option<&(String, String)>) -> Option<String> {
    use std::sync::OnceLock;
    use std::time::Duration;
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    let agent = AGENT.get_or_init(|| {
        ureq::Agent::config_builder()
            .https_only(true)
            .http_status_as_error(false)
            // ureq never forwards `Authorization` across a redirect (its default), so a
            // mirror's credentials reach the mirror alone.
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into()
    });
    let mut request = agent.get(url).header(
        "User-Agent",
        concat!("fleetreach/", env!("CARGO_PKG_VERSION")),
    );
    if let Some((user, password)) = auth {
        request = request.header("Authorization", basic(user, password));
    }
    let mut resp = request.call().ok()?;
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
fn fetch(_url: &str, _auth: Option<&(String, String)>) -> Option<String> {
    None
}

/// An HTTP `Basic` header value.
#[cfg_attr(not(feature = "network"), allow(dead_code))]
fn basic(user: &str, password: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = format!("{user}:{password}");
    let mut out = String::from("Basic ");
    for chunk in input.as_bytes().chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
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

    fn settings(mirrors: &str, servers: &str) -> String {
        format!(
            "<settings xmlns=\"http://maven.apache.org/SETTINGS/1.2.0\">\
             <mirrors>{mirrors}</mirrors><servers>{servers}</servers></settings>"
        )
    }

    fn mirror(id: &str, of: &str, url: &str) -> String {
        format!("<mirror><id>{id}</id><mirrorOf>{of}</mirrorOf><url>{url}</url></mirror>")
    }

    fn env(name: &str) -> Option<String> {
        (name == "ART_TOKEN").then(|| "s3cret".to_string())
    }

    #[test]
    fn the_mirror_of_central_is_chosen_like_maven_does() {
        assert!(mirrors_central("*"));
        assert!(mirrors_central("external:*"));
        assert!(mirrors_central("internal,central"));
        assert!(!mirrors_central("*,!central"));
        assert!(!mirrors_central("snapshots"));
        assert!(!mirrors_central("external:http:*"));

        let text = settings(
            &(mirror("all", "*", "https://wild.example/maven")
                + &mirror("corp", "central", "https://art.example/maven/")),
            "",
        );
        let remote = from_settings(&text, &env).unwrap();
        assert_eq!(
            remote.mirror.as_deref(),
            Some("corp"),
            "an exact id beats a pattern"
        );
        assert_eq!(remote.url, "https://art.example/maven");
        assert_eq!(remote.host(), "art.example");

        let none = settings(&mirror("snap", "snapshots", "https://x.example"), "");
        assert_eq!(from_settings(&none, &env).unwrap(), Remote::central());
        assert_eq!(
            from_settings("<settings/>", &env).unwrap(),
            Remote::central()
        );
    }

    #[test]
    fn credentials_come_from_the_mirrors_server_with_env_expansion() {
        let text = settings(
            &mirror("corp", "*", "https://art.example/maven"),
            "<server><id>other</id><username>x</username><password>y</password></server>\
             <server><id>corp</id><username>ci</username><password>${env.ART_TOKEN}</password></server>",
        );
        let remote = from_settings(&text, &env).unwrap();
        assert_eq!(remote.auth, Some(("ci".to_string(), "s3cret".to_string())));
        assert_eq!(basic("ci", "s3cret"), "Basic Y2k6czNjcmV0");
        assert_eq!(basic("a", "bc"), "Basic YTpiYw==");
    }

    #[test]
    fn an_unusable_mirror_stops_rather_than_falling_back_to_central() {
        let http = settings(&mirror("corp", "*", "http://art.example/maven"), "");
        assert!(from_settings(&http, &env)
            .unwrap_err()
            .contains("not HTTPS"));
        let encrypted = settings(
            &mirror("corp", "*", "https://art.example/maven"),
            "<server><id>corp</id><username>ci</username><password>{COQLCE6DU6GtcS5P=}</password></server>",
        );
        assert!(from_settings(&encrypted, &env)
            .unwrap_err()
            .contains("encrypted"));
        let unset = settings(
            &mirror("corp", "*", "https://art.example/maven"),
            "<server><id>corp</id><username>ci</username><password>${env.MISSING}</password></server>",
        );
        assert!(from_settings(&unset, &env)
            .unwrap_err()
            .contains("MISSING is not set"));
        assert!(from_settings("<settings><mirrors>", &env).is_err());
    }
}
