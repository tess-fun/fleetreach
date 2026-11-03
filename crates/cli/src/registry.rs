//! Pulling images from OCI registries (spec 16, row 10): `--image docker://ghcr.io/o/app@sha256:...`
//! and `ref = "..."` in `[[image]]`.
//!
//! A pull lands in a content-addressed cache and is then read as an OCI layout directory, by
//! the same code that reads one from disk. Everything is checked against a digest: the manifest
//! named by the reference, the manifest a tag resolves to (its digest computed here, the
//! registry's header is not believed), and each blob against the manifest. What a pull writes is
//! named by what it hashes to, so `--offline` reads a digest pulled before and a non-network
//! build reads the same cache.
//!
//! Credentials come from Docker's config (`$DOCKER_CONFIG/config.json`, `~/.docker/config.json`)
//! and its credential helpers. They go to the registry and to a token service of the same
//! domain, over TLS, and to nothing else: a redirect (to a blob store) drops them, and a token
//! realm on another domain gets an anonymous request.

// Without `network` only the cache is read, and the login and challenge code goes unused.
#![cfg_attr(not(feature = "network"), allow(dead_code))]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Manifests are small; a larger one is not one.
const MAX_MANIFEST_BYTES: u64 = 4 << 20;
/// The largest blob pulled.
const MAX_BLOB_BYTES: u64 = 16 << 30;
/// The platform of a multi-platform image when none is named.
const DEFAULT_PLATFORM: &str = "linux/amd64";
const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.docker.distribution.manifest.list.v2+json, \
    application/vnd.docker.distribution.manifest.v2+json";

/// A parsed image reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// `docker.io`, `ghcr.io`, `localhost:5000`.
    pub registry: String,
    /// `library/debian`.
    pub repository: String,
    /// `None` with a digest.
    pub tag: Option<String>,
    pub digest: Option<String>,
}

impl Reference {
    /// Parse `[registry/]repository[:tag][@sha256:hex]` as Docker does: the first component is a
    /// registry when it has a `.` or `:` or is `localhost`, the default is Docker Hub, and a
    /// bare name is under `library/` there.
    pub fn parse(text: &str) -> Result<Reference, String> {
        let bad = |why: &str| format!("image reference `{text}`: {why}");
        let (name, digest) = match text.split_once('@') {
            Some((name, digest)) => {
                let hex = digest
                    .strip_prefix("sha256:")
                    .ok_or_else(|| bad("only sha256 digests are supported"))?;
                if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(bad("the digest is not sha256:<64 hex digits>"));
                }
                (name, Some(digest.to_ascii_lowercase()))
            }
            None => (text, None),
        };
        let (registry, path) = match name.split_once('/') {
            Some((first, rest))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first.to_string(), rest)
            }
            _ => ("docker.io".to_string(), name),
        };
        // A `:` after the last `/` is a tag; one before it was the registry's port.
        let (path, tag) = match path.rsplit_once(':') {
            Some((p, t)) if !t.contains('/') => (p, Some(t.to_string())),
            _ => (path, None),
        };
        let valid = |c: char| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-' | '/')
        };
        if path.is_empty()
            || !path.chars().all(valid)
            || path.split('/').any(|p| p.is_empty() || p.starts_with('.'))
        {
            return Err(bad("the repository name is not valid"));
        }
        let tag_ok = |t: &String| {
            !t.is_empty()
                && t.len() <= 128
                && t.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        };
        if tag.as_ref().is_some_and(|t| !tag_ok(t)) {
            return Err(bad("the tag is not valid"));
        }
        if !registry
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
        {
            return Err(bad("the registry name is not valid"));
        }
        let repository = if registry == "docker.io" && !path.contains('/') {
            format!("library/{path}")
        } else {
            path.to_string()
        };
        let tag = match (&digest, tag) {
            (Some(_), _) => None,
            (None, Some(t)) => Some(t),
            (None, None) => Some("latest".to_string()),
        };
        Ok(Reference {
            registry,
            repository,
            tag,
            digest,
        })
    }

    /// The digest or tag, as the manifest URL takes it.
    fn selector(&self) -> &str {
        self.digest
            .as_deref()
            .or(self.tag.as_deref())
            .unwrap_or("latest")
    }
}

/// A pulled image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pulled {
    /// An OCI layout directory holding it.
    pub layout: PathBuf,
    /// The digest of the image's manifest, for this platform.
    pub digest: String,
}

/// Where manifests and blobs come from.
pub(crate) trait Fetch {
    /// Write what the registry has at `path` (`manifests/<selector>`, `blobs/<digest>`) to
    /// `out`, up to `limit` bytes.
    fn get(&mut self, path: &str, limit: u64, out: &mut dyn Write) -> Result<(), String>;
}

/// The source of a run that must not touch the network.
struct NoRegistry(&'static str);

impl Fetch for NoRegistry {
    fn get(&mut self, path: &str, _: u64, _: &mut dyn Write) -> Result<(), String> {
        Err(format!("{path} is not in the cache, and {}", self.0))
    }
}

#[derive(Deserialize, Clone)]
struct Descriptor {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    platform: Option<Platform>,
}

#[derive(Deserialize, Clone)]
struct Platform {
    #[serde(default)]
    os: String,
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    variant: Option<String>,
}

#[derive(Deserialize)]
struct Manifest {
    #[serde(default)]
    manifests: Option<Vec<Descriptor>>,
    #[serde(default)]
    config: Option<Descriptor>,
    #[serde(default)]
    layers: Vec<Descriptor>,
}

fn hex_of(digest: &str) -> Result<&str, String> {
    digest
        .strip_prefix("sha256:")
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| format!("unsupported digest `{digest}`"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The content-addressed cache.
struct Store {
    root: PathBuf,
}

/// A writer that hashes what passes through.
struct Hashing<W> {
    inner: W,
    hasher: Sha256,
    written: u64,
}

impl<W: Write> Write for Hashing<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Store {
    fn blob_path(&self, digest: &str) -> Result<PathBuf, String> {
        Ok(self.root.join("blobs/sha256").join(hex_of(digest)?))
    }

    /// A unique name beside the blobs, so parallel pulls of a shared layer do not collide.
    fn scratch(&self) -> Result<PathBuf, String> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = self.root.join("blobs/sha256");
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        Ok(dir.join(format!("tmp-{}-{n}", std::process::id())))
    }

    /// Fetch `path` into the store. With `want`, what arrives must hash to it. Returns its
    /// digest.
    fn fetch(
        &self,
        source: &mut dyn Fetch,
        path: &str,
        want: Option<&str>,
        size: Option<u64>,
        limit: u64,
    ) -> Result<String, String> {
        let tmp = self.scratch()?;
        let result = (|| {
            let file = File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
            let mut out = Hashing {
                inner: io::BufWriter::new(file),
                hasher: Sha256::new(),
                written: 0,
            };
            source.get(path, size.map_or(limit, |s| s.min(limit)), &mut out)?;
            out.flush().map_err(|e| format!("{}: {e}", tmp.display()))?;
            let hex: String = out
                .hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let got = format!("sha256:{hex}");
            if want.is_some_and(|w| w != got) {
                return Err(format!("{path}: the content does not match its digest"));
            }
            if size.is_some_and(|s| s != out.written) {
                return Err(format!(
                    "{path}: the content is not the size its manifest says"
                ));
            }
            let dest = self.blob_path(&got)?;
            std::fs::rename(&tmp, &dest).map_err(|e| format!("{}: {e}", dest.display()))?;
            Ok(got)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// The blob of `descriptor`, fetched unless the store has it.
    fn blob(
        &self,
        source: &mut dyn Fetch,
        descriptor: &Descriptor,
        limit: u64,
    ) -> Result<(), String> {
        if self.blob_path(&descriptor.digest)?.is_file() {
            return Ok(());
        }
        let path = format!("blobs/{}", descriptor.digest);
        self.fetch(
            source,
            &path,
            Some(&descriptor.digest),
            descriptor.size,
            limit,
        )
        .map(|_| ())
    }

    /// The manifest with `digest`, fetched unless the store has it. What the store has is
    /// checked again, as this is what names everything else.
    fn manifest(&self, source: &mut dyn Fetch, digest: &str) -> Result<Vec<u8>, String> {
        let path = self.blob_path(digest)?;
        if !path.is_file() {
            self.fetch(
                source,
                &format!("manifests/{digest}"),
                Some(digest),
                None,
                MAX_MANIFEST_BYTES,
            )?;
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if format!("sha256:{}", sha256_hex(&bytes)) != digest {
            let _ = std::fs::remove_file(&path);
            return Err(format!("the cached manifest {digest} is corrupt"));
        }
        Ok(bytes)
    }

    /// An OCI layout of one image over the store's blobs: hard links, so a base shared by a
    /// fleet is on disk once.
    fn layout(&self, digest: &str, blobs: &[&str]) -> Result<PathBuf, String> {
        let dir = self.root.join("layouts").join(hex_of(digest)?);
        let in_layout = dir.join("blobs/sha256");
        std::fs::create_dir_all(&in_layout).map_err(|e| format!("{}: {e}", dir.display()))?;
        for blob in blobs {
            let (from, to) = (self.blob_path(blob)?, in_layout.join(hex_of(blob)?));
            if !to.is_file() && std::fs::hard_link(&from, &to).is_err() && !to.is_file() {
                std::fs::copy(&from, &to).map_err(|e| format!("{}: {e}", to.display()))?;
            }
        }
        let index = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": digest,
            }],
        });
        let tmp = self.scratch()?;
        std::fs::write(&tmp, index.to_string()).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, dir.join("index.json"))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        std::fs::write(dir.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        Ok(dir)
    }
}

fn label(p: &Platform) -> String {
    match &p.variant {
        Some(v) => format!("{}/{}/{v}", p.os, p.architecture),
        None => format!("{}/{}", p.os, p.architecture),
    }
}

/// The entry of a multi-platform index for `wanted`: an exact match, or, as `linux/arm64` is
/// usually published as `linux/arm64/v8`, the one image of that OS and architecture.
fn pick<'a>(entries: &'a [Descriptor], wanted: &str) -> Result<&'a Descriptor, String> {
    let images: Vec<&Descriptor> = entries
        .iter()
        .filter(|d| d.platform.as_ref().is_some_and(|p| p.os != "unknown"))
        .collect();
    let labelled = |d: &&&Descriptor| d.platform.as_ref().map(label);
    if let Some(d) = images
        .iter()
        .find(|d| labelled(d).as_deref() == Some(wanted))
    {
        return Ok(d);
    }
    let close: Vec<&&Descriptor> = images
        .iter()
        .filter(|d| {
            labelled(d).is_some_and(|l| l.strip_prefix(wanted).is_some_and(|v| v.starts_with('/')))
        })
        .collect();
    if let [one] = close[..] {
        return Ok(one);
    }
    let have: Vec<String> = images.iter().filter_map(|d| labelled(&d)).collect();
    Err(format!(
        "no image for {wanted} (it has {}); choose one with `platform`",
        have.join(", ")
    ))
}

/// Whether a layer is one the image reader can read.
fn readable_layer(media_type: &str) -> bool {
    media_type.is_empty()
        || matches!(
            media_type,
            "application/vnd.oci.image.layer.v1.tar"
                | "application/vnd.oci.image.layer.v1.tar+gzip"
                | "application/vnd.oci.image.layer.v1.tar+zstd"
                | "application/vnd.docker.image.rootfs.diff.tar.gzip"
                | "application/vnd.docker.image.rootfs.diff.tar"
        )
}

/// Bring the image `reference` into `store` from `source`.
fn pull_into(
    store: &Store,
    source: &mut dyn Fetch,
    reference: &Reference,
    platform: Option<&str>,
) -> Result<Pulled, String> {
    let top = match &reference.digest {
        Some(digest) => digest.clone(),
        None => store.fetch(
            source,
            &format!("manifests/{}", reference.selector()),
            None,
            None,
            MAX_MANIFEST_BYTES,
        )?,
    };
    let parse = |bytes: &[u8]| {
        serde_json::from_slice::<Manifest>(bytes).map_err(|e| format!("manifest: {e}"))
    };
    let mut digest = top.clone();
    let mut manifest = parse(&store.manifest(source, &top)?)?;
    if let Some(entries) = &manifest.manifests {
        let entry = pick(entries, platform.unwrap_or(DEFAULT_PLATFORM))?;
        digest = entry.digest.clone();
        manifest = parse(&store.manifest(source, &digest)?)?;
        if manifest.manifests.is_some() {
            return Err("an image index points at another index".to_string());
        }
    }
    let config = manifest
        .config
        .as_ref()
        .ok_or("the manifest has no config: it is not an image")?;
    if let Some(layer) = manifest
        .layers
        .iter()
        .find(|l| !readable_layer(&l.media_type))
    {
        return Err(format!(
            "layer {} is `{}`, which is not an image layer fleetreach reads",
            layer.digest, layer.media_type
        ));
    }
    store.blob(source, config, MAX_MANIFEST_BYTES.max(16 << 20))?;
    for layer in &manifest.layers {
        store.blob(source, layer, MAX_BLOB_BYTES)?;
    }
    let mut blobs: Vec<&str> = vec![&digest, &config.digest];
    blobs.extend(manifest.layers.iter().map(|l| l.digest.as_str()));
    Ok(Pulled {
        layout: store.layout(&digest, &blobs)?,
        digest,
    })
}

/// Pull `reference`, or find it in the cache. `offline` keeps to the cache, so a tag, which
/// only the registry can resolve, is refused.
pub fn pull(reference: &str, platform: Option<&str>, offline: bool) -> Result<Pulled, String> {
    let reference = Reference::parse(reference)?;
    let root = crate::osvdb::private_subdir("images")
        .ok_or("no usable cache directory for pulled images")?;
    make_private(&root)?;
    let store = Store { root };
    let local = |why: &'static str| NoRegistry(why);
    if offline || !cfg!(feature = "network") {
        let why = if offline {
            "--offline keeps to the cache"
        } else {
            "this build has no network support (build with `--features network`)"
        };
        if reference.digest.is_none() {
            return Err(format!(
                "a tag needs the registry, and {why}; name the image by digest"
            ));
        }
        return pull_into(&store, &mut local(why), &reference, platform);
    }
    #[cfg(feature = "network")]
    {
        let mut client = client::Client::new(&reference)?;
        pull_into(&store, &mut client, &reference, platform)
    }
    #[cfg(not(feature = "network"))]
    Err("this build has no network support".to_string())
}

/// Create the cache directory, closed to other users.
fn make_private(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok(())
}

/// A registry login.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Credentials {
    pub(crate) user: String,
    pub(crate) secret: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credentials({}, <secret>)", self.user)
    }
}

#[derive(Deserialize, Default)]
struct DockerConfig {
    #[serde(default)]
    auths: BTreeMap<String, DockerAuth>,
    #[serde(rename = "credsStore", default)]
    creds_store: Option<String>,
    #[serde(rename = "credHelpers", default)]
    cred_helpers: BTreeMap<String, String>,
}

#[derive(Deserialize, Default)]
struct DockerAuth {
    #[serde(default)]
    auth: Option<String>,
}

/// The names Docker's config may file `registry` under.
fn config_keys(registry: &str) -> Vec<String> {
    if registry == "docker.io" {
        return [
            "https://index.docker.io/v1/",
            "index.docker.io",
            "docker.io",
            "registry-1.docker.io",
        ]
        .map(String::from)
        .to_vec();
    }
    vec![registry.to_string(), format!("https://{registry}")]
}

fn decode_auth(auth: &str) -> Option<Credentials> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(auth.trim())
        .ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (user, secret) = text.split_once(':')?;
    Some(Credentials {
        user: user.to_string(),
        secret: secret.to_string(),
    })
}

/// A helper name, which becomes part of a program name.
fn helper_name(name: &str) -> Option<&str> {
    (!name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
    .then_some(name)
}

/// Ask `docker-credential-<helper>` for the login of `server`. A helper that is missing or
/// has none means no login.
fn from_helper(helper: &str, server: &str) -> Option<Credentials> {
    use std::process::{Command, Stdio};
    #[derive(Deserialize)]
    struct Answer {
        #[serde(rename = "Username")]
        username: String,
        #[serde(rename = "Secret")]
        secret: String,
    }
    let mut child = Command::new(format!("docker-credential-{}", helper_name(helper)?))
        .arg("get")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(server.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let answer: Answer = serde_json::from_slice(&out.stdout).ok()?;
    // `<token>` marks an OAuth refresh token, which is no password.
    (answer.username != "<token>" && !answer.secret.is_empty()).then_some(Credentials {
        user: answer.username,
        secret: answer.secret,
    })
}

/// The login for `registry` in `config`: its credential helper, its `auths` entry, then the
/// default store, as Docker looks.
fn lookup(
    config: &DockerConfig,
    registry: &str,
    helper: &dyn Fn(&str, &str) -> Option<Credentials>,
) -> Option<Credentials> {
    let keys = config_keys(registry);
    keys.iter()
        .find_map(|k| helper(config.cred_helpers.get(k)?, k))
        .or_else(|| {
            keys.iter()
                .find_map(|k| decode_auth(config.auths.get(k)?.auth.as_deref()?))
        })
        .or_else(|| {
            let store = config.creds_store.as_deref()?;
            keys.iter().find_map(|k| helper(store, k))
        })
}

/// The login for `registry`, from Docker's config.
pub(crate) fn credentials(registry: &str) -> Option<Credentials> {
    let dir = std::env::var_os("DOCKER_CONFIG")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".docker")))?;
    let text = std::fs::read(dir.join("config.json")).ok()?;
    let config: DockerConfig = serde_json::from_slice(&text).ok()?;
    lookup(&config, registry, &from_helper)
}

/// A `WWW-Authenticate` challenge: its scheme, and its parameters.
fn challenge(header: &str) -> Option<(String, BTreeMap<String, String>)> {
    let (scheme, rest) = header.trim().split_once(' ').unwrap_or((header.trim(), ""));
    let mut params = BTreeMap::new();
    let mut rest = rest.trim();
    while let Some((key, value)) = rest.split_once('=') {
        let key = key
            .trim()
            .trim_start_matches(',')
            .trim()
            .to_ascii_lowercase();
        let (value, tail) = match value.strip_prefix('"') {
            Some(quoted) => quoted.split_once('"')?,
            None => value.split_once(',').unwrap_or((value, "")),
        };
        params.insert(key, value.to_string());
        rest = tail.trim();
    }
    Some((scheme.to_ascii_lowercase(), params))
}

/// The host of an `http(s)` URL.
fn host_of(url: &str) -> Option<&str> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    // Userinfo in a URL is a way to dress one host as another.
    if authority.contains('@') {
        return None;
    }
    Some(authority)
}

fn is_local(host: &str) -> bool {
    let name = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(v6),
        None => host.rsplit_once(':').map_or(host, |(h, _)| h),
    };
    matches!(name, "localhost" | "127.0.0.1" | "::1")
}

/// Whether `url` may be requested at all: TLS, or this machine.
fn allowed_url(url: &str) -> bool {
    url.starts_with("https://") && host_of(url).is_some()
        || (url.starts_with("http://") && host_of(url).is_some_and(is_local))
}

/// Whether a token service at `realm` may see the login of `registry`: an allowed URL on the
/// registry's own domain (`auth.docker.io` for Docker Hub, `ghcr.io` for itself).
fn realm_trusted(realm: &str, registry: &str) -> bool {
    fn domain(host: &str) -> String {
        let name = host.rsplit_once(':').map_or(host, |(h, _)| h);
        let labels: Vec<&str> = name.split('.').collect();
        labels[labels.len().saturating_sub(2)..].join(".")
    }
    allowed_url(realm) && host_of(realm).is_some_and(|h| domain(h) == domain(registry))
}

#[cfg(feature = "network")]
mod client {
    use super::{
        allowed_url, challenge, credentials, host_of, is_local, realm_trusted, Credentials, Fetch,
        Reference, ACCEPT,
    };
    use std::io::{Read, Write};
    use std::time::Duration;

    const MAX_REDIRECTS: usize = 5;
    const MAX_TOKEN_BYTES: u64 = 1 << 20;

    pub(super) struct Client {
        agent: ureq::Agent,
        /// `https://ghcr.io`.
        base: String,
        registry: String,
        repository: String,
        login: Option<Credentials>,
        /// The `Authorization` value in use.
        auth: Option<String>,
    }

    fn basic(login: &Credentials) -> String {
        use base64::Engine;
        let pair = format!("{}:{}", login.user, login.secret);
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(pair)
        )
    }

    fn query(value: &str) -> String {
        let mut out = String::new();
        for b in value.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                out.push(char::from(b));
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }

    impl Client {
        pub(super) fn new(reference: &Reference) -> Result<Client, String> {
            let host = match reference.registry.as_str() {
                "docker.io" => "registry-1.docker.io",
                other => other,
            };
            let scheme = if is_local(host) { "http" } else { "https" };
            let agent = ureq::Agent::config_builder()
                // Followed by hand, to drop credentials and refuse plain http.
                .max_redirects(0)
                .http_status_as_error(false)
                .timeout_connect(Some(Duration::from_secs(15)))
                .timeout_recv_response(Some(Duration::from_secs(60)))
                .timeout_recv_body(Some(Duration::from_secs(30 * 60)))
                .build()
                .into();
            Ok(Client {
                agent,
                base: format!("{scheme}://{host}"),
                registry: reference.registry.clone(),
                repository: reference.repository.clone(),
                login: credentials(&reference.registry),
                auth: None,
            })
        }

        /// Answer a challenge, setting `auth`.
        fn authorize(&mut self, header: &str) -> Result<(), String> {
            let (scheme, params) =
                challenge(header).ok_or("the registry's challenge cannot be read")?;
            if scheme == "basic" {
                let login = self
                    .login
                    .as_ref()
                    .ok_or("the registry wants a login, and Docker's config has none for it")?;
                self.auth = Some(basic(login));
                return Ok(());
            }
            if scheme != "bearer" {
                return Err(format!("unsupported authentication `{scheme}`"));
            }
            let realm = params.get("realm").ok_or("the challenge has no realm")?;
            if !allowed_url(realm) {
                return Err("the registry's token service is not on TLS".to_string());
            }
            let scope = params
                .get("scope")
                .cloned()
                .unwrap_or_else(|| format!("repository:{}:pull", self.repository));
            let mut url = format!("{realm}?scope={}", query(&scope));
            if let Some(service) = params.get("service") {
                url.push_str(&format!("&service={}", query(service)));
            }
            let mut request = self.agent.get(&url);
            if let Some(login) = self
                .login
                .as_ref()
                .filter(|_| realm_trusted(realm, &self.registry))
            {
                request = request.header("Authorization", basic(login));
            }
            let mut response = request.call().map_err(|e| format!("token service: {e}"))?;
            if response.status() != 200 {
                return Err(format!(
                    "the token service answered {} (no access to {}, or a login is needed)",
                    response.status().as_u16(),
                    self.repository
                ));
            }
            #[derive(serde::Deserialize)]
            struct Answer {
                token: Option<String>,
                access_token: Option<String>,
            }
            let bytes = response
                .body_mut()
                .with_config()
                .limit(MAX_TOKEN_BYTES)
                .read_to_vec()
                .map_err(|e| format!("token service: {e}"))?;
            let answer: Answer =
                serde_json::from_slice(&bytes).map_err(|e| format!("token service: {e}"))?;
            let token = answer
                .token
                .or(answer.access_token)
                .ok_or("the token service sent no token")?;
            self.auth = Some(format!("Bearer {token}"));
            Ok(())
        }
    }

    impl Fetch for Client {
        fn get(&mut self, path: &str, limit: u64, out: &mut dyn Write) -> Result<(), String> {
            let mut url = format!("{}/v2/{}/{path}", self.base, self.repository);
            let origin = host_of(&url).unwrap_or_default().to_string();
            let mut challenged = false;
            let mut hops = 0;
            loop {
                let mut request = self.agent.get(&url).header("Accept", ACCEPT);
                // Only the registry itself sees the token, never where it redirects.
                if let Some(auth) = self
                    .auth
                    .as_ref()
                    .filter(|_| host_of(&url) == Some(origin.as_str()))
                {
                    request = request.header("Authorization", auth);
                }
                let mut response = request.call().map_err(|e| format!("{path}: {e}"))?;
                let status = response.status().as_u16();
                match status {
                    200 => {
                        let mut reader = response
                            .body_mut()
                            .with_config()
                            .limit(limit.saturating_add(1))
                            .reader()
                            .take(limit.saturating_add(1));
                        let n =
                            std::io::copy(&mut reader, out).map_err(|e| format!("{path}: {e}"))?;
                        if n > limit {
                            return Err(format!("{path}: larger than its limit"));
                        }
                        return Ok(());
                    }
                    401 if !challenged => {
                        challenged = true;
                        let header = response
                            .headers()
                            .get("www-authenticate")
                            .and_then(|v| v.to_str().ok())
                            .ok_or("401 with no challenge")?
                            .to_string();
                        self.authorize(&header)?;
                    }
                    301 | 302 | 303 | 307 | 308 if hops < MAX_REDIRECTS => {
                        hops += 1;
                        let location = response
                            .headers()
                            .get("location")
                            .and_then(|v| v.to_str().ok())
                            .ok_or("a redirect with no location")?;
                        url = if location.starts_with('/') {
                            let scheme = url.split("://").next().unwrap_or("https");
                            format!("{scheme}://{}{location}", host_of(&url).unwrap_or_default())
                        } else {
                            location.to_string()
                        };
                        if !allowed_url(&url) {
                            return Err(format!("{path}: redirected off TLS"));
                        }
                    }
                    401 | 403 => {
                        return Err(format!(
                            "{path}: access denied ({status}); log in with `docker login`"
                        ))
                    }
                    404 => return Err(format!("{path}: not found in {}", self.repository)),
                    429 => return Err(format!("{path}: the registry is rate limiting (429)")),
                    other => return Err(format!("{path}: the registry answered {other}")),
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::unwrap_used, clippy::panic)]
        use super::*;
        use std::io::{BufRead, BufReader};
        use std::net::TcpListener;
        use std::sync::mpsc;

        /// Serve `answers` in turn, sending each request's head to `seen`.
        fn serve(answers: Vec<String>, seen: mpsc::Sender<String>) -> u16 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            std::thread::spawn(move || {
                for answer in answers {
                    let (stream, _) = listener.accept().unwrap();
                    let mut reader = BufReader::new(stream);
                    let mut head = String::new();
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        if line.trim().is_empty() {
                            break;
                        }
                        head.push_str(&line);
                    }
                    seen.send(head).unwrap();
                    reader.get_mut().write_all(answer.as_bytes()).unwrap();
                }
            });
            port
        }

        fn answer(status: &str, headers: &str, body: &str) -> String {
            format!(
                "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n\
                 {body}",
                body.len()
            )
        }

        fn client(port: u16) -> Client {
            let reference = Reference::parse(&format!("127.0.0.1:{port}/r")).unwrap();
            let mut client = Client::new(&reference).unwrap();
            client.login = Some(Credentials {
                user: "u".to_string(),
                secret: "p".to_string(),
            });
            client
        }

        #[test]
        fn a_redirect_never_carries_the_login() {
            let (to_cdn, cdn_saw) = mpsc::channel();
            let cdn = serve(vec![answer("200 OK", "", "layer")], to_cdn);
            let (to_registry, registry_saw) = mpsc::channel();
            let location = format!("Location: http://localhost:{cdn}/object\r\n");
            let registry = serve(
                vec![
                    answer(
                        "401 Unauthorized",
                        "WWW-Authenticate: Basic realm=\"r\"\r\n",
                        "",
                    ),
                    answer("307 Temporary Redirect", &location, ""),
                ],
                to_registry,
            );
            let mut out = Vec::new();
            client(registry).get("blobs/x", 100, &mut out).unwrap();
            assert_eq!(out, b"layer");
            let (first, second) = (registry_saw.recv().unwrap(), registry_saw.recv().unwrap());
            assert!(!first.to_lowercase().contains("authorization"), "{first}");
            assert!(
                second.to_lowercase().contains("authorization: basic"),
                "{second}"
            );
            let at_cdn = cdn_saw.recv().unwrap();
            assert!(!at_cdn.to_lowercase().contains("authorization"), "{at_cdn}");
        }

        #[test]
        fn a_token_service_on_another_domain_gets_no_login() {
            let (to_realm, realm_saw) = mpsc::channel();
            let realm = serve(vec![answer("200 OK", "", r#"{"token":"t"}"#)], to_realm);
            let (to_registry, registry_saw) = mpsc::channel();
            let challenge =
                format!("WWW-Authenticate: Bearer realm=\"http://localhost:{realm}/token\"\r\n");
            let registry = serve(
                vec![
                    answer("401 Unauthorized", &challenge, ""),
                    answer("200 OK", "", "m"),
                ],
                to_registry,
            );
            let mut c = client(registry);
            // The login is for `example.com`; the realm is not on that domain.
            c.registry = "example.com".to_string();
            let mut out = Vec::new();
            c.get("manifests/1", 100, &mut out).unwrap();
            let at_realm = realm_saw.recv().unwrap();
            assert!(
                !at_realm.to_lowercase().contains("authorization"),
                "{at_realm}"
            );
            registry_saw.recv().unwrap();
            let second = registry_saw.recv().unwrap();
            assert!(second.contains("uthorization: Bearer t"), "{second}");
        }

        #[test]
        fn a_redirect_to_plain_http_is_refused() {
            let (to_registry, _saw) = mpsc::channel();
            let registry = serve(
                vec![answer(
                    "302 Found",
                    "Location: http://cdn.example/object\r\n",
                    "",
                )],
                to_registry,
            );
            let err = client(registry)
                .get("blobs/x", 100, &mut Vec::new())
                .unwrap_err();
            assert!(err.contains("off TLS"), "{err}");
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn r(text: &str) -> Reference {
        Reference::parse(text).unwrap()
    }

    #[test]
    fn references_read_as_docker_reads_them() {
        let hub = r("debian");
        assert_eq!(hub.registry, "docker.io");
        assert_eq!(hub.repository, "library/debian");
        assert_eq!(hub.tag.as_deref(), Some("latest"));
        assert_eq!(r("grafana/grafana:11").repository, "grafana/grafana");
        let port = r("localhost:5000/a/b");
        assert_eq!(port.registry, "localhost:5000");
        assert_eq!(port.repository, "a/b");
        assert_eq!(port.tag.as_deref(), Some("latest"));
        let hex = "a".repeat(64);
        let pinned = r(&format!("ghcr.io/o/app:1.2@sha256:{hex}"));
        assert_eq!(pinned.registry, "ghcr.io");
        assert_eq!(pinned.tag, None);
        assert_eq!(pinned.selector(), format!("sha256:{hex}"));
        for bad in [
            "",
            "Upper/case",
            "a//b",
            "a/../b",
            "a@sha256:abc",
            "a@md5:abc",
            "a:b/c:",
            "evil.io/a?x=1",
            "a:ta g",
        ] {
            assert!(Reference::parse(bad).is_err(), "{bad}");
        }
    }

    /// A registry in memory.
    #[derive(Default)]
    struct Fake {
        paths: BTreeMap<String, Vec<u8>>,
        asked: Vec<String>,
    }

    impl Fetch for Fake {
        fn get(&mut self, path: &str, limit: u64, out: &mut dyn Write) -> Result<(), String> {
            self.asked.push(path.to_string());
            let data = self.paths.get(path).ok_or(format!("{path}: not found"))?;
            if data.len() as u64 > limit {
                return Err(format!("{path}: larger than its limit"));
            }
            out.write_all(data).map_err(|e| e.to_string())
        }
    }

    fn digest(b: &[u8]) -> String {
        format!("sha256:{}", sha256_hex(b))
    }

    /// A store in a fresh directory, and a registry with one image, `(tag, manifest digest)`.
    fn fixture(name: &str) -> (Store, Fake, String) {
        let root = std::env::temp_dir().join(format!("fr-reg-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut fake = Fake::default();
        let (layer, config) = (b"layer bytes".to_vec(), b"{}".to_vec());
        let manifest = format!(
            r#"{{"schemaVersion":2,"config":{{"digest":"{}","size":{}}},"layers":[{{
            "mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{}","size":{}}}]}}"#,
            digest(&config),
            config.len(),
            digest(&layer),
            layer.len()
        )
        .into_bytes();
        let id = digest(&manifest);
        fake.paths
            .insert(format!("blobs/{}", digest(&layer)), layer);
        fake.paths
            .insert(format!("blobs/{}", digest(&config)), config);
        fake.paths
            .insert("manifests/1".to_string(), manifest.clone());
        fake.paths.insert(format!("manifests/{id}"), manifest);
        (Store { root }, fake, id)
    }

    #[test]
    fn a_tag_pull_makes_a_layout_a_digest_can_read_offline() {
        let (store, mut fake, id) = fixture("tag");
        let pulled = pull_into(&store, &mut fake, &r("a/b:1"), None).unwrap();
        assert_eq!(pulled.digest, id);
        let index = std::fs::read_to_string(pulled.layout.join("index.json")).unwrap();
        assert!(index.contains(&id));
        // Named by digest, everything is in the cache: the registry is not needed.
        let mut none = NoRegistry("offline");
        let by_digest = r(&format!("a/b@{id}"));
        let again = pull_into(&store, &mut none, &by_digest, None).unwrap();
        assert_eq!(again, pulled);
        let _ = std::fs::remove_dir_all(&store.root);
    }

    #[test]
    fn nothing_that_does_not_match_its_digest_is_kept() {
        let (store, mut fake, id) = fixture("tamper");
        // The registry swaps the manifest behind a pinned digest.
        fake.paths.insert(format!("manifests/{id}"), b"{}".to_vec());
        let pinned = r(&format!("a/b@{id}"));
        let err = pull_into(&store, &mut fake, &pinned, None).unwrap_err();
        assert!(err.contains("does not match"), "{err}");
        // A layer swapped for one of the same size.
        let (store, mut fake, _) = fixture("tamper2");
        let layer = fake
            .paths
            .keys()
            .find(|k| k.starts_with("blobs/") && fake.paths[*k].len() > 5)
            .cloned()
            .unwrap();
        fake.paths.insert(layer, b"LAYER BYTES".to_vec());
        let err = pull_into(&store, &mut fake, &r("a/b:1"), None).unwrap_err();
        assert!(err.contains("does not match"), "{err}");
        let left: Vec<_> = std::fs::read_dir(store.root.join("blobs/sha256"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("tmp-"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
        let _ = std::fs::remove_dir_all(&store.root);
    }

    #[test]
    fn a_corrupted_cache_is_not_believed() {
        let (store, mut fake, id) = fixture("cache");
        pull_into(&store, &mut fake, &r("a/b:1"), None).unwrap();
        std::fs::write(store.blob_path(&id).unwrap(), b"{}").unwrap();
        let err = pull_into(&store, &mut NoRegistry("x"), &r(&format!("a/b@{id}")), None);
        assert!(err.unwrap_err().contains("corrupt"));
        let _ = std::fs::remove_dir_all(&store.root);
    }

    #[test]
    fn indexes_pick_a_platform_and_artifacts_are_refused() {
        let entry = |os: &str, arch: &str, variant: Option<&str>| Descriptor {
            media_type: String::new(),
            digest: format!("sha256:{arch}"),
            size: None,
            platform: Some(Platform {
                os: os.into(),
                architecture: arch.into(),
                variant: variant.map(String::from),
            }),
        };
        let entries = [
            entry("unknown", "unknown", None),
            entry("linux", "amd64", None),
            entry("linux", "arm64", Some("v8")),
        ];
        assert_eq!(
            pick(&entries, "linux/amd64").unwrap().digest,
            "sha256:amd64"
        );
        assert_eq!(
            pick(&entries, "linux/arm64").unwrap().digest,
            "sha256:arm64"
        );
        let err = pick(&entries, "linux/s390x").err().unwrap();
        assert!(err.contains("linux/amd64, linux/arm64/v8"), "{err}");
        assert!(readable_layer(
            "application/vnd.oci.image.layer.v1.tar+zstd"
        ));
        assert!(!readable_layer(
            "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
        ));
    }

    #[test]
    fn logins_are_found_as_docker_finds_them() {
        use base64::Engine;
        let enc = base64::engine::general_purpose::STANDARD.encode("me:pw");
        let config: DockerConfig = serde_json::from_str(&format!(
            r#"{{"auths":{{"https://index.docker.io/v1/":{{"auth":"{enc}"}},"plain.io":{{}}}},
            "credHelpers":{{"ecr.aws":"ecr"}},"credsStore":"desktop"}}"#
        ))
        .unwrap();
        let helper = |name: &str, _: &str| {
            Some(Credentials {
                user: name.to_string(),
                secret: "s".to_string(),
            })
        };
        let none = |_: &str, _: &str| None;
        assert_eq!(lookup(&config, "docker.io", &none).unwrap().secret, "pw");
        assert_eq!(lookup(&config, "ecr.aws", &helper).unwrap().user, "ecr");
        assert_eq!(
            lookup(&config, "other.io", &helper).unwrap().user,
            "desktop"
        );
        assert_eq!(lookup(&config, "other.io", &none), None);
        assert_eq!(helper_name("../evil"), None);
        assert_eq!(helper_name("ecr-login"), Some("ecr-login"));
        let shown = format!("{:?}", lookup(&config, "docker.io", &none).unwrap());
        assert!(!shown.contains("pw"), "{shown}");
    }

    #[test]
    fn challenges_and_what_may_see_a_login() {
        let (scheme, params) = challenge(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/debian:pull""#,
        )
        .unwrap();
        assert_eq!(scheme, "bearer");
        assert_eq!(params["realm"], "https://auth.docker.io/token");
        assert_eq!(params["scope"], "repository:library/debian:pull");
        assert_eq!(challenge(r#"Basic realm="x""#).unwrap().0, "basic");
        assert!(realm_trusted("https://auth.docker.io/token", "docker.io"));
        assert!(realm_trusted("https://ghcr.io/token", "ghcr.io"));
        assert!(realm_trusted("http://localhost:5001/t", "localhost:5000"));
        for (realm, registry) in [
            ("https://evil.example/token", "ghcr.io"),
            ("http://auth.docker.io/token", "docker.io"),
            ("https://ghcr.io@evil.example/token", "ghcr.io"),
            ("https://ghcr.io.evil.example/token", "ghcr.io"),
        ] {
            assert!(!realm_trusted(realm, registry), "{realm}");
        }
        assert!(allowed_url("https://cdn.example/x"));
        assert!(allowed_url("http://[::1]:5000/x"));
        assert!(!allowed_url("http://cdn.example/x"));
    }
}
