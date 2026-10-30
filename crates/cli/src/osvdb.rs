//! OSV export databases for the toolchain-free feeders (spec 01).
//!
//! Every non-Rust feeder matches against an osv.dev ecosystem export. Instead of one
//! `--<eco>-vuln-db` flag per ecosystem, a single directory laid out like the osv.dev bucket
//! (`<dir>/<Ecosystem>/all.zip`, also OSV-Scanner's offline layout) serves them all, and the
//! default cache under `~/.cache/fleetreach/osv/` is kept fresh automatically in network
//! builds. Resolution order per ecosystem: the explicit flag (or its env var), then
//! `--osv-dir` / `FLEETREACH_OSV_DIR` / `[settings.osv] dir`, then the default cache.
//!
//! Fail-closed: a sync failure never replaces a good copy, and an ecosystem with no usable
//! export stays an errored gap in the feeder. Every resolved export carries an age (the
//! upstream `Last-Modified` recorded at download, else the file's mtime) so `--max-db-age`
//! covers OSV data the same way it covers RustSec.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use fleetreach_core::{Ecosystem, OsvProvenance};
use serde::{Deserialize, Serialize};

/// The osv.dev bucket every export is fetched from (fixed host; never taken from data).
pub const OSV_BUCKET: &str = "https://osv-vulnerabilities.storage.googleapis.com";

/// The env var that turns automatic syncing off (`off`, `0`, `false`).
pub const SYNC_ENV: &str = "FLEETREACH_OSV_SYNC";

/// The env var naming an OSV directory, equivalent to `--osv-dir`.
pub const DIR_ENV: &str = "FLEETREACH_OSV_DIR";

/// Default interval after which a cached export is re-checked upstream.
pub const DEFAULT_REFRESH: Duration = Duration::from_secs(6 * 3600);

/// The ecosystems served by osv.dev exports, in a stable order. Go is absent: its offline
/// matcher reads a vuln.go.dev mirror, a different format.
pub const OSV_ECOSYSTEMS: &[Ecosystem] = &[
    Ecosystem::Npm,
    Ecosystem::Pypi,
    Ecosystem::RubyGems,
    Ecosystem::Packagist,
    Ecosystem::NuGet,
    Ecosystem::Julia,
    Ecosystem::Swift,
    Ecosystem::Hex,
    Ecosystem::GitHubActions,
    Ecosystem::Maven,
];

/// The osv.dev directory name of an ecosystem's export, or `None` if it has none.
pub fn osv_name(eco: Ecosystem) -> Option<&'static str> {
    Some(match eco {
        Ecosystem::Npm => "npm",
        Ecosystem::Pypi => "PyPI",
        Ecosystem::RubyGems => "RubyGems",
        Ecosystem::Packagist => "Packagist",
        Ecosystem::NuGet => "NuGet",
        Ecosystem::Julia => "Julia",
        Ecosystem::Swift => "SwiftURL",
        Ecosystem::Hex => "Hex",
        Ecosystem::GitHubActions => "GitHub Actions",
        Ecosystem::Maven => "Maven",
        Ecosystem::Cargo | Ecosystem::Go => return None,
    })
}

/// Parse an ecosystem name as `fleet.toml` spells it, or as osv.dev does (case-insensitive).
pub fn parse_ecosystem(name: &str) -> Option<Ecosystem> {
    let lower = name.trim().to_ascii_lowercase();
    let eco = match lower.as_str() {
        "npm" => Ecosystem::Npm,
        "pypi" | "python" => Ecosystem::Pypi,
        "rubygems" | "ruby" => Ecosystem::RubyGems,
        "packagist" | "composer" | "php" => Ecosystem::Packagist,
        "nuget" | "dotnet" => Ecosystem::NuGet,
        "julia" => Ecosystem::Julia,
        "swift" | "swifturl" => Ecosystem::Swift,
        "hex" | "elixir" => Ecosystem::Hex,
        "githubactions" | "github actions" | "actions" | "gha" => Ecosystem::GitHubActions,
        "maven" | "gradle" | "java" => Ecosystem::Maven,
        _ => return None,
    };
    Some(eco)
}

/// Where a resolved export came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// An explicit `--<eco>-vuln-db` flag or its env var.
    Flag,
    /// `--osv-dir`, `FLEETREACH_OSV_DIR` or `[settings.osv] dir`.
    Dir,
    /// The default cache (possibly synced this run).
    Cache,
}

impl SourceKind {
    fn as_str(self) -> &'static str {
        match self {
            SourceKind::Flag => "flag",
            SourceKind::Dir => "dir",
            SourceKind::Cache => "cache",
        }
    }
}

/// One ecosystem's resolved export: the path a feeder loads plus what we know of its age.
#[derive(Debug, Clone)]
pub struct OsvSource {
    pub ecosystem: Ecosystem,
    pub kind: SourceKind,
    /// An `all.zip` or a directory of OSV JSON records.
    pub path: PathBuf,
    pub meta: Option<Meta>,
}

impl OsvSource {
    /// The `file://` URL the feeders' `*_db_path` helpers expect.
    pub fn url(&self) -> String {
        format!("file://{}", self.path.display())
    }

    /// Age in seconds: from the upstream `Last-Modified` recorded at download, else from the
    /// file's mtime. `None` when neither is known (refused under `--max-db-age`).
    pub fn age_seconds(&self, now: SystemTime) -> Option<(u64, &'static str)> {
        if let Some(upstream) = self.meta.as_ref().and_then(Meta::upstream_time) {
            return Some((secs_between(upstream, now), "upstream"));
        }
        let mtime = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok()?;
        Some((secs_between(mtime, now), "mtime"))
    }

    /// The report's provenance record for this export.
    pub fn provenance(&self) -> OsvProvenance {
        let now = SystemTime::now();
        OsvProvenance {
            ecosystem: osv_name(self.ecosystem).unwrap_or_default().to_string(),
            source: self.kind.as_str().to_string(),
            path: self.path.display().to_string(),
            upstream_modified: self.meta.as_ref().and_then(|m| m.last_modified.clone()),
            fetched_at: self.meta.as_ref().map(|m| m.fetched_at.clone()),
            sha256: self.meta.as_ref().map(|m| m.sha256.clone()),
            age_basis: self
                .age_seconds(now)
                .map_or("unknown", |(_, basis)| basis)
                .to_string(),
        }
    }
}

fn secs_between(then: SystemTime, now: SystemTime) -> u64 {
    now.duration_since(then).map_or(0, |d| d.as_secs())
}

/// What a sync recorded next to an `all.zip` (`all.zip.meta.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub url: String,
    pub etag: Option<String>,
    /// The upstream `Last-Modified` header, verbatim (an HTTP date).
    pub last_modified: Option<String>,
    /// RFC3339 time of the last successful check (200 or 304), for people.
    pub fetched_at: String,
    /// The same instant as Unix seconds, for the refresh check.
    #[serde(default)]
    pub fetched_unix: u64,
    pub sha256: String,
    pub size: u64,
}

impl Meta {
    fn upstream_time(&self) -> Option<SystemTime> {
        self.last_modified.as_deref().and_then(parse_http_date)
    }

    fn fetched_time(&self) -> Option<SystemTime> {
        (self.fetched_unix > 0)
            .then(|| SystemTime::UNIX_EPOCH + Duration::from_secs(self.fetched_unix))
    }
}

fn meta_path(zip: &Path) -> PathBuf {
    let mut name = zip.file_name().unwrap_or_default().to_os_string();
    name.push(".meta.json");
    zip.with_file_name(name)
}

fn read_meta(zip: &Path) -> Option<Meta> {
    let text = std::fs::read_to_string(meta_path(zip)).ok()?;
    serde_json::from_str(&text).ok()
}

/// Parse an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`), the only HTTP date form servers
/// may send. Anything else is `None` (age then falls back to mtime).
pub fn parse_http_date(s: &str) -> Option<SystemTime> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    let [_, day, month, year, clock, "GMT"] = parts.as_slice() else {
        return None;
    };
    let month = match *month {
        "Jan" => time::Month::January,
        "Feb" => time::Month::February,
        "Mar" => time::Month::March,
        "Apr" => time::Month::April,
        "May" => time::Month::May,
        "Jun" => time::Month::June,
        "Jul" => time::Month::July,
        "Aug" => time::Month::August,
        "Sep" => time::Month::September,
        "Oct" => time::Month::October,
        "Nov" => time::Month::November,
        "Dec" => time::Month::December,
        _ => return None,
    };
    let mut hms = clock.split(':').map(str::parse::<u8>);
    let (Some(Ok(h)), Some(Ok(m)), Some(Ok(sec)), None) =
        (hms.next(), hms.next(), hms.next(), hms.next())
    else {
        return None;
    };
    let date = time::Date::from_calendar_date(year.parse().ok()?, month, day.parse().ok()?).ok()?;
    let dt = date.with_hms(h, m, sec).ok()?.assume_utc();
    Some(SystemTime::from(dt))
}

/// The export inside an OSV directory: `<dir>/<Name>/all.zip`, else an unzipped
/// `<dir>/<Name>/` holding records.
fn locate_in(dir: &Path, eco: Ecosystem) -> Option<PathBuf> {
    let eco_dir = dir.join(osv_name(eco)?);
    let zip = eco_dir.join("all.zip");
    if zip.is_file() {
        return Some(zip);
    }
    let has_records = std::fs::read_dir(&eco_dir).ok()?.flatten().any(|e| {
        e.path().extension().and_then(|x| x.to_str()) == Some("json")
            && !e.file_name().to_string_lossy().ends_with(".meta.json")
    });
    has_records.then_some(eco_dir)
}

/// The default OSV cache, `<cache root>/osv`. `None` when there is no usable cache root,
/// or the directory exists but is a symlink or is writable by others (a planted export
/// could hide findings).
pub fn default_cache_dir() -> Option<PathBuf> {
    private_subdir("osv")
}

/// `$XDG_CACHE_HOME/fleetreach/<name>` or `~/.cache/fleetreach/<name>`, refused when it
/// exists as a symlink, a non-directory, or writable by others. Shared by the OSV cache and
/// the fleet-source checkouts (spec 06).
pub fn private_subdir(name: &str) -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
    let dir = base.join("fleetreach").join(name);
    match std::fs::symlink_metadata(&dir) {
        Ok(md) if md.file_type().is_symlink() || !md.is_dir() => None,
        Ok(md) if shared_writable(&md) => None,
        _ => Some(dir),
    }
}

#[cfg(unix)]
fn shared_writable(md: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode() & 0o022 != 0
}

#[cfg(not(unix))]
fn shared_writable(_md: &std::fs::Metadata) -> bool {
    false
}

/// Whether automatic syncing is allowed by the environment.
pub fn sync_enabled_by_env() -> bool {
    !matches!(
        std::env::var(SYNC_ENV).map(|v| v.to_ascii_lowercase()),
        Ok(v) if v == "off" || v == "0" || v == "false"
    )
}

/// Everything resolution needs besides the per-ecosystem explicit values.
#[derive(Debug, Clone)]
pub struct Options {
    /// `--osv-dir`, `FLEETREACH_OSV_DIR` or `[settings.osv] dir`, already resolved.
    pub dir: Option<PathBuf>,
    /// The default cache root, if usable.
    pub cache: Option<PathBuf>,
    /// Fetch or refresh missing/stale exports into the cache (network builds only).
    pub sync: bool,
    pub refresh: Duration,
    pub quiet: bool,
}

/// Resolve the export for every ecosystem in `needed`. `explicit` holds the flag/env value
/// per ecosystem. Ecosystems that resolve to nothing are absent from the map (the feeder
/// then reports an honest gap); sync failures are returned as warnings, never errors.
pub fn resolve_all(
    needed: &[Ecosystem],
    explicit: &BTreeMap<Ecosystem, String>,
    opts: &Options,
) -> (BTreeMap<Ecosystem, OsvSource>, Vec<String>) {
    let mut found = BTreeMap::new();
    let mut to_cache = Vec::new();
    for &eco in needed {
        if osv_name(eco).is_none() {
            continue;
        }
        if let Some(url) = explicit.get(&eco) {
            // Only `file://` values name a local export; anything else is passed through
            // unchanged and the feeder decides (today: an honest gap).
            if let Some(path) = url.strip_prefix("file://") {
                let path = PathBuf::from(path);
                let meta = read_meta(&path);
                found.insert(
                    eco,
                    OsvSource {
                        ecosystem: eco,
                        kind: SourceKind::Flag,
                        path,
                        meta,
                    },
                );
            }
            continue;
        }
        if let Some(path) = opts.dir.as_deref().and_then(|d| locate_in(d, eco)) {
            let meta = read_meta(&path);
            found.insert(
                eco,
                OsvSource {
                    ecosystem: eco,
                    kind: SourceKind::Dir,
                    path,
                    meta,
                },
            );
            continue;
        }
        to_cache.push(eco);
    }

    let mut warnings = Vec::new();
    let Some(cache) = opts.cache.as_deref() else {
        return (found, warnings);
    };
    let synced: Vec<(Ecosystem, Result<(), String>)> = if opts.sync {
        sync_many(cache, &to_cache, opts.refresh, false, opts.quiet)
    } else {
        Vec::new()
    };
    for (eco, result) in synced {
        if let Err(e) = result {
            warnings.push(format!(
                "could not refresh the OSV {} export: {e}",
                osv_name(eco).unwrap_or_default()
            ));
        }
    }
    for eco in to_cache {
        if let Some(path) = locate_in(cache, eco) {
            let meta = read_meta(&path);
            found.insert(
                eco,
                OsvSource {
                    ecosystem: eco,
                    kind: SourceKind::Cache,
                    path,
                    meta,
                },
            );
        }
    }
    (found, warnings)
}

/// Check every resolved export against `--max-db-age` (seconds). Unknown age refuses, as it
/// does for the RustSec DB.
pub fn check_ages(
    sources: &BTreeMap<Ecosystem, OsvSource>,
    limit: i64,
    now: SystemTime,
) -> Result<(), String> {
    for src in sources.values() {
        let name = osv_name(src.ecosystem).unwrap_or_default();
        match src.age_seconds(now) {
            Some((age, basis)) if i64::try_from(age).unwrap_or(i64::MAX) > limit => {
                return Err(format!(
                    "OSV {name} export at {} is {age}s old ({basis}), older than --max-db-age \
                     {limit}s; refresh it with `fleetreach db sync`",
                    src.path.display()
                ));
            }
            Some(_) => {}
            None => {
                return Err(format!(
                    "cannot determine the age of the OSV {name} export at {}; refusing under \
                     --max-db-age",
                    src.path.display()
                ))
            }
        }
    }
    Ok(())
}

/// Sync `ecosystems` into `root` in parallel. `force` re-downloads even when fresh.
pub fn sync_many(
    root: &Path,
    ecosystems: &[Ecosystem],
    refresh: Duration,
    force: bool,
    quiet: bool,
) -> Vec<(Ecosystem, Result<(), String>)> {
    use rayon::prelude::*;
    ecosystems
        .par_iter()
        .map(|&eco| (eco, sync_one(root, eco, refresh, force, quiet)))
        .collect()
}

/// Whether the cached export for `eco` under `root` was checked within `refresh`.
fn is_fresh(root: &Path, eco: Ecosystem, refresh: Duration) -> bool {
    let Some(name) = osv_name(eco) else {
        return false;
    };
    let zip = root.join(name).join("all.zip");
    if !zip.is_file() {
        return false;
    }
    read_meta(&zip)
        .and_then(|m| m.fetched_time())
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|age| age < refresh)
}

#[cfg(feature = "network")]
fn sync_one(
    root: &Path,
    eco: Ecosystem,
    refresh: Duration,
    force: bool,
    quiet: bool,
) -> Result<(), String> {
    if !force && is_fresh(root, eco, refresh) {
        return Ok(());
    }
    net::download(root, eco, force, quiet)
}

#[cfg(not(feature = "network"))]
fn sync_one(
    root: &Path,
    eco: Ecosystem,
    refresh: Duration,
    force: bool,
    _quiet: bool,
) -> Result<(), String> {
    if !force && is_fresh(root, eco, refresh) {
        return Ok(());
    }
    let _ = root;
    Err("this build has no network support (install with `--features network`)".to_string())
}

/// Create `dir` and its missing parents, each private (0700 on Unix).
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

#[cfg(feature = "network")]
mod net {
    use std::io::{Read, Write};
    use std::path::Path;
    use std::sync::OnceLock;
    use std::time::Duration;

    use fleetreach_core::Ecosystem;
    use sha2::{Digest, Sha256};

    use super::{create_private_dir, meta_path, osv_name, read_meta, Meta, OSV_BUCKET};

    /// Hard cap on one export's size, far above any osv.dev export today.
    const MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;

    fn agent() -> &'static ureq::Agent {
        static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
        AGENT.get_or_init(|| {
            ureq::Agent::config_builder()
                .https_only(true)
                // The bucket serves objects directly; a redirect would leave the fixed host.
                .max_redirects(0)
                .http_status_as_error(false)
                .timeout_connect(Some(Duration::from_secs(15)))
                .timeout_recv_response(Some(Duration::from_secs(60)))
                // Large exports: bound stalls, not the whole transfer.
                .timeout_recv_body(Some(Duration::from_secs(30 * 60)))
                .build()
                .into()
        })
    }

    fn url_for(name: &str) -> String {
        // Object names contain spaces (`GitHub Actions`).
        format!("{OSV_BUCKET}/{}/all.zip", name.replace(' ', "%20"))
    }

    pub(super) fn download(
        root: &Path,
        eco: Ecosystem,
        force: bool,
        quiet: bool,
    ) -> Result<(), String> {
        let name = osv_name(eco).ok_or("no osv.dev export for this ecosystem")?;
        let dir = root.join(name);
        create_private_dir(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        let zip = dir.join("all.zip");
        let url = url_for(name);
        let previous = if zip.is_file() && !force {
            read_meta(&zip)
        } else {
            None
        };

        let mut request = agent().get(&url);
        if let Some(meta) = &previous {
            if let Some(etag) = &meta.etag {
                request = request.header("If-None-Match", etag);
            }
            if let Some(lm) = &meta.last_modified {
                request = request.header("If-Modified-Since", lm);
            }
        }
        let mut response = request.call().map_err(|e| format!("GET {url}: {e}"))?;
        let status = response.status().as_u16();
        if status == 304 {
            if let Some(mut meta) = previous {
                meta.fetched_at = super::now_rfc3339();
                meta.fetched_unix = super::now_unix();
                write_meta(&zip, &meta)?;
            }
            return Ok(());
        }
        if status != 200 {
            return Err(format!("GET {url}: HTTP {status}"));
        }
        let header = |key: &str| {
            response
                .headers()
                .get(key)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let etag = header("etag");
        let last_modified = header("last-modified");
        let expected_len = header("content-length").and_then(|v| v.parse::<u64>().ok());
        if !quiet {
            let size =
                expected_len.map_or(String::new(), |n| format!(" ({})", super::human_size(n)));
            eprintln!("fetching OSV {name} export{size}...");
        }

        // Stream to a temp file beside the target, hashing as we go; rename only once the
        // archive is complete and opens, so a failed download never replaces a good copy.
        let tmp = dir.join("all.zip.partial");
        let result = (|| {
            let mut file = std::fs::File::create(&tmp)
                .map_err(|e| format!("creating {}: {e}", tmp.display()))?;
            let mut reader = response.body_mut().with_config().limit(MAX_BYTES).reader();
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; 1 << 16];
            let mut written: u64 = 0;
            loop {
                let n = reader
                    .read(&mut buf)
                    .map_err(|e| format!("reading {url}: {e}"))?;
                if n == 0 {
                    break;
                }
                let chunk = buf.get(..n).unwrap_or_default();
                hasher.update(chunk);
                file.write_all(chunk)
                    .map_err(|e| format!("writing {}: {e}", tmp.display()))?;
                written += n as u64;
            }
            file.sync_all()
                .map_err(|e| format!("writing {}: {e}", tmp.display()))?;
            if expected_len.is_some_and(|len| len != written) {
                return Err(format!("{url}: truncated download ({written} bytes)"));
            }
            let check =
                std::fs::File::open(&tmp).map_err(|e| format!("reopening download: {e}"))?;
            zip::ZipArchive::new(check).map_err(|e| format!("{url}: not a valid zip: {e}"))?;
            let sha256 = hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            Ok(Meta {
                url: url.clone(),
                etag,
                last_modified,
                fetched_at: super::now_rfc3339(),
                fetched_unix: super::now_unix(),
                sha256,
                size: written,
            })
        })();
        let meta = match result {
            Ok(meta) => meta,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
        };
        std::fs::rename(&tmp, &zip).map_err(|e| format!("installing {}: {e}", zip.display()))?;
        write_meta(&zip, &meta)
    }

    fn write_meta(zip: &Path, meta: &Meta) -> Result<(), String> {
        let path = meta_path(zip);
        let json = serde_json::to_string_pretty(meta).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| format!("writing {}: {e}", path.display()))
    }
}

#[cfg(any(feature = "network", test))]
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(any(feature = "network", test))]
fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// One row of `fleetreach db status`.
pub fn status_rows(root: &Path, now: SystemTime) -> Vec<[String; 5]> {
    OSV_ECOSYSTEMS
        .iter()
        .filter_map(|&eco| {
            let name = osv_name(eco)?;
            let Some(path) = locate_in(root, eco) else {
                return Some([
                    name.to_string(),
                    "missing".to_string(),
                    String::new(),
                    String::new(),
                    String::new(),
                ]);
            };
            let src = OsvSource {
                ecosystem: eco,
                kind: SourceKind::Cache,
                meta: read_meta(&path),
                path,
            };
            let age = src
                .age_seconds(now)
                .map_or("unknown".to_string(), |(s, basis)| {
                    format!("{} ({basis})", human_age(s))
                });
            let size = src
                .meta
                .as_ref()
                .map_or(String::new(), |m| human_size(m.size));
            let sha = src
                .meta
                .as_ref()
                .map_or(String::new(), |m| m.sha256.chars().take(12).collect());
            Some([name.to_string(), "present".to_string(), age, size, sha])
        })
        .collect()
}

fn human_size(bytes: u64) -> String {
    match bytes {
        b if b < 1_000_000 => format!("{} KB", b.div_ceil(1000)),
        b => format!("{} MB", b / 1_000_000),
    }
}

fn human_age(secs: u64) -> String {
    match secs {
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86_400),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_imf_fixdate() {
        let t = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        let secs = t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 784_111_777);
        assert!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT").is_none());
        assert!(parse_http_date("Sun, 06 Nov 1994 08:49:37 PST").is_none());
    }

    #[test]
    fn every_osv_ecosystem_has_a_bucket_name_and_parses_back() {
        for &eco in OSV_ECOSYSTEMS {
            let name = osv_name(eco).unwrap();
            assert_eq!(parse_ecosystem(name), Some(eco), "{name}");
        }
        assert!(osv_name(Ecosystem::Go).is_none());
        assert!(osv_name(Ecosystem::Cargo).is_none());
    }

    #[test]
    fn resolution_prefers_flag_then_dir_then_cache() {
        let tmp = std::env::temp_dir().join(format!("fr-osv-{}", std::process::id()));
        let dir = tmp.join("dir");
        let cache = tmp.join("cache");
        for root in [&dir, &cache] {
            std::fs::create_dir_all(root.join("npm")).unwrap();
            std::fs::write(root.join("npm/all.zip"), b"x").unwrap();
            std::fs::create_dir_all(root.join("PyPI")).unwrap();
            std::fs::write(root.join("PyPI/GHSA-1.json"), b"{}").unwrap();
        }
        std::fs::create_dir_all(cache.join("Hex")).unwrap();
        std::fs::write(cache.join("Hex/all.zip"), b"x").unwrap();

        let mut explicit = BTreeMap::new();
        explicit.insert(Ecosystem::Npm, "file:///elsewhere/all.zip".to_string());
        let opts = Options {
            dir: Some(dir.clone()),
            cache: Some(cache.clone()),
            sync: false,
            refresh: DEFAULT_REFRESH,
            quiet: true,
        };
        let needed = [
            Ecosystem::Npm,
            Ecosystem::Pypi,
            Ecosystem::Hex,
            Ecosystem::Maven,
            Ecosystem::Cargo,
        ];
        let (found, warnings) = resolve_all(&needed, &explicit, &opts);
        assert!(warnings.is_empty());
        assert_eq!(found[&Ecosystem::Npm].kind, SourceKind::Flag);
        assert_eq!(
            found[&Ecosystem::Npm].path,
            PathBuf::from("/elsewhere/all.zip")
        );
        assert_eq!(found[&Ecosystem::Pypi].kind, SourceKind::Dir);
        assert_eq!(found[&Ecosystem::Pypi].path, dir.join("PyPI"));
        assert_eq!(found[&Ecosystem::Hex].kind, SourceKind::Cache);
        assert!(!found.contains_key(&Ecosystem::Maven), "absent stays a gap");
        assert!(!found.contains_key(&Ecosystem::Cargo));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn age_gate_uses_upstream_time_and_refuses_unknown() {
        let tmp = std::env::temp_dir().join(format!("fr-osv-age-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let zip = tmp.join("all.zip");
        std::fs::write(&zip, b"x").unwrap();
        let meta = Meta {
            url: String::new(),
            etag: None,
            last_modified: Some("Sun, 06 Nov 1994 08:49:37 GMT".to_string()),
            fetched_at: now_rfc3339(),
            fetched_unix: now_unix(),
            sha256: String::new(),
            size: 1,
        };
        let src = OsvSource {
            ecosystem: Ecosystem::Npm,
            kind: SourceKind::Cache,
            path: zip.clone(),
            meta: Some(meta),
        };
        let mut sources = BTreeMap::new();
        sources.insert(Ecosystem::Npm, src);
        let err = check_ages(&sources, 7 * 86_400, SystemTime::now()).unwrap_err();
        assert!(err.contains("older than --max-db-age"), "{err}");

        // No meta: the file's mtime (just written) is the basis, so it passes.
        let src = sources.get_mut(&Ecosystem::Npm).unwrap();
        src.meta = None;
        assert!(check_ages(&sources, 7 * 86_400, SystemTime::now()).is_ok());

        // A path that does not exist has no age at all: refused.
        let src = sources.get_mut(&Ecosystem::Npm).unwrap();
        src.path = tmp.join("missing.zip");
        let err = check_ages(&sources, 7 * 86_400, SystemTime::now()).unwrap_err();
        assert!(err.contains("cannot determine"), "{err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn sync_env_switch() {
        // Only the documented spellings turn it off.
        for (v, on) in [("off", false), ("0", false), ("FALSE", false), ("1", true)] {
            std::env::set_var(SYNC_ENV, v);
            assert_eq!(sync_enabled_by_env(), on, "{v}");
        }
        std::env::remove_var(SYNC_ENV);
        assert!(sync_enabled_by_env());
    }
}
