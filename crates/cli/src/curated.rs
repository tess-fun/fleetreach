//! The curated-research sources beyond the osv.dev exports (spec 16, row 12): CVE 5.x
//! records from `cvelistV5` and vendor CSAF VEX (Red Hat first). Each lives as a compact
//! index next to the OSV exports, so one directory still serves an air-gapped host:
//!
//! - `<dir>/cvelistV5/index.jsonl.gz`
//! - `<dir>/csaf/<provider>/index.jsonl.gz`
//!
//! each with an `index.jsonl.gz.meta.json` recording where it came from (the upstream file
//! name, its sha256 and `Last-Modified`). `db sync --source` fetches and indexes them in
//! network builds; `db import` indexes a local copy (a `cvelistV5` checkout or release zip, a
//! CSAF directory or `.tar.zst`). A failed fetch or index never replaces a good index.

use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::osvdb::{self, Meta};
use crate::{csaf, cve5};

/// The CSAF providers fleetreach knows how to fetch.
pub const CSAF_PROVIDERS: &[&str] = &["redhat"];

/// Red Hat's VEX directory: `archive_latest.txt` names the newest full archive.
pub const REDHAT_VEX: &str = "https://security.access.redhat.com/data/csaf/v2/vex";

/// The newest `cvelistV5` release.
pub const CVELIST_LATEST: &str =
    "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest";

/// What an import or sync produced, for the command's summary line.
#[derive(Debug, Clone, Copy, Default)]
pub struct Indexed {
    pub records: usize,
    pub documents: usize,
    pub skipped: usize,
}

/// Index a local CVE input (see [`cve5::read_all`]) into `root`.
///
/// # Errors
///
/// An unreadable input or an index that cannot be written.
pub fn import_cve(root: &Path, input: &Path, upstream: Option<Meta>) -> Result<Indexed, String> {
    let (summaries, skipped) = cve5::read_all(input)?;
    if summaries.is_empty() {
        return Err(format!("{}: no CVE records found", input.display()));
    }
    let path = cve5::index_path(root);
    cve5::write_index(&path, &summaries)?;
    write_meta(&path, upstream.unwrap_or_else(|| local_meta(input)))?;
    Ok(Indexed {
        records: summaries.len(),
        documents: summaries.len(),
        skipped,
    })
}

/// Index a local CSAF input (see [`csaf::read_all`]) into `root` under `provider`.
///
/// # Errors
///
/// An unreadable input or an index that cannot be written.
pub fn import_csaf(
    root: &Path,
    provider: &str,
    input: &Path,
    upstream: Option<Meta>,
) -> Result<Indexed, String> {
    if provider.is_empty()
        || !provider
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(format!(
            "`{provider}` is not a provider name (letters, digits, - and _)"
        ));
    }
    let result = csaf::read_all(input)?;
    if result.documents == 0 {
        return Err(format!("{}: no CSAF documents found", input.display()));
    }
    let path = csaf::index_path(root, provider);
    csaf::write_index(&path, &result.records)?;
    write_meta(&path, upstream.unwrap_or_else(|| local_meta(input)))?;
    Ok(Indexed {
        records: result.records.len(),
        documents: result.documents,
        skipped: result.not_csaf,
    })
}

/// Provenance of an index built from a local file or directory: its path, and its sha256 and
/// mtime when it is a file.
fn local_meta(input: &Path) -> Meta {
    let (sha256, size) = if input.is_file() {
        sha256_file(input).unwrap_or_default()
    } else {
        (String::new(), 0)
    };
    let last_modified = std::fs::metadata(input)
        .and_then(|m| m.modified())
        .ok()
        .map(http_date);
    Meta {
        url: format!("file://{}", input.display()),
        etag: None,
        last_modified,
        fetched_at: osvdb::now_rfc3339(),
        fetched_unix: osvdb::now_unix(),
        sha256,
        size,
    }
}

fn write_meta(index: &Path, meta: Meta) -> Result<(), String> {
    let path = osvdb::meta_path(index);
    let json = serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("writing {}: {e}", path.display()))
}

pub(crate) fn sha256_file(path: &Path) -> std::io::Result<(String, u64)> {
    use sha2::{Digest, Sha256};
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(buf.get(..n).unwrap_or_default());
        size += n as u64;
    }
    Ok((
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        size,
    ))
}

/// An IMF-fixdate, the form [`osvdb::parse_http_date`] reads back.
fn http_date(t: SystemTime) -> String {
    let dt = time::OffsetDateTime::from(t);
    let weekday = dt.weekday().to_string();
    let month = dt.month().to_string();
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        weekday.get(..3).unwrap_or(""),
        dt.day(),
        month.get(..3).unwrap_or(""),
        dt.year(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

/// `db status` rows for the CVE and CSAF indexes under `root`: name, status, age, size, sha256.
#[must_use]
pub fn status_rows(root: &Path, now: SystemTime) -> Vec<[String; 5]> {
    let mut rows = Vec::new();
    let mut row = |name: String, index: &Path| {
        if !index.is_file() {
            rows.push([
                name,
                "missing".to_string(),
                String::new(),
                String::new(),
                String::new(),
            ]);
            return;
        }
        let meta = osvdb::read_meta(index);
        let age = meta
            .as_ref()
            .and_then(Meta::upstream_time)
            .map(|t| (t, "upstream"))
            .or_else(|| {
                std::fs::metadata(index)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|t| (t, "mtime"))
            })
            .map_or("unknown".to_string(), |(t, basis)| {
                let secs = now.duration_since(t).unwrap_or(Duration::ZERO).as_secs();
                format!("{} ({basis})", osvdb::human_age(secs))
            });
        let size = std::fs::metadata(index).map_or(String::new(), |m| osvdb::human_size(m.len()));
        let sha = meta
            .as_ref()
            .map_or(String::new(), |m| m.sha256.chars().take(12).collect());
        rows.push([name, "present".to_string(), age, size, sha]);
    };
    row("CVE (cvelistV5)".to_string(), &cve5::index_path(root));
    for provider in CSAF_PROVIDERS {
        row(
            format!("CSAF ({provider})"),
            &csaf::index_path(root, provider),
        );
    }
    rows
}

/// Whether the index at `index` was checked upstream within `refresh`.
fn is_fresh(index: &Path, refresh: Duration) -> bool {
    index.is_file()
        && osvdb::read_meta(index)
            .and_then(|m| m.fetched_time())
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .is_some_and(|age| age < refresh)
}

/// Fetch the newest `cvelistV5` release into `root` and index it.
///
/// # Errors
///
/// No network support in this build, or a failed fetch or index (the old index stays).
pub fn sync_cve(
    root: &Path,
    refresh: Duration,
    force: bool,
    quiet: bool,
) -> Result<Indexed, String> {
    let index = cve5::index_path(root);
    if !force && is_fresh(&index, refresh) {
        return Ok(Indexed::default());
    }
    net::sync_cve(root, &index, force, quiet)
}

/// Fetch the newest full CSAF VEX archive of `provider` into `root` and index it.
///
/// # Errors
///
/// An unknown provider, no network support, or a failed fetch or index (the old index stays).
pub fn sync_csaf(
    root: &Path,
    provider: &str,
    refresh: Duration,
    force: bool,
    quiet: bool,
) -> Result<Indexed, String> {
    if !CSAF_PROVIDERS.contains(&provider) {
        return Err(format!(
            "no CSAF feed is known for `{provider}` (known: {}); index a local copy with `db import --csaf`",
            CSAF_PROVIDERS.join(", ")
        ));
    }
    let index = csaf::index_path(root, provider);
    if !force && is_fresh(&index, refresh) {
        return Ok(Indexed::default());
    }
    net::sync_redhat(root, &index, force, quiet)
}

#[cfg(not(feature = "network"))]
mod net {
    use std::path::Path;

    use super::Indexed;

    const NO_NETWORK: &str =
        "this build has no network support (install with `--features network`, or index a local copy with `db import`)";

    pub(super) fn sync_cve(_: &Path, _: &Path, _: bool, _: bool) -> Result<Indexed, String> {
        Err(NO_NETWORK.to_string())
    }

    pub(super) fn sync_redhat(_: &Path, _: &Path, _: bool, _: bool) -> Result<Indexed, String> {
        Err(NO_NETWORK.to_string())
    }
}

#[cfg(feature = "network")]
mod net {
    use std::io::{Read as _, Write as _};
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;
    use std::time::Duration;

    use sha2::{Digest, Sha256};

    use super::{import_csaf, import_cve, Indexed, CVELIST_LATEST, REDHAT_VEX};
    use crate::osvdb::{self, Meta};

    /// Far above either archive today (650 MB and 420 MB).
    const MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;

    /// GitHub serves release assets through a redirect to its asset host; Red Hat serves
    /// directly. Redirects stay on HTTPS.
    fn agent() -> &'static ureq::Agent {
        static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
        AGENT.get_or_init(|| {
            ureq::Agent::config_builder()
                .https_only(true)
                .max_redirects(5)
                .http_status_as_error(false)
                .timeout_connect(Some(Duration::from_secs(15)))
                .timeout_recv_response(Some(Duration::from_secs(60)))
                .timeout_recv_body(Some(Duration::from_secs(30 * 60)))
                .build()
                .into()
        })
    }

    fn get_text(url: &str) -> Result<String, String> {
        let mut response = agent()
            .get(url)
            .header("Accept", "application/vnd.github+json, text/plain")
            .call()
            .map_err(|e| format!("GET {url}: {e}"))?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(format!("GET {url}: HTTP {status}"));
        }
        response
            .body_mut()
            .with_config()
            .limit(1 << 20)
            .read_to_string()
            .map_err(|e| format!("GET {url}: {e}"))
    }

    /// Stream `url` to `dest`, hashing as it goes. Returns the provenance to record.
    fn download(url: &str, dest: &Path, quiet: bool, label: &str) -> Result<Meta, String> {
        let mut response = agent()
            .get(url)
            .call()
            .map_err(|e| format!("GET {url}: {e}"))?;
        let status = response.status().as_u16();
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
                expected_len.map_or(String::new(), |n| format!(" ({})", osvdb::human_size(n)));
            eprintln!("fetching {label}{size}...");
        }
        let mut file =
            std::fs::File::create(dest).map_err(|e| format!("creating {}: {e}", dest.display()))?;
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
                .map_err(|e| format!("writing {}: {e}", dest.display()))?;
            written += n as u64;
        }
        file.sync_all()
            .map_err(|e| format!("writing {}: {e}", dest.display()))?;
        if expected_len.is_some_and(|len| len != written) {
            return Err(format!("{url}: truncated download ({written} bytes)"));
        }
        Ok(Meta {
            url: url.to_string(),
            etag,
            last_modified,
            fetched_at: osvdb::now_rfc3339(),
            fetched_unix: osvdb::now_unix(),
            sha256: hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            size: written,
        })
    }

    /// When the upstream file is the one already indexed, only the check time moves.
    fn unchanged(index: &Path, url: &str) -> bool {
        let Some(mut meta) = osvdb::read_meta(index) else {
            return false;
        };
        if meta.url != url || !index.is_file() {
            return false;
        }
        meta.fetched_at = osvdb::now_rfc3339();
        meta.fetched_unix = osvdb::now_unix();
        super::write_meta(index, meta).is_ok()
    }

    /// Download into a temp file beside the index, index it, then delete the download.
    fn fetch_and_index(
        dir: &Path,
        url: &str,
        name: &str,
        quiet: bool,
        index: impl FnOnce(&Path, Meta) -> Result<Indexed, String>,
    ) -> Result<Indexed, String> {
        osvdb::create_private_dir(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        let tmp: PathBuf = dir.join(format!("{name}.partial"));
        let result = download(url, &tmp, quiet, name).and_then(|meta| index(&tmp, meta));
        let _ = std::fs::remove_file(&tmp);
        result
    }

    pub(super) fn sync_cve(
        root: &Path,
        index: &Path,
        force: bool,
        quiet: bool,
    ) -> Result<Indexed, String> {
        let release: serde_json::Value = serde_json::from_str(&get_text(CVELIST_LATEST)?)
            .map_err(|e| format!("{CVELIST_LATEST}: {e}"))?;
        let asset = release
            .get("assets")
            .and_then(|a| a.as_array())
            .into_iter()
            .flatten()
            .find(|a| {
                a.get("name")
                    .and_then(|n| n.as_str())
                    .is_some_and(|n| n.ends_with("_all_CVEs_at_midnight.zip.zip"))
            })
            .ok_or_else(|| {
                format!("{CVELIST_LATEST}: no full-snapshot asset in the newest release")
            })?;
        let url = asset
            .get("browser_download_url")
            .and_then(|u| u.as_str())
            .filter(|u| u.starts_with("https://github.com/CVEProject/cvelistV5/releases/download/"))
            .ok_or_else(|| format!("{CVELIST_LATEST}: unexpected asset URL"))?
            .to_string();
        if !force && unchanged(index, &url) {
            return Ok(Indexed::default());
        }
        let dir = root.join(crate::cve5::CVE_DIR);
        fetch_and_index(&dir, &url, "cvelistV5 snapshot", quiet, |tmp, meta| {
            import_cve(root, tmp, Some(meta))
        })
    }

    pub(super) fn sync_redhat(
        root: &Path,
        index: &Path,
        force: bool,
        quiet: bool,
    ) -> Result<Indexed, String> {
        let latest_url = format!("{REDHAT_VEX}/archive_latest.txt");
        let name = get_text(&latest_url)?.trim().to_string();
        // A bare file name; anything else would leave the fixed directory.
        if !name.starts_with("csaf_vex_")
            || !name.ends_with(".tar.zst")
            || name.contains(['/', '\\'])
            || name.contains("..")
        {
            return Err(format!("{latest_url}: unexpected archive name `{name}`"));
        }
        let url = format!("{REDHAT_VEX}/{name}");
        if !force && unchanged(index, &url) {
            return Ok(Indexed::default());
        }
        let dir = crate::csaf::provider_dir(root, "redhat");
        fetch_and_index(
            &dir,
            &url,
            "Red Hat CSAF VEX archive",
            quiet,
            |tmp, meta| import_csaf(root, "redhat", tmp, Some(meta)),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn http_date_round_trips() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(http_date(t), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(osvdb::parse_http_date(&http_date(t)), Some(t));
    }

    #[test]
    fn import_writes_index_meta_and_status() {
        let root = std::env::temp_dir().join(format!("fr-curated-{}", std::process::id()));
        let input = root.join("in");
        std::fs::create_dir_all(input.join("cves/2024/1xxx")).unwrap();
        std::fs::write(
            input.join("cves/2024/1xxx/CVE-2024-1234.json"),
            r#"{"cveMetadata":{"cveId":"CVE-2024-1234","state":"PUBLISHED"},"containers":{"cna":{}}}"#,
        )
        .unwrap();
        let out = root.join("db");
        let indexed = import_cve(&out, &input, None).unwrap();
        assert_eq!(indexed.records, 1);
        let rows = status_rows(&out, SystemTime::now());
        assert_eq!(rows[0][1], "present");
        assert_eq!(rows[1][1], "missing");
        assert!(import_csaf(&out, "../x", &input, None).is_err());
        assert!(
            import_csaf(&out, "redhat", &input, None).is_err(),
            "no CSAF in a CVE tree"
        );
        assert!(sync_csaf(&out, "nobody", Duration::ZERO, false, true).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
