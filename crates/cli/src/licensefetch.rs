//! `licenses --download` (spec 16, row 20): the license files of a package that is not on this
//! machine, from the archive its lockfile pins.
//!
//! | Ecosystem | Archive | Checked against |
//! |-----------|---------|-----------------|
//! | npm | `registry.npmjs.org` tarball | the lockfile's `integrity` |
//! | Cargo | `static.crates.io` crate | `Cargo.lock`'s `checksum` |
//! | PyPI | the source distribution with that hash | the lock's `sha256` |
//! | RubyGems | `rubygems.org` gem | `CHECKSUMS` in `Gemfile.lock` |
//! | Hex | `repo.hex.pm` tarball | mix's outer checksum |
//! | Go | `proxy.golang.org` zip | the tree hash in `go.sum` |
//!
//! A package with no such hash is not fetched: nothing would say the file is the one in use.
//! That is every NuGet package (`contentHash` skips the signature), a package with only a SHA-1
//! `integrity`, a wheel-only Python package and a lock with no `CHECKSUMS`.
//!
//! Only packages from the public registry are asked for. An archive is never unpacked: its
//! license files are copied out, under names checked here, and the archive is dropped. The
//! cache is keyed by hash, shared by every repo, and read by `--detect` with no network.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use fleetreach_core::inventory::Checksum;
use fleetreach_core::Ecosystem;
use rayon::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::health::Fetch;
use crate::licensetext::is_license_file;

const DOWNLOADS_AT_ONCE: usize = 16;
/// The most read out of one archive, which keeps a small file from unpacking without end.
const MAX_UNPACKED: u64 = 1 << 30;
const MAX_FILE: u64 = 1 << 20;

/// What says an archive is the one in use.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Pin {
    /// The hash of the file the registry serves.
    File(Checksum),
    /// The `h1:` value of `go.sum`, a hash of the module's tree.
    GoTree(String),
}

impl Pin {
    /// The name of the package's directory in the cache: nothing but hex and a dash.
    pub fn key(&self) -> Option<String> {
        match self {
            Pin::File(sum) => {
                let algorithm = sum.algorithm.to_ascii_lowercase();
                Some(format!("{algorithm}-{}", sum.hex))
            }
            Pin::GoTree(h1) => {
                let raw = base64::engine::general_purpose::STANDARD.decode(h1).ok()?;
                Some(format!("go-h1-{}", to_hex(&raw)))
            }
        }
    }
}

/// The strongest hash this code can check, of those a lockfile lists.
pub fn file_pin(checksums: &[Checksum]) -> Option<Pin> {
    let strength = |c: &&Checksum| {
        ["SHA-256", "SHA-384", "SHA-512"]
            .iter()
            .position(|a| *a == c.algorithm)
    };
    let best = checksums
        .iter()
        .filter(|c| strength(c).is_some())
        .max_by_key(strength);
    best.cloned().map(Pin::File)
}

/// One archive to fetch.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Wanted {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub pin: Pin,
}

/// What a download run did.
#[derive(Debug, Default)]
pub struct Outcome {
    pub fetched: usize,
    /// Packages the registry does not have.
    pub missing: usize,
    /// What went wrong, one line per package.
    pub failed: Vec<String>,
    /// Packages whose file did not match the lockfile.
    pub tampered: Vec<String>,
}

/// Where license files are kept.
pub fn cache_root() -> Option<PathBuf> {
    crate::osvdb::private_subdir("license-files")
}

/// Fetches what `wanted` names and the cache does not hold.
///
/// # Errors
///
/// When there is no usable cache directory, or this build has no network.
pub fn download(wanted: BTreeSet<Wanted>) -> Result<Outcome, String> {
    let root = cache_root().ok_or("no usable cache directory for license files")?;
    let client = crate::health::archive_client()
        .ok_or("--download needs a build with the `network` feature")?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(DOWNLOADS_AT_ONCE)
        .build()
        .map_err(|e| e.to_string())?;
    Ok(pool.install(|| download_with(&wanted, &root, client.as_ref())))
}

enum Got {
    Kept,
    Missing,
    Tampered,
}

fn download_with(wanted: &BTreeSet<Wanted>, root: &Path, fetch: &dyn Fetch) -> Outcome {
    let mut by_key = BTreeMap::new();
    for want in wanted {
        if let Some(key) = want.pin.key().filter(|key| !root.join(key).is_dir()) {
            by_key.entry(key).or_insert(want);
        }
    }
    let results: Vec<(&Wanted, Result<Got, String>)> = by_key
        .par_iter()
        .map(|(key, want)| (*want, fetch_one(want, key, root, fetch)))
        .collect();
    let mut outcome = Outcome::default();
    for (want, result) in results {
        let label = format!("{} {}", want.name, want.version);
        match result {
            Ok(Got::Kept) => outcome.fetched += 1,
            Ok(Got::Missing) => outcome.missing += 1,
            Ok(Got::Tampered) => outcome.tampered.push(label),
            Err(e) => outcome.failed.push(format!("{label}: {e}")),
        }
    }
    outcome
}

fn fetch_one(want: &Wanted, key: &str, root: &Path, fetch: &dyn Fetch) -> Result<Got, String> {
    let Some(url) = archive_url(want, fetch)? else {
        return Ok(Got::Missing);
    };
    let Some(body) = fetch.get(&url)? else {
        return Ok(Got::Missing);
    };
    let files = match &want.pin {
        Pin::File(sum) if !matches_file(sum, &body) => return Ok(Got::Tampered),
        Pin::File(_) => license_files(want.ecosystem, &url, &body)?,
        Pin::GoTree(h1) => {
            let (tree, files) = go_tree(&want.name, &want.version, &body)?;
            if tree != *h1 {
                return Ok(Got::Tampered);
            }
            files
        }
    };
    keep(root, key, &files)?;
    Ok(Got::Kept)
}

/// Where the archive is. PyPI is asked which of a release's files has the hash.
fn archive_url(want: &Wanted, fetch: &dyn Fetch) -> Result<Option<String>, String> {
    let (name, version) = (&want.name, &want.version);
    Ok(Some(match want.ecosystem {
        Ecosystem::Npm => {
            let base = name.rsplit('/').next().unwrap_or(name);
            format!("https://registry.npmjs.org/{name}/-/{base}-{version}.tgz")
        }
        Ecosystem::Cargo => {
            format!("https://static.crates.io/crates/{name}/{name}-{version}.crate")
        }
        Ecosystem::RubyGems => format!("https://rubygems.org/gems/{name}-{version}.gem"),
        Ecosystem::Hex => format!("https://repo.hex.pm/tarballs/{name}-{version}.tar"),
        Ecosystem::Go => {
            let (module, at) = (
                crate::scope::cache_escaped(name),
                crate::scope::cache_escaped(version),
            );
            format!("https://proxy.golang.org/{module}/@v/{at}.zip")
        }
        Ecosystem::Pypi => {
            let Pin::File(sum) = &want.pin else {
                return Ok(None);
            };
            let url = format!("https://pypi.org/pypi/{name}/{version}/json");
            let Some(body) = fetch.get(&url)? else {
                return Ok(None);
            };
            let release: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
            return Ok(pypi_url(&release, &sum.hex));
        }
        _ => return Ok(None),
    }))
}

fn pypi_url(release: &Value, sha256: &str) -> Option<String> {
    let files = release.get("urls")?.as_array()?;
    let file = files
        .iter()
        .find(|file| file["digests"]["sha256"].as_str() == Some(sha256))?;
    file.get("url")?.as_str().map(str::to_string)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn matches_file(sum: &Checksum, body: &[u8]) -> bool {
    let actual = match sum.algorithm {
        "SHA-256" => to_hex(&Sha256::digest(body)),
        "SHA-384" => to_hex(&Sha384::digest(body)),
        "SHA-512" => to_hex(&Sha512::digest(body)),
        _ => return false,
    };
    actual == sum.hex
}

/// Stored name to contents.
type Files = BTreeMap<String, Vec<u8>>;

/// The name a file at `path` in a package's root is kept under, when it is a license file:
/// checked here because an archive can name anything.
fn kept_name(path: &str) -> Option<String> {
    let path = path.strip_prefix("./").unwrap_or(path);
    let safe = |part: &str| !matches!(part, "" | "." | "..") && !part.contains(['\\', '\0']);
    let parts: Vec<&str> = path.split('/').collect();
    match parts[..] {
        [name] if safe(name) && is_license_file(name) => Some(name.to_string()),
        [dir, name] if dir.eq_ignore_ascii_case("licenses") && safe(name) => {
            Some(format!("LICENSES/{name}"))
        }
        _ => None,
    }
}

/// `path` without its first `strip` directories.
fn below(path: &str, strip: usize) -> Option<&str> {
    let path = path.strip_prefix("./").unwrap_or(path);
    let mut rest = path;
    for _ in 0..strip {
        rest = rest.split_once('/')?.1;
    }
    Some(rest)
}

fn read_capped(reader: impl Read, cap: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut limited = reader.take(cap + 1);
    limited.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}

/// Copies the license files of a tar stream into `out`.
fn from_tar(reader: impl Read, strip: usize, out: &mut Files) -> Result<(), String> {
    let mut limited = reader.take(MAX_UNPACKED);
    let mut archive = tar::Archive::new(&mut limited);
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .into_owned();
        if let Some(name) = below(&path, strip).and_then(kept_name) {
            let bytes = read_capped(entry, MAX_FILE)?;
            out.insert(name, bytes);
        }
    }
    if limited.limit() == 0 {
        return Err("the archive unpacks to too much".to_string());
    }
    Ok(())
}

/// A `.gem` and a Hex tarball are plain tars holding a gzipped tar of the package.
fn from_inner_tar(body: &[u8], inner: &str, out: &mut Files) -> Result<(), String> {
    let mut archive = tar::Archive::new(body);
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.path().is_ok_and(|p| p == Path::new(inner)) {
            return from_tar(flate2::read::GzDecoder::new(entry), 0, out);
        }
    }
    Err(format!("no {inner} in the archive"))
}

/// Calls `each` with the name and contents of every file of a zip.
fn each_zip_file(body: &[u8], mut each: impl FnMut(&str, Vec<u8>)) -> Result<(), String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(body)).map_err(|e| e.to_string())?;
    let mut total = 0;
    for index in 0..archive.len() {
        let file = archive.by_index(index).map_err(|e| e.to_string())?;
        if file.is_dir() {
            continue;
        }
        let name = file.name().map_err(|e| e.to_string())?.to_string();
        let bytes = read_capped(file, MAX_UNPACKED)?;
        total += bytes.len() as u64;
        if total > MAX_UNPACKED {
            return Err("the archive unpacks to too much".to_string());
        }
        each(&name, bytes);
    }
    Ok(())
}

fn license_files(ecosystem: Ecosystem, url: &str, body: &[u8]) -> Result<Files, String> {
    let mut out = Files::new();
    match ecosystem {
        Ecosystem::RubyGems => from_inner_tar(body, "data.tar.gz", &mut out)?,
        Ecosystem::Hex => from_inner_tar(body, "contents.tar.gz", &mut out)?,
        Ecosystem::Pypi if url.ends_with(".zip") => each_zip_file(body, |path, bytes| {
            if let Some(name) = below(path, 1).and_then(kept_name) {
                out.insert(name, bytes);
            }
        })?,
        _ => from_tar(flate2::read::GzDecoder::new(body), 1, &mut out)?,
    }
    Ok(out)
}

/// The `go.sum` hash of a module zip, and its license files. As `dirhash.Hash1`: the SHA-256 of
/// a sorted list of `<sha256 of file>  <name>` lines.
fn go_tree(module: &str, version: &str, body: &[u8]) -> Result<(String, Files), String> {
    let root = format!("{module}@{version}/");
    let mut lines = Vec::new();
    let mut out = Files::new();
    each_zip_file(body, |path, bytes| {
        lines.push(format!("{}  {path}\n", to_hex(&Sha256::digest(&bytes))));
        let name = path.strip_prefix(root.as_str()).and_then(kept_name);
        if let Some(name) = name.filter(|_| bytes.len() as u64 <= MAX_FILE) {
            out.insert(name, bytes);
        }
    })?;
    lines.sort_by(|a, b| a[66..].cmp(&b[66..]));
    let sum = Sha256::digest(lines.concat().as_bytes());
    Ok((base64::engine::general_purpose::STANDARD.encode(sum), out))
}

/// Writes `files` to the cache whole or not at all: a directory there is complete.
fn keep(root: &Path, key: &str, files: &Files) -> Result<(), String> {
    let work = root.join(format!(".{key}.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let mut used = BTreeSet::new();
    let mut write = || -> std::io::Result<()> {
        std::fs::create_dir_all(&work)?;
        for (index, (name, bytes)) in files.iter().enumerate() {
            // A case-insensitive disk would take `LICENSE` and `license` for one file.
            let stored = if used.insert(name.to_lowercase()) {
                name.clone()
            } else {
                match name.split_once('/') {
                    Some((dir, _)) => format!("{dir}/license-{index}"),
                    None => format!("license-{index}"),
                }
            };
            let path = work.join(stored);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, bytes)?;
        }
        Ok(())
    };
    let written = write().and_then(|()| std::fs::rename(&work, root.join(key)));
    if written.is_err() {
        let _ = std::fs::remove_dir_all(&work);
    }
    // Another run may have put the same package there first.
    match written {
        Err(e) if !root.join(key).is_dir() => Err(e.to_string()),
        _ => Ok(()),
    }
}

/// The module versions `go.sum` pins, with the hash of each module's tree.
pub fn go_sums(text: &str) -> BTreeMap<(String, String), String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        if let (Some(module), Some(version), Some(hash)) =
            (words.next(), words.next(), words.next())
        {
            if let Some(h1) = hash
                .strip_prefix("h1:")
                .filter(|_| !version.ends_with("/go.mod"))
            {
                out.insert((module.to_string(), version.to_string()), h1.to_string());
            }
        }
    }
    out
}

/// Whether the Go toolchain here is told to keep `module` off the public proxy: `GOPRIVATE` and
/// `GONOPROXY` are comma-separated globs over the path's leading elements.
pub fn go_private(module: &str) -> bool {
    ["GOPRIVATE", "GONOPROXY"].iter().any(|name| {
        let patterns = std::env::var(name).unwrap_or_default();
        patterns
            .split(',')
            .any(|pattern| matches_prefix(pattern, module))
    })
}

fn matches_prefix(pattern: &str, module: &str) -> bool {
    let mut elements = module.split('/');
    !pattern.is_empty()
        && pattern
            .split('/')
            .all(|want| elements.next().is_some_and(|have| glob(want, have)))
}

/// `*` in one path element, the only wildcard these lists use in practice. An element with a
/// `?` or `[` matches anything, so a pattern read too widely keeps a module private.
fn glob(pattern: &str, text: &str) -> bool {
    if pattern.contains(['?', '[']) {
        return true;
    }
    let Some((head, tail)) = pattern.split_once('*') else {
        return pattern == text;
    };
    let Some(rest) = text.strip_prefix(head) else {
        return false;
    };
    if tail.contains('*') {
        return (0..=rest.len())
            .filter(|i| rest.is_char_boundary(*i))
            .any(|i| glob(tail, &rest[i..]));
    }
    rest.ends_with(tail)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::collections::HashMap;
    use std::io::Write;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct Fake {
        bodies: HashMap<String, Vec<u8>>,
        asked: Mutex<Vec<String>>,
    }

    impl Fetch for Fake {
        fn get(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
            self.asked.lock().unwrap().push(url.to_string());
            Ok(self.bodies.get(url).cloned())
        }

        fn github(&self, _: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }

        fn has_github_token(&self) -> bool {
            false
        }
    }

    fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            // `append_data` refuses `..`, which a hostile archive would not.
            let name = &mut header.as_old_mut().name;
            name[..path.len()].copy_from_slice(path.as_bytes());
            header.set_cksum();
            builder.append(&header, *bytes).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(bytes).unwrap();
        gz.finish().unwrap()
    }

    fn sha256_pin(body: &[u8]) -> Pin {
        Pin::File(Checksum::new("SHA-256", &to_hex(&Sha256::digest(body))).unwrap())
    }

    fn crate_wanted(pin: Pin) -> Wanted {
        Wanted {
            ecosystem: Ecosystem::Cargo,
            name: "demo".to_string(),
            version: "1.0.0".to_string(),
            pin,
        }
    }

    const URL: &str = "https://static.crates.io/crates/demo/demo-1.0.0.crate";

    fn kept(root: &Path, pin: &Pin) -> Vec<String> {
        let dir = root.join(pin.key().unwrap());
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn only_license_files_of_a_matching_archive_are_kept() {
        let root = tempfile::tempdir().unwrap();
        let body = gzip(&tar_of(&[
            ("demo-1.0.0/LICENSE-MIT", b"mit"),
            ("demo-1.0.0/LICENSES/Apache-2.0.txt", b"apache"),
            ("demo-1.0.0/src/lib.rs", b"code"),
            ("demo-1.0.0/vendor/LICENSE", b"not the package's own"),
            ("demo-1.0.0/../../LICENSE", b"out of the root"),
        ]));
        let pin = sha256_pin(&body);
        let fetch = Fake {
            bodies: HashMap::from([(URL.to_string(), body)]),
            ..Fake::default()
        };
        let wanted = BTreeSet::from([crate_wanted(pin.clone())]);
        let outcome = download_with(&wanted, root.path(), &fetch);
        assert_eq!(
            (outcome.fetched, outcome.failed.len()),
            (1, 0),
            "{:?}",
            outcome.failed
        );
        assert_eq!(kept(root.path(), &pin), ["LICENSE-MIT", "LICENSES"]);
        assert!(!root.path().join("LICENSE").exists());

        // Offline from here: what the cache holds is not asked for again.
        fetch.asked.lock().unwrap().clear();
        assert_eq!(download_with(&wanted, root.path(), &fetch).fetched, 0);
        assert!(fetch.asked.lock().unwrap().is_empty());
    }

    #[test]
    fn an_archive_the_lockfile_does_not_pin_is_dropped() {
        let root = tempfile::tempdir().unwrap();
        let body = gzip(&tar_of(&[("demo-1.0.0/LICENSE", b"mit")]));
        let pin = sha256_pin(b"something else");
        let fetch = Fake {
            bodies: HashMap::from([(URL.to_string(), body)]),
            ..Fake::default()
        };
        let outcome = download_with(
            &BTreeSet::from([crate_wanted(pin.clone())]),
            root.path(),
            &fetch,
        );
        assert_eq!(outcome.tampered, ["demo 1.0.0"]);
        assert!(!root.path().join(pin.key().unwrap()).exists());
    }

    #[test]
    fn a_package_with_no_license_file_is_remembered_and_a_404_is_not() {
        let root = tempfile::tempdir().unwrap();
        let body = gzip(&tar_of(&[("demo-1.0.0/src/lib.rs", b"code")]));
        let pin = sha256_pin(&body);
        let wanted = BTreeSet::from([crate_wanted(pin.clone())]);
        let outcome = download_with(&wanted, root.path(), &Fake::default());
        assert_eq!(outcome.missing, 1);
        assert!(!root.path().join(pin.key().unwrap()).exists());
        let fetch = Fake {
            bodies: HashMap::from([(URL.to_string(), body)]),
            ..Fake::default()
        };
        assert_eq!(download_with(&wanted, root.path(), &fetch).fetched, 1);
        assert!(kept(root.path(), &pin).is_empty());
    }

    #[test]
    fn gems_and_hex_keep_the_package_in_an_inner_tar() {
        let inner = gzip(&tar_of(&[("LICENSE.txt", b"mit"), ("lib/a.rb", b"code")]));
        let gem = tar_of(&[("metadata.gz", b"x"), ("data.tar.gz", &inner)]);
        let files = license_files(Ecosystem::RubyGems, "", &gem).unwrap();
        assert_eq!(files.keys().collect::<Vec<_>>(), ["LICENSE.txt"]);
        let hex = tar_of(&[("VERSION", b"3"), ("contents.tar.gz", &inner)]);
        let files = license_files(Ecosystem::Hex, "", &hex).unwrap();
        assert_eq!(files.keys().collect::<Vec<_>>(), ["LICENSE.txt"]);
    }

    #[test]
    fn names_differing_in_case_stay_two_files() {
        let root = tempfile::tempdir().unwrap();
        let files = Files::from([
            ("LICENSE".to_string(), b"one".to_vec()),
            ("license".to_string(), b"two".to_vec()),
        ]);
        keep(root.path(), "k", &files).unwrap();
        assert_eq!(std::fs::read_dir(root.path().join("k")).unwrap().count(), 2);
    }

    #[test]
    fn the_go_tree_hash_is_dirhash() {
        let mut zipped = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        zipped
            .start_file("example.com/m@v1.0.0/go.mod", options)
            .unwrap();
        zipped.write_all(b"module example.com/m\n").unwrap();
        zipped
            .start_file("example.com/m@v1.0.0/LICENSE", options)
            .unwrap();
        zipped.write_all(b"mit").unwrap();
        let body = zipped.finish().unwrap().into_inner();
        let (tree, files) = go_tree("example.com/m", "v1.0.0", &body).unwrap();
        let listing = format!(
            "{}  example.com/m@v1.0.0/LICENSE\n{}  example.com/m@v1.0.0/go.mod\n",
            to_hex(&Sha256::digest(b"mit")),
            to_hex(&Sha256::digest(b"module example.com/m\n")),
        );
        let expected = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(listing));
        assert_eq!(tree, expected);
        assert_eq!(files.keys().collect::<Vec<_>>(), ["LICENSE"]);
    }

    #[test]
    fn go_sum_lines_and_private_patterns() {
        let sums = go_sums("a.io/m v1.0.0 h1:abc=\na.io/m v1.0.0/go.mod h1:def=\n");
        assert_eq!(sums.len(), 1);
        assert_eq!(sums[&("a.io/m".to_string(), "v1.0.0".to_string())], "abc=");
        assert!(matches_prefix("*.corp.example", "git.corp.example/team/x"));
        assert!(matches_prefix("github.com/acme", "github.com/acme/tool"));
        assert!(!matches_prefix("github.com/acme", "github.com/acmeco/tool"));
        assert!(!matches_prefix("", "github.com/acme"));
    }

    #[test]
    fn pypi_finds_the_file_by_its_hash() {
        let release = serde_json::json!({"urls": [
            {"url": "https://f/a.whl", "digests": {"sha256": "aa"}},
            {"url": "https://f/a.tar.gz", "digests": {"sha256": "bb"}},
        ]});
        assert_eq!(
            pypi_url(&release, "bb").as_deref(),
            Some("https://f/a.tar.gz")
        );
        assert_eq!(pypi_url(&release, "cc"), None);
    }

    #[test]
    fn the_strongest_hash_this_code_can_check_is_the_pin() {
        let sha1 = Checksum::new("SHA-1", &"a".repeat(40)).unwrap();
        let sha512 = Checksum::new("SHA-512", &"b".repeat(128)).unwrap();
        assert_eq!(file_pin(std::slice::from_ref(&sha1)), None);
        assert_eq!(file_pin(&[sha1, sha512.clone()]), Some(Pin::File(sha512)));
    }
}
