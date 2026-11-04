//! Incremental updates of an osv.dev export (spec 16, row 11).
//!
//! Each ecosystem's bucket directory holds `modified_id.csv`, one `<modified>,<id>` line per
//! record of its `all.zip`, and every record as `<id>.json`. A sync reads the listing,
//! fetches the records whose `modified` differs from the local export, drops the ids the
//! listing no longer has and rewrites `all.zip`, copying the unchanged entries as they are.
//!
//! What the local export holds comes from the export itself: a `modified` map read from the
//! records, saved in `all.zip.index.json` and tied to the zip's hash. A listing saved next to
//! the zip could be newer than the zip it was fetched with, and would then hide that record's
//! change for good. A fetched record's own `modified` goes in the map for the same reason.
//!
//! Every doubt here ends in a whole-export download, never a half-updated export.
#![cfg_attr(not(feature = "network"), allow(dead_code))]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// More changed records than this and the whole export is the cheaper download.
const MAX_CHANGED: usize = 5000;

/// Record id to its `modified`, with the fraction's trailing zeros removed: the listing
/// prints nine digits where a record drops them (`.13615237Z`, `.136152370Z`).
pub(crate) type Modified = BTreeMap<String, String>;

/// `all.zip.index.json`: what an `all.zip` holds, and the listing it was last checked against.
#[derive(Serialize, Deserialize)]
pub(crate) struct Index {
    /// The `all.zip` this describes; any other zip makes the index worthless.
    pub zip_sha256: String,
    /// The `ETag` of the listing, for a conditional GET.
    pub listing_etag: Option<String>,
    pub modified: Modified,
}

fn index_path(zip: &Path) -> PathBuf {
    zip.with_file_name("all.zip.index.json")
}

pub(crate) fn read_index(zip: &Path, zip_sha256: &str) -> Option<Index> {
    let text = std::fs::read(index_path(zip)).ok()?;
    let index: Index = serde_json::from_slice(&text).ok()?;
    (index.zip_sha256 == zip_sha256).then_some(index)
}

pub(crate) fn write_index(zip: &Path, index: &Index) -> Result<(), String> {
    let path = index_path(zip);
    let tmp = path.with_extension("partial");
    let json = serde_json::to_vec(index).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, json).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("installing {}: {e}", path.display()))
}

fn normalized(modified: &str) -> String {
    match modified.strip_suffix('Z').and_then(|t| t.split_once('.')) {
        Some((seconds, fraction)) => {
            let fraction = fraction.trim_end_matches('0');
            if fraction.is_empty() {
                format!("{seconds}Z")
            } else {
                format!("{seconds}.{fraction}Z")
            }
        }
        None => modified.to_string(),
    }
}

/// An id that is safe in a URL and a zip entry name. Every id osv.dev exports today is.
pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('.')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

/// Parse a `modified_id.csv`. An odd line refuses the whole listing.
pub(crate) fn parse_listing(text: &str) -> Result<Modified, String> {
    let mut out = Modified::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let (modified, id) = line
            .split_once(',')
            .filter(|(modified, id)| modified.ends_with('Z') && valid_id(id))
            .ok_or_else(|| format!("unexpected listing line `{line}`"))?;
        out.insert(id.to_string(), normalized(modified));
    }
    if out.is_empty() {
        return Err("empty listing".to_string());
    }
    Ok(out)
}

/// The `modified` of a record's JSON, checked to be the record `id`.
pub(crate) fn record_modified(id: &str, json: &[u8]) -> Result<String, String> {
    #[derive(Deserialize)]
    struct Record {
        id: String,
        modified: String,
    }
    let record: Record = serde_json::from_slice(json).map_err(|e| format!("record {id}: {e}"))?;
    if record.id != id {
        return Err(format!("record {id} says it is {}", record.id));
    }
    Ok(normalized(&record.modified))
}

/// What an export holds, read from its records.
pub(crate) fn read_export(zip: &Path) -> Result<Modified, String> {
    let file = std::fs::File::open(zip).map_err(|e| format!("opening {}: {e}", zip.display()))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| format!("reading {}: {e}", zip.display()))?;
    let mut out = Modified::new();
    let mut json = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("reading {}: {e}", zip.display()))?;
        let name = entry
            .name()
            .map_err(|e| format!("reading {}: {e}", zip.display()))?;
        let Some(id) = name.strip_suffix(".json").map(str::to_string) else {
            continue;
        };
        json.clear();
        entry
            .read_to_end(&mut json)
            .map_err(|e| format!("reading {}: {e}", zip.display()))?;
        let modified = record_modified(&id, &json)?;
        out.insert(id, modified);
    }
    Ok(out)
}

/// The ids to fetch and how many to drop, or `None` when so much changed that the whole
/// export is the better download (which also covers a listing that lost most of its ids).
pub(crate) fn plan(have: &Modified, want: &Modified) -> Option<(Vec<String>, usize)> {
    let fetch: Vec<String> = want
        .iter()
        .filter(|(id, modified)| have.get(*id) != Some(*modified))
        .map(|(id, _)| id.clone())
        .collect();
    let removed = have.keys().filter(|id| !want.contains_key(*id)).count();
    let changed = fetch.len() + removed;
    (changed <= MAX_CHANGED && changed <= have.len() / 4 + 100).then_some((fetch, removed))
}

/// Write the export holding exactly `ids`, to `tmp`: `fetched` records as new entries, the
/// rest copied still compressed from `zip`. Returns the sha256 and size of the result.
pub(crate) fn rewrite(
    zip: &Path,
    tmp: &Path,
    ids: impl Iterator<Item = impl AsRef<str>>,
    fetched: &BTreeMap<String, Vec<u8>>,
) -> Result<(String, u64), String> {
    let source = std::fs::File::open(zip).map_err(|e| format!("opening {}: {e}", zip.display()))?;
    let mut archive =
        zip::ZipArchive::new(source).map_err(|e| format!("reading {}: {e}", zip.display()))?;
    let file =
        std::fs::File::create(tmp).map_err(|e| format!("creating {}: {e}", tmp.display()))?;
    let mut out = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    // The order of osv.dev's zips: `A-1.json` before `A-1-2.json`.
    let mut names: Vec<String> = ids.map(|id| format!("{}.json", id.as_ref())).collect();
    names.sort();
    for name in names {
        let written = match name.strip_suffix(".json").and_then(|id| fetched.get(id)) {
            Some(json) => out
                .start_file(name.as_str(), options)
                .and_then(|()| out.write_all(json).map_err(Into::into)),
            None => archive
                .index_for_name(&name)
                .ok_or(zip::result::ZipError::FileNotFound)
                .and_then(|i| archive.by_index_raw(i))
                .and_then(|entry| out.raw_copy_file(entry)),
        };
        written.map_err(|e| format!("writing {name} to {}: {e}", tmp.display()))?;
    }
    let file = out
        .finish()
        .map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    file.sync_all()
        .map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    crate::curated::sha256_file(tmp).map_err(|e| format!("reading {}: {e}", tmp.display()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn record(id: &str, modified: &str) -> Vec<u8> {
        format!(r#"{{"id":"{id}","modified":"{modified}","summary":"{id}"}}"#).into_bytes()
    }

    fn export(dir: &Path, records: &[(&str, &str)]) -> PathBuf {
        let zip = dir.join("all.zip");
        let mut out = zip::ZipWriter::new(std::fs::File::create(&zip).unwrap());
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (id, modified) in records {
            out.start_file(format!("{id}.json"), options).unwrap();
            out.write_all(&record(id, modified)).unwrap();
        }
        out.finish().unwrap();
        zip
    }

    fn contents(zip: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut archive = zip::ZipArchive::new(std::fs::File::open(zip).unwrap()).unwrap();
        let mut out = BTreeMap::new();
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).unwrap();
            let mut json = Vec::new();
            entry.read_to_end(&mut json).unwrap();
            out.insert(entry.name().unwrap().to_string(), json);
        }
        out
    }

    #[test]
    fn a_listing_and_a_record_agree_on_a_trimmed_fraction() {
        let want = parse_listing("2026-11-03T16:11:17.136152370Z,A-1\n").unwrap();
        let json = record("A-1", "2026-11-03T16:11:17.13615237Z");
        assert_eq!(want["A-1"], record_modified("A-1", &json).unwrap());
        assert_eq!(
            normalized("2026-11-03T16:11:17.000Z"),
            "2026-11-03T16:11:17Z"
        );
        assert_eq!(normalized("2026-11-03T16:11:17Z"), "2026-11-03T16:11:17Z");
    }

    #[test]
    fn an_odd_listing_is_refused_whole() {
        assert!(parse_listing("").is_err());
        assert!(parse_listing("<html>nope</html>\n").is_err());
        assert!(parse_listing("2026-01-01T00:00:00Z,A-1\n2026-01-01T00:00:00Z,../x\n").is_err());
        assert!(parse_listing("2026-01-01T00:00:00Z,a/b\n").is_err());
        assert!(parse_listing("2026-01-01T00:00:00Z,.hidden\n").is_err());
        assert!(parse_listing("2026-01-01T00:00:00Z,SUSE-SU-2024:0001-1\n").is_ok());
    }

    #[test]
    fn a_record_that_names_another_id_is_refused() {
        assert!(record_modified("A-1", &record("A-2", "2026-01-01T00:00:00Z")).is_err());
        assert!(record_modified("A-1", b"{}").is_err());
    }

    #[test]
    fn the_plan_fetches_changes_and_counts_removals() {
        let have = parse_listing(
            "2026-01-01T00:00:00Z,A-1\n2026-01-01T00:00:00Z,A-2\n2026-01-01T00:00:00Z,A-3\n",
        )
        .unwrap();
        let want = parse_listing(
            "2026-01-02T00:00:00Z,A-1\n2026-01-01T00:00:00Z,A-2\n2026-01-01T00:00:00Z,A-4\n",
        )
        .unwrap();
        let (fetch, removed) = plan(&have, &want).unwrap();
        assert_eq!(fetch, ["A-1", "A-4"]);
        assert_eq!(removed, 1);
        assert_eq!(plan(&have, &have).unwrap(), (Vec::new(), 0));
    }

    #[test]
    fn a_mass_change_is_a_whole_download() {
        let listing = |day: u32, n: u32| {
            (0..n)
                .map(|i| format!("2026-01-{day:02}T00:00:00Z,A-{i}\n"))
                .collect::<String>()
        };
        let have = parse_listing(&listing(1, 1000)).unwrap();
        assert!(plan(&have, &parse_listing(&listing(2, 1000)).unwrap()).is_none());
        // A listing that lost most of its ids is not obeyed either.
        assert!(plan(&have, &parse_listing(&listing(1, 100)).unwrap()).is_none());
    }

    #[test]
    fn a_rewrite_holds_exactly_the_wanted_records() {
        let dir = tempfile::tempdir().unwrap();
        let zip = export(
            dir.path(),
            &[
                ("A-1", "2026-01-01T00:00:00Z"),
                ("A-2", "2026-01-01T00:00:00Z"),
                // In the zip but in neither listing: must not survive.
                ("A-3", "2026-01-01T00:00:00Z"),
            ],
        );
        let tmp = dir.path().join("all.zip.partial");
        let fresh = record("A-2", "2026-01-02T00:00:00Z");
        let added = record("A-4", "2026-01-02T00:00:00Z");
        let fetched = BTreeMap::from([
            ("A-2".to_string(), fresh.clone()),
            ("A-4".to_string(), added.clone()),
        ]);
        let (sha, size) = rewrite(&zip, &tmp, ["A-1", "A-2", "A-4"].iter(), &fetched).unwrap();
        assert_eq!(size, std::fs::metadata(&tmp).unwrap().len());
        assert_eq!(crate::curated::sha256_file(&tmp).unwrap().0, sha);
        let got = contents(&tmp);
        assert_eq!(got.len(), 3);
        assert_eq!(got["A-1.json"], record("A-1", "2026-01-01T00:00:00Z"));
        assert_eq!(got["A-2.json"], fresh);
        assert_eq!(got["A-4.json"], added);
        assert_eq!(read_export(&tmp).unwrap()["A-2"], "2026-01-02T00:00:00Z");
    }

    #[test]
    fn a_record_missing_from_the_zip_fails_the_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let zip = export(dir.path(), &[("A-1", "2026-01-01T00:00:00Z")]);
        let tmp = dir.path().join("all.zip.partial");
        assert!(rewrite(&zip, &tmp, ["A-1", "A-9"].iter(), &BTreeMap::new()).is_err());
    }

    #[test]
    fn an_index_counts_only_for_its_own_zip() {
        let dir = tempfile::tempdir().unwrap();
        let zip = dir.path().join("all.zip");
        let index = Index {
            zip_sha256: "abc".to_string(),
            listing_etag: Some("\"e\"".to_string()),
            modified: Modified::from([("A-1".to_string(), "t".to_string())]),
        };
        write_index(&zip, &index).unwrap();
        assert!(read_index(&zip, "abc").is_some());
        assert!(read_index(&zip, "def").is_none());
    }
}
