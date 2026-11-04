//! License detection from the text of a package's license files (spec 16, row 20).
//!
//! What a package declares can be wrong or absent, and Go modules declare nothing. This reads
//! the license files in a package's own directory and matches them against the SPDX list, with
//! the matcher and the texts of the `spdx` crate, so the answer is what the package ships.
//!
//! A text the matcher does not place at [`CONFIDENCE`] is named as unrecognized, never guessed
//! at. SPDX ids that share a text (`GPL-3.0-only`, `GPL-3.0-or-later`) cannot be told apart from
//! it, so they compare as one license.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use rayon::prelude::*;
use sha2::{Digest, Sha256};
use spdx::detection::scan::{ScanMode, Scanner};
use spdx::detection::{LicenseEntry, Store, TextData};

/// How close a text must be to a license's to count as it.
const CONFIDENCE: f32 = 0.9;
/// A license file past this is not a license file.
const MAX_FILE: u64 = 1 << 20;
/// A text this close to a license is that license and nothing else.
const WHOLE: f32 = 0.98;
/// Lines a top-down scan moves at a time.
const STEP: usize = 5;
/// Top-down windows over one text.
const MAX_WINDOWS: usize = 100;
/// Passes over a text holding several licenses.
const MAX_PASSES: u16 = 6;

/// Where the operative part of the Apache and GNU licenses ends.
const END_OF_TERMS: &str = "END OF TERMS AND CONDITIONS";

/// The part of an SPDX text that packages ship alone, as `(id, from, up to)`, an empty end being
/// the end of the text. The notices the Apache and Mozilla licenses ask projects to use, by id
/// because FSL-1.1-ALv2 quotes the same words, and the LGPL, whose SPDX text goes on to hold all
/// of the GPL it adds to.
const PARTS: &[(&str, &str, &str)] = &[
    (
        "Apache-2.0",
        "Licensed under the Apache License, Version 2.0",
        "",
    ),
    (
        "MPL-2.0",
        "This Source Code Form is subject",
        "If it is not possible",
    ),
    (
        "LGPL-3.0",
        "GNU LESSER",
        "GNU GENERAL PUBLIC LICENSE\nVersion 3",
    ),
];

fn part_of<'a>(text: &'a str, from: &str, to: &str) -> Option<&'a str> {
    let start = text.find(from)?;
    let rest = &text[start..];
    match to {
        "" => Some(rest),
        _ => rest.find(to).map(|end| &rest[..end]),
    }
}

/// What a package's license files say.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Detected {
    /// The SPDX ids found.
    pub ids: BTreeSet<String>,
    /// License files nothing matched.
    pub unrecognized: Vec<String>,
}

impl Detected {
    /// The ids as an SPDX expression: everything a package ships applies, as far as text can say.
    pub fn expression(&self) -> Option<String> {
        let ids: Vec<&str> = self.ids.iter().map(String::as_str).collect();
        (!ids.is_empty()).then(|| ids.join(" AND "))
    }
}

/// Whether `name` is a file a package keeps its license in.
pub fn is_license_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let stem = ["license", "licence", "copying", "unlicense", "copyright"]
        .iter()
        .any(|s| lower.starts_with(s))
        || lower.ends_with("-license")
        || lower.ends_with("-license.txt")
        || lower.ends_with("-license.md");
    let extension = lower.rsplit_once('.').map_or("", |(_, e)| e);
    stem && matches!(
        extension,
        "" | "txt"
            | "md"
            | "markdown"
            | "rst"
            | "lesser"
            | "mit"
            | "apache"
            | "bsd"
            | "gpl"
            | "lgpl"
            | "mpl"
    )
}

/// The matcher, its store built once from the texts in the `spdx` crate.
pub struct Detector {
    store: OnceLock<Store>,
    /// Text hash -> ids. A fleet ships the same few license files thousands of times.
    seen: Mutex<HashMap<[u8; 32], BTreeSet<String>>>,
}

impl Default for Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector {
    pub fn new() -> Detector {
        Detector {
            store: OnceLock::new(),
            seen: Mutex::default(),
        }
    }

    fn store(&self) -> &Store {
        self.store.get_or_init(|| {
            // Ids sharing a text are one entry, under the first that is not deprecated.
            let mut by_text: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
            for (id, text) in spdx::text::LICENSE_TEXTS {
                by_text.entry(*text).or_default().push(*id);
            }
            // Withdrawn ids have a current one to say instead.
            by_text.retain(|_, ids| {
                ids.iter()
                    .any(|id| spdx::license_id(id).is_some_and(|l| !l.is_deprecated()))
            });
            let entries: Vec<(String, LicenseEntry)> = by_text
                .into_par_iter()
                .map(|(text, ids)| {
                    let current =
                        |id: &&&str| spdx::license_id(id).is_some_and(|l| !l.is_deprecated());
                    let name = ids.iter().find(current).map_or("", |id| id).to_string();
                    let mut entry = LicenseEntry::new(TextData::new(text).without_text());
                    // Most copies stop here, before how to apply the license: without that
                    // form Apache-2.0 is nearer Pixar's Apache-derived text than its own.
                    if let Some((terms, _)) = text.split_once(END_OF_TERMS) {
                        entry.alternates.push(TextData::new(terms).without_text());
                    }
                    for (id, from, to) in PARTS {
                        if family(&name) == *id {
                            if let Some(part) = part_of(text, from, to) {
                                entry.alternates.push(TextData::new(part).without_text());
                            }
                        }
                    }
                    entry.aliases = ids
                        .iter()
                        .filter(|id| **id != name)
                        .map(ToString::to_string)
                        .collect();
                    (name, entry)
                })
                .collect();
            let mut store = Store::new();
            for (name, entry) in entries {
                store.insert_entry(name, entry);
            }
            store
        })
    }

    /// The SPDX ids in one license text.
    pub fn text(&self, text: &str) -> BTreeSet<String> {
        let key: [u8; 32] = Sha256::digest(text.as_bytes()).into();
        if let Some(hit) = self.lock().get(&key) {
            return hit.clone();
        }
        // A file holding only an SPDX expression says it plainly.
        if let Ok(expression) = spdx::Expression::parse(text.trim()) {
            let named = expression.requirements().filter_map(|r| r.req.license.id());
            let ids: BTreeSet<String> = named.map(|id| id.name.to_string()).collect();
            self.lock().insert(key, ids.clone());
            return ids;
        }
        let store = self.store();
        let scanner = Scanner::new(store)
            .confidence_threshold(CONFIDENCE)
            .shallow_limit(WHOLE)
            .optimize(true)
            .max_passes(MAX_PASSES);
        let data = TextData::new(text);
        let result = scanner.scan(&data);
        let whole = result.license.iter().map(|l| l.name);
        let parts = result.containing.iter().map(|c| c.license.name);
        let mut ids: BTreeSet<String> = whole.chain(parts).map(str::to_string).collect();
        // Not one license throughout: elimination stops at the first it cannot see past, and
        // a second license missed is the one that could matter.
        if result.score < WHOLE {
            // A window at every line of a bundler's notice file would take minutes.
            let lines = text.lines().count();
            let step_size = STEP.max(lines / MAX_WINDOWS);
            let mode = ScanMode::TopDown { step_size };
            let top_down = Scanner::with_scan_mode(store, mode).confidence_threshold(CONFIDENCE);
            let parts = top_down.scan(&data);
            ids.extend(parts.containing.iter().map(|c| c.license.name.to_string()));
        }
        self.lock().insert(key, ids.clone());
        ids
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], BTreeSet<String>>> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What the given `(file name, bytes)` license files say.
    pub fn files<'a>(&self, files: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> Detected {
        let mut out = Detected::default();
        for (name, bytes) in files {
            let ids = self.text(&String::from_utf8_lossy(bytes));
            if ids.is_empty() {
                out.unrecognized.push(name.to_string());
            }
            out.ids.extend(ids);
        }
        out
    }

    /// What the license files in `dir` say, or `None` when it holds none.
    pub fn dir(&self, dir: &Path) -> Option<Detected> {
        let files = read_license_files(dir);
        if files.is_empty() {
            return None;
        }
        Some(self.files(files.iter().map(|(n, b)| (n.as_str(), b.as_slice()))))
    }
}

/// The license files directly in `dir`, and in the `LICENSES` or `licenses` directory beside
/// them (REUSE, PEP 639). Links are not followed: a package chooses what is in its directory.
fn read_license_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .collect();
    names.sort_by_key(std::fs::DirEntry::file_name);
    for entry in names {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() && name.eq_ignore_ascii_case("licenses") {
            let mut inner: Vec<_> = std::fs::read_dir(entry.path())
                .into_iter()
                .flatten()
                .flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
                .collect();
            inner.sort_by_key(std::fs::DirEntry::file_name);
            for file in inner {
                push_file(
                    &mut out,
                    &file,
                    format!("{name}/{}", file.file_name().to_string_lossy()),
                );
            }
        } else if kind.is_file() && is_license_file(&name) {
            push_file(&mut out, &entry, name);
        }
    }
    out
}

fn push_file(out: &mut Vec<(String, Vec<u8>)>, entry: &std::fs::DirEntry, name: String) {
    let small = entry.metadata().is_ok_and(|m| m.len() <= MAX_FILE);
    if let (true, Ok(bytes)) = (small, std::fs::read(entry.path())) {
        out.push((name, bytes));
    }
}

/// The id without what a text cannot say: `GPL-3.0-only`, `GPL-3.0-or-later`, `GPL-3.0+` and
/// `GPL-3.0` are one text.
fn family(id: &str) -> &str {
    id.trim_end_matches('+')
        .trim_end_matches("-only")
        .trim_end_matches("-or-later")
}

/// The detected ids no declared id accounts for. A variant of what is declared is accounted
/// for: `Python-2.0.1` and `Python-2.0` differ in a name, and so do most such pairs.
pub fn undeclared<'a>(detected: &'a Detected, declared: &[String]) -> Vec<&'a str> {
    let declared: BTreeSet<&str> = declared.iter().map(|id| family(id)).collect();
    detected
        .ids
        .iter()
        .map(String::as_str)
        .filter(|id| !declared.iter().any(|d| family(id).starts_with(d)))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const MIT: &str = "MIT License\n\nCopyright (c) 2021 Someone Else\n\nPermission is hereby \
        granted, free of charge, to any person obtaining a copy of this software and associated \
        documentation files (the \"Software\"), to deal in the Software without restriction, \
        including without limitation the rights to use, copy, modify, merge, publish, distribute, \
        sublicense, and/or sell copies of the Software, and to permit persons to whom the \
        Software is furnished to do so, subject to the following conditions:\n\nThe above \
        copyright notice and this permission notice shall be included in all copies or \
        substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT \
        WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF \
        MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL \
        THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, \
        WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN \
        CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\n";

    #[test]
    fn license_files_are_told_from_the_rest() {
        for name in [
            "LICENSE",
            "LICENSE.md",
            "LICENSE-MIT",
            "LICENSE-APACHE",
            "LICENCE.txt",
            "COPYING",
            "COPYING.LESSER",
            "UNLICENSE",
            "license.rst",
            "MIT-LICENSE",
            "MIT-LICENSE.txt",
        ] {
            assert!(is_license_file(name), "{name}");
        }
        for name in [
            "license.rs",
            "license.go",
            "license.json",
            "licenses.py",
            "README.md",
        ] {
            assert!(!is_license_file(name), "{name}");
        }
    }

    #[test]
    fn a_text_is_placed_and_noise_is_not() {
        let detector = Detector::new();
        assert_eq!(detector.text(MIT), BTreeSet::from(["MIT".to_string()]));
        assert!(detector
            .text("All rights reserved. Do not copy.")
            .is_empty());
    }

    #[test]
    fn a_notice_or_an_expression_alone_is_enough() {
        let detector = Detector::new();
        let notice = "Copyright 2015 Someone.\n\nLicensed under the Apache License, Version 2.0 \
            (the \"License\");\nyou may not use this file except in compliance with the \
            License.\nYou may obtain a copy of the License at\n\n    \
            http://www.apache.org/licenses/LICENSE-2.0\n\nUnless required by applicable law or \
            agreed to in writing, software\ndistributed under the License is distributed on an \
            \"AS IS\" BASIS,\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or \
            implied.\nSee the License for the specific language governing permissions and\n\
            limitations under the License.\n";
        assert_eq!(
            detector.text(notice),
            BTreeSet::from(["Apache-2.0".to_string()])
        );
        let mozilla = "This Source Code Form is subject to the terms of the Mozilla Public\n\
            License, v. 2.0. If a copy of the MPL was not distributed with this\n\
            file, You can obtain one at https://mozilla.org/MPL/2.0/.\n";
        assert_eq!(
            detector.text(mozilla),
            BTreeSet::from(["MPL-2.0".to_string()])
        );
        let both = BTreeSet::from(["Apache-2.0".to_string(), "MIT".to_string()]);
        assert_eq!(detector.text("MIT OR Apache-2.0\n"), both);
    }

    #[test]
    fn a_directory_says_what_each_file_says() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("LICENSE-MIT"), MIT).unwrap();
        std::fs::write(dir.path().join("LICENSE-OTHER"), "Ask us first.").unwrap();
        std::fs::write(dir.path().join("license.rs"), "fn main() {}").unwrap();
        let got = Detector::new().dir(dir.path()).unwrap();
        assert_eq!(got.expression().as_deref(), Some("MIT"));
        assert_eq!(got.unrecognized, vec!["LICENSE-OTHER"]);
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(Detector::new().dir(empty.path()), None);
    }

    #[test]
    fn what_a_text_cannot_say_is_no_mismatch() {
        let detected = Detected {
            ids: BTreeSet::from(["GPL-3.0-only".to_string(), "MIT".to_string()]),
            unrecognized: Vec::new(),
        };
        let declared = vec!["GPL-3.0-or-later".to_string()];
        assert_eq!(undeclared(&detected, &declared), vec!["MIT"]);
    }
}
