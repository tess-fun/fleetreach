//! The curated sink records shipped in `data/` all load: one invalid record fails CI.

#![allow(clippy::panic)]

use std::path::Path;

use fleetreach_sinks::record::{load_dir, Status};

#[test]
fn shipped_records_are_valid() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("data");
    let set = load_dir(&dir).unwrap_or_else(|e| panic!("{e}"));
    assert!(set.records.len() >= 100);
    // Every record's file sits under the directory of its ecosystem.
    for r in set.records.values() {
        let sub = match r.ecosystem.as_str() {
            "Maven" => "maven",
            "PyPI" => "pypi",
            "npm" => "npm",
            "NuGet" => "nuget",
            other => panic!("unexpected ecosystem {other}"),
        };
        let file = dir.join(sub).join(format!("{}.json", r.id));
        assert!(file.is_file(), "{}", file.display());
        if r.status == Status::Reviewed {
            assert!(r.review.is_some());
        }
    }
}

// A reviewer's "proves nothing" and the field a scanner reads must not drift apart: a note
// alone would leave `supports_not_reached` true on a record that cannot support it.
#[test]
fn notes_and_reached_by_name_agree() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("data");
    let set = load_dir(&dir).unwrap_or_else(|e| panic!("{e}"));
    for r in set.reviewed() {
        let said = r
            .note
            .as_deref()
            .is_some_and(|n| n.contains("no sink reached proves nothing"));
        assert_eq!(said, r.reached_by_name, "{}", r.id);
    }
}
