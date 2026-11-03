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
        assert_eq!(r.ecosystem, "Maven");
        let file = dir.join("maven").join(format!("{}.json", r.id));
        assert!(file.is_file(), "{}", file.display());
        if r.status == Status::Reviewed {
            assert!(r.review.is_some());
        }
    }
}
