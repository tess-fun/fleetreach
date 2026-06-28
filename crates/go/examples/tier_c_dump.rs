//! Tier-C differential harness: dump the Tier-C offline
//! matcher's findings for many module dirs as JSON, one object per line:
//! `{"dir","advisory","module","version","kind"}` where kind is `direct`|`transitive`.
//!
//! Used by E1 (differential vs govulncheck) and E3 (direct vs transitive blast radius).
//!
//! Usage:
//!   tier_c_dump <db_root> <module_dir>...
//!   tier_c_dump <db_root> --dirs-file <file>   # one module dir per line (avoids ARG_MAX)
#![allow(clippy::expect_used)] // a small research harness: usage errors abort by design

use std::path::Path;

use fleetreach_core::{DependencyKind, Occurrence, RepoId};
use fleetreach_go::{scan_offline, GoDb};

fn main() {
    let mut args = std::env::args().skip(1);
    let db_root = args
        .next()
        .expect("usage: tier_c_dump <db_root> [<module_dir>... | --dirs-file <file>]");
    let db_root = Path::new(&db_root);

    let rest: Vec<String> = args.collect();
    let dirs: Vec<String> = match rest.split_first() {
        Some((flag, tail)) if flag == "--dirs-file" => {
            let file = tail.first().expect("--dirs-file needs a path");
            std::fs::read_to_string(file)
                .expect("read dirs file")
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect()
        }
        _ => rest,
    };

    // Load the mirror once, then reuse it for every module dir.
    let db = GoDb::load(db_root).expect("load Go OSV mirror");
    for dir in dirs {
        let repo = RepoId(dir.clone());
        match scan_offline(Path::new(&dir), &db, &repo) {
            Ok(findings) => {
                for f in &findings {
                    for occ in &f.occurrences {
                        if let Occurrence::InRepo {
                            package,
                            installed,
                            dependency_kind,
                            ..
                        } = occ
                        {
                            let kind = match dependency_kind {
                                DependencyKind::Direct => "direct",
                                DependencyKind::Transitive => "transitive",
                            };
                            println!(
                                "{}",
                                serde_json::json!({
                                    "dir": dir,
                                    "advisory": f.advisory_id,
                                    "module": package,
                                    "version": installed.to_string(),
                                    "kind": kind,
                                })
                            );
                        }
                    }
                }
            }
            // Fail-loud per the matcher's contract: a broken go.mod / mirror is a gap,
            // recorded as an error line rather than a silent empty result.
            Err(e) => eprintln!("ERROR {dir}: {e}"),
        }
    }
}
