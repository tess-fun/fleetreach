//! Prints every chain the import engine finds in a directory of repos, as one JSON line each:
//! `{repo, ecosystem, package, chain, file, line}`. Used by `docs/differential/import_chains.py`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use fleetreach_cli::config::Repo;
use fleetreach_cli::import_reach::{analyze, ECOSYSTEMS};
use fleetreach_core::RepoId;

fn main() {
    for dir in std::env::args().skip(1) {
        let path = PathBuf::from(&dir);
        let repo = Repo {
            id: RepoId(dir.clone()),
            path,
            glob: true,
            glob_max_depth: 7,
            vex_product_id: None,
            ecosystem: None,
        };
        let ecosystems: BTreeSet<_> = ECOSYSTEMS.into_iter().collect();
        for ((_, ecosystem), chains) in analyze(&repo, &ecosystems) {
            for (package, chain, file, line) in chains.all() {
                let row = serde_json::json!({
                    "repo": dir,
                    "ecosystem": ecosystem,
                    "package": package,
                    "chain": chain,
                    "file": file,
                    "line": line,
                });
                println!("{row}");
            }
        }
    }
}
