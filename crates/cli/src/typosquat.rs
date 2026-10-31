//! Typosquat detection (spec 10, phase 2): a dependency whose name is one edit (an insertion,
//! deletion, substitution or adjacent swap) from a popular package of the same ecosystem that
//! it is not, other than a sibling in the same npm scope or a version digit appended to it.
//! Offline: the popular names are bundled (`data/popular/*.txt`, refreshed at release time by
//! `scripts/update-popular.py`); nothing about the fleet leaves the machine.
//!
//! Names are compared after each ecosystem's own normalization (PEP 503 for PyPI; case and
//! `-`/`_` for crates.io), so a spelling the registry treats as the same package is never
//! flagged. Names shorter than five characters are skipped (too many legitimate neighbours),
//! as is anything on the popular list itself. Matching uses a symmetric-delete index, then a
//! true Damerau-Levenshtein (optimal string alignment) distance check.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use fleetreach_core::Ecosystem;

const NPM: &str = include_str!("../data/popular/npm.txt");
const PYPI: &str = include_str!("../data/popular/pypi.txt");
const CARGO: &str = include_str!("../data/popular/cargo.txt");

/// Names shorter than this are not checked.
const MIN_LEN: usize = 5;

/// The edit distance allowed. Distance 2 flagged mostly unrelated pairs on a 22,000-package
/// corpus (`yaml_parser` / `toml-parser`), while known typosquats are one edit away.
fn allowed(_len: usize) -> usize {
    1
}

/// Pairs that are one edit apart for ordinary reasons: siblings in the same npm scope (one
/// publisher owns a scope) and a version digit appended to a name (`perf-event2`).
fn benign(name: &str, target: &str) -> bool {
    let scope = |n: &str| {
        n.strip_prefix('@')
            .and_then(|r| r.split_once('/'))
            .map(|(s, _)| s.to_string())
    };
    if scope(name).is_some() && scope(name) == scope(target) {
        return true;
    }
    let digits_after = |long: &str, short: &str| {
        long.strip_prefix(short)
            .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
    };
    let stem = |n: &str| n.trim_end_matches(|c: char| c.is_ascii_digit()).to_string();
    digits_after(name, target)
        || digits_after(target, name)
        // `vue-clipboard2` / `vue-clipboard3`: the same name, another major version.
        || (stem(name) == stem(target) && stem(name).len() < name.len() && stem(target).len() < target.len())
}

/// How an ecosystem spells "the same name".
fn normalize(ecosystem: Ecosystem, name: &str) -> String {
    match ecosystem {
        Ecosystem::Pypi => {
            let mut out = String::new();
            let mut sep = false;
            for c in name.chars() {
                if matches!(c, '-' | '_' | '.') {
                    sep = true;
                } else {
                    if sep && !out.is_empty() {
                        out.push('-');
                    }
                    sep = false;
                    out.extend(c.to_lowercase());
                }
            }
            out
        }
        Ecosystem::Cargo => name.to_lowercase().replace('_', "-"),
        _ => name.to_string(),
    }
}

struct Index {
    popular: BTreeSet<String>,
    /// A popular name and each of its deletions (up to the allowed distance) -> the names.
    deletes: BTreeMap<String, Vec<String>>,
}

fn deletions(word: &str, depth: usize, out: &mut BTreeSet<String>) {
    if depth == 0 {
        return;
    }
    let chars: Vec<char> = word.chars().collect();
    for i in 0..chars.len() {
        let shorter: String = chars[..i].iter().chain(&chars[i + 1..]).collect();
        if out.insert(shorter.clone()) {
            deletions(&shorter, depth - 1, out);
        }
    }
}

fn build(ecosystem: Ecosystem, data: &str) -> Index {
    let popular: BTreeSet<String> = data
        .lines()
        .map(|l| normalize(ecosystem, l.trim()))
        .filter(|l| !l.is_empty())
        .collect();
    let mut deletes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for name in &popular {
        let len = name.chars().count();
        if len < MIN_LEN {
            continue;
        }
        let mut keys = BTreeSet::from([name.clone()]);
        deletions(name, allowed(len), &mut keys);
        for key in keys {
            deletes.entry(key).or_default().push(name.clone());
        }
    }
    Index { popular, deletes }
}

fn index(ecosystem: Ecosystem) -> Option<&'static Index> {
    static NPM_IX: OnceLock<Index> = OnceLock::new();
    static PYPI_IX: OnceLock<Index> = OnceLock::new();
    static CARGO_IX: OnceLock<Index> = OnceLock::new();
    Some(match ecosystem {
        Ecosystem::Npm => NPM_IX.get_or_init(|| build(ecosystem, NPM)),
        Ecosystem::Pypi => PYPI_IX.get_or_init(|| build(ecosystem, PYPI)),
        Ecosystem::Cargo => CARGO_IX.get_or_init(|| build(ecosystem, CARGO)),
        _ => return None,
    })
}

/// Optimal string alignment distance (Damerau-Levenshtein with adjacent transpositions).
fn osa(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = best;
        }
    }
    d[a.len()][b.len()]
}

/// The popular package `name` looks like, if it is a likely typosquat of one.
pub fn lookalike(ecosystem: Ecosystem, name: &str) -> Option<String> {
    let ix = index(ecosystem)?;
    let norm = normalize(ecosystem, name);
    let len = norm.chars().count();
    if len < MIN_LEN || ix.popular.contains(&norm) {
        return None;
    }
    let mut keys = BTreeSet::from([norm.clone()]);
    deletions(&norm, allowed(len), &mut keys);
    let mut best: Option<(usize, String)> = None;
    for key in &keys {
        for target in ix.deletes.get(key).into_iter().flatten() {
            let limit = allowed(len.max(target.chars().count()));
            let dist = osa(&norm, target);
            if dist > 0
                && dist <= limit
                && !benign(&norm, target)
                && best.as_ref().is_none_or(|(d, t)| (dist, target) < (*d, t))
            {
                best = Some((dist, target.clone()));
            }
        }
    }
    best.map(|(_, t)| t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_typosquats_are_caught() {
        // Historic npm and PyPI typosquat campaigns.
        assert_eq!(
            lookalike(Ecosystem::Npm, "crossenv").as_deref(),
            Some("cross-env")
        );
        assert_eq!(
            lookalike(Ecosystem::Npm, "loadsh").as_deref(),
            Some("lodash")
        );
        assert_eq!(
            lookalike(Ecosystem::Pypi, "reqeusts").as_deref(),
            Some("requests")
        );
        assert_eq!(
            lookalike(Ecosystem::Pypi, "python-dateutl").as_deref(),
            Some("python-dateutil")
        );
        assert_eq!(
            lookalike(Ecosystem::Cargo, "serde-jsno").as_deref(),
            Some("serde-json")
        );
    }

    #[test]
    fn same_scope_siblings_and_digit_suffixes_pass() {
        assert_eq!(lookalike(Ecosystem::Npm, "@fluentui/react-tags"), None);
        assert_eq!(lookalike(Ecosystem::Npm, "@types/intl"), None);
        assert_eq!(lookalike(Ecosystem::Cargo, "perf-event2"), None);
        assert_eq!(lookalike(Ecosystem::Npm, "vue-clipboard3"), None);
        assert_eq!(
            lookalike(Ecosystem::Cargo, "merge_derive"),
            None,
            "two edits away"
        );
    }

    #[test]
    fn popular_short_and_equivalent_names_pass() {
        assert_eq!(lookalike(Ecosystem::Npm, "lodash"), None);
        assert_eq!(lookalike(Ecosystem::Npm, "ms"), None, "too short to judge");
        // PEP 503 and crates.io treat these spellings as the same package.
        assert_eq!(lookalike(Ecosystem::Pypi, "Python_Dateutil"), None);
        assert_eq!(lookalike(Ecosystem::Cargo, "serde_json"), None);
        assert_eq!(
            lookalike(Ecosystem::Go, "github.com/x/y"),
            None,
            "no list for Go"
        );
    }

    #[test]
    fn distance_counts_transpositions_once() {
        assert_eq!(osa("lodash", "loadsh"), 1);
        assert_eq!(osa("abc", "abc"), 0);
        assert_eq!(osa("kitten", "sitting"), 3);
    }
}
