//! CI-enforced golden regression for the Packagist (Composer) comparator.
//!
//! A bespoke version comparator is exactly where a silent false-clean hides: flip an ordering
//! and an advisory's range matcher quietly decides a vulnerable version is "fixed". This test
//! loads a committed corpus of `(a, b, sign)` orderings (`tests/fixtures/ordering.tsv`), each
//! exercising a documented Composer quirk (notably the `-pN` patch-above-release ladder), and
//! asserts the comparator reproduces every one — so a regression fails CI without a PHP
//! toolchain present. It also checks antisymmetry.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::cmp::Ordering;

use fleetreach_packagist::parse_composer_version;

fn sign(o: Ordering) -> i32 {
    match o {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

#[test]
fn comparator_matches_golden_ordering_corpus() {
    let corpus = include_str!("fixtures/ordering.tsv");
    let mut checked = 0usize;

    for (lineno, raw) in corpus.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        assert_eq!(
            cols.len(),
            3,
            "fixture line {}: expected `a<TAB>b<TAB>sign`, got {raw:?}",
            lineno + 1
        );
        let (a, b, expected) = (cols[0], cols[1], cols[2]);
        let expected: i32 = expected
            .parse()
            .unwrap_or_else(|_| panic!("fixture line {}: bad sign {expected:?}", lineno + 1));

        let va = parse_composer_version(a)
            .unwrap_or_else(|| panic!("fixture line {}: unparseable version {a:?}", lineno + 1));
        let vb = parse_composer_version(b)
            .unwrap_or_else(|| panic!("fixture line {}: unparseable version {b:?}", lineno + 1));

        assert_eq!(
            sign(va.cmp(&vb)),
            expected,
            "fixture line {}: cmp({a:?}, {b:?}) = {} but golden says {expected}",
            lineno + 1,
            sign(va.cmp(&vb)),
        );
        assert_eq!(
            sign(vb.cmp(&va)),
            -expected,
            "fixture line {}: cmp({b:?}, {a:?}) is not the antisymmetric of cmp({a:?}, {b:?})",
            lineno + 1,
        );
        checked += 1;
    }

    assert!(
        checked >= 10,
        "expected a non-trivial corpus, ran {checked}"
    );
}
