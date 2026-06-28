//! CI-enforced golden regression for the `Gem::Version` comparator.
//!
//! A bespoke version comparator is exactly where a silent false-clean hides: flip an
//! ordering and an advisory's range matcher quietly decides a vulnerable version is "fixed".
//! The unit tests in `version.rs` cover specific cases, but nothing pinned the comparator's
//! agreement with *modern* RubyGems across the tricky edges — notably the canonical-segments
//! change in RubyGems 3.3.0, which disagrees with an old system Ruby (e.g. macOS 2.6) on
//! prereleases with differing-length numeric cores. This test loads a committed corpus of
//! `(a, b, sign)` orderings (`tests/fixtures/ordering.tsv`) and asserts the comparator
//! reproduces each — so a regression fails CI without needing a Ruby toolchain present.
//!
//! It also checks antisymmetry (`cmp(b, a) == -cmp(a, b)`), catching a comparator that is
//! merely inconsistent rather than wrong in a specific direction.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::cmp::Ordering;

use fleetreach_rubygems::parse_rubygems_version;

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

        let va = parse_rubygems_version(a)
            .unwrap_or_else(|| panic!("fixture line {}: unparseable version {a:?}", lineno + 1));
        let vb = parse_rubygems_version(b)
            .unwrap_or_else(|| panic!("fixture line {}: unparseable version {b:?}", lineno + 1));

        assert_eq!(
            sign(va.cmp(&vb)),
            expected,
            "fixture line {}: cmp({a:?}, {b:?}) = {} but golden says {expected}",
            lineno + 1,
            sign(va.cmp(&vb)),
        );
        // Antisymmetry: reversing the operands must reverse the sign.
        assert_eq!(
            sign(vb.cmp(&va)),
            -expected,
            "fixture line {}: cmp({b:?}, {a:?}) is not the antisymmetric of cmp({a:?}, {b:?})",
            lineno + 1,
        );
        checked += 1;
    }

    assert!(
        checked >= 18,
        "expected a non-trivial corpus, ran {checked}"
    );
}
