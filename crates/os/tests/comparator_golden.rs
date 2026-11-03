//! Golden comparator cases, each checked against the real tool: `dpkg --compare-versions`
//! (dpkg 1.21.23, debian:12) and `apk version -t` (apk-tools 2.14.4, alpine:3.20).
//!
//! The hand-picked edge cases pin the rules that differ from SemVer. The pair files under
//! `tests/data` are 800 pairs per family sampled from the full differential run (619,997 dpkg
//! and 619,999 apk pairs drawn from the osv.dev distro exports, 0 mismatches), and
//! `apk-invalid.txt` is every version in those exports that `apk version -c` rejects.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::cmp::Ordering;

use fleetreach_os::{ApkVersion, DebVersion};

fn op(s: &str) -> Ordering {
    match s {
        "<" => Ordering::Less,
        "=" => Ordering::Equal,
        ">" => Ordering::Greater,
        other => panic!("bad op {other}"),
    }
}

const DEB_EDGES: &[(&str, &str, &str)] = &[
    ("1.0~rc1", "1.0", "<"),
    ("1.0", "1.0+b1", "<"),
    ("1:0.1", "9.9", ">"),
    ("1.0-1", "1.0-1~bpo12+1", ">"),
    ("1.0~~", "1.0~", "<"),
    ("1.0~~a", "1.0~~", ">"),
    ("1.0a", "1.0", ">"),
    ("1.0", "1.0-0", "="),
    ("0:1.0", "1.0", "="),
    ("1.01", "1.1", "="),
    ("2.36-9+deb12u14", "2.36-9+deb12u9", ">"),
    ("1.0.0", "1.0", ">"),
    ("1.0-1ubuntu0.1", "1.0-1ubuntu1", "<"),
    ("1.2.3+dfsg-1", "1.2.3-1", ">"),
    ("1.0", "1.0.", "<"),
    ("1.0-1", "1.0-1.1", "<"),
    ("3.0.20-1~deb12u2", "3.0.20-1", "<"),
    ("2:1.0", "1:9.0", ">"),
    ("1.0+really0.9", "1.0", ">"),
    ("1.0-a", "1.0-+", "<"),
];

const APK_EDGES: &[(&str, &str, &str)] = &[
    ("1.0_rc1", "1.0", "<"),
    ("1.0_p1", "1.0", ">"),
    ("1.0-r1", "1.0", ">"),
    ("1.0a", "1.0", ">"),
    ("1.0_alpha", "1.0_beta", "<"),
    ("1.01", "1.1", "<"),
    ("1.0_git20240101", "1.0", ">"),
    ("1.0_cvs", "1.0_svn", "<"),
    ("1.10", "1.9", ">"),
    ("1.0-r10", "1.0-r9", ">"),
    ("1.0.0", "1.0", ">"),
    ("1_rc1", "1_pre1", ">"),
    ("1.2_beta3_p4", "1.2_beta3", ">"),
    ("1.0_pre1", "1.0_alpha2", ">"),
    ("1.001", "1.01", "<"),
    ("1.0b", "1.0a", ">"),
    ("1.2.3_rc1-r0", "1.2.3-r0", "<"),
    ("1.0_hg", "1.0_p", "<"),
    ("2.36.1a_git20240101-r1", "2.36.1_git20240101-r1", ">"),
    ("0.1", "0.01", ">"),
];

fn deb_cmp(a: &str, b: &str) -> Ordering {
    let pa = DebVersion::parse(a).unwrap_or_else(|| panic!("dpkg accepts {a}"));
    let pb = DebVersion::parse(b).unwrap_or_else(|| panic!("dpkg accepts {b}"));
    pa.cmp(&pb)
}

fn apk_cmp(a: &str, b: &str) -> Ordering {
    let pa = ApkVersion::parse(a).unwrap_or_else(|| panic!("apk accepts {a}"));
    let pb = ApkVersion::parse(b).unwrap_or_else(|| panic!("apk accepts {b}"));
    pa.cmp(&pb)
}

fn check(
    name: &str,
    rows: impl Iterator<Item = (String, String, String)>,
    cmp: fn(&str, &str) -> Ordering,
) {
    let mut n = 0;
    for (a, b, want) in rows {
        let want = op(&want);
        assert_eq!(cmp(&a, &b), want, "{name}: {a} vs {b}");
        assert_eq!(cmp(&b, &a), want.reverse(), "{name}: {b} vs {a}");
        n += 1;
    }
    assert!(n > 0, "{name}: no rows");
}

fn rows(text: &str) -> impl Iterator<Item = (String, String, String)> + '_ {
    text.lines().filter(|l| !l.is_empty()).map(|l| {
        let mut f = l.split('\t');
        let (a, b, o) = (f.next().unwrap(), f.next().unwrap(), f.next().unwrap());
        (a.to_string(), b.to_string(), o.to_string())
    })
}

fn edges(list: &'static [(&str, &str, &str)]) -> impl Iterator<Item = (String, String, String)> {
    list.iter()
        .map(|(a, b, o)| (a.to_string(), b.to_string(), o.to_string()))
}

#[test]
fn dpkg_edge_cases() {
    check("dpkg", edges(DEB_EDGES), deb_cmp);
}

#[test]
fn apk_edge_cases() {
    check("apk", edges(APK_EDGES), apk_cmp);
}

#[test]
fn dpkg_sampled_from_the_exports() {
    check("dpkg", rows(include_str!("data/deb-pairs.tsv")), deb_cmp);
}

#[test]
fn apk_sampled_from_the_exports() {
    check("apk", rows(include_str!("data/apk-pairs.tsv")), apk_cmp);
}

#[test]
fn apk_rejects_what_apk_rejects() {
    for v in include_str!("data/apk-invalid.txt")
        .lines()
        .filter(|l| !l.is_empty())
    {
        assert!(ApkVersion::parse(v).is_none(), "apk rejects {v}");
    }
}
