//! Maven `ComparableVersion` parsing and ordering — the one piece of Maven-specific version
//! handling the matcher needs, and the false-clean-critical one.
//!
//! Maven versions are **not** SemVer. They follow Apache Maven's `ComparableVersion`: a
//! version is tokenized into integer items, string *qualifier* items, and nested lists (split
//! on `.`, `-`, and every digit/letter boundary), then compared with qualifier-aware rules.
//! The load-bearing specifics a SemVer comparator gets wrong:
//!
//! - Qualifiers order `alpha < beta < milestone < rc < snapshot < <release> < sp`, so a
//!   `-rc`/`-milestone`/`-alpha` sorts **below** the release while `-sp` sorts **above** it.
//! - `ga`, `final`, and `release` are aliases for the release (`1.0.0.RELEASE == 1.0.0`), and
//!   `cr` is an alias for `rc`.
//! - Single-letter `a`/`b`/`m` directly before a number mean `alpha`/`beta`/`milestone`.
//! - Trailing "null" items are insignificant, so `1` == `1.0` == `1.0.0`.
//! - Integer items compare as arbitrary-precision (so Jenkins-style `2646.v…` build numbers
//!   order numerically), and an integer always outranks a qualifier at the same position.
//!
//! This is a faithful port of `org.apache.maven.artifact.versioning.ComparableVersion`; the
//! matcher is validated differentially against the real Java class.

use std::cmp::Ordering;

use fleetreach_core::semver::{Prerelease, Version as SemverVersion};

/// One parsed item: an integer (a leading-zero-stripped digit string, arbitrary precision), a
/// normalized string qualifier, or a nested list (introduced by `-` and digit/letter splits).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    Int(String),
    Str(String),
    List(Vec<Item>),
}

/// The recognized qualifiers, in ascending order; the empty string is the release level.
const QUALIFIERS: [&str; 7] = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];
/// The comparable index of the release qualifier (`""`), as a string (`"5"`).
const RELEASE_INDEX: &str = "5";

/// A parsed Maven version: the verbatim string (for display / `to_semver`) and the root item
/// list. Equality is defined by the ordering (so `1` equals `1.0`).
#[derive(Debug, Clone)]
pub struct Version {
    raw: String,
    items: Vec<Item>,
}

/// Parse a Maven version string into a [`Version`]. Never fails — Maven's `ComparableVersion`
/// accepts any string — so this returns a `Version` for any input; the `Option` is kept for
/// signature parity with the other feeders' parsers (it is always `Some`).
pub fn parse_maven_version(raw: &str) -> Option<Version> {
    Some(Version {
        raw: raw.trim().to_string(),
        items: parse_items(raw.trim()),
    })
}

/// Maximum item-tree nesting depth `parse_items` will build. Bounds the recursion of the
/// (otherwise unbounded) comparison/normalization on adversarial input. See `open` below.
const MAX_PARSE_DEPTH: usize = 256;

/// Tokenize a version into the root item list, mirroring `ComparableVersion.parseVersion`.
fn parse_items(version: &str) -> Vec<Item> {
    let version = version.to_ascii_lowercase();
    let bytes = version.as_bytes();
    // `current` is the in-progress list; `stack` holds its ancestors. Opening a sub-list pushes
    // `current` onto `stack` and starts a fresh `current`; the sub-list is re-attached as its
    // parent's last child during the bottom-up assembly.
    let mut current: Vec<Item> = Vec::new();
    let mut stack: Vec<Vec<Item>> = Vec::new();
    // Open a sub-list: the old `current` becomes a parent on the stack. A `-` separator (and
    // each digit/letter boundary) opens a level, so a pathological version like `1-1-1-...`
    // would otherwise nest one level per separator and make the *recursive* compare/normalize
    // (`cmp_item` -> `cmp_lists` -> `cmp_item`, `normalize` -> `cmp_item`) overflow the stack —
    // a DoS reachable from a hostile `pom.xml`/`gradle.lockfile` version or a poisoned OSV
    // mirror bound. We cap nesting depth: beyond the cap, further separators stay flat in the
    // current list. Real Maven versions nest a handful of levels; `MAX_DEPTH` is orders of
    // magnitude beyond anything legitimate, so correctness for real input is unchanged.
    let open = |cur: &mut Vec<Item>, stack: &mut Vec<Vec<Item>>| {
        if stack.len() < MAX_PARSE_DEPTH {
            stack.push(std::mem::take(cur));
        }
    };
    let separated = |is_digit: bool, version: &str, start: usize, i: usize| {
        if i == start {
            Item::Int("0".to_string())
        } else if is_digit {
            int_item(&version[start..i])
        } else {
            string_item(&version[start..i], false)
        }
    };
    let mut is_digit = false;
    let mut start = 0;

    for i in 0..bytes.len() {
        let c = bytes[i] as char;
        if c == '.' {
            current.push(separated(is_digit, &version, start, i));
            start = i + 1;
        } else if c == '-' {
            current.push(separated(is_digit, &version, start, i));
            start = i + 1;
            open(&mut current, &mut stack); // open a sub-list
        } else if c.is_ascii_digit() {
            if !is_digit && i > start {
                // letter → digit boundary: the letter run is a qualifier *followed by a digit*.
                // Maven 3.9 treats `.X` as `-X` for a string qualifier X: open a sub-list
                // before it when the current list is non-empty (MNG: `1.0.0.X1 < 1.0.0-X2`).
                if !current.is_empty() {
                    open(&mut current, &mut stack);
                }
                current.push(string_item(&version[start..i], true));
                start = i;
                open(&mut current, &mut stack);
            }
            is_digit = true;
        } else {
            if is_digit && i > start {
                // digit → letter boundary: the digit run is an integer item.
                current.push(int_item(&version[start..i]));
                start = i;
                open(&mut current, &mut stack);
            }
            is_digit = false;
        }
    }
    if version.len() > start {
        // A trailing string qualifier is likewise treated as `-X` (open a sub-list first).
        if !is_digit && !current.is_empty() {
            open(&mut current, &mut stack);
        }
        let item = if is_digit {
            int_item(&version[start..])
        } else {
            string_item(&version[start..], false)
        };
        current.push(item);
    }

    // Assemble bottom-up, normalizing each list (inner lists first, as Java does).
    normalize(&mut current);
    while let Some(mut parent) = stack.pop() {
        parent.push(Item::List(current));
        normalize(&mut parent);
        current = parent;
    }
    current
}

/// An integer item with leading zeros stripped (`"0"` for an all-zero run).
fn int_item(s: &str) -> Item {
    let stripped = s.trim_start_matches('0');
    Item::Int(if stripped.is_empty() {
        "0".to_string()
    } else {
        stripped.to_string()
    })
}

/// A string qualifier item, applying Maven's single-letter and alias normalizations.
fn string_item(value: &str, followed_by_digit: bool) -> Item {
    let mut v = value.to_string();
    if followed_by_digit && v.len() == 1 {
        v = match v.as_str() {
            "a" => "alpha",
            "b" => "beta",
            "m" => "milestone",
            other => other,
        }
        .to_string();
    }
    let v = match v.as_str() {
        "ga" | "final" | "release" => "",
        "cr" => "rc",
        other => other,
    };
    Item::Str(v.to_string())
}

/// Remove trailing "null"-equivalent items (`ComparableVersion.ListItem.normalize`).
fn normalize(list: &mut Vec<Item>) {
    let mut i = list.len();
    while i > 0 {
        i -= 1;
        if cmp_item(&list[i], None) == Ordering::Equal {
            list.remove(i);
        } else if !matches!(list[i], Item::List(_)) {
            break;
        }
    }
}

/// The comparable qualifier string: a known qualifier's index, else `"7-<qualifier>"` (sorts
/// after every known qualifier, and lexically among unknowns).
fn comparable_qualifier(q: &str) -> String {
    match QUALIFIERS.iter().position(|&x| x == q) {
        Some(idx) => idx.to_string(),
        None => format!("{}-{}", QUALIFIERS.len(), q),
    }
}

/// Compare two integer digit-strings as arbitrary-precision integers.
fn cmp_int(a: &str, b: &str) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Compare item `a` against item `b` (or against "null" when `b` is `None`), per
/// `ComparableVersion`'s per-type rules.
fn cmp_item(a: &Item, b: Option<&Item>) -> Ordering {
    match a {
        Item::Int(av) => match b {
            None => {
                if av == "0" {
                    Ordering::Equal
                } else {
                    Ordering::Greater
                }
            }
            Some(Item::Int(bv)) => cmp_int(av, bv),
            Some(Item::Str(_)) | Some(Item::List(_)) => Ordering::Greater,
        },
        Item::Str(av) => match b {
            None => comparable_qualifier(av).as_str().cmp(RELEASE_INDEX),
            Some(Item::Int(_)) | Some(Item::List(_)) => Ordering::Less,
            Some(Item::Str(bv)) => comparable_qualifier(av).cmp(&comparable_qualifier(bv)),
        },
        Item::List(al) => match b {
            // Compare the entire list against null (MNG-6964: not just the first item).
            None => {
                for item in al {
                    let r = cmp_item(item, None);
                    if r != Ordering::Equal {
                        return r;
                    }
                }
                Ordering::Equal
            }
            Some(Item::Int(_)) => Ordering::Less,
            Some(Item::Str(_)) => Ordering::Greater,
            Some(Item::List(bl)) => cmp_lists(al, bl),
        },
    }
}

/// Element-wise list comparison with null padding (the shorter side pads with "null").
fn cmp_lists(a: &[Item], b: &[Item]) -> Ordering {
    let n = a.len().max(b.len());
    for k in 0..n {
        let result = match (a.get(k), b.get(k)) {
            (None, None) => Ordering::Equal,
            // left is null: `-1 * right.compareTo(null)`.
            (None, Some(ri)) => cmp_item(ri, None).reverse(),
            (Some(li), r) => cmp_item(li, r),
        };
        if result != Ordering::Equal {
            return result;
        }
    }
    Ordering::Equal
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        cmp_lists(&self.items, &other.items) == Ordering::Equal
    }
}
impl Eq for Version {}
impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_lists(&self.items, &other.items)
    }
}
impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

/// Coerce a [`Version`] into the `semver::Version` the shared finding model stores.
/// **Detection never uses this** — the matcher compares true Maven versions — so it is only
/// the displayed/remediation form. Best-effort: the leading numeric run becomes
/// `major.minor.patch` and the rest a sanitized SemVer pre-release; Maven's richer ordering is
/// not fully expressible in SemVer, but this never changes a detection verdict.
pub fn to_semver(v: &Version) -> SemverVersion {
    if let Ok(sv) = SemverVersion::parse(&v.raw) {
        return sv;
    }
    // Split the raw version into dot/dash-separated tokens; take the leading integer tokens.
    let mut nums: Vec<u64> = Vec::new();
    let mut tail: Vec<String> = Vec::new();
    let mut in_tail = false;
    for tok in v.raw.split(['.', '-', '_', '+']) {
        if !in_tail {
            if let Ok(n) = tok.parse::<u64>() {
                nums.push(n);
                continue;
            }
            in_tail = true;
        }
        let s = sanitize(tok);
        if !s.is_empty() {
            tail.push(s);
        }
    }
    let mut sv = SemverVersion::new(
        nums.first().copied().unwrap_or(0),
        nums.get(1).copied().unwrap_or(0),
        nums.get(2).copied().unwrap_or(0),
    );
    for extra in nums.iter().skip(3) {
        tail.insert(0, extra.to_string());
    }
    if !tail.is_empty() {
        if let Ok(p) = Prerelease::new(&tail.join(".")) {
            sv.pre = p;
        }
    }
    sv
}

fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_dash = false;
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

/// Gradle's version order (`DefaultVersionComparator`), which Gradle uses for ranges, prefix
/// versions and conflict resolution. Unlike Maven's, an extra numeric part makes a version
/// higher (`3.0.0-M5` is above `3`, so outside `[2.2,3)`), a number beats a word, and only
/// `dev` (lowest) and `rc`, `snapshot`, `final`, `ga`, `release`, `sp` (highest, in that
/// order) have special places; other words compare as strings, case kept.
#[must_use]
pub fn gradle_cmp(a: &str, b: &str) -> Ordering {
    let (pa, pb) = (gradle_parts(a), gradle_parts(b));
    for (x, y) in pa.iter().zip(&pb) {
        if x == y {
            continue;
        }
        let (nx, ny) = (numeric(x), numeric(y));
        match (nx, ny) {
            (Some(nx), Some(ny)) => match cmp_digits(nx, ny) {
                Ordering::Equal => continue,
                o => return o,
            },
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (None, None) => {}
        }
        let (sx, sy) = (special(x), special(y));
        return match (sx, sy) {
            (Some(sx), _) => sx.cmp(&sy.unwrap_or(0)),
            (None, Some(sy)) => 0.cmp(&sy),
            (None, None) => x.cmp(y),
        };
    }
    match pa.len().cmp(&pb.len()) {
        Ordering::Equal => Ordering::Equal,
        Ordering::Greater => {
            if numeric(pa[pb.len()]).is_some() {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        }
        Ordering::Less => {
            if numeric(pb[pa.len()]).is_some() {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }
    }
}

/// Gradle's `VersionParser`: parts split at `.`, `-`, `_`, `+` and where digits meet letters;
/// a trailing separator adds no part.
fn gradle_parts(v: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut prev_digit: Option<bool> = None;
    for (i, c) in v.char_indices() {
        // A separator always ends a part, an empty one too (`1..0` is 1, "", 0).
        if matches!(c, '.' | '-' | '_' | '+') {
            parts.push(&v[start..i]);
            start = i + c.len_utf8();
            prev_digit = None;
            continue;
        }
        let digit = c.is_ascii_digit();
        if start < i && prev_digit.is_some_and(|p| p != digit) {
            parts.push(&v[start..i]);
            start = i;
        }
        prev_digit = Some(digit);
    }
    if start < v.len() {
        parts.push(&v[start..]);
    }
    parts
}

/// A part of digits only, without its leading zeros.
fn numeric(part: &str) -> Option<&str> {
    (!part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        .then(|| part.trim_start_matches('0'))
}

fn cmp_digits(a: &str, b: &str) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// The special words' places: `dev` below every word, the rest above.
fn special(part: &str) -> Option<i8> {
    match part.to_ascii_lowercase().as_str() {
        "dev" => Some(-1),
        "rc" => Some(1),
        "snapshot" => Some(2),
        "final" => Some(3),
        "ga" => Some(4),
        "release" => Some(5),
        "sp" => Some(6),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn v(s: &str) -> Version {
        parse_maven_version(s).unwrap()
    }

    #[test]
    fn gradle_order_matches_gradles_comparator() {
        // Each row as Gradle 8.14.3's DefaultVersionComparator orders it (the differential
        // oracle agreed on all of 306,536 pairs).
        let rows: &[(&str, &str, i8)] = &[
            ("3.0.0-M5", "3", 1),
            ("3.0.0-M5", "3.0.0", -1),
            ("1.0", "1.0.0", -1),
            ("1.0", "1..0", 1),
            ("1.0-dev", "1.0-ALPHA", -1),
            ("1.0-zeta", "1.0-rc", -1),
            ("1.0-rc", "1.0-snapshot", -1),
            ("1.0-ga", "1.0-final", 1),
            ("1.0-ga", "1.0-release", -1),
            ("1.0-ga", "1.0", -1),
            ("1.0-sp", "1.0", -1),
            ("1.0-ga", "1.0.RELEASE", -1),
            ("1.0-RC1", "1.0-rc", 0),
            ("1.0-SNAPSHOT", "1.0-snapshot", 0),
            ("1.0.Final", "1.0-final", 0),
            ("2.0.0-RC2", "2.0.0-rc2", 0),
            ("1.a", "1.1", -1),
            ("1_0", "1.0", 0),
            ("1.0a1", "1.0.a", 1),
            ("1.01", "1.001", 0),
            ("01", "1", 0),
            ("1.0-alpha10", "1.0-alpha2", 1),
        ];
        for (a, b, want) in rows {
            let want = match want {
                -1 => Ordering::Less,
                0 => Ordering::Equal,
                _ => Ordering::Greater,
            };
            assert_eq!(gradle_cmp(a, b), want, "{a} vs {b}");
            assert_eq!(gradle_cmp(b, a), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn trailing_nulls_insignificant() {
        assert_eq!(v("1"), v("1.0"));
        assert_eq!(v("1.0"), v("1.0.0"));
        assert!(v("1.0") < v("1.0.1"));
        assert!(v("1.0.1") < v("1.1"));
    }

    #[test]
    fn qualifier_ordering() {
        assert!(v("1.0-alpha-1") < v("1.0"));
        assert!(v("1.0-rc") < v("1.0"));
        assert!(v("1.0-milestone-1") < v("1.0-rc-1"));
        assert!(v("1.0-alpha-1") < v("1.0-beta-1"));
        assert!(v("1.0") < v("1.0-sp")); // sp sorts ABOVE release
        assert!(v("1.0-rc-1") < v("1.0-rc-2"));
    }

    #[test]
    fn release_aliases_equal_release() {
        assert_eq!(v("1.0-ga"), v("1.0"));
        assert_eq!(v("1.0-final"), v("1.0"));
        assert_eq!(v("3.0.0.RELEASE"), v("3.0.0"));
        assert_eq!(v("1.0-cr-1"), v("1.0-rc-1")); // cr aliases rc
    }

    #[test]
    fn single_letter_aliases() {
        assert_eq!(v("1.0a1"), v("1.0-alpha-1"));
        assert_eq!(v("1.0b1"), v("1.0-beta-1"));
        assert_eq!(v("1.0m1"), v("1.0-milestone-1"));
    }

    #[test]
    fn jenkins_build_numbers_compare_numerically() {
        assert!(v("2646.v6ed3b5b01ff1") < v("2656.vf7a"));
        assert!(v("2.387.1") < v("2.394"));
        // Arbitrary-precision: a longer integer is greater.
        assert!(v("99999999999999999999") < v("100000000000000000000"));
    }

    #[test]
    fn int_outranks_qualifier() {
        assert!(v("1.0.1") > v("1.0-rc")); // 1.0.1 has an int where 1.0-rc has a qualifier
    }

    #[test]
    fn to_semver_best_effort() {
        assert_eq!(to_semver(&v("1.2.3")).to_string(), "1.2.3");
        assert!(to_semver(&v("1.0-rc-1")) < to_semver(&v("1.0.0")));
    }

    #[test]
    fn deeply_nested_version_does_not_overflow_the_stack() {
        // A pathological version (one `-` per separator) used to nest one item-list level per
        // separator, so the recursive compare/normalize overflowed the stack. The depth cap
        // keeps this bounded: parsing and comparing must complete without aborting. We go well
        // past MAX_PARSE_DEPTH to prove the cap, not the raw recursion limit, is what saves us.
        let huge = "1".to_string() + &"-1".repeat(MAX_PARSE_DEPTH * 8);
        let a = v(&huge);
        let b = v(&huge);
        assert_eq!(a, b); // exercises normalize + cmp_lists to full depth
                          // Comparison against an ordinary version is total and panic-free.
        let _ = a.cmp(&v("1.0.0"));
    }
}
