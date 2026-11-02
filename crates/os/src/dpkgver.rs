//! Debian package versions (`[epoch:]upstream[-revision]`) and their ordering, the one piece
//! of Debian-specific logic where a mistake is a false-clean.
//!
//! The ordering is dpkg's own (`lib/dpkg/version.c`): epochs compare numerically, then the
//! upstream version and the revision each compare with `verrevcmp`, which alternates between
//! a run of non-digits (compared character by character, with `~` sorting before everything,
//! even the end of the string, and letters before other punctuation) and a run of digits
//! (compared as numbers of any length). So `1.0~rc1 < 1.0 < 1.0+b1 < 1.0-1`, and
//! `2:1.0 > 1:9.9`. Parsing accepts exactly what `dpkg --compare-versions` accepts: dpkg
//! only warns about a version that does not start with a digit or holds unusual characters,
//! so those parse too. Validated against `dpkg --compare-versions` (see the crate docs).

use std::cmp::Ordering;

/// A parsed Debian version. Equality and ordering follow dpkg, so `1.0` and `1.00` (and
/// `0:1.0`) are equal although their strings differ; [`raw`](DebVersion::raw) keeps the
/// string as written.
#[derive(Debug, Clone)]
pub struct DebVersion {
    raw: String,
    epoch: u32,
    upstream: String,
    revision: String,
}

impl DebVersion {
    /// Parse a version as dpkg does. `None` for what dpkg rejects outright: an empty
    /// string, embedded whitespace, a non-numeric or out-of-range epoch, nothing after the
    /// epoch's colon, or an empty revision after the last hyphen.
    pub fn parse(s: &str) -> Option<DebVersion> {
        let raw = s.trim();
        if raw.is_empty() || raw.chars().any(char::is_whitespace) {
            return None;
        }
        let (epoch, rest) = match raw.split_once(':') {
            Some((e, rest)) => {
                if e.is_empty() || !e.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let epoch: u32 = e.parse().ok()?;
                if epoch > i32::MAX as u32 || rest.is_empty() {
                    return None;
                }
                (epoch, rest)
            }
            None => (0, raw),
        };
        let (upstream, revision) = match rest.rsplit_once('-') {
            Some((_, "")) => return None,
            Some((u, r)) => (u, r),
            None => (rest, ""),
        };
        if upstream.is_empty() {
            return None;
        }
        Some(DebVersion {
            raw: raw.to_string(),
            epoch,
            upstream: upstream.to_string(),
            revision: revision.to_string(),
        })
    }

    /// The version as written.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The epoch (`0` when absent).
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The upstream part, between the epoch and the last hyphen.
    pub fn upstream(&self) -> &str {
        &self.upstream
    }

    /// The Debian revision after the last hyphen (empty for a native package).
    pub fn revision(&self) -> &str {
        &self.revision
    }
}

/// The weight of one character in a non-digit run: the end of the string and digits weigh
/// 0, `~` sorts before them, letters keep their code, everything else sorts after letters.
fn order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(b'~') => -1,
        Some(c) => i32::from(c) + 256,
    }
}

/// dpkg's `verrevcmp`: compare two upstream versions or two revisions.
fn verrevcmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0usize, 0usize);
    let at = |k: usize| a.get(k).copied();
    let bt = |k: usize| b.get(k).copied();
    while i < a.len() || j < b.len() {
        // A run of non-digits, character by character.
        while at(i).is_some_and(|c| !c.is_ascii_digit())
            || bt(j).is_some_and(|c| !c.is_ascii_digit())
        {
            let (ac, bc) = (order(at(i)), order(bt(j)));
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        // A run of digits, as a number of any length: skip leading zeros, then the longer
        // run wins, and equal lengths compare by their first differing digit.
        while at(i) == Some(b'0') {
            i += 1;
        }
        while bt(j) == Some(b'0') {
            j += 1;
        }
        let mut first_diff = Ordering::Equal;
        while at(i).is_some_and(|c| c.is_ascii_digit()) && bt(j).is_some_and(|c| c.is_ascii_digit())
        {
            if first_diff == Ordering::Equal {
                first_diff = at(i).cmp(&bt(j));
            }
            i += 1;
            j += 1;
        }
        if at(i).is_some_and(|c| c.is_ascii_digit()) {
            return Ordering::Greater;
        }
        if bt(j).is_some_and(|c| c.is_ascii_digit()) {
            return Ordering::Less;
        }
        if first_diff != Ordering::Equal {
            return first_diff;
        }
    }
    Ordering::Equal
}

impl Ord for DebVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| verrevcmp(&self.upstream, &other.upstream))
            .then_with(|| verrevcmp(&self.revision, &other.revision))
    }
}

impl PartialOrd for DebVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for DebVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for DebVersion {}

impl std::fmt::Display for DebVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn cmp(a: &str, b: &str) -> Ordering {
        DebVersion::parse(a)
            .unwrap()
            .cmp(&DebVersion::parse(b).unwrap())
    }

    #[test]
    fn tilde_sorts_before_everything() {
        assert_eq!(cmp("1.0~rc1", "1.0"), Ordering::Less);
        assert_eq!(cmp("1.0~~", "1.0~"), Ordering::Less);
        assert_eq!(cmp("1.0~", "1.0"), Ordering::Less);
        assert_eq!(cmp("1.0", "1.0+b1"), Ordering::Less);
    }

    #[test]
    fn epoch_dominates_and_zero_epoch_is_none() {
        assert_eq!(cmp("1:0.1", "9.9"), Ordering::Greater);
        assert_eq!(cmp("0:1.0", "1.0"), Ordering::Equal);
        assert_eq!(cmp("2:1.0", "10:0.1"), Ordering::Less);
    }

    #[test]
    fn digits_compare_numerically_letters_before_punctuation() {
        assert_eq!(cmp("1.10", "1.9"), Ordering::Greater);
        assert_eq!(cmp("1.00", "1.0"), Ordering::Equal);
        assert_eq!(cmp("1.0a", "1.0+"), Ordering::Less);
        assert_eq!(cmp("1.0-1", "1.0-1.1"), Ordering::Less);
        assert_eq!(cmp("2.36.1-8+deb12u1", "2.36.1-8+deb12u2"), Ordering::Less);
        assert_eq!(
            cmp(
                "123456789012345678901234567890",
                "123456789012345678901234567891"
            ),
            Ordering::Less
        );
    }

    #[test]
    fn revision_split_at_last_hyphen() {
        let v = DebVersion::parse("1:2.0-rc-3").unwrap();
        assert_eq!((v.epoch(), v.upstream(), v.revision()), (1, "2.0-rc", "3"));
        assert_eq!(cmp("1.0", "1.0-0"), Ordering::Equal);
    }

    #[test]
    fn rejects_what_dpkg_rejects() {
        for bad in [
            "",
            " ",
            "1 0",
            "a:1.0",
            ":1.0",
            "1:",
            "1.0-",
            "-1",
            "99999999999:1",
        ] {
            assert!(DebVersion::parse(bad).is_none(), "{bad:?}");
        }
        // dpkg only warns about these, so they still compare.
        assert!(DebVersion::parse("a1.0").is_some());
        assert!(DebVersion::parse("1.0_x").is_some());
    }
}
