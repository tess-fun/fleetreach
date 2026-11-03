//! rpm's version ordering: `[epoch:]version[-release]`, each part compared with
//! `rpmvercmp` (rpm's `rpmio/rpmvercmp.c`), validated against rpm itself (see
//! `tests/comparator_golden.rs`).
//!
//! `rpmvercmp` splits a string into runs of ASCII digits and runs of ASCII letters; anything
//! else only separates runs. Numeric runs compare as numbers (leading zeros dropped) and beat
//! letter runs; `~` sorts before everything, even the end of the string (`1.0~rc1 < 1.0`);
//! `^` sorts after the end of the string but before anything else (`1.0 < 1.0^git1 < 1.0.1`).
//!
//! A missing epoch is 0, as rpm treats it. A missing release sorts below any release, rpm's
//! rule for comparing two full EVRs.

use std::cmp::Ordering;
use std::fmt;

/// A parsed rpm `[epoch:]version[-release]`.
#[derive(Debug, Clone)]
pub struct RpmVersion {
    epoch: u64,
    /// Whether the epoch was written (only for display: `0:1.0-1` round-trips).
    epoch_written: bool,
    version: String,
    release: Option<String>,
}

impl RpmVersion {
    /// Parse `[epoch:]version[-release]`. `None` for an empty version or an epoch that is
    /// not a number.
    pub fn parse(s: &str) -> Option<RpmVersion> {
        let s = s.trim();
        let (epoch, epoch_written, rest) = match s.split_once(':') {
            Some((e, rest)) => {
                let e = if e.is_empty() {
                    0
                } else {
                    e.parse::<u64>().ok()?
                };
                (e, true, rest)
            }
            None => (0, false, s),
        };
        let (version, release) = match rest.rsplit_once('-') {
            Some((v, r)) => (v, Some(r.to_string())),
            None => (rest, None),
        };
        if version.is_empty() || release.as_deref() == Some("") {
            return None;
        }
        Some(RpmVersion {
            epoch,
            epoch_written,
            version: version.to_string(),
            release,
        })
    }

    /// The epoch (0 when none was written).
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl fmt::Display for RpmVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.epoch_written {
            write!(f, "{}:", self.epoch)?;
        }
        f.write_str(&self.version)?;
        if let Some(r) = &self.release {
            write!(f, "-{r}")?;
        }
        Ok(())
    }
}

impl Ord for RpmVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| rpmvercmp(&self.version, &other.version))
            .then_with(|| match (&self.release, &other.release) {
                (Some(a), Some(b)) => rpmvercmp(a, b),
                (a, b) => a.is_some().cmp(&b.is_some()),
            })
    }
}

impl PartialOrd for RpmVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Equal in rpm's order (`1.0` and `1_0` are equal), not as strings.
impl PartialEq for RpmVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for RpmVersion {}

/// rpm's `rpmvercmp` on one version or release string.
pub fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    let sep = |c: u8| !c.is_ascii_alphanumeric() && c != b'~' && c != b'^';
    while i < a.len() || j < b.len() {
        while i < a.len() && sep(a[i]) {
            i += 1;
        }
        while j < b.len() && sep(b[j]) {
            j += 1;
        }
        let (ca, cb) = (a.get(i).copied(), b.get(j).copied());
        if ca == Some(b'~') || cb == Some(b'~') {
            if ca != Some(b'~') {
                return Ordering::Greater;
            }
            if cb != Some(b'~') {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        if ca == Some(b'^') || cb == Some(b'^') {
            if ca.is_none() {
                return Ordering::Less;
            }
            if cb.is_none() {
                return Ordering::Greater;
            }
            if ca != Some(b'^') {
                return Ordering::Greater;
            }
            if cb != Some(b'^') {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        let (Some(ca), Some(_)) = (ca, cb) else {
            break;
        };
        let numeric = ca.is_ascii_digit();
        let run = |s: &[u8], from: usize| {
            let mut end = from;
            while end < s.len()
                && (if numeric {
                    s[end].is_ascii_digit()
                } else {
                    s[end].is_ascii_alphabetic()
                })
            {
                end += 1;
            }
            end
        };
        let (ea, eb) = (run(a, i), run(b, j));
        // `b` has a run of the other kind here: numbers beat letters.
        if eb == j {
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let (mut sa, mut sb) = (&a[i..ea], &b[j..eb]);
        if numeric {
            while sa.first() == Some(&b'0') {
                sa = &sa[1..];
            }
            while sb.first() == Some(&b'0') {
                sb = &sb[1..];
            }
            match sa.len().cmp(&sb.len()) {
                Ordering::Equal => {}
                longer => return longer,
            }
        }
        match sa.cmp(sb) {
            Ordering::Equal => {}
            other => return other,
        }
        i = ea;
        j = eb;
    }
    match (i >= a.len(), j >= b.len()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        _ => Ordering::Greater,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn cmp(a: &str, b: &str) -> Ordering {
        RpmVersion::parse(a)
            .unwrap()
            .cmp(&RpmVersion::parse(b).unwrap())
    }

    #[test]
    fn rpmvercmp_cases_from_rpm_tests() {
        // From rpm's own test suite (tests/rpmvercmp.at).
        use Ordering::*;
        for (a, b, want) in [
            ("1.0", "1.0", Equal),
            ("1.0", "2.0", Less),
            ("2.0.1", "2.0", Greater),
            ("2.0", "2.0.1", Less),
            ("5.5p1", "5.5p2", Less),
            ("5.5p10", "5.5p1", Greater),
            ("10xyz", "10.1xyz", Less),
            ("xyz10", "xyz10.1", Less),
            ("xyz.4", "8", Less),
            ("8", "xyz.4", Greater),
            ("5.5p1", "5.6p1", Less),
            ("6.0.rc1", "6.0", Greater),
            ("10b2", "10a1", Greater),
            ("1.0aa", "1.0a", Greater),
            ("10.0001", "10.1", Equal),
            ("10.0001", "10.0039", Less),
            ("4.999.9", "5.0", Less),
            ("20101121", "20101122", Less),
            ("2_0", "2_0", Equal),
            ("2.0", "2_0", Equal),
            ("a", "a", Equal),
            ("a+", "a_", Equal),
            ("+a", "_a", Equal),
            ("+", "_", Equal),
            ("1.0~rc1", "1.0", Less),
            ("1.0~rc1", "1.0~rc2", Less),
            ("1.0~rc1~git123", "1.0~rc1", Less),
            ("1.0^", "1.0", Greater),
            ("1.0^git1", "1.0", Greater),
            ("1.0^git1", "1.01", Less),
            ("1.0^20160101", "1.0.1", Less),
            ("1.0^20160101^git1", "1.0^20160101", Greater),
            ("1.0~rc1^git1", "1.0~rc1", Greater),
            ("1.0^git1~pre", "1.0^git1", Less),
        ] {
            assert_eq!(rpmvercmp(a, b), want, "{a} vs {b}");
            assert_eq!(rpmvercmp(b, a), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn epoch_and_release() {
        assert_eq!(cmp("1:1.0-1", "2.0-1"), Ordering::Greater);
        assert_eq!(
            cmp("0:1.0-1", "1.0-1"),
            Ordering::Equal,
            "no epoch is epoch 0"
        );
        assert_eq!(
            cmp("1.0", "1.0-1"),
            Ordering::Less,
            "no release sorts first"
        );
        assert_eq!(cmp("3.0.7-27.el9", "3.0.7-28.el9"), Ordering::Less);
        assert_eq!(
            cmp(
                "1:0.1.15-2.git2d0b8a3.module_el8.5.0+119+9a9ec082",
                "1:0.1.15-2.git2d0b8a3.module_el8.4.0+1"
            ),
            Ordering::Greater
        );
        assert_eq!(RpmVersion::parse("0:1.0-1").unwrap().to_string(), "0:1.0-1");
        assert_eq!(RpmVersion::parse("2.0").unwrap().to_string(), "2.0");
        assert!(RpmVersion::parse("x:1.0").is_none());
        assert!(RpmVersion::parse("1.0-").is_none());
        assert!(RpmVersion::parse("").is_none());
    }
}
