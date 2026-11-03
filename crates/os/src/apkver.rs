//! Alpine package versions and their ordering, as apk-tools 2.14 defines them
//! (`src/version.c`, the same in 2.14.4 on Alpine 3.20 and 2.14.12 on Wolfi). Alpine,
//! Wolfi, Chainguard, MinimOS, Alpaquita and CleanStart all use it.
//!
//! A version is Gentoo-shaped: `digits{.digits}[letter]{_suffix[digits]}[-r digits]`, read
//! as a stream of typed tokens that must appear in that order. Pre-release suffixes
//! (`_alpha`, `_beta`, `_pre`, `_rc`) sort below the release, post-release ones (`_cvs`,
//! `_svn`, `_git`, `_hg`, `_p`) above it, and a longer version is greater unless what it adds
//! is a pre-release suffix. Two quirks that a semver-like comparator gets wrong:
//!
//! - after a dot, a component with leading zeros compares as a fraction would: `1.05 <
//!   1.5` and `1.005 < 1.05`, and even `1.00 < 1.0`;
//! - the revision is its own token, so `1.0 < 1.0-r0`.
//!
//! Versions apk-tools would reject (`apk version -c`) do not parse, so they are never
//! compared; a digit run of 18 or more digits is one of them.

use std::cmp::Ordering;

/// Token types in the order a version must present them; the order matters, because the
/// comparison falls back to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Tok {
    Invalid,
    DigitOrZero,
    Digit,
    Letter,
    Suffix,
    SuffixNo,
    RevisionNo,
    End,
}

const PRE_SUFFIXES: [&[u8]; 4] = [b"alpha", b"beta", b"pre", b"rc"];
const POST_SUFFIXES: [&[u8]; 5] = [b"cvs", b"svn", b"git", b"hg", b"p"];

/// A cursor over one version string, yielding the token values apk-tools does.
struct Cursor<'a> {
    rest: &'a [u8],
    tok: Tok,
}

impl<'a> Cursor<'a> {
    fn new(s: &'a str) -> Self {
        Cursor {
            rest: s.as_bytes(),
            tok: Tok::Digit,
        }
    }

    /// Classify the separator at the cursor (consuming it) into the next token type.
    fn advance_type(&mut self) {
        let first = self.rest.first().copied();
        let mut next = Tok::Invalid;
        match first {
            None | Some(0) => next = Tok::End,
            Some(c)
                if matches!(self.tok, Tok::Digit | Tok::DigitOrZero) && c.is_ascii_lowercase() =>
            {
                next = Tok::Letter
            }
            Some(c) if self.tok == Tok::Letter && c.is_ascii_digit() => next = Tok::Digit,
            Some(c) if self.tok == Tok::Suffix && c.is_ascii_digit() => next = Tok::SuffixNo,
            Some(c) => {
                match c {
                    b'.' => next = Tok::DigitOrZero,
                    b'_' => next = Tok::Suffix,
                    b'-' if self.rest.get(1) == Some(&b'r') => {
                        next = Tok::RevisionNo;
                        self.rest = self.rest.get(1..).unwrap_or_default();
                    }
                    _ => {}
                }
                self.rest = self.rest.get(1..).unwrap_or_default();
            }
        }
        // Tokens only move forward, with three allowed steps back: a dot after a digit run,
        // a suffix after a suffix number, and a digit after a letter.
        if next < self.tok
            && !matches!(
                (next, self.tok),
                (Tok::DigitOrZero, Tok::Digit)
                    | (Tok::Suffix, Tok::SuffixNo)
                    | (Tok::Digit, Tok::Letter)
            )
        {
            next = Tok::Invalid;
        }
        self.tok = next;
    }

    /// The value of the token at the cursor, moving past it.
    fn next_value(&mut self) -> i64 {
        if self.rest.is_empty() {
            self.tok = Tok::End;
            return 0;
        }
        let len: usize;
        let mut value: i64 = 0;
        let mut forced: Option<Tok> = None;
        let digits = |rest: &[u8], value: &mut i64| -> Option<usize> {
            let n = rest.iter().take_while(|c| c.is_ascii_digit()).count();
            if n >= 18 {
                return None;
            }
            for c in rest.get(..n).unwrap_or_default() {
                *value = *value * 10 + i64::from(c - b'0');
            }
            Some(n)
        };
        match self.tok {
            // After a dot, leading zeros count against the component: each zero beyond
            // the first lowers it by one, and the digits that follow are a new token.
            Tok::DigitOrZero if self.rest.first() == Some(&b'0') => {
                let extra = self.rest.iter().skip(1).take_while(|&&c| c == b'0').count();
                // A run of zeros keeps its last zero for the digit token that follows.
                let extra = extra.min(self.rest.len().saturating_sub(1));
                len = extra;
                value = -(extra as i64);
                forced = Some(Tok::Digit);
            }
            Tok::DigitOrZero | Tok::Digit | Tok::SuffixNo | Tok::RevisionNo => {
                match digits(self.rest, &mut value) {
                    Some(n) => len = n,
                    None => {
                        self.tok = Tok::Invalid;
                        return -1;
                    }
                }
            }
            Tok::Letter => {
                value = i64::from(self.rest.first().copied().unwrap_or_default());
                len = 1;
            }
            Tok::Suffix => {
                let starts = |s: &[u8]| self.rest.starts_with(s);
                if let Some(i) = PRE_SUFFIXES.iter().position(|s| starts(s)) {
                    len = PRE_SUFFIXES[i].len();
                    value = i as i64 - PRE_SUFFIXES.len() as i64;
                } else if let Some(i) = POST_SUFFIXES.iter().position(|s| starts(s)) {
                    len = POST_SUFFIXES[i].len();
                    value = i as i64;
                } else {
                    self.tok = Tok::Invalid;
                    return -1;
                }
            }
            Tok::Invalid | Tok::End => {
                self.tok = Tok::Invalid;
                return -1;
            }
        }
        self.rest = self.rest.get(len..).unwrap_or_default();
        if self.rest.is_empty() {
            self.tok = Tok::End;
        } else if let Some(t) = forced {
            self.tok = t;
        } else {
            self.advance_type();
        }
        value
    }
}

/// apk-tools' `apk_version_validate`.
fn valid(s: &str) -> bool {
    let mut c = Cursor::new(s);
    while !matches!(c.tok, Tok::End | Tok::Invalid) {
        c.next_value();
    }
    c.tok == Tok::End
}

/// apk-tools' `apk_version_compare` for two strings.
fn compare(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (Cursor::new(a), Cursor::new(b));
    let (mut av, mut bv) = (0i64, 0i64);
    while a.tok == b.tok && !matches!(a.tok, Tok::End | Tok::Invalid) && av == bv {
        av = a.next_value();
        bv = b.next_value();
    }
    if av != bv {
        return av.cmp(&bv);
    }
    if a.tok == b.tok {
        return Ordering::Equal;
    }
    // Equal so far: the longer version is greater, unless what it continues with is a
    // pre-release suffix (or an invalid one).
    let (at, bt) = (a.tok, b.tok);
    if at == Tok::Suffix && a.next_value() < 0 {
        return Ordering::Less;
    }
    if bt == Tok::Suffix && b.next_value() < 0 {
        return Ordering::Greater;
    }
    // A later token type in the stream means the other version went further.
    bt.cmp(&at)
}

/// A parsed apk version. Equality and ordering follow apk-tools, so distinct strings can be
/// equal; [`raw`](ApkVersion::raw) keeps the string as written.
#[derive(Debug, Clone)]
pub struct ApkVersion {
    raw: String,
}

impl ApkVersion {
    /// Parse a version; `None` when apk-tools would call it invalid.
    pub fn parse(s: &str) -> Option<ApkVersion> {
        let s = s.trim();
        (!s.is_empty() && valid(s)).then(|| ApkVersion { raw: s.to_string() })
    }

    /// The version as written.
    pub fn raw(&self) -> &str {
        &self.raw
    }
}

impl Ord for ApkVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        compare(&self.raw, &other.raw)
    }
}

impl PartialOrd for ApkVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ApkVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for ApkVersion {}

impl std::fmt::Display for ApkVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn cmp(a: &str, b: &str) -> Ordering {
        ApkVersion::parse(a)
            .unwrap()
            .cmp(&ApkVersion::parse(b).unwrap())
    }

    #[test]
    fn suffixes_and_revisions() {
        assert_eq!(cmp("1.0_rc1", "1.0"), Ordering::Less);
        assert_eq!(cmp("1.0_alpha", "1.0_beta"), Ordering::Less);
        assert_eq!(cmp("1.0_p1", "1.0"), Ordering::Greater);
        assert_eq!(cmp("1.0", "1.0-r0"), Ordering::Less);
        assert_eq!(cmp("1.0-r9", "1.0-r10"), Ordering::Less);
        assert_eq!(cmp("4.4.3_p1-r0", "4.4.3-r9"), Ordering::Greater);
    }

    #[test]
    fn leading_zeros_after_a_dot() {
        assert_eq!(cmp("1.05", "1.5"), Ordering::Less);
        assert_eq!(cmp("1.005", "1.05"), Ordering::Less);
        assert_eq!(cmp("1.00", "1.0"), Ordering::Less);
        assert_eq!(cmp("1.0", "1.0"), Ordering::Equal);
        assert_eq!(cmp("1.10", "1.9"), Ordering::Greater);
    }

    #[test]
    fn letters() {
        assert_eq!(cmp("1.0a", "1.0b"), Ordering::Less);
        assert_eq!(cmp("1.0a", "1.0"), Ordering::Greater);
        assert_eq!(cmp("1.0a", "1.0.1"), Ordering::Less);
    }

    #[test]
    fn validation() {
        for ok in [
            "0",
            "a1",
            "1..0",
            "1.0-r",
            "12345678901234567",
            "1.2.3-r0",
            "1.0_rc1_p2-r3",
            "2.36.1a_git20240101-r1",
        ] {
            assert!(ApkVersion::parse(ok).is_some(), "{ok}");
        }
        for bad in ["", "1.0-1", "1.0_foo", "1.0+x", "123456789012345678"] {
            assert!(ApkVersion::parse(bad).is_none(), "{bad:?}");
        }
    }
}
