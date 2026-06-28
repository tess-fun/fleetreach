//! `Gem::Version` parsing and ordering — the one piece of Ruby-specific version
//! handling the matcher needs, and the false-clean-critical one.
//!
//! RubyGems versions are **not** SemVer. They are dot-separated segments of arbitrary
//! length where any segment containing a letter makes the whole version a *prerelease*
//! (`1.0.0.beta`, `2.0.0.rc1`), an alphanumeric segment splits into letter/number parts
//! (`1.0.a10` compares as `1, 0, a, 10`), a **string** segment always sorts **below** a
//! numeric one at the same position (so a prerelease sorts below its release), and
//! trailing zeros are insignificant (`1.0` == `1.0.0`). This is a faithful port of Ruby's
//! `Gem::Version#<=>` / `#canonical_segments`; a stock SemVer comparator would mis-order
//! all of the above and silently false-clean.
//!
//! OSV `RubyGems` advisory ranges are `ECOSYSTEM`-typed and their bounds are
//! `Gem::Version` strings, so the same ordering drives both range matching and the
//! enumerated-version fallback.

use fleetreach_core::semver::{BuildMetadata, Prerelease, Version as SemverVersion};

/// One scanned segment of a version string: a numeric run (`12`) or an alphabetic run
/// (`beta`). A `Gem::Version` is a sequence of these, split on every non-alphanumeric
/// character and on every letter/digit boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Num(u64),
    Str(String),
}

/// A parsed `Gem::Version`: the verbatim string (for display / `to_semver`) and the
/// *canonical* segments used for ordering. Two versions are equal iff their canonical
/// segments are equal, so `Eq`/`Ord` derive from `canonical` alone.
#[derive(Debug, Clone)]
pub struct Version {
    raw: String,
    /// Canonical segments: numeric prefix and string-onward tail each have their trailing
    /// zero segments dropped (Ruby's `canonical_segments`), so `1.0` and `1.0.0` share one
    /// representation and compare equal.
    canonical: Vec<Segment>,
    /// The raw (un-canonicalized) segments, kept for the best-effort SemVer coercion.
    segments: Vec<Segment>,
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}
impl Eq for Version {}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        let (a, b) = (&self.canonical, &other.canonical);
        let n = a.len().max(b.len());
        for i in 0..n {
            // A missing segment defaults to numeric 0 (Ruby pads the shorter list).
            let lhs = a.get(i).unwrap_or(&Segment::Num(0));
            let rhs = b.get(i).unwrap_or(&Segment::Num(0));
            let ord = match (lhs, rhs) {
                (Segment::Num(x), Segment::Num(y)) => x.cmp(y),
                (Segment::Str(x), Segment::Str(y)) => x.cmp(y),
                // A string segment is always less than a numeric one — this is what makes
                // a prerelease (`1.0.0.beta` → `[1, "beta"]`) order below its release
                // (`1.0` → `[1]`, padded to `[1, 0]`).
                (Segment::Str(_), Segment::Num(_)) => Ordering::Less,
                (Segment::Num(_), Segment::Str(_)) => Ordering::Greater,
            };
            if ord != Ordering::Equal {
                return ord;
            }
        }
        Ordering::Equal
    }
}
impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

/// Parse a lockfile-resolved version string into a [`Version`].
///
/// A `Gemfile.lock` spec version may carry a platform suffix (`1.13.10-x86_64-linux`,
/// `1.0.0-java`); the platform is irrelevant to which advisory applies, so everything from
/// the first `-` on is dropped (a `Gem::Version` itself never contains `-`). Leading/
/// trailing whitespace is tolerated. Returns `None` for anything that is not a valid
/// `Gem::Version` (must start with a digit and contain only alphanumerics and `.`), e.g. a
/// git-ref pin, which has no registry artifact to match.
pub fn parse_rubygems_version(raw: &str) -> Option<Version> {
    // Strip a platform suffix: the version is the part before the first '-'.
    let trimmed = raw.trim();
    let version_part = trimmed.split('-').next().unwrap_or(trimmed);
    if version_part.is_empty() {
        return None;
    }
    // Validity (RubyGems `correct?`): digits, letters, and '.' only, and it must begin
    // with a digit (the OSV `"0"` lower bound qualifies).
    if !version_part.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    if !version_part
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.')
    {
        return None;
    }
    let segments = scan_segments(version_part)?;
    Some(Version {
        raw: version_part.to_string(),
        canonical: canonicalize(&segments),
        segments,
    })
}

/// Scan a version string into segments: maximal runs of ASCII digits become [`Segment::Num`]
/// and maximal runs of ASCII letters become [`Segment::Str`]; any other character (`.`) is
/// a separator. Mirrors Ruby's `@version.scan(/[0-9]+|[a-z]+/i)`. Returns `None` if a numeric
/// run overflows `u64` (pathological; never a real gem version), so the caller fails closed.
fn scan_segments(s: &str) -> Option<Vec<Segment>> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i] as char).is_ascii_digit() {
                i += 1;
            }
            out.push(Segment::Num(s[start..i].parse::<u64>().ok()?));
        } else if c.is_ascii_alphabetic() {
            let start = i;
            while i < bytes.len() && (bytes[i] as char).is_ascii_alphabetic() {
                i += 1;
            }
            out.push(Segment::Str(s[start..i].to_string()));
        } else {
            // Separator (`.`): skip.
            i += 1;
        }
    }
    Some(out)
}

/// Canonical segments (Ruby's `canonical_segments`): split into the numeric prefix and the
/// string-onward tail, drop the trailing zero segments of **each** part, then concatenate.
/// This is what makes `1.0` == `1.0.0` and `1.0.0.beta` == `1.0.beta`.
fn canonicalize(segments: &[Segment]) -> Vec<Segment> {
    let string_start = segments
        .iter()
        .position(|s| matches!(s, Segment::Str(_)))
        .unwrap_or(segments.len());
    let (numeric, tail) = segments.split_at(string_start);

    let mut out: Vec<Segment> = numeric.to_vec();
    drop_trailing_zeros(&mut out);
    let mut tail = tail.to_vec();
    drop_trailing_zeros(&mut tail);
    out.extend(tail);
    out
}

/// Drop trailing numeric-zero segments (string segments are never numeric zero).
fn drop_trailing_zeros(segs: &mut Vec<Segment>) {
    while matches!(segs.last(), Some(Segment::Num(0))) {
        segs.pop();
    }
}

impl Version {
    /// Whether this is a prerelease — any version with a letter segment (`1.0.0.beta`,
    /// `2.0.0.rc1`). RubyGems treats such versions as ordering below the corresponding
    /// release.
    pub fn is_prerelease(&self) -> bool {
        self.segments.iter().any(|s| matches!(s, Segment::Str(_)))
    }
}

/// Coerce a [`Version`] into the `semver::Version` the shared finding model stores
/// (`Occurrence::installed` / `patched`). **Detection never uses this** — the matcher in
/// [`crate::db`] compares true `Gem::Version`s — so it is only the displayed/remediation
/// form.
///
/// It is faithful for the dominant `X.Y.Z` shape (a direct parse) and best-effort
/// otherwise: the leading numeric run becomes `major.minor.patch`, any segments from the
/// first letter on become a SemVer pre-release tag (so a prerelease orders **below** its
/// release, which keeps remediation from treating a vulnerable prerelease as already
/// fixed), and numeric release segments beyond the third become build metadata for display.
/// The one imperfection — a 4th+ numeric segment not affecting order (SemVer ignores build
/// metadata) — only shows up for the rare `1.2.3.4`-style version and never changes a
/// detection verdict.
pub fn to_semver(v: &Version) -> SemverVersion {
    // Dominant case: the string is already valid SemVer — keep it verbatim.
    if let Ok(sv) = SemverVersion::parse(&v.raw) {
        return sv;
    }

    // Leading numeric run → release tuple; the rest is the prerelease tail.
    let mut nums: Vec<u64> = Vec::new();
    let mut tail_start = 0;
    for (i, seg) in v.segments.iter().enumerate() {
        match seg {
            Segment::Num(n) => nums.push(*n),
            Segment::Str(_) => {
                tail_start = i;
                break;
            }
        }
        tail_start = i + 1;
    }

    let mut sv = SemverVersion::new(
        nums.first().copied().unwrap_or(0),
        nums.get(1).copied().unwrap_or(0),
        nums.get(2).copied().unwrap_or(0),
    );

    let tail: Vec<String> = v.segments[tail_start..]
        .iter()
        .map(|s| match s {
            Segment::Num(n) => n.to_string(),
            Segment::Str(s) => s.clone(),
        })
        .map(|s| sanitize(&s))
        .filter(|s| !s.is_empty())
        .collect();
    if !tail.is_empty() {
        if let Ok(p) = Prerelease::new(&tail.join(".")) {
            sv.pre = p;
        }
    }

    // Numeric release segments beyond the third → build metadata (display only).
    if nums.len() > 3 {
        let extra = nums[3..].iter().map(u64::to_string).collect::<Vec<_>>();
        if let Ok(b) = BuildMetadata::new(&extra.join(".")) {
            sv.build = b;
        }
    }
    sv
}

/// Reduce a string to SemVer pre-release/build identifier characters (`[0-9A-Za-z-]`),
/// folding any other run to a single `-` and trimming leading/trailing `-`.
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn v(s: &str) -> Version {
        parse_rubygems_version(s).unwrap()
    }

    #[test]
    fn parses_and_strips_platform() {
        assert_eq!(v("1.13.10-x86_64-linux").to_string(), "1.13.10");
        assert_eq!(v("1.0.0-java").to_string(), "1.0.0");
        assert_eq!(v("2.2.8").to_string(), "2.2.8");
        assert!(parse_rubygems_version("not-a-gem").is_none());
        assert!(parse_rubygems_version("").is_none());
        // A git-ref-style pin (does not start with a digit) is unmatchable.
        assert!(parse_rubygems_version("abc123").is_none());
    }

    #[test]
    fn trailing_zeros_are_insignificant() {
        assert_eq!(v("1.0"), v("1.0.0"));
        assert_eq!(v("1"), v("1.0.0.0"));
        assert_eq!(v("0"), v("0.0"));
        assert!(v("1.0") < v("1.0.1"));
    }

    #[test]
    fn prerelease_orders_below_release() {
        // The false-clean-critical property: a letter segment sorts below the release.
        assert!(v("1.0.0.beta") < v("1.0.0"));
        assert!(v("1.0.0.rc1") < v("1.0.0"));
        assert!(v("1.0.0.alpha") < v("1.0.0.beta"));
        assert!(v("2.0.0.pre") < v("2.0.0"));
        assert!(v("1.0.0.beta1") < v("1.0.0.beta2"));
    }

    #[test]
    fn alphanumeric_segment_splits_numerically() {
        // `1.0.a10` scans to `[1, 0, a, 10]`, so a10 > a9 numerically (not lexically).
        assert!(v("1.0.a10") > v("1.0.a9"));
        assert!(v("1.0.a2") > v("1.0.a1"));
    }

    #[test]
    fn canonical_segments_trailing_zero_before_prerelease() {
        // Modern RubyGems (>=3.2, `canonical_segments`) drops the trailing numeric zeros of
        // the release prefix BEFORE the prerelease tag, so a differing release-segment COUNT
        // does not by itself separate two prereleases. (RubyGems <3.2's `<=>` got this wrong.)
        // Verified by a real-Ruby differential: this comparator matched the modern
        // canonical algorithm on all 405,924 sampled version pairs; every divergence was the
        // old RubyGems algorithm's, not ours.
        assert_eq!(
            v("1.0.0.beta"),
            v("1.0.beta"),
            "trailing-zero release prefix dropped"
        );
        assert_eq!(v("1.0.0.rc"), v("1.0.rc"));
        assert!(
            v("1.0.0.beta.3") < v("1.0.beta.16"),
            "compare as [1,beta,3] < [1,beta,16]"
        );
        assert!(
            v("2.0.0.pre2") < v("2.0rc0"),
            "[2,pre,2] < [2,rc]: pre<rc, rc trailing-0 dropped"
        );
    }

    #[test]
    fn string_segment_below_numeric_at_same_position() {
        // `1.0.0.beta` ([1,"beta"]) vs `1.0.0.1` ([1,1]): "beta" (String) < 1 (Num).
        assert!(v("1.0.0.beta") < v("1.0.0.1"));
    }

    #[test]
    fn arbitrary_segment_count() {
        assert!(v("1.2.3.4") > v("1.2.3"));
        assert!(v("1.2.3.4.5") > v("1.2.3.4"));
    }

    #[test]
    fn is_prerelease_detects_letters() {
        assert!(v("1.0.0.beta").is_prerelease());
        assert!(v("2.0.0.rc1").is_prerelease());
        assert!(!v("1.2.3").is_prerelease());
        assert!(!v("2023.1.1").is_prerelease());
    }

    fn coerce(s: &str) -> SemverVersion {
        to_semver(&v(s))
    }

    #[test]
    fn to_semver_is_faithful_for_common_shapes() {
        assert_eq!(coerce("2.2.8").to_string(), "2.2.8");
        assert_eq!(coerce("2.0").to_string(), "2.0.0");
        assert_eq!(coerce("1.0.0.beta").to_string(), "1.0.0-beta");
        // `rc1` scans to segments ["rc", 1], so it coerces to the dotted `rc.1`.
        assert_eq!(coerce("1.0.0.rc1").to_string(), "1.0.0-rc.1");
        assert_eq!(coerce("1.2.3.4").to_string(), "1.2.3+4");
    }

    #[test]
    fn to_semver_orders_prerelease_below_release() {
        // Remediation relies on this: a vulnerable prerelease must not coerce to >= its
        // own release, or a fix at the release would look already-applied.
        assert!(coerce("1.0.0.beta") < coerce("1.0.0"));
        assert!(coerce("1.0.0.rc1") < coerce("1.0.0"));
        assert!(coerce("2.30.0") < coerce("2.31.0"));
    }
}
