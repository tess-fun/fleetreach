//! Composer version parsing and ordering — the one piece of PHP/Packagist-specific
//! version handling the matcher needs, and the false-clean-critical one.
//!
//! Packagist versions are **not** SemVer. Composer compares versions with PHP's
//! [`version_compare`](https://www.php.net/manual/en/function.version-compare.php)
//! semantics, which differ from SemVer in one load-bearing way: a stability modifier is
//! ordered
//!
//! ```text
//! dev  <  alpha (a)  <  beta (b)  <  RC (rc)  <  <stable>  <  patch (p, pl)
//! ```
//!
//! so `alpha`/`beta`/`RC` prereleases sort **below** their release (as in SemVer) but a
//! `patch` level (`2.4.5-p1`, used heavily by Magento) sorts **above** it — the opposite of
//! SemVer, where any `-suffix` is a prerelease below the release. A stock SemVer comparator
//! would mis-order every `-pN` version and silently false-clean a patched-but-still-affected
//! install (or false-positive a patched one). The modifier name is also matched
//! case-insensitively and with/without a separating `.` (`-RC1` == `-rc.1` == `-rc1`), and
//! trailing zero segments are insignificant (`1.0` == `1.0.0`).
//!
//! OSV `Packagist` advisory ranges are `ECOSYSTEM`-typed and their bounds are Composer
//! version strings, so the same ordering drives both range matching and the
//! enumerated-version fallback.

use fleetreach_core::semver::{BuildMetadata, Prerelease, Version as SemverVersion};

/// One token of a canonicalized version: a numeric run (`12`) or an alphabetic stability
/// word (`beta`). PHP's `version_compare` canonicalizes a version into a sequence of these,
/// splitting on every separator (`.`, `-`, `_`, `+`) and on every digit/letter boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Num(u64),
    Word(String),
}

/// A parsed Composer version: the verbatim string (for display / `to_semver`) and the
/// canonicalized tokens used for ordering. Equality is defined by the ordering (so `1.0`
/// equals `1.0.0`), used by the enumerated-version fallback.
#[derive(Debug, Clone)]
pub struct Version {
    raw: String,
    tokens: Vec<Token>,
}

/// The stability order of an alphabetic version word, following PHP `version_compare`'s
/// special-form table (`dev` lowest, `patch` above stable). A numeric token is order `0`
/// (the implied `#`/stable rank) when compared against a word. Unrecognized words (rare,
/// non-standard tags) default to `0` so they neither sink below a prerelease nor float
/// above stable.
fn word_order(w: &str) -> i32 {
    match w {
        "dev" => -6,
        "alpha" | "a" => -5,
        "beta" | "b" => -4,
        "rc" => -3,
        "stable" => 0,
        "patch" | "pl" | "p" => 1,
        _ => 0,
    }
}

impl Version {
    /// Compare element-wise, padding the shorter token list with numeric `0` (so trailing
    /// `.0` segments are insignificant and a missing segment ranks as stable). A
    /// numeric/word mismatch compares stability orders; two numbers compare numerically.
    fn compare(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        let (a, b) = (&self.tokens, &other.tokens);
        let n = a.len().max(b.len());
        for i in 0..n {
            let zero = Token::Num(0);
            let lhs = a.get(i).unwrap_or(&zero);
            let rhs = b.get(i).unwrap_or(&zero);
            let ord = match (lhs, rhs) {
                (Token::Num(x), Token::Num(y)) => x.cmp(y),
                // A number ranks as stable (`#`, order 0) against a stability word; the word
                // ranks by its own order. This is what makes `2.4.5` < `2.4.5-p1` (patch) but
                // `2.4.5` > `2.4.5-beta1` (prerelease).
                _ => order_of(lhs).cmp(&order_of(rhs)),
            };
            if ord != Ordering::Equal {
                return ord;
            }
        }
        Ordering::Equal
    }
}

/// The stability rank of a token: numeric tokens are `0` (stable), words use [`word_order`].
fn order_of(t: &Token) -> i32 {
    match t {
        Token::Num(_) => 0,
        Token::Word(w) => word_order(w),
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.compare(other) == std::cmp::Ordering::Equal
    }
}
impl Eq for Version {}
impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.compare(other)
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

/// Parse a Composer/lockfile version string into a [`Version`].
///
/// A leading `v`/`V` is stripped (Composer ignores it). The string must then begin with a
/// digit; anything else — notably a `dev-master`/`dev-<branch>` reference, which a
/// `composer.lock` records for a VCS pin — has no registry release to match against and
/// returns `None` (the same stance as the npm/RubyGems feeders' non-registry pins).
/// Returns `None` if a numeric run overflows `u64` (pathological; never a real version), so
/// the caller fails closed.
pub fn parse_composer_version(raw: &str) -> Option<Version> {
    let trimmed = raw.trim();
    let unprefixed = trimmed.strip_prefix(['v', 'V']).unwrap_or(trimmed);
    // Composer ignores SemVer build metadata (everything from the first `+`) when ordering,
    // so `6.0.0+ea2` == `6.0.0`. Drop it before tokenizing.
    let core = unprefixed.split('+').next().unwrap_or(unprefixed);
    if !core.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    // Composer normalizes the modifier case (`-RC1` == `-rc1`), so canonicalize lowercased.
    let mut tokens = tokenize(&core.to_ascii_lowercase())?;
    if tokens.is_empty() {
        return None;
    }
    // Composer normalizes the numeric core to four components (`X.Y.Z.W`) BEFORE the
    // stability tail, so a stability modifier always lines up against another modifier and
    // never against a bare numeric segment: `3.0-beta` and `3.0.0-alpha` must compare their
    // suffixes, not `beta` against `0`. Pad the leading numeric run to four with zeros (the
    // padding is insignificant for pure-numeric versions, since the comparison already pads
    // the shorter side with zero).
    let core_len = tokens
        .iter()
        .position(|t| matches!(t, Token::Word(_)))
        .unwrap_or(tokens.len());
    if core_len < 4 {
        tokens.splice(
            core_len..core_len,
            std::iter::repeat_n(Token::Num(0), 4 - core_len),
        );
    }
    Some(Version {
        // `raw` keeps the build metadata (display only); ordering uses `tokens`.
        raw: unprefixed.to_string(),
        tokens,
    })
}

/// Canonicalize a (lowercased) version string into tokens, mirroring PHP's
/// `version_compare` canonicalization: `.`/`-`/`_`/`+` are separators, and a digit/letter
/// boundary also splits, so `2.4.5-p1` and `2.4.5p1` both tokenize to `[2,4,5,"p",1]`.
/// Returns `None` if a numeric run overflows `u64`.
fn tokenize(s: &str) -> Option<Vec<Token>> {
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
            out.push(Token::Num(s[start..i].parse::<u64>().ok()?));
        } else if c.is_ascii_alphabetic() {
            let start = i;
            while i < bytes.len() && (bytes[i] as char).is_ascii_alphabetic() {
                i += 1;
            }
            out.push(Token::Word(s[start..i].to_string()));
        } else {
            // Separator (`.`, `-`, `_`, `+`): skip.
            i += 1;
        }
    }
    Some(out)
}

impl Version {
    /// Whether this is a prerelease — its first non-numeric stability word ranks below
    /// stable (`dev`/`alpha`/`beta`/`RC`). A `patch` (`-pN`) does **not** count, since it
    /// ranks above the release.
    pub fn is_prerelease(&self) -> bool {
        self.tokens
            .iter()
            .find_map(|t| match t {
                Token::Word(w) => Some(word_order(w) < 0),
                Token::Num(_) => None,
            })
            .unwrap_or(false)
    }

    /// The numeric release core (the leading run of numeric segments), with trailing zeros
    /// dropped so `1.2.0` and `1.2` share a representation. Two versions with the same core
    /// are the same release, differing only in a stability tail.
    fn release_core(&self) -> Vec<u64> {
        let mut core: Vec<u64> = self
            .tokens
            .iter()
            .take_while(|t| matches!(t, Token::Num(_)))
            .map(|t| match t {
                Token::Num(n) => *n,
                Token::Word(_) => 0,
            })
            .collect();
        while matches!(core.last(), Some(0)) {
            core.pop();
        }
        core
    }

    /// Whether `self` is at or after an OSV `introduced` lower bound, with **Composer**
    /// semantics: a bare `>=X` bound (X a stable release) is floored by Composer's constraint
    /// parser at `X-dev`, so it **includes the prereleases of X** (`8.7.0-rc1` satisfies
    /// `>=8.7.0`). A plain `>=` would order `8.7.0-rc1` below `8.7.0` and **false-clean** a
    /// prerelease pinned at the boundary — unlike PEP 440 / RubyGems, where a prerelease is
    /// excluded from `>=X`. So a prerelease of the exact (stable) introduced release counts
    /// as in range; everything else is the normal ordering. (A prerelease bound is used
    /// verbatim — Composer adds the `-dev` floor only to stable bounds.)
    pub fn at_or_after_introduced(&self, introduced: &Version) -> bool {
        self >= introduced
            || (!introduced.is_prerelease()
                && self.is_prerelease()
                && self.release_core() == introduced.release_core())
    }
}

/// Coerce a [`Version`] into the `semver::Version` the shared finding model stores
/// (`Occurrence::installed` / `patched`). **Detection never uses this** — the matcher in
/// [`crate::db`] compares true Composer versions — so it is only the displayed/remediation
/// form.
///
/// It is faithful for the dominant `X.Y.Z` shape (a direct parse, keeping a `-beta1`/`-p1`
/// tail verbatim) and best-effort otherwise: the leading numeric run becomes
/// `major.minor.patch`, any stability tail becomes a SemVer pre-release, and numeric release
/// segments beyond the third become build metadata for display.
///
/// One imperfection, documented: a `patch` level (`-pN`) ranks **above** its release in
/// Composer but renders as a SemVer pre-release (which ranks below). This only affects the
/// stored/remediation view, never a detection verdict (which uses the true comparator), and
/// in practice never changes a remediation target, because a fix at the bare release would
/// already have marked a `-pN` install not-affected before any finding was emitted.
pub fn to_semver(v: &Version) -> SemverVersion {
    // Dominant case: the string is already valid SemVer — keep it verbatim.
    if let Ok(sv) = SemverVersion::parse(&v.raw) {
        return sv;
    }

    // Leading numeric run → release tuple; the rest is the prerelease tail.
    let mut nums: Vec<u64> = Vec::new();
    let mut tail_start = 0;
    for (i, tok) in v.tokens.iter().enumerate() {
        match tok {
            Token::Num(n) => nums.push(*n),
            Token::Word(_) => {
                tail_start = i;
                break;
            }
        }
        tail_start = i + 1;
    }

    // Drop the four-component core padding (and any genuine trailing-zero segment) so the
    // displayed version stays clean (`3.0` → `3.0.0`, not `3.0.0+0`).
    while nums.len() > 3 && matches!(nums.last(), Some(0)) {
        nums.pop();
    }

    let mut sv = SemverVersion::new(
        nums.first().copied().unwrap_or(0),
        nums.get(1).copied().unwrap_or(0),
        nums.get(2).copied().unwrap_or(0),
    );

    let tail: Vec<String> = v.tokens[tail_start..]
        .iter()
        .map(|t| match t {
            Token::Num(n) => n.to_string(),
            Token::Word(s) => s.clone(),
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
        parse_composer_version(s).unwrap()
    }

    #[test]
    fn parses_and_strips_v_prefix() {
        assert_eq!(v("1.2.3").to_string(), "1.2.3");
        assert_eq!(v("v1.2.3").to_string(), "1.2.3");
        assert_eq!(v("V2.6.4").to_string(), "2.6.4");
        // A dev/branch reference (does not start with a digit) is unmatchable.
        assert!(parse_composer_version("dev-master").is_none());
        assert!(parse_composer_version("dev-feature/x").is_none());
        assert!(parse_composer_version("").is_none());
    }

    #[test]
    fn trailing_zeros_are_insignificant() {
        assert_eq!(v("1.0"), v("1.0.0"));
        assert_eq!(v("3.1"), v("3.1.0.0"));
        assert_eq!(v("2.0"), v("2.0.0"));
        assert!(v("1.0") < v("1.0.1"));
        assert!(v("1.2.3.4") > v("1.2.3"));
    }

    #[test]
    fn prerelease_orders_below_release() {
        // The standard prerelease cases — like SemVer.
        assert!(v("1.0.0-alpha1") < v("1.0.0-beta1"));
        assert!(v("1.0.0-beta1") < v("1.0.0-rc1"));
        assert!(v("1.0.0-rc1") < v("1.0.0"));
        assert!(v("2.7.0-rc1") < v("2.7.0"));
        assert!(v("1.0.0-dev") < v("1.0.0-alpha1"));
    }

    #[test]
    fn patch_level_orders_above_release() {
        // The false-clean-critical Composer divergence from SemVer: `-pN`/`-pl`/`-patch`
        // is a patch level that sorts ABOVE the release (Magento's scheme).
        assert!(v("2.4.5-p1") > v("2.4.5"));
        assert!(v("2.4.5-p2") > v("2.4.5-p1"));
        assert!(v("2.4.5-pl1") > v("2.4.5"));
        assert!(v("2.4.5-patch1") > v("2.4.5"));
        // ...and a patch still sorts below the next release.
        assert!(v("2.4.5-p99") < v("2.4.6"));
        // The whole stability ladder in one chain.
        assert!(v("1.0.0-dev") < v("1.0.0-alpha"));
        assert!(v("1.0.0-rc1") < v("1.0.0"));
        assert!(v("1.0.0") < v("1.0.0-p1"));
    }

    #[test]
    fn modifier_case_and_separator_are_normalized() {
        // `-RC1` == `-rc.1` == `-rc1`; Composer normalizes modifier case and the optional
        // separating dot.
        assert_eq!(v("1.0.0-RC1"), v("1.0.0-rc1"));
        assert_eq!(v("1.0.0-rc.1"), v("1.0.0-rc1"));
        assert_eq!(v("1.0.0-BETA2"), v("1.0.0-beta.2"));
        // Short and long forms alias.
        assert_eq!(v("1.0.0-a1"), v("1.0.0-alpha1"));
        assert_eq!(v("1.0.0-b1"), v("1.0.0-beta1"));
    }

    #[test]
    fn mixed_numeric_component_counts_align_the_modifier() {
        // Composer pads the numeric core to four components before the stability tail, so a
        // 2-component and a 3-component version compare their suffixes, not suffix-vs-number.
        // (Corpus differential vs composer/semver surfaced these.)
        assert_eq!(v("1.0-RC1"), v("1.0.0-rc1"));
        assert!(v("3.0-beta.7") > v("3.0.0a3")); // beta > alpha at the aligned position
        assert!(v("3.0.0-alpha42") < v("3.0-beta1"));
        assert!(v("2.0-beta.3.5") > v("2.0.0-beta.0"));
        assert!(v("4.0-beta.28") > v("4.0.0-beta4"));
        // A 4-component release with a suffix still aligns against a short one.
        assert!(v("3.0.0.0-beta") > v("3.0-alpha"));
    }

    #[test]
    fn introduced_bound_includes_prereleases_of_its_release() {
        // Composer floors a bare `>=X` at `X-dev`, so a prerelease of the introduced
        // release is in range (corpus differential vs composer/semver: drupal/core
        // 8.7.0-rc1 was missed by a plain `>=`). Asserts Composer's exact rule.
        assert!(v("8.7.0-rc1").at_or_after_introduced(&v("8.7.0")));
        assert!(v("8.7.0-alpha1").at_or_after_introduced(&v("8.7.0")));
        // A prerelease of a HIGHER release is already covered by normal ordering.
        assert!(v("8.8.0-rc1").at_or_after_introduced(&v("8.7.0")));
        // A prerelease BELOW the introduced release is not.
        assert!(!v("8.6.0-rc1").at_or_after_introduced(&v("8.7.0")));
        assert!(!v("8.7.0-rc1").at_or_after_introduced(&v("8.7.1")));
        // A prerelease introduced bound (Magento `2.4.7-beta1`) is used verbatim.
        assert!(v("2.4.7-beta1").at_or_after_introduced(&v("2.4.7-beta1")));
        assert!(!v("2.4.7-alpha1").at_or_after_introduced(&v("2.4.7-beta1")));
        // Stable controls.
        assert!(v("8.7.0").at_or_after_introduced(&v("8.7.0")));
        assert!(!v("8.6.9").at_or_after_introduced(&v("8.7.0")));
    }

    #[test]
    fn build_metadata_is_ignored() {
        // Composer ignores SemVer `+build` metadata for ordering.
        assert_eq!(v("6.0.0+ea2"), v("6.0.0"));
        assert_eq!(v("2.4.8+ea2"), v("2.4.8"));
        assert!(v("6.0.0+ea2") < v("6.0.1"));
    }

    #[test]
    fn alpha_dot_number_orders_numerically() {
        // `-beta.10` > `-beta.9` (the number is its own token, compared numerically).
        assert!(v("1.10.0-alpha.10") > v("1.10.0-alpha.9"));
        assert!(v("5.0.0-beta.27") > v("5.0.0-beta.3"));
    }

    #[test]
    fn is_prerelease_excludes_patch() {
        assert!(v("1.0.0-beta1").is_prerelease());
        assert!(v("2.7.0-rc1").is_prerelease());
        assert!(v("1.0.0-dev").is_prerelease());
        assert!(!v("1.2.3").is_prerelease());
        assert!(!v("2.4.5-p1").is_prerelease(), "patch is above the release");
    }

    fn coerce(s: &str) -> SemverVersion {
        to_semver(&v(s))
    }

    #[test]
    fn to_semver_is_faithful_for_common_shapes() {
        assert_eq!(coerce("2.2.8").to_string(), "2.2.8");
        assert_eq!(coerce("3.1").to_string(), "3.1.0");
        assert_eq!(coerce("1.0.0-beta1").to_string(), "1.0.0-beta1");
        assert_eq!(coerce("1.2.3.4").to_string(), "1.2.3+4");
    }

    #[test]
    fn to_semver_orders_prerelease_below_release() {
        // Remediation relies on this for the common prerelease case.
        assert!(coerce("1.0.0-beta1") < coerce("1.0.0"));
        assert!(coerce("2.30.0") < coerce("2.31.0"));
    }
}
