//! Parse GitHub Actions workflow files into the set of actions a repo **uses** — the input
//! the OSV matcher scans. Read straight from `.github/workflows/*.yml`, so it needs **no
//! toolchain and no network**.
//!
//! An action reference is a `uses:` value, `owner/repo[/subpath]@ref`:
//!
//! ```yaml
//! steps:
//!   - uses: actions/checkout@v4
//!   - uses: tj-actions/changed-files@a1b2c3...   # a SHA pin
//!   - uses: ./.github/actions/local             # a local action (skipped)
//! ```
//!
//! The reference's `@ref` is a git tag, branch, or commit SHA. Only a **version tag**
//! (`v4`, `4.1.1`) can be matched against the OSV semantic ranges; a branch (`@main`) or a
//! commit SHA has no semantic version and is skipped — an honest gap, since resolving a SHA
//! to its release would need the network. Local (`./…`) and `docker://…` references are not
//! registry actions and are skipped. Action names are case-insensitive (GitHub treats
//! `owner/repo` case-insensitively), matched lowercased.

use fleetreach_core::semver::Version;

/// One action a workflow `uses:`, with its raw `@ref` (a tag, branch, or SHA). The matcher
/// keeps only those whose ref parses as a version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UsedAction {
    /// The action identity (`owner/repo[/subpath]`), lowercased.
    pub name: String,
    /// The raw `@ref` — a tag like `v4.1.1`, a branch, or a commit SHA.
    pub version_ref: String,
}

/// Extract every `uses:` action reference from one workflow file's text. Local (`./…`,
/// `../…`) and `docker://…` references are skipped. Deduplicated within the file.
pub fn used_actions(workflow_text: &str) -> Vec<UsedAction> {
    let mut out = Vec::new();
    for line in workflow_text.lines() {
        let Some(value) = uses_value(line) else {
            continue;
        };
        // Local or docker references are not registry actions.
        if value.starts_with("./") || value.starts_with("../") || value.starts_with("docker://") {
            continue;
        }
        let Some((name, reference)) = value.split_once('@') else {
            continue; // a local action with no ref, or malformed
        };
        if name.is_empty() || reference.is_empty() || !name.contains('/') {
            continue;
        }
        out.push(UsedAction {
            name: name.to_ascii_lowercase(),
            version_ref: reference.to_string(),
        });
    }
    out.sort();
    out.dedup();
    out
}

/// The value of a `uses:` key on a YAML line, or `None` if the line has none. Tolerates list
/// markers (`- uses:`), surrounding quotes, and trailing `# comments`; takes the first
/// whitespace-delimited token as the reference (a `uses:` value never contains a space).
fn uses_value(line: &str) -> Option<&str> {
    let idx = line.find("uses:")?;
    // `uses` must be a YAML key: at line start or preceded by whitespace or a `-` list marker.
    let before = &line[..idx];
    if !before
        .chars()
        .last()
        .is_none_or(|c| c.is_whitespace() || c == '-')
    {
        return None;
    }
    let after = line[idx + "uses:".len()..].trim();
    // Strip a surrounding quote, then take the first token (refs have no spaces) and drop a
    // trailing inline comment.
    let after = after
        .trim_start_matches(['"', '\''])
        .split_whitespace()
        .next()?;
    let token = after.trim_end_matches(['"', '\'']);
    let token = token.split('#').next().unwrap_or(token);
    (!token.is_empty()).then_some(token)
}

/// Parse a GitHub Actions `@ref` into a semantic [`Version`], or `None` if it is not a version
/// tag (a branch name or commit SHA). A leading `v` is stripped; a partial tag is padded
/// (`v4` → `4.0.0`, `4.1` → `4.1.0`), which is how OSV's GitHub Actions ranges treat a
/// major/minor tag. A commit SHA (non-numeric or an overflowing all-digit run) and a branch
/// name fail to parse and are skipped.
pub fn parse_gha_version(raw: &str) -> Option<Version> {
    let s = raw.trim();
    let s = s.strip_prefix(['v', 'V']).unwrap_or(s);
    // The numeric core is the leading `[0-9.]+`; anything after (a `-pre`/`+build`) is a tail.
    let core_end = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let (core, tail) = s.split_at(core_end);
    let mut nums: Vec<u64> = Vec::new();
    for part in core.split('.') {
        if part.is_empty() {
            return None;
        }
        nums.push(part.parse::<u64>().ok()?);
    }
    if nums.is_empty() || nums.len() > 3 {
        return None;
    }
    while nums.len() < 3 {
        nums.push(0);
    }
    Version::parse(&format!("{}.{}.{}{}", nums[0], nums[1], nums[2], tail)).ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn names(text: &str) -> Vec<(String, String)> {
        used_actions(text)
            .into_iter()
            .map(|a| (a.name, a.version_ref))
            .collect()
    }

    #[test]
    fn extracts_uses_refs_and_skips_local_docker() {
        let wf = r#"
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - name: setup
        uses: "actions/setup-node@v4.1.0"   # quoted + comment
      - uses: tj-actions/changed-files@0aabc
      - uses: ./.github/actions/local
      - uses: docker://alpine:3.8
      - run: echo "not a uses line"
"#;
        assert_eq!(
            names(wf),
            vec![
                ("actions/checkout".into(), "v4".into()),
                ("actions/setup-node".into(), "v4.1.0".into()),
                ("tj-actions/changed-files".into(), "0aabc".into()),
            ]
        );
    }

    #[test]
    fn lowercases_and_keeps_subpaths() {
        let wf = "  - uses: Super-Linter/Super-Linter/slim@v5\n";
        assert_eq!(
            names(wf),
            vec![("super-linter/super-linter/slim".into(), "v5".into())]
        );
    }

    #[test]
    fn parses_full_partial_and_prerelease_tags() {
        assert_eq!(parse_gha_version("v4").unwrap().to_string(), "4.0.0");
        assert_eq!(parse_gha_version("v4.1").unwrap().to_string(), "4.1.0");
        assert_eq!(parse_gha_version("4.1.1").unwrap().to_string(), "4.1.1");
        assert_eq!(parse_gha_version("46.0.1").unwrap().to_string(), "46.0.1");
        assert_eq!(parse_gha_version("87").unwrap().to_string(), "87.0.0");
        assert_eq!(
            parse_gha_version("v2.0.0-beta").unwrap().to_string(),
            "2.0.0-beta"
        );
    }

    #[test]
    fn rejects_shas_and_branches() {
        assert!(parse_gha_version("a1b2c3d4e5f6a7b8c9d0").is_none()); // SHA (hex w/ letters)
        assert!(parse_gha_version("main").is_none());
        assert!(parse_gha_version("release/v2").is_none());
        // A 40-digit all-numeric SHA overflows the numeric parse → skipped.
        assert!(parse_gha_version(&"1".repeat(40)).is_none());
    }
}
