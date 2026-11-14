//! Parse a Maven project's pinned dependencies into a flat, deduplicated set — the input the
//! OSV matcher scans. Maven has no single universal lockfile, so two toolchain-free inputs are
//! supported:
//!
//! - **`gradle.lockfile`** (Gradle dependency locking): the **full resolved transitive
//!   closure**, one `group:artifact:version=configs` line per dependency. This is the
//!   high-fidelity input.
//! - **`pom.xml`** (Maven): best-effort — the **direct** dependencies whose `<version>` is a
//!   literal (a `${property}` or a version range cannot be resolved without running Maven, so
//!   they are skipped). It does not see the transitive closure.
//!
//! Package names are Maven coordinates `group:artifact`, matched verbatim (case-sensitive).

use std::collections::BTreeMap;

/// One resolved dependency: its `group:artifact` coordinate, exact version, and whether it is
/// a direct dependency (true for `pom.xml` entries, false for `gradle.lockfile`, which is the
/// full closure without a direct/transitive flag).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub direct: bool,
}

/// Parse a `gradle.lockfile` into a deduplicated, sorted set of installed packages. Each
/// dependency line is `group:artifact:version=config,config`; comment lines (`#`) and the
/// `empty=` marker are skipped. The closure has no direct/transitive flag, so every entry is
/// reported transitive (a conservative under-claim that never hides a finding).
pub fn parse_gradle_lockfile(text: &str) -> Vec<InstalledPackage> {
    let mut packages = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("empty=") {
            continue;
        }
        // `group:artifact:version=configs` → take the coordinate before `=`.
        let coord = line.split('=').next().unwrap_or(line);
        // version is after the last `:`; the rest is `group:artifact`.
        let Some((name, version)) = coord.rsplit_once(':') else {
            continue;
        };
        if name.is_empty() || version.is_empty() || !name.contains(':') {
            continue; // not a `group:artifact:version` coordinate
        }
        packages.push(InstalledPackage {
            name: name.to_string(),
            version: version.to_string(),
            direct: false,
        });
    }
    dedupe(packages)
}

/// Check that `text` has the shape Gradle writes, so a damaged lockfile is refused rather
/// than read short: the reader skips lines it does not know, so a stray line would be
/// dropped and a file cut short would read as a smaller, clean project.
///
/// # Errors
///
/// A line that is not a comment, `group:artifact:version=configs` or `empty=configs`, or a
/// non-empty file with no `empty=` line (Gradle always ends the file with one).
pub fn check_gradle_lockfile(text: &str) -> Result<(), String> {
    let mut has_empty = false;
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("empty=") {
            has_empty = true;
            continue;
        }
        let coord = line.split_once('=').map(|(c, _)| c);
        if !coord.is_some_and(|c| c.split(':').count() >= 3 && c.split(':').all(|p| !p.is_empty()))
        {
            let shown: String = line.chars().take(60).collect();
            return Err(format!(
                "line {}: `{}` is not `group:artifact:version=configs`; the file is damaged",
                n + 1,
                shown.escape_debug()
            ));
        }
    }
    if !has_empty && !text.trim().is_empty() {
        return Err(
            "has no `empty=` line, which Gradle always writes last; the file looks cut \
                    short"
                .to_string(),
        );
    }
    Ok(())
}

/// The lockfile of the Gradle build in `dir`, by name: `gradle.lockfile` (Gradle's own
/// dependency locking), else `versions.lock` from Palantir's gradle-consistent-versions, which
/// counts only beside its `versions.props` (the name alone is too common to claim).
pub fn gradle_lockfile(dir: &std::path::Path) -> Option<&'static str> {
    if dir.join("gradle.lockfile").is_file() {
        Some("gradle.lockfile")
    } else if dir.join("versions.lock").is_file() && dir.join("versions.props").is_file() {
        Some("versions.lock")
    } else {
        None
    }
}

/// Check and parse a lockfile [`gradle_lockfile`] named.
///
/// # Errors
///
/// The file is damaged ([`check_gradle_lockfile`], [`check_versions_lock`]).
pub fn read_gradle_lockfile(name: &str, text: &str) -> Result<Vec<InstalledPackage>, String> {
    if name == "versions.lock" {
        check_versions_lock(text)?;
        Ok(parse_versions_lock(text))
    } else {
        check_gradle_lockfile(text)?;
        Ok(parse_gradle_lockfile(text))
    }
}

/// Parse gradle-consistent-versions' `versions.lock`: `group:artifact:version (N constraints:
/// hash)` per line, the production closure first, then a `[Test dependencies]` section.
/// Like `gradle.lockfile`, every entry is reported transitive.
pub fn parse_versions_lock(text: &str) -> Vec<InstalledPackage> {
    let mut packages = Vec::new();
    for line in text.lines() {
        let Some(coord) = versions_lock_coordinate(line.trim()) else {
            continue;
        };
        if let Some((name, version)) = coord.rsplit_once(':') {
            packages.push(InstalledPackage {
                name: name.to_string(),
                version: version.to_string(),
                direct: false,
            });
        }
    }
    dedupe(packages)
}

/// `group:artifact:version` of a `versions.lock` entry line.
fn versions_lock_coordinate(line: &str) -> Option<&str> {
    let (coord, rest) = line.split_once(" (")?;
    let parts: Vec<&str> = coord.split(':').collect();
    let shaped = parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && !p.contains(char::is_whitespace))
        && rest.ends_with(')')
        && rest.contains("constraint");
    shaped.then_some(coord)
}

/// Check that `text` has the shape gradle-consistent-versions writes, so a damaged file is
/// refused rather than read short.
///
/// # Errors
///
/// A line that is not a comment, a `[section]` header or a `group:artifact:version (N
/// constraints: hash)` entry, or a file with no entry at all.
pub fn check_versions_lock(text: &str) -> Result<(), String> {
    let mut entries = 0usize;
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            continue;
        }
        if versions_lock_coordinate(line).is_none() {
            let shown: String = line.chars().take(60).collect();
            return Err(format!(
                "line {}: `{}` is not `group:artifact:version (N constraints: hash)`; the file \
                 is damaged",
                n + 1,
                shown.escape_debug()
            ));
        }
        entries += 1;
    }
    if entries == 0 {
        return Err("has no dependency lines; the file looks cut short".to_string());
    }
    Ok(())
}

/// Parse a `pom.xml` for its direct dependencies with literal versions. A small tag scan (not
/// a full XML parser): for each `<dependency>…</dependency>` block, read `<groupId>`,
/// `<artifactId>`, and `<version>`. A dependency with no version, a `${property}` version, or a
/// version range (`[`/`(`) is skipped (it cannot be resolved without running Maven).
pub fn parse_pom_xml(text: &str) -> Vec<InstalledPackage> {
    let mut packages = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("<dependency>") {
        let after = &rest[start + "<dependency>".len()..];
        let Some(end) = after.find("</dependency>") else {
            break;
        };
        let block = &after[..end];
        rest = &after[end + "</dependency>".len()..];

        let (Some(group), Some(artifact)) = (tag(block, "groupId"), tag(block, "artifactId"))
        else {
            continue;
        };
        let Some(version) = tag(block, "version") else {
            continue; // managed elsewhere, not a concrete pin we can match
        };
        // A property reference or a version range cannot be resolved offline.
        if version.contains("${") || version.starts_with('[') || version.starts_with('(') {
            continue;
        }
        packages.push(InstalledPackage {
            name: format!("{group}:{artifact}"),
            version: version.to_string(),
            direct: true,
        });
    }
    dedupe(packages)
}

/// The trimmed text content of the first `<tag>…</tag>` in `block`, or `None`.
fn tag<'a>(block: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = block.find(&open)? + open.len();
    let end = block[start..].find(&close)? + start;
    let value = block[start..end].trim();
    (!value.is_empty()).then_some(value)
}

/// Collapse duplicate `(name, version)` rows into one, `direct` winning if any was direct, and
/// sort for deterministic output.
fn dedupe(packages: Vec<InstalledPackage>) -> Vec<InstalledPackage> {
    let mut by_key: BTreeMap<(String, String), bool> = BTreeMap::new();
    for p in packages {
        let e = by_key.entry((p.name, p.version)).or_insert(false);
        *e = *e || p.direct;
    }
    by_key
        .into_iter()
        .map(|((name, version), direct)| InstalledPackage {
            name,
            version,
            direct,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn rows(pkgs: &[InstalledPackage]) -> Vec<(&str, &str, bool)> {
        pkgs.iter()
            .map(|p| (p.name.as_str(), p.version.as_str(), p.direct))
            .collect()
    }

    #[test]
    fn parses_and_checks_versions_lock() {
        let lock = "# Run ./gradlew writeVersionsLocks to regenerate this file. Blank lines are \
                    to minimize merge conflicts.\n\n\
                    com.google.guava:guava:33.7.2-jre (3 constraints: 203acbe1)\n\n\
                    org.jspecify:jspecify:1.0.1 (8 constraints: 967df209)\n\n\
                    [Test dependencies]\n\n\
                    junit:junit:4.13.2 (1 constraints: 3c05153b)\n";
        check_versions_lock(lock).unwrap();
        assert_eq!(
            rows(&parse_versions_lock(lock)),
            [
                ("com.google.guava:guava", "33.7.2-jre", false),
                ("junit:junit", "4.13.2", false),
                ("org.jspecify:jspecify", "1.0.1", false),
            ]
        );
        assert!(check_versions_lock(&lock.replace(" (8 constraints: 967df209)", "")).is_err());
        assert!(check_versions_lock("# header only\n").is_err());
        assert_eq!(
            read_gradle_lockfile("versions.lock", lock).unwrap().len(),
            3
        );
    }

    #[test]
    fn parses_gradle_lockfile() {
        let lock = r#"# Gradle generated lockfile
com.fasterxml.jackson.core:jackson-databind:2.9.8=compileClasspath,runtimeClasspath
org.slf4j:slf4j-api:1.7.25=runtimeClasspath
empty=annotationProcessor
"#;
        assert_eq!(
            rows(&parse_gradle_lockfile(lock)),
            vec![
                (
                    "com.fasterxml.jackson.core:jackson-databind",
                    "2.9.8",
                    false
                ),
                ("org.slf4j:slf4j-api", "1.7.25", false),
            ]
        );
    }

    #[test]
    fn parses_pom_direct_deps_skips_property_and_range() {
        let pom = r#"<project>
          <dependencies>
            <dependency>
              <groupId>org.apache.derby</groupId>
              <artifactId>derby</artifactId>
              <version>10.14.2.0</version>
            </dependency>
            <dependency>
              <groupId>com.example</groupId>
              <artifactId>managed</artifactId>
            </dependency>
            <dependency>
              <groupId>com.example</groupId>
              <artifactId>prop</artifactId>
              <version>${prop.version}</version>
            </dependency>
            <dependency>
              <groupId>com.example</groupId>
              <artifactId>ranged</artifactId>
              <version>[1.0,2.0)</version>
            </dependency>
          </dependencies>
        </project>"#;
        assert_eq!(
            rows(&parse_pom_xml(pom)),
            vec![("org.apache.derby:derby", "10.14.2.0", true)]
        );
    }

    #[test]
    fn empty_inputs() {
        assert!(parse_gradle_lockfile("# only comments\n").is_empty());
        assert!(parse_pom_xml("<project></project>").is_empty());
    }

    #[test]
    fn a_damaged_gradle_lockfile_is_refused_not_read_short() {
        let good = "# This is a Gradle generated file for dependency locking.\n# Manual edits can break the build and are not advised.\n# This file is expected to be part of source control.\ncom.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath\norg.example:lib:1.0:jdk8=runtimeClasspath\nempty=annotationProcessor\n";
        check_gradle_lockfile(good).unwrap();
        let cut = &good[..good.find("empty=").unwrap()];
        assert!(check_gradle_lockfile(cut)
            .unwrap_err()
            .contains("cut short"));
        let stray = good.replacen("org.example", "{{{ ][ garbage\norg.example", 1);
        assert!(check_gradle_lockfile(&stray)
            .unwrap_err()
            .contains("damaged"));
        assert!(check_gradle_lockfile(&good.replacen("guava:31.1-jre=", "guava=", 1)).is_err());
    }
}
