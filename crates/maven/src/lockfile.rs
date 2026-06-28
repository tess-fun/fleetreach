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
}
