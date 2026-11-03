//! Java archives inside an image, reduced to what identifies their contents.
//!
//! A `.jar`, `.war` or `.ear` is summarized the moment the image reader has it, so a large
//! Spring Boot jar costs a few lines of memory rather than its size. Nothing in an archive is
//! run. Four kinds of evidence, best first, for an archive and every archive nested in it
//! (`BOOT-INF/lib/`, `WEB-INF/lib/`):
//!
//! - `META-INF/maven/<group>/<artifact>/pom.properties`: exact coordinates, one per library a
//!   shaded jar holds.
//! - The file name (`spring-core-5.3.20.jar`) for jars with no `pom.properties`, as Gradle
//!   and Ant builds have: an artifact and version with no group. The group is settled against
//!   the advisory data by the caller, with the archive's OSGi bundle name and top class
//!   packages as evidence.
//! - The OSGi headers of `META-INF/MANIFEST.MF` for a jar whose file name has no version
//!   (Tomcat's `catalina.jar` is the bundle `org.apache.tomcat-catalina`, 9.0.50), which the
//!   caller places among the advisory data's coordinates.
//! - None of these: an archive nothing can identify, for the caller to report as a coverage gap.

use std::io::{Cursor, Read};

/// The largest archive read; a bigger one is a coverage gap.
pub const MAX_ARCHIVE_BYTES: u64 = 1 << 30;
/// The largest nested archive unpacked, and all of them together for one archive: a zip
/// bomb stops here.
const MAX_NESTED_BYTES: u64 = 512 << 20;
const MAX_TOTAL_BYTES: u64 = 4 << 30;
/// How deep archives nest (a jar in a war in an ear is 3).
const MAX_DEPTH: usize = 4;
/// `pom.properties` files are a few lines, and a manifest's main section comes first.
const MAX_PROPERTIES_BYTES: u64 = 64 << 10;
/// Class packages kept per archive, as evidence for its group.
const MAX_PACKAGES: usize = 64;

/// What one archive holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    /// Exact coordinates: `group:artifact`, version, and where.
    Coordinates {
        name: String,
        version: String,
        path: String,
    },
    /// An artifact and version from a file name, with the archive's class packages
    /// (`org/springframework`).
    FileName {
        artifact: String,
        version: String,
        path: String,
        packages: Vec<String>,
        /// The OSGi bundle name, when the manifest has one.
        bundle: Option<String>,
    },
    /// An OSGi bundle name and version from a manifest, for a file name with no version.
    Bundle {
        name: String,
        version: String,
        path: String,
    },
    /// An archive nothing identifies.
    Unknown { path: String },
    /// An archive that could not be read.
    Unreadable { path: String, reason: String },
}

/// Whether `path` names a Java archive.
pub fn is_archive(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    [".jar", ".war", ".ear", ".par", ".kar", ".jpi", ".hpi"]
        .iter()
        .any(|e| name.ends_with(e))
}

/// An artifact and version from an archive's file name: the version starts at the first `-`
/// followed by a digit (`jackson-databind-2.13.0.jar`, `log4j-1.2-api-2.17.1.jar` is the rare
/// name this reads wrongly, and its version then matches nothing).
fn from_file_name(path: &str) -> Option<(String, String)> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let stem = name.rsplit_once('.')?.0;
    let at = stem
        .char_indices()
        .find(|(i, c)| {
            *c == '-'
                && *i > 0
                && stem[i + 1..]
                    .chars()
                    .next()
                    .is_some_and(|d| d.is_ascii_digit())
        })?
        .0;
    Some((stem[..at].to_string(), stem[at + 1..].to_string()))
}

/// A `key=value` from a `.properties` text.
fn property<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .find(|(k, _)| k.trim() == key)
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty() && !v.contains("${"))
}

/// The bundle name and version in a `MANIFEST.MF`: `Bundle-SymbolicName` without its
/// directives, and the first of `Implementation-Version` and `Bundle-Version` that is a
/// version (a build may put a commit or a placeholder there).
fn manifest(text: &str) -> (Option<String>, Option<String>) {
    // A long value continues on lines starting with a space.
    let text = text.replace("\r\n", "\n").replace("\n ", "");
    let main = text.split("\n\n").next().unwrap_or_default();
    let header = |key: &str| {
        main.lines()
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.trim())
            .filter(|v| !v.is_empty())
    };
    let name = header("Bundle-SymbolicName")
        .and_then(|v| v.split(';').next())
        .map(|v| v.trim().to_string());
    let version = ["Implementation-Version", "Bundle-Version"]
        .iter()
        .filter_map(|k| header(k))
        .find(|v| v.starts_with(|c: char| c.is_ascii_digit()))
        .map(str::to_string);
    (name, version)
}

struct Walk {
    out: Vec<Found>,
    budget: u64,
}

impl Walk {
    fn archive(&mut self, path: &str, data: &[u8], depth: usize) {
        let unreadable = |reason: String| Found::Unreadable {
            path: path.to_string(),
            reason,
        };
        let mut zip = match zip::ZipArchive::new(Cursor::new(data)) {
            Ok(z) => z,
            Err(e) => {
                self.out.push(unreadable(e.to_string()));
                return;
            }
        };
        let names: Vec<String> = zip
            .file_names()
            .filter_map(Result::ok)
            .map(std::borrow::Cow::into_owned)
            .collect();
        let mut coordinates = 0;
        let mut nested = 0;
        for name in &names {
            if name.starts_with("META-INF/maven/") && name.ends_with("/pom.properties") {
                let mut text = String::new();
                let read = zip.by_name(name).and_then(|f| {
                    f.take(MAX_PROPERTIES_BYTES)
                        .read_to_string(&mut text)
                        .map_err(Into::into)
                });
                if read.is_err() {
                    continue;
                }
                let found = (
                    property(&text, "groupId"),
                    property(&text, "artifactId"),
                    property(&text, "version"),
                );
                if let (Some(g), Some(a), Some(v)) = found {
                    coordinates += 1;
                    self.out.push(Found::Coordinates {
                        name: format!("{g}:{a}"),
                        version: v.to_string(),
                        path: path.to_string(),
                    });
                }
            } else if is_archive(name) {
                nested += 1;
                let at = format!("{path}!{name}");
                if depth >= MAX_DEPTH {
                    self.out.push(Found::Unreadable {
                        path: at,
                        reason: "nested too deeply".to_string(),
                    });
                    continue;
                }
                let mut inner = Vec::new();
                let read = match zip.by_name(name) {
                    Ok(f) if f.size() > MAX_NESTED_BYTES || f.size() > self.budget => {
                        Err("too large to unpack".to_string())
                    }
                    Ok(f) => f
                        .take(MAX_NESTED_BYTES)
                        .read_to_end(&mut inner)
                        .map_err(|e| e.to_string()),
                    Err(e) => Err(e.to_string()),
                };
                match read {
                    Ok(n) => {
                        self.budget = self.budget.saturating_sub(n as u64);
                        self.archive(&at, &inner, depth + 1);
                    }
                    Err(reason) => self.out.push(Found::Unreadable { path: at, reason }),
                }
            }
        }
        if coordinates > 0 {
            return;
        }
        let mut bytes = Vec::new();
        if let Ok(f) = zip.by_name("META-INF/MANIFEST.MF") {
            // What was read before an error is still the start of the manifest.
            let _ = f.take(MAX_PROPERTIES_BYTES).read_to_end(&mut bytes);
        }
        let (bundle, version) = manifest(&String::from_utf8_lossy(&bytes));
        match (from_file_name(path), bundle, version) {
            (Some((artifact, version)), bundle, _) => self.out.push(Found::FileName {
                artifact,
                version,
                path: path.to_string(),
                packages: packages(&names),
                bundle,
            }),
            (None, Some(name), Some(version)) => self.out.push(Found::Bundle {
                name,
                version,
                path: path.to_string(),
            }),
            // A war or fat jar with no name of its own is its nested archives, and its own
            // classes are the application's.
            (None, ..) if nested > 0 => {}
            (None, ..) => self.out.push(Found::Unknown {
                path: path.to_string(),
            }),
        }
    }
}

/// The two-level class packages of an archive's entries (`org/springframework`), most
/// frequent evidence kept first by sorted order and a cap.
fn packages(names: &[String]) -> Vec<String> {
    let mut out: Vec<String> = names
        .iter()
        .filter(|n| n.ends_with(".class"))
        .map(|n| n.strip_prefix("BOOT-INF/classes/").unwrap_or(n))
        .map(|n| n.strip_prefix("WEB-INF/classes/").unwrap_or(n))
        .filter_map(|n| {
            let mut parts = n.split('/');
            let (a, b) = (parts.next()?, parts.next()?);
            Some(if b.ends_with(".class") {
                a.to_string()
            } else {
                format!("{a}/{b}")
            })
        })
        .collect();
    out.sort();
    out.dedup();
    out.truncate(MAX_PACKAGES);
    out
}

/// Everything `data`, an archive at `path`, holds.
pub fn inspect(path: &str, data: &[u8]) -> Vec<Found> {
    let mut walk = Walk {
        out: Vec::new(),
        budget: MAX_TOTAL_BYTES,
    };
    walk.archive(path, data, 0);
    walk.out
}

/// [`inspect`] as text, what the image reader keeps in place of the archive: one tab-separated
/// record per line.
pub(crate) fn digest(path: &str, data: &[u8]) -> Vec<u8> {
    let clean = |s: &str| s.replace(['\t', '\n'], " ");
    let mut out = String::new();
    for f in inspect(path, data) {
        let line = match f {
            Found::Coordinates {
                name,
                version,
                path,
            } => format!("C\t{}\t{}\t{}", clean(&name), clean(&version), clean(&path)),
            Found::FileName {
                artifact,
                version,
                path,
                packages,
                bundle,
            } => format!(
                "F\t{}\t{}\t{}\t{}\t{}",
                clean(&artifact),
                clean(&version),
                clean(&path),
                clean(&packages.join(",")),
                clean(bundle.as_deref().unwrap_or_default())
            ),
            Found::Bundle {
                name,
                version,
                path,
            } => format!("B\t{}\t{}\t{}", clean(&name), clean(&version), clean(&path)),
            Found::Unknown { path } => format!("U\t{}", clean(&path)),
            Found::Unreadable { path, reason } => {
                format!("X\t{}\t{}", clean(&path), clean(&reason))
            }
        };
        out.push_str(&line);
        out.push('\n');
    }
    out.into_bytes()
}

/// The records of a [`digest`].
pub(crate) fn parse_digest(digest: &[u8]) -> Vec<Found> {
    String::from_utf8_lossy(digest)
        .lines()
        .filter_map(|l| {
            let cols: Vec<&str> = l.split('\t').collect();
            Some(match cols[..] {
                ["C", name, version, path] => Found::Coordinates {
                    name: name.to_string(),
                    version: version.to_string(),
                    path: path.to_string(),
                },
                ["F", artifact, version, path, packages, bundle] => Found::FileName {
                    artifact: artifact.to_string(),
                    version: version.to_string(),
                    path: path.to_string(),
                    packages: packages
                        .split(',')
                        .filter(|p| !p.is_empty())
                        .map(str::to_string)
                        .collect(),
                    bundle: Some(bundle).filter(|b| !b.is_empty()).map(str::to_string),
                },
                ["B", name, version, path] => Found::Bundle {
                    name: name.to_string(),
                    version: version.to_string(),
                    path: path.to_string(),
                },
                ["U", path] => Found::Unknown {
                    path: path.to_string(),
                },
                ["X", path, reason] => Found::Unreadable {
                    path: path.to_string(),
                    reason: reason.to_string(),
                },
                _ => return None,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use std::io::Write;

    fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, data) in entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn pom(g: &str, a: &str, v: &str) -> Vec<u8> {
        format!("#generated\nversion={v}\ngroupId={g}\nartifactId={a}\n").into_bytes()
    }

    #[test]
    fn archive_names() {
        assert!(is_archive("opt/app.jar") && is_archive("x/y.war") && is_archive("p.hpi"));
        assert!(!is_archive("opt/app.jar.sha1") && !is_archive("jar"));
        let name = |p: &str| from_file_name(p);
        assert_eq!(
            name("lib/spring-core-5.3.20.jar"),
            Some(("spring-core".into(), "5.3.20".into()))
        );
        assert_eq!(name("lib/catalina.jar"), None);
    }

    #[test]
    fn fat_jars_are_read_through() {
        let log4j = zip(&[(
            "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties",
            &pom("org.apache.logging.log4j", "log4j-core", "2.14.1"),
        )]);
        let spring = zip(&[("org/springframework/core/Foo.class", b"")]);
        let unnamed = zip(&[("com/acme/Foo.class", b"")]);
        let broken: &[u8] = b"not a zip";
        let app = zip(&[
            (
                "META-INF/maven/com.acme/app/pom.properties",
                &pom("com.acme", "app", "${revision}"),
            ),
            ("BOOT-INF/lib/log4j-core-2.14.1.jar", &log4j),
            ("BOOT-INF/lib/spring-core-5.3.20.jar", &spring),
            ("BOOT-INF/lib/internal.jar", &unnamed),
            ("BOOT-INF/lib/broken-1.0.jar", broken),
        ]);
        let found = inspect("opt/app.jar", &app);
        let want = [
            Found::Coordinates {
                name: "org.apache.logging.log4j:log4j-core".into(),
                version: "2.14.1".into(),
                path: "opt/app.jar!BOOT-INF/lib/log4j-core-2.14.1.jar".into(),
            },
            Found::FileName {
                artifact: "spring-core".into(),
                version: "5.3.20".into(),
                path: "opt/app.jar!BOOT-INF/lib/spring-core-5.3.20.jar".into(),
                packages: vec!["org/springframework".into()],
                bundle: None,
            },
            Found::Unknown {
                path: "opt/app.jar!BOOT-INF/lib/internal.jar".into(),
            },
        ];
        assert_eq!(found[..3], want[..]);
        assert!(
            matches!(&found[3], Found::Unreadable { path, .. } if path.ends_with("broken-1.0.jar"))
        );
        // `app.jar` itself: an unresolved version names nothing, and its nested jars speak.
        assert_eq!(found.len(), 4);
        // What the image reader keeps reads back the same.
        assert_eq!(parse_digest(&digest("opt/app.jar", &app)), found);
    }

    #[test]
    fn manifests_name_bundles() {
        let text = "Manifest-Version: 1.0\r\nBundle-SymbolicName: org.apache.tomcat-catal\r\n ina;singleton:=true\r\nImplementation-Version: ${v}\r\nBundle-Version: 9.0.50\r\n\r\nName: a/B.class\r\nBundle-Version: 1\r\n";
        let catalina = zip(&[("META-INF/MANIFEST.MF", text.as_bytes())]);
        let found = inspect("lib/catalina.jar", &catalina);
        assert_eq!(
            found,
            vec![Found::Bundle {
                name: "org.apache.tomcat-catalina".into(),
                version: "9.0.50".into(),
                path: "lib/catalina.jar".into(),
            }]
        );
        assert_eq!(parse_digest(&digest("lib/catalina.jar", &catalina)), found);
        // A versioned file name keeps its version, and the bundle name helps place it.
        let found = inspect("lib/h2-2.2.224.jar", &catalina);
        assert!(
            matches!(&found[0], Found::FileName { version, bundle: Some(b), .. }
            if version == "2.2.224" && b == "org.apache.tomcat-catalina")
        );
        // No version to go with the name: nothing to match.
        let bare = zip(&[(
            "META-INF/MANIFEST.MF",
            b"Bundle-SymbolicName: a.b\nBundle-Version: x\n",
        )]);
        assert!(matches!(&inspect("a.jar", &bare)[0], Found::Unknown { .. }));
    }

    #[test]
    fn nesting_is_bounded() {
        let mut inner = zip(&[("a/B.class", b"")]);
        for _ in 0..6 {
            inner = zip(&[("x.jar", &inner)]);
        }
        let found = inspect("top.jar", &inner);
        assert!(found
            .iter()
            .any(|f| matches!(f, Found::Unreadable { reason, .. } if reason.contains("deeply"))));
    }
}
