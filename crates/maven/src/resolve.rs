//! Resolve a `pom.xml` into the dependency tree Maven would build, without running Maven
//! (spec 04). Reads POMs only, never jars or plugins.
//!
//! - **Effective model**: the parent chain (a local `relativePath`, default `../pom.xml`, when
//!   its coordinates match, else the repository), `<properties>` and `${project.*}`
//!   interpolation, `dependencyManagement` merged down the parents and through imported BOMs
//!   (`<scope>import</scope>`), and profiles marked `activeByDefault`.
//! - **Graph**: breadth-first with Maven's mediation: the nearest declaration of an artifact
//!   wins (the first one at equal depth), the root's `dependencyManagement` sets the version
//!   and scope of transitive artifacts, `<exclusions>` (including `*`) prune subtrees, and
//!   `optional` dependencies are not inherited. Scopes follow Maven's propagation table (a
//!   dependency's own `test` and `provided` dependencies are on no classpath) and widen when an
//!   artifact is reached by several paths; `test` and `provided` artifacts are dev scope.
//! - **Ranges** (`[1.0,2.0)`) pick the highest matching version listed in
//!   `maven-metadata.xml`, ordered with the `ComparableVersion` port.
//! - **Reactors**: `<modules>` are resolved from their local POMs, and a dependency on a
//!   sibling module follows that module's dependencies instead of the repository.
//!
//! Where POMs come from is the caller's [`PomSource`]: the local Maven repository, a cache,
//! or a network fetcher. Anything that cannot be resolved (a missing POM, an undefined
//! property, a range with no metadata) is recorded in [`Resolution::missing`] by name, and
//! what did resolve is still returned: the caller reports partial coverage, never a clean one.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use fleetreach_core::DepGraph;
use roxmltree::{Document, Node};

use crate::version::{gradle_cmp, parse_maven_version};

/// Where POMs and version listings come from.
pub trait PomSource {
    /// The POM text of `group:artifact:version`, if available.
    fn pom(&self, group: &str, artifact: &str, version: &str) -> Option<String>;
    /// The `maven-metadata.xml` text of `group:artifact`, if available.
    fn metadata(&self, group: &str, artifact: &str) -> Option<String>;
    /// The Gradle module metadata (`.module`) of `group:artifact:version`, if available. Read
    /// only for Gradle builds, and only when the POM says one was published.
    fn module(&self, _group: &str, _artifact: &str, _version: &str) -> Option<String> {
        None
    }
    /// The version listing of `group:artifact` that the repository `repo_id` gave, kept
    /// beside the local copy as `maven-metadata-<id>.xml`, if available. Maven merges the
    /// listing of every repository a build declares into a range's candidates.
    fn repo_metadata(&self, _group: &str, _artifact: &str, _repo_id: &str) -> Option<String> {
        None
    }
}

/// POMs from local repositories (`~/.m2/repository`, a cache, Gradle's download cache), first hit
/// wins.
pub struct LocalRepositories {
    /// Maven layout: `<group as dirs>/<artifact>/<version>/<artifact>-<version>.pom`.
    pub roots: Vec<PathBuf>,
    /// Gradle's download cache (`~/.gradle/caches/modules-2/files-2.1`): `<group>/<artifact>/
    /// <version>/<sha1>/<file>`, the group kept whole.
    pub gradle_roots: Vec<PathBuf>,
}

impl LocalRepositories {
    /// A file of Gradle's cache, from the first hash folder (in name order) that holds it.
    /// A coordinate that could leave the cache (a separator, `..`) is never looked up.
    fn gradle_file(&self, group: &str, artifact: &str, version: &str, ext: &str) -> Option<String> {
        let plain =
            |s: &str| !s.is_empty() && !s.starts_with('.') && !s.contains(['/', '\\', '\0']);
        if !(plain(group) && plain(artifact) && plain(version)) {
            return None;
        }
        let file = format!("{artifact}-{version}.{ext}");
        self.gradle_roots.iter().find_map(|root| {
            let dir = root.join(group).join(artifact).join(version);
            let mut hashes: Vec<PathBuf> = std::fs::read_dir(&dir)
                .ok()?
                .flatten()
                .map(|e| e.path())
                .collect();
            hashes.sort();
            hashes
                .iter()
                .find_map(|h| fleetreach_core::repofile::read_to_string(h.join(&file)).ok())
        })
    }

    /// Gradle's cache keeps no `maven-metadata.xml`; the versions it holds a POM or `.module`
    /// file of stand in for one, as when Gradle settles a range offline (smack-core's
    /// `[1.0.0, 1.0.999]` jxmpp, 1.0.3 in the cache Gradle filled).
    fn gradle_listing(&self, group: &str, artifact: &str) -> Option<String> {
        let plain =
            |s: &str| !s.is_empty() && !s.starts_with('.') && !s.contains(['/', '\\', '\0']);
        if !(plain(group) && plain(artifact)) {
            return None;
        }
        let mut versions: Vec<String> = Vec::new();
        for root in &self.gradle_roots {
            let Ok(entries) = std::fs::read_dir(root.join(group).join(artifact)) else {
                continue;
            };
            for entry in entries.flatten() {
                let version = entry.file_name().to_string_lossy().to_string();
                // A version name only: nothing that could break the listing's XML.
                let version_like = version
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'));
                if !plain(&version) || !version_like || versions.contains(&version) {
                    continue;
                }
                let held = ["pom", "module"].iter().any(|ext| {
                    std::fs::read_dir(entry.path()).is_ok_and(|hashes| {
                        hashes.flatten().any(|h| {
                            h.path()
                                .join(format!("{artifact}-{version}.{ext}"))
                                .is_file()
                        })
                    })
                });
                if held {
                    versions.push(version);
                }
            }
        }
        if versions.is_empty() {
            return None;
        }
        versions.sort();
        let listed: String = versions
            .iter()
            .map(|v| format!("<version>{v}</version>"))
            .collect();
        Some(format!(
            "<metadata><versioning><versions>{listed}</versions></versioning></metadata>"
        ))
    }

    fn dir(root: &Path, group: &str, artifact: &str) -> PathBuf {
        let mut p = root.to_path_buf();
        for part in group.split('.') {
            p.push(part);
        }
        p.push(artifact);
        p
    }
}

impl PomSource for LocalRepositories {
    fn pom(&self, group: &str, artifact: &str, version: &str) -> Option<String> {
        self.roots
            .iter()
            .find_map(|root| {
                let path = Self::dir(root, group, artifact)
                    .join(version)
                    .join(format!("{artifact}-{version}.pom"));
                fleetreach_core::repofile::read_to_string(path).ok()
            })
            .or_else(|| self.gradle_file(group, artifact, version, "pom"))
    }

    fn metadata(&self, group: &str, artifact: &str) -> Option<String> {
        self.roots
            .iter()
            .find_map(|root| {
                let dir = Self::dir(root, group, artifact);
                ["maven-metadata.xml", "maven-metadata-central.xml"]
                    .iter()
                    .find_map(|f| fleetreach_core::repofile::read_to_string(dir.join(f)).ok())
            })
            .or_else(|| self.gradle_listing(group, artifact))
    }

    fn module(&self, group: &str, artifact: &str, version: &str) -> Option<String> {
        self.roots
            .iter()
            .find_map(|root| {
                let path = Self::dir(root, group, artifact)
                    .join(version)
                    .join(format!("{artifact}-{version}.module"));
                fleetreach_core::repofile::read_to_string(path).ok()
            })
            .or_else(|| self.gradle_file(group, artifact, version, "module"))
    }

    fn repo_metadata(&self, group: &str, artifact: &str, repo_id: &str) -> Option<String> {
        // An id is a file-name part only: anything that could leave the folder is refused.
        let plain = !repo_id.is_empty()
            && repo_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            && !repo_id.contains("..");
        if !plain {
            return None;
        }
        self.roots.iter().find_map(|root| {
            let file =
                Self::dir(root, group, artifact).join(format!("maven-metadata-{repo_id}.xml"));
            fleetreach_core::repofile::read_to_string(file).ok()
        })
    }
}

/// Try each source in order.
pub struct Chain<'a>(pub Vec<&'a dyn PomSource>);

impl PomSource for Chain<'_> {
    fn pom(&self, g: &str, a: &str, v: &str) -> Option<String> {
        self.0.iter().find_map(|s| s.pom(g, a, v))
    }
    fn metadata(&self, g: &str, a: &str) -> Option<String> {
        self.0.iter().find_map(|s| s.metadata(g, a))
    }
    fn module(&self, g: &str, a: &str, v: &str) -> Option<String> {
        self.0.iter().find_map(|s| s.module(g, a, v))
    }
    fn repo_metadata(&self, g: &str, a: &str, id: &str) -> Option<String> {
        self.0.iter().find_map(|s| s.repo_metadata(g, a, id))
    }
}

/// One resolved artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDep {
    /// `group:artifact`.
    pub name: String,
    pub version: String,
    /// Declared by a module of the project itself.
    pub direct: bool,
    /// `test` or `provided` scope: not part of the runtime classpath.
    pub dev: bool,
    pub scope: String,
}

/// The resolved tree of a project.
#[derive(Debug, Default)]
pub struct Resolution {
    pub packages: Vec<ResolvedDep>,
    pub graph: DepGraph,
    /// What could not be resolved, one line per item.
    pub missing: Vec<String>,
}

// ---- POM model ----

#[derive(Debug, Clone, Default)]
struct Dep {
    group: String,
    artifact: String,
    version: Option<String>,
    scope: Option<String>,
    kind: Option<String>,
    classifier: Option<String>,
    optional: bool,
    /// An `<optional>` that names a property (`${prometheus.client.optional}` in the
    /// Kubernetes client), decided when the dependency is interpolated.
    optional_expr: Option<String>,
    exclusions: Vec<(String, String)>,
    /// From Gradle module metadata: a `platform` dependency, whose managed versions and
    /// constraints count as requests.
    platform: bool,
    /// Relocations followed to reach this coordinate, which bounds a relocation cycle.
    hops: u8,
    /// A `system` dependency's `<systemPath>`.
    system_path: Option<String>,
}

impl Dep {
    /// A `system` dependency whose path Maven's model validator rejects: missing, or not
    /// absolute. A property Maven fills from its own environment (`${java.home}`,
    /// `${env.JAVA_HOME}`) counts as absolute.
    fn bad_system_path(&self) -> bool {
        if self.scope.as_deref() != Some("system") {
            return false;
        }
        let Some(path) = self.system_path.as_deref().map(str::trim) else {
            return true;
        };
        let bytes = path.as_bytes();
        let drive = bytes.len() > 2
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\');
        let from_env = ["${env.", "${java.home}", "${user.home}", "${maven.home}"]
            .iter()
            .any(|p| path.starts_with(p));
        !(path.starts_with(['/', '\\']) || drive || from_env)
    }
    fn key(&self) -> (String, String) {
        (self.group.clone(), self.artifact.clone())
    }
    /// The artifact this dependency names as Maven's resolver sees it: group, artifact, file
    /// extension and classifier, a type becoming its extension and default classifier
    /// (`test-jar` is `jar` + `tests`). Mediation and transitive management go by this:
    /// hadoop-minicluster's `test-jar` hadoop-common is hudi's managed `tests` jar.
    fn artifact_key(&self) -> (String, String, String, String) {
        let kind = self.kind.as_deref().unwrap_or("jar");
        let (ext, classifier) = match kind {
            "test-jar" => ("jar", "tests"),
            "ejb-client" => ("jar", "client"),
            "java-source" => ("jar", "sources"),
            "javadoc" => ("jar", "javadoc"),
            "ejb" | "maven-plugin" | "java" => ("jar", ""),
            other => (other, ""),
        };
        let classifier = self
            .classifier
            .clone()
            .filter(|c| !c.is_empty())
            .unwrap_or_else(|| classifier.to_string());
        (
            self.group.clone(),
            self.artifact.clone(),
            ext.to_string(),
            classifier,
        )
    }
    fn mgmt_key(&self) -> (String, String, String, String) {
        (
            self.group.clone(),
            self.artifact.clone(),
            self.kind.clone().unwrap_or_else(|| "jar".into()),
            self.classifier.clone().unwrap_or_default(),
        )
    }
}

#[derive(Debug, Clone, Default)]
struct RawPom {
    group: Option<String>,
    artifact: String,
    version: Option<String>,
    parent: Option<(String, String, String, Option<String>)>,
    properties: BTreeMap<String, String>,
    deps: Vec<Dep>,
    mgmt: Vec<Dep>,
    modules: Vec<String>,
    /// `<distributionManagement><relocation>`: group, artifact and version it moved to, each
    /// `None` when unchanged.
    relocation: Option<(Option<String>, Option<String>, Option<String>)>,
    /// The ids of the `<repositories>` this POM declares.
    repositories: Vec<String>,
}

fn child<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Option<Node<'a, 'i>> {
    node.children()
        .find(|c| c.is_element() && c.tag_name().name() == name)
}

fn children<'a, 'i>(node: Node<'a, 'i>, name: &'a str) -> impl Iterator<Item = Node<'a, 'i>> + 'a {
    node.children()
        .filter(move |c| c.is_element() && c.tag_name().name() == name)
}

fn text(node: Node<'_, '_>, name: &str) -> Option<String> {
    child(node, name)
        .and_then(|c| c.text())
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

fn parse_deps(list: Option<Node<'_, '_>>) -> Vec<Dep> {
    let Some(list) = list else {
        return Vec::new();
    };
    children(list, "dependency")
        .filter_map(|d| {
            Some(Dep {
                group: text(d, "groupId")?,
                artifact: text(d, "artifactId")?,
                version: text(d, "version"),
                scope: text(d, "scope"),
                kind: text(d, "type"),
                classifier: text(d, "classifier"),
                optional: text(d, "optional").is_some_and(|o| maven_true(&o)),
                optional_expr: text(d, "optional").filter(|o| o.contains("${")),
                exclusions: child(d, "exclusions")
                    .map(|ex| {
                        children(ex, "exclusion")
                            .filter_map(|e| Some((text(e, "groupId")?, text(e, "artifactId")?)))
                            .collect()
                    })
                    .unwrap_or_default(),
                platform: false,
                hops: 0,
                system_path: text(d, "systemPath"),
            })
        })
        .collect()
}

/// A copy of `xml` with every element name XML does not allow (a `:` with no namespace, a
/// leading `-`) renamed, open and close tags alike, or `None` when there is none. Maven's
/// parser reads such names: hadoop-project 3.1.4 passes `<Xlint:-unchecked/>` to javac.
fn rename_unreadable_elements(xml: &str) -> Option<String> {
    let valid = |name: &str| {
        let mut chars = name.chars();
        chars.next().is_some_and(|c| c.is_alphabetic() || c == '_')
            && chars.all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_'))
    };
    let mut out = String::with_capacity(xml.len());
    let mut changed = false;
    let mut rest = xml;
    while let Some(at) = rest.find('<') {
        out.push_str(&rest[..=at]);
        rest = &rest[at + 1..];
        let close = rest.starts_with('/');
        if close {
            out.push('/');
            rest = &rest[1..];
        }
        if rest.starts_with(['?', '!']) {
            continue;
        }
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
            .unwrap_or(rest.len());
        let name = &rest[..end];
        if !name.is_empty() && !valid(name) {
            out.push_str("fleetreach-unreadable-element");
            changed = true;
        } else {
            out.push_str(name);
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    changed.then_some(out)
}

/// A copy of `xml` without its `<!DOCTYPE ...>` when the declaration has no internal subset
/// (no `[`), or `None`. Maven's parser skips such a line; oshi-core 6.1.1 starts with
/// `<!DOCTYPE project>`. A declaration with entities stays, so the strict error stands.
fn drop_plain_doctype(xml: &str) -> Option<String> {
    let at = xml.find("<!DOCTYPE")?;
    let len = xml[at..].find('>')? + 1;
    if xml[at..at + len].contains('[') {
        return None;
    }
    Some(format!("{}{}", &xml[..at], &xml[at + len..]))
}

fn parse_pom(xml: &str, gradle: bool) -> Result<RawPom, String> {
    parse_pom_in(xml, gradle, None, &MavenCli::default())
}

/// The `-P` and `-D` arguments of a build's `.mvn/maven.config`, which Maven puts in front
/// of every command line (spring-cloud-gateway's `-P spring`).
#[derive(Debug, Clone, Default)]
struct MavenCli {
    /// Profile ids switched on, for the build's own POMs.
    on: BTreeSet<String>,
    /// Profile ids switched off (`!id` or `-id`).
    off: BTreeSet<String>,
    /// User properties: they decide `<property>` activation and override POM properties.
    props: BTreeMap<String, String>,
}

impl MavenCli {
    /// Read `<dir>/.mvn/maven.config`; a missing or unreadable file is an empty one. Every
    /// other option (`-T1C`, `--no-transfer-progress`) is ignored, and `#` starts a comment.
    fn read(dir: &Path) -> Self {
        let mut cli = Self::default();
        let Ok(text) =
            fleetreach_core::repofile::read_to_string(dir.join(".mvn").join("maven.config"))
        else {
            return cli;
        };
        let tokens: Vec<&str> = text
            .lines()
            .map(|l| l.split('#').next().unwrap_or(""))
            .flat_map(str::split_whitespace)
            .collect();
        let mut i = 0;
        while i < tokens.len() {
            let t = tokens[i];
            i += 1;
            let mut value = |flag: &str, long: &str| -> Option<String> {
                if t == flag || t == long {
                    let v = tokens.get(i).map(|v| (*v).to_string());
                    i += 1;
                    v
                } else {
                    t.strip_prefix(flag)
                        .filter(|v| !v.is_empty())
                        .map(str::to_string)
                }
            };
            if let Some(list) = value("-P", "--activate-profiles") {
                for id in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    match id.strip_prefix(['!', '-']) {
                        Some(off) => cli.off.insert(off.trim_start_matches('?').to_string()),
                        None => cli.on.insert(id.trim_start_matches(['+', '?']).to_string()),
                    };
                }
            } else if let Some(def) = value("-D", "--define") {
                let (k, v) = def.split_once('=').unwrap_or((def.as_str(), "true"));
                if !k.is_empty() {
                    cli.props.insert(k.to_string(), v.to_string());
                }
            }
        }
        cli
    }
}

/// [`parse_pom`] for a POM of this build, in `basedir`, where a profile's `<file>` activation
/// is checked against the checkout and `.mvn/maven.config`'s `-P` ids apply.
fn parse_pom_in(
    xml: &str,
    gradle: bool,
    basedir: Option<&Path>,
    cli: &MavenCli,
) -> Result<RawPom, String> {
    let xml = xml.trim_start_matches('\u{feff}');
    let repaired;
    let doc = match Document::parse(xml) {
        Ok(doc) => doc,
        Err(e) => {
            let plain = drop_plain_doctype(xml);
            let base = plain.as_deref().unwrap_or(xml);
            repaired = rename_unreadable_elements(base)
                .or(plain)
                .ok_or_else(|| e.to_string())?;
            Document::parse(&repaired).map_err(|_| e.to_string())?
        }
    };
    let project = doc.root_element();
    if project.tag_name().name() != "project" {
        return Err("not a POM (no <project>)".into());
    }
    let mut pom = RawPom {
        group: text(project, "groupId"),
        artifact: text(project, "artifactId").ok_or("POM without artifactId")?,
        version: text(project, "version"),
        parent: child(project, "parent").and_then(|p| {
            Some((
                text(p, "groupId")?,
                text(p, "artifactId")?,
                text(p, "version")?,
                child(p, "relativePath").map(|r| r.text().unwrap_or("").trim().to_string()),
            ))
        }),
        ..RawPom::default()
    };
    let absorb = |node: Node<'_, '_>, pom: &mut RawPom| {
        if let Some(props) = child(node, "properties") {
            for p in props.children().filter(Node::is_element) {
                pom.properties.insert(
                    p.tag_name().name().to_string(),
                    p.text().unwrap_or("").trim().to_string(),
                );
            }
        }
        pom.deps.extend(parse_deps(child(node, "dependencies")));
        pom.mgmt.extend(parse_deps(
            child(node, "dependencyManagement").and_then(|m| child(m, "dependencies")),
        ));
    };
    absorb(project, &mut pom);
    let mut profile_modules: Vec<String> = Vec::new();
    if let Some(profiles) = child(project, "profiles") {
        let profiles: Vec<_> = children(profiles, "profile").collect();
        let by_default = |p: &Node<'_, '_>| {
            child(*p, "activation")
                .and_then(|a| text(a, "activeByDefault"))
                .as_deref()
                == Some("true")
        };
        // Gradle honours `activeByDefault` and a system property's absence (`<name>!x</name>`,
        // never set in a build; resteasy's parent imports its BOM so), the default ones only
        // when no absence one is on. Maven also switches profiles on by the build's JDK, and
        // then the default ones only when none other in this POM is on. In the build's own
        // POMs, `-P` ids from `.mvn/maven.config` switch profiles on or off.
        let id = |p: &Node<'_, '_>| text(*p, "id").unwrap_or_default();
        let named = |p: &Node<'_, '_>, set: &BTreeSet<String>| {
            !gradle && basedir.is_some() && set.contains(&id(p))
        };
        let triggered: Vec<_> = if gradle {
            profiles
                .iter()
                .filter(|p| {
                    child(**p, "activation")
                        .and_then(|a| child(a, "property"))
                        .and_then(|prop| text(prop, "name"))
                        .is_some_and(|name| name.trim().starts_with('!'))
                })
                .collect()
        } else {
            profiles
                .iter()
                .filter(|p| !named(p, &cli.off))
                .filter(|p| {
                    named(p, &cli.on)
                        || child(**p, "activation")
                            .is_some_and(|a| maven_activation(a, basedir, &cli.props))
                })
                .collect()
        };
        let active: Vec<_> = if triggered.is_empty() {
            profiles
                .iter()
                .filter(|p| by_default(p) && !named(p, &cli.off))
                .collect()
        } else {
            triggered
        };
        for profile in active {
            absorb(*profile, &mut pom);
            // A profile can add reactor modules (dubbo's `<jdk>[17,)</jdk>` ones).
            if let Some(modules) = child(*profile, "modules") {
                profile_modules.extend(
                    children(modules, "module")
                        .filter_map(|m| m.text().map(|t| t.trim().to_string())),
                );
            }
        }
    }
    pom.repositories = child(project, "repositories")
        .map(|r| {
            children(r, "repository")
                .filter_map(|r| text(r, "id"))
                .collect()
        })
        .unwrap_or_default();
    pom.relocation = child(project, "distributionManagement")
        .and_then(|d| child(d, "relocation"))
        .map(|r| {
            (
                text(r, "groupId"),
                text(r, "artifactId"),
                text(r, "version"),
            )
        });
    if let Some(modules) = child(project, "modules") {
        pom.modules = children(modules, "module")
            .filter_map(|m| m.text().map(|t| t.trim().to_string()))
            .collect();
    }
    for m in profile_modules {
        if !pom.modules.contains(&m) {
            pom.modules.push(m);
        }
    }
    Ok(pom)
}

/// A POM with its parents, properties and managed versions applied.
#[derive(Debug, Clone, Default)]
struct Effective {
    group: String,
    artifact: String,
    deps: Vec<Dep>,
    mgmt: BTreeMap<(String, String, String, String), Dep>,
    modules: Vec<String>,
    /// Properties after this POM (inherited by its children).
    props: BTreeMap<String, String>,
    /// Gradle `dependencyConstraints`: versions requested for artifacts that are present.
    constraints: Vec<Dep>,
    /// Where this POM says the artifact moved (its own relocation, never a parent's).
    relocation: Option<(String, String, String)>,
    /// The management and dependency entries of this POM and its parents as written, parent
    /// first: Maven interpolates what a child inherits with the child's properties.
    raw_mgmt: Vec<Dep>,
    raw_deps: Vec<Dep>,
    /// Built from a POM, so `raw_mgmt` and `raw_deps` are complete.
    raw_inherited: bool,
    /// The `mgmt` entries a `.module` platform takes from the platforms it depends on, not
    /// its own constraints: an `enforcedPlatform` forces only its own.
    nested_mgmt: BTreeSet<(String, String, String, String)>,
}

const MAX_DEPTH: usize = 24;

struct Resolver<'s> {
    source: &'s dyn PomSource,
    cache: BTreeMap<(String, String, String), Option<Effective>>,
    missing: BTreeSet<String>,
    /// Resolving for Gradle: module metadata is read where published.
    gradle: bool,
    /// Project properties that override the same-named property of an imported BOM, as the
    /// Spring dependency-management plugin does (`ext['jackson-bom.version'] = '2.21.7'`).
    bom_overrides: BTreeMap<String, String>,
    /// Inside a BOM the build imports, where `bom_overrides` apply.
    importing: bool,
    /// The folders of this build's modules by artifactId: Maven reads a parent or an imported
    /// BOM from the reactor before any repository (dubbo imports its own dependencies BOM).
    reactor: BTreeMap<String, Vec<PathBuf>>,
    /// The version ranges a Maven walk met, by key: Maven's nearest-wins selector skips a
    /// version that falls outside any of them.
    ranges: BTreeMap<MgmtKey, Vec<String>>,
    /// Every version a Maven walk met for each key, nearest first (a range as its own pick).
    candidates: BTreeMap<MgmtKey, Vec<String>>,
    /// The version that walk selected for each key.
    chosen: BTreeMap<MgmtKey, String>,
    /// Range pins placed at the nearest occurrence, because no occurrence that asks the
    /// pinned version itself was reached.
    loose: BTreeSet<MgmtKey>,
    /// The repository ids this Maven build's own POMs declare.
    repo_ids: BTreeSet<String>,
    /// The build's `.mvn/maven.config` arguments (Maven only).
    cli: MavenCli,
    /// Resolving Gradle's `compileClasspath`: runtime-scoped dependencies are not on it and
    /// take no part in its conflict resolution.
    compile_only: bool,
}

impl Resolver<'_> {
    /// The effective model of a POM text (`dir` for a local `relativePath` parent).
    fn effective(
        &mut self,
        xml: &str,
        dir: Option<&Path>,
        depth: usize,
    ) -> Result<Effective, String> {
        if depth > MAX_DEPTH {
            return Err("parent or BOM chain too deep".into());
        }
        let raw = parse_pom_in(xml, self.gradle, dir, &self.cli)?;
        let parent = match &raw.parent {
            Some((g, a, v, rel)) => {
                let local = dir.and_then(|d| {
                    let rel = rel.clone().unwrap_or_else(|| "../pom.xml".into());
                    if rel.is_empty() {
                        return None;
                    }
                    let mut path = d.join(&rel);
                    if path.is_dir() {
                        path = path.join("pom.xml");
                    }
                    let text = fleetreach_core::repofile::read_to_string(&path).ok()?;
                    let p = parse_pom(&text, self.gradle).ok()?;
                    (p.artifact == *a).then_some((text, path.parent().map(Path::to_path_buf)))
                });
                match local {
                    Some((text, pdir)) => {
                        Some(self.effective(&text, pdir.as_deref(), depth + 1)?)
                    }
                    None => self.remote(g, a, v, depth + 1),
                }
            }
            None => None,
        };
        let group = raw
            .group
            .clone()
            .or_else(|| raw.parent.as_ref().map(|p| p.0.clone()))
            .unwrap_or_default();
        let version = raw
            .version
            .clone()
            .or_else(|| raw.parent.as_ref().map(|p| p.2.clone()))
            .unwrap_or_default();
        // Properties: the parent's, then this POM's, then the project model.
        let mut props: BTreeMap<String, String> =
            parent.as_ref().map(|p| p.props.clone()).unwrap_or_default();
        props.extend(raw.properties.clone());
        // Maven's user properties (`-D`) override what a POM sets.
        if !self.gradle {
            for (k, v) in &self.cli.props {
                props.insert(k.clone(), v.clone());
            }
        }
        if self.importing {
            for (k, v) in &self.bom_overrides {
                if let Some(slot) = props.get_mut(k) {
                    slot.clone_from(v);
                }
            }
        }
        for (k, v) in [
            ("project.groupId", &group),
            ("project.artifactId", &raw.artifact),
            ("project.version", &version),
            ("pom.groupId", &group),
            ("pom.version", &version),
            ("version", &version),
        ] {
            props.insert(k.to_string(), v.clone());
        }
        if let Some((pg, _, pv, _)) = &raw.parent {
            props.insert("project.parent.version".into(), pv.clone());
            props.insert("project.parent.groupId".into(), pg.clone());
            props.insert("parent.version".into(), pv.clone());
        }
        // Maven merges what a POM inherits before interpolating, so a property this POM sets
        // also decides a version its parent manages (`<jackson.version>` under a Boot parent).
        // The merged model lists this POM's entries before its parent's, at every level, so
        // a grandchild tries its parent's imports before its grandparent's (dubbo's Boot 1
        // modules import Boot 1.5 under a parent whose own BOM imports Boot 2.7).
        let inherit = parent.as_ref().filter(|p| p.raw_inherited);
        let own_mgmt_len = raw.mgmt.len();
        let mut raw_mgmt = raw.mgmt.clone();
        raw_mgmt.extend(inherit.map(|p| p.raw_mgmt.clone()).unwrap_or_default());
        // Maven lists a POM's own dependencies before the ones it inherits, which only join
        // when it does not declare them itself: the order decides which of two equally near
        // transitive versions wins (seatunnel's clickhouse-jdbc httpcore 4.4.13 over one
        // under an inherited dependency). Gradle keeps the parent's first.
        let inherited_deps = inherit.map(|p| p.raw_deps.clone()).unwrap_or_default();
        let own_deps_first = !self.gradle;
        let mut raw_deps = if own_deps_first {
            raw.deps.clone()
        } else {
            inherited_deps.clone()
        };
        let own_deps_len = raw.deps.len();
        if own_deps_first {
            raw_deps.extend(inherited_deps);
        } else {
            raw_deps.extend(raw.deps.iter().cloned());
        }
        // A parent read some other way keeps its own resolved entries.
        let mut mgmt = match (&parent, inherit) {
            (Some(p), None) => p.mgmt.clone(),
            _ => BTreeMap::new(),
        };
        let mut imports = Vec::new();
        for (i, d) in raw_mgmt.iter().enumerate() {
            let d = self.interp_dep(d, &props);
            if d.scope.as_deref() == Some("import") {
                imports.push(d);
            } else if i < own_mgmt_len {
                mgmt.insert(d.mgmt_key(), d);
            } else {
                mgmt.entry(d.mgmt_key()).or_insert(d);
            }
        }
        // Imported BOMs add only what this POM (and its parents) did not manage itself.
        for bom in imports {
            let Some(v) = bom.version.clone() else {
                continue;
            };
            let outer = self.importing;
            self.importing |= depth == 0 && !self.bom_overrides.is_empty();
            let eff = self.remote(&bom.group, &bom.artifact, &v, depth + 1);
            self.importing = outer;
            if let Some(eff) = eff {
                for (k, d) in eff.mgmt {
                    mgmt.entry(k).or_insert(d);
                }
            }
        }
        let resolved_parent_deps = match (&parent, inherit) {
            (Some(p), None) => p.deps.clone(),
            _ => Vec::new(),
        };
        let mut deps: Vec<Dep> = if own_deps_first {
            Vec::new()
        } else {
            resolved_parent_deps.clone()
        };
        for (i, d) in raw_deps.iter().enumerate() {
            let mut d = self.interp_dep(d, &props);
            if own_deps_first
                && i >= own_deps_len
                && deps.iter().any(|x| x.mgmt_key() == d.mgmt_key())
            {
                continue;
            }
            if let Some(m) = mgmt.get(&d.mgmt_key()) {
                if d.version.is_none() {
                    d.version.clone_from(&m.version);
                }
                if d.scope.is_none() {
                    d.scope.clone_from(&m.scope);
                }
                if d.exclusions.is_empty() {
                    d.exclusions.clone_from(&m.exclusions);
                }
            }
            // Gradle: every declaration requests its version (a sibling project's too), the
            // highest wins, and the broadest scope.
            // An optional declaration adds nothing in Gradle and changes no other one:
            // netty-common 4.1.3's optional javassist leaves the test-scoped one it inherits
            // from netty-parent off every classpath (Hystrix keeps powermock's 3.18.2-GA).
            if self.gradle {
                if let Some(x) = deps.iter_mut().find(|x| x.mgmt_key() == d.mgmt_key()) {
                    if d.optional {
                        continue;
                    }
                    if x.optional {
                        *x = d;
                        continue;
                    }
                    let plain = |v: &Option<String>| {
                        v.clone()
                            .filter(|v| !v.starts_with(['[', '(']) && !v.ends_with('+'))
                    };
                    if let (Some(new), Some(old)) = (plain(&d.version), plain(&x.version)) {
                        if gradle_cmp(&new, &old) == std::cmp::Ordering::Greater {
                            x.version.clone_from(&d.version);
                        }
                    }
                    let rank = |s: &Option<String>| scope_rank(s.as_deref().unwrap_or("compile"));
                    if rank(&d.scope) > rank(&x.scope) {
                        x.scope.clone_from(&d.scope);
                    }
                    continue;
                }
            }
            // Maven identifies a dependency by group, artifact, type and classifier: a
            // `test-jar` of an artifact is a different dependency from its jar.
            deps.retain(|x| x.mgmt_key() != d.mgmt_key());
            deps.push(d);
        }
        if own_deps_first {
            for d in resolved_parent_deps {
                if !deps.iter().any(|x| x.mgmt_key() == d.mgmt_key()) {
                    deps.push(d);
                }
            }
        }
        let relocation = raw.relocation.map(|(g, a, v)| {
            let interp = |x: Option<String>, default: &str, me: &mut Self| {
                x.map_or_else(
                    || default.to_string(),
                    |x| interpolate(&x, &props, &mut me.missing),
                )
            };
            (
                interp(g, &group, self),
                interp(a, &raw.artifact, self),
                interp(v, &version, self),
            )
        });
        // Gradle keeps a relocation POM as a module of its own and depends on the target
        // (real Gradle lists both `mysql:mysql-connector-java` and `com.mysql:mysql-connector-j`).
        if self.gradle {
            if let Some((g, a, v)) = &relocation {
                if (g, a) != (&group, &raw.artifact) || *v != version {
                    deps.push(Dep {
                        group: g.clone(),
                        artifact: a.clone(),
                        version: Some(v.clone()),
                        ..Dep::default()
                    });
                }
            }
        }
        // flink-table-planner's module is `flink-table-planner_${scala.binary.version}`; Maven
        // names it with the property's value, and its siblings depend on it by that name.
        let artifact = if raw.artifact.contains("${") {
            interpolate(&raw.artifact, &props, &mut self.missing)
        } else {
            raw.artifact
        };
        Ok(Effective {
            group,
            artifact,
            deps,
            mgmt,
            modules: raw.modules,
            props,
            constraints: Vec::new(),
            relocation,
            raw_mgmt,
            raw_deps,
            raw_inherited: true,
            nested_mgmt: BTreeSet::new(),
        })
    }

    fn interp_dep(&mut self, d: &Dep, props: &BTreeMap<String, String>) -> Dep {
        let mut d = d.clone();
        d.group = interpolate(&d.group, props, &mut self.missing);
        d.artifact = interpolate(&d.artifact, props, &mut self.missing);
        d.version = d.version.map(|v| interpolate(&v, props, &mut self.missing));
        d.scope = d.scope.map(|v| interpolate(&v, props, &mut self.missing));
        d.kind = d.kind.map(|v| interpolate(&v, props, &mut self.missing));
        d.classifier = d
            .classifier
            .map(|v| interpolate(&v, props, &mut self.missing));
        d.system_path = d
            .system_path
            .map(|v| interpolate(&v, props, &mut BTreeSet::new()));
        // Exclusions are part of the model too: drill's JDBC driver excludes
        // `${calcite.groupId}:calcite-core` from its java-exec module.
        let mut quiet = BTreeSet::new();
        for (g, a) in &mut d.exclusions {
            *g = interpolate(g, props, &mut quiet);
            *a = interpolate(a, props, &mut quiet);
        }
        // Gradle never treats such a flag as optional: real Gradle lists the Kubernetes
        // client's Google auth libraries (pulsar).
        if let Some(o) = d.optional_expr.take().filter(|_| !self.gradle) {
            d.optional = maven_true(&interpolate(&o, props, &mut self.missing));
        }
        d
    }

    /// The effective model of a repository POM, cached; `None` (recorded as missing) when
    /// it is not available.
    fn remote(&mut self, g: &str, a: &str, v: &str, depth: usize) -> Option<Effective> {
        let key = (g.to_string(), a.to_string(), v.to_string());
        if let Some(hit) = self.cache.get(&key) {
            return hit.clone();
        }
        // Guard against cycles while this POM is being built.
        self.cache.insert(key.clone(), None);
        if let Some(eff) = self.reactor_module(g, a, v, depth) {
            self.cache.insert(key, Some(eff.clone()));
            return Some(eff);
        }
        let result = match self.source.pom(g, a, v) {
            Some(xml) if self.gradle && crate::gradle_module::pom_points_to_module(&xml) => {
                match self.module_effective(g, a, v) {
                    Some(eff) => Some(eff),
                    None => match self.effective(&xml, None, depth) {
                        Ok(eff) => Some(eff),
                        Err(e) => {
                            self.missing.insert(format!("{g}:{a}:{v}: {e}"));
                            None
                        }
                    },
                }
            }
            Some(xml) => match self.effective(&xml, None, depth) {
                Ok(mut eff) => {
                    // Maven refuses a published model whose `system` dependency has no
                    // absolute `<systemPath>` and lists the artifact with no dependencies:
                    // druid 1.2.6 points at `${project.basedir}/lib/openjdk-1.8-tools.jar`.
                    if !self.gradle && eff.deps.iter().any(Dep::bad_system_path) {
                        self.missing.insert(format!(
                            "{g}:{a}:{v}: a system dependency has no absolute systemPath, \
                             so Maven reads none of its dependencies"
                        ));
                        eff.deps.clear();
                    }
                    Some(eff)
                }
                Err(e) => {
                    self.missing.insert(format!("{g}:{a}:{v}: {e}"));
                    None
                }
            },
            None => {
                self.missing
                    .insert(format!("{g}:{a}:{v}: POM not available"));
                None
            }
        };
        self.cache.insert(key, result.clone());
        result
    }

    /// `g:a:v` when it is a module of this build: its own folder's POM, matched on the
    /// coordinates its effective model ends up with.
    fn reactor_module(&mut self, g: &str, a: &str, v: &str, depth: usize) -> Option<Effective> {
        let dirs = self.reactor.get(a)?.clone();
        for d in dirs {
            let Ok(xml) = fleetreach_core::repofile::read_to_string(d.join("pom.xml")) else {
                continue;
            };
            let Ok(eff) = self.effective(&xml, Some(&d), depth) else {
                continue;
            };
            // `project.version` is as written (`${revision}`), so it is interpolated here.
            let mut ignore = BTreeSet::new();
            let version = eff
                .props
                .get("project.version")
                .map(|x| interpolate(x, &eff.props, &mut ignore));
            let group = interpolate(&eff.group, &eff.props, &mut ignore);
            if group == g && version.as_deref() == Some(v) {
                return Some(eff);
            }
        }
        None
    }

    /// The runtime variant of `g:a:v`'s Gradle module metadata as an effective model; `None`
    /// (with a note) when it is not available or has no such variant, so the POM is read.
    fn module_effective(&mut self, g: &str, a: &str, v: &str) -> Option<Effective> {
        let Some(json) = self.source.module(g, a, v) else {
            self.missing.insert(format!(
                "{g}:{a}:{v}: Gradle module metadata not available, read the POM instead"
            ));
            return None;
        };
        let variant = match crate::gradle_module::runtime_variant(&json) {
            Ok(variant) => variant,
            Err(e) => {
                self.missing
                    .insert(format!("{g}:{a}:{v}: {e}, read the POM instead"));
                return None;
            }
        };
        let dep = |d: crate::gradle_module::ModuleDep| Dep {
            group: d.group,
            artifact: d.module,
            version: d.version,
            exclusions: d.excludes,
            platform: d.platform,
            ..Dep::default()
        };
        let mut constraints: Vec<Dep> = variant.constraints.into_iter().map(dep).collect();
        // A platform's constraints are its managed versions, for a BOM imported by the build.
        let mut mgmt: BTreeMap<MgmtKey, Dep> = constraints
            .iter()
            .map(|c| (c.mgmt_key(), c.clone()))
            .collect();
        // And so are those of the platforms it depends on, in turn: micronaut-platform's own
        // constraints are 7, its 73 platform dependencies (micronaut-logging-bom, ...) manage
        // the rest. Where two set one artifact, the higher version holds, as conflict
        // resolution would settle it.
        let nested: Vec<(String, String, String)> = variant
            .dependencies
            .iter()
            .filter(|d| d.platform)
            .filter_map(|d| Some((d.group.clone(), d.module.clone(), d.version.clone()?)))
            .collect();
        let own_keys: BTreeSet<MgmtKey> = mgmt.keys().cloned().collect();
        let mut nested_mgmt = BTreeSet::new();
        for (pg, pa, pv) in nested {
            let Some(inner) = self.remote(&pg, &pa, &pv, 1) else {
                continue;
            };
            for (key, m) in inner.mgmt {
                match mgmt.get(&key) {
                    Some(own)
                        if own.version.as_deref().zip(m.version.as_deref()).is_none_or(
                            |(a, b)| crate::version::gradle_cmp(a, b) != std::cmp::Ordering::Less,
                        ) => {}
                    _ => {
                        if !own_keys.contains(&key) {
                            nested_mgmt.insert(key.clone());
                        }
                        mgmt.insert(key, m);
                    }
                }
            }
        }
        // A constraint of the runtime variant alone does not hold on a compile classpath.
        for c in &mut constraints {
            if variant
                .runtime_only_constraints
                .iter()
                .any(|(g, m)| *g == c.group && *m == c.artifact)
            {
                c.scope = Some("runtime".to_string());
            }
        }
        let api_only = variant.api_only.into_iter().map(|d| Dep {
            scope: Some(COMPILE_ONLY_API.to_string()),
            ..dep(d)
        });
        let runtime_only = variant.runtime_only;
        Some(Effective {
            group: g.to_string(),
            artifact: a.to_string(),
            deps: variant
                .dependencies
                .into_iter()
                .map(|d| {
                    let at_runtime_only = runtime_only
                        .iter()
                        .any(|(g, m)| *g == d.group && *m == d.module);
                    Dep {
                        scope: at_runtime_only.then(|| "runtime".to_string()),
                        ..dep(d)
                    }
                })
                .chain(api_only)
                .collect(),
            mgmt,
            constraints,
            nested_mgmt,
            ..Effective::default()
        })
    }

    /// The published versions of `g:a`: the default listing, merged in a Maven build with
    /// those of the repositories the build declares (flink declares Red Hat's, whose
    /// `lang-tag` 1.7.0.redhat-00003 is the highest match of `[1.4.3,)`).
    fn listed_versions(&mut self, g: &str, a: &str) -> Option<Vec<String>> {
        let mut listed = self
            .source
            .metadata(g, a)
            .map(|xml| metadata_versions(&xml));
        if !self.gradle {
            for id in &self.repo_ids {
                if let Some(xml) = self.source.repo_metadata(g, a, id) {
                    let all = listed.get_or_insert_with(Vec::new);
                    for v in metadata_versions(&xml) {
                        if !all.contains(&v) {
                            all.push(v);
                        }
                    }
                }
            }
        }
        listed
    }

    /// The version Maven's `RELEASE` or `LATEST` stands for: the `<release>` or `<latest>` of
    /// the repository metadata updated last (COLA's state machine asks junit-jupiter
    /// `RELEASE`). Recorded as missing when no metadata names one.
    fn meta_version(&mut self, g: &str, a: &str, which: &str) -> Option<String> {
        let tag = if which == "RELEASE" {
            "release"
        } else {
            "latest"
        };
        let mut files: Vec<String> = self.source.metadata(g, a).into_iter().collect();
        for id in &self.repo_ids {
            files.extend(self.source.repo_metadata(g, a, id));
        }
        let picked = files
            .iter()
            .filter_map(|xml| {
                let doc = Document::parse(xml).ok()?;
                let field = |name: &str| {
                    doc.descendants()
                        .find(|n| {
                            n.tag_name().name() == name
                                && n.parent()
                                    .is_some_and(|p| p.tag_name().name() == "versioning")
                        })
                        .and_then(|n| n.text())
                        .map(|t| t.trim().to_string())
                        .filter(|t| !t.is_empty())
                };
                Some((field("lastUpdated").unwrap_or_default(), field(tag)?))
            })
            .max()
            .map(|(_, v)| v);
        if picked.is_none() {
            self.missing
                .insert(format!("{g}:{a}: no metadata names its {which} version"));
        }
        picked
    }

    /// Maven's collector reads a range's versions lowest first and stops at the first one that
    /// relocates, following the relocation instead (system-rules asks `junit:junit-dep
    /// [4.9,)`: 4.9 and 4.10, then 4.11-beta-1 moves to `junit:junit`, whose conflict the
    /// project's own junit wins). That version, if any; only for ranges of at most 16
    /// published versions, so a wide range never reads every POM.
    fn first_relocating(&mut self, g: &str, a: &str, declared: &str) -> Option<String> {
        let ranges = parse_ranges(declared.trim())?;
        let listed = self.listed_versions(g, a)?;
        let mut matching: Vec<_> = listed
            .into_iter()
            .filter(|v| ranges.iter().any(|r| r.contains(v)))
            .filter_map(|v| parse_maven_version(&v).map(|p| (p, v)))
            .collect();
        if matching.len() > 16 {
            return None;
        }
        matching.sort_by(|x, y| x.0.cmp(&y.0));
        matching.into_iter().map(|(_, v)| v).find(|v| {
            self.remote(g, a, v, 0)
                .and_then(|eff| eff.relocation)
                .is_some_and(|(rg, ra, rv)| {
                    (rg.as_str(), ra.as_str(), rv.as_str()) != (g, a, v.as_str())
                })
        })
    }

    /// A concrete version for a declared one: as is, or the highest listed match of a range.
    fn pick_version(&mut self, g: &str, a: &str, declared: &str) -> Option<String> {
        let declared = declared.trim();
        if !self.gradle && matches!(declared, "RELEASE" | "LATEST") {
            return self.meta_version(g, a, declared);
        }
        // Gradle's prefix version: the highest listed version that starts with what comes
        // before the `+` (Hystrix's `javassist:3.19+` is 3.19.0-GA), `+` alone any version.
        if let Some(prefix) = declared.strip_suffix('+').filter(|_| self.gradle) {
            let Some(listed) = self.listed_versions(g, a) else {
                self.missing.insert(format!(
                    "{g}:{a}: version {declared} needs a version listing"
                ));
                return None;
            };
            let best = listed
                .into_iter()
                .filter(|v| v.starts_with(prefix))
                .max_by(|x, y| gradle_cmp(x, y));
            if best.is_none() {
                self.missing
                    .insert(format!("{g}:{a}: no published version matches {declared}"));
            }
            return best;
        }
        if !declared.starts_with(['[', '(']) {
            return Some(declared.to_string());
        }
        // Maven's resolver takes a range of one version (`[1.53.0]`, `[1,1]`) as that version
        // without reading metadata (grpc-netty-shaded pins grpc-core so).
        if let Some(inner) = declared.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let bounds: Vec<&str> = inner.split(',').map(str::trim).collect();
            let one = match bounds[..] {
                [v] => Some(v),
                [lo, hi] if lo == hi => Some(lo),
                _ => None,
            };
            if let Some(v) = one.filter(|v| !v.is_empty() && !v.contains(['[', ']', '(', ')'])) {
                return Some(v.to_string());
            }
        }
        let ranges = parse_ranges(declared)?;
        let listed = self.listed_versions(g, a);
        let Some(listed) = listed else {
            self.missing.insert(format!(
                "{g}:{a}: range {declared} needs maven-metadata.xml"
            ));
            return None;
        };
        // Gradle orders versions its own way: `[2.2,3)` leaves out 3.0.0-M5, which Maven
        // puts below 3 (ehcache 3.10.8's jaxb-runtime is 2.4.0-b180830.0438).
        let best = if self.gradle {
            listed
                .into_iter()
                .filter(|v| ranges.iter().any(|r| r.contains_gradle(v)))
                .max_by(|x, y| gradle_cmp(x, y))
        } else {
            listed
                .into_iter()
                .filter(|v| ranges.iter().any(|r| r.contains(v)))
                .filter_map(|v| parse_maven_version(&v).map(|p| (p, v)))
                .max_by(|x, y| x.0.cmp(&y.0))
                .map(|(_, v)| v)
        };
        if best.is_none() {
            self.missing
                .insert(format!("{g}:{a}: no published version matches {declared}"));
        }
        best
    }
}

/// Substitute `${name}` (repeatedly, bounded); an undefined property is recorded and left.
fn interpolate(
    s: &str,
    props: &BTreeMap<String, String>,
    missing: &mut BTreeSet<String>,
) -> String {
    let mut out = s.to_string();
    for _ in 0..10 {
        let Some(start) = out.find("${") else {
            return out;
        };
        let Some(end) = out[start..].find('}') else {
            return out;
        };
        let name = &out[start + 2..start + end];
        let Some(value) = props.get(name) else {
            missing.insert(format!("property ${{{name}}} is not defined"));
            return out;
        };
        out = format!("{}{}{}", &out[..start], value, &out[start + end + 1..]);
    }
    out
}

/// The `java.version` a Maven build is assumed to run on, for `<jdk>` profile activation:
/// the current LTS, as the differential oracle runs it.
const JAVA_VERSION: &str = "21.0.5";

/// Maven 3.9's `JdkVersionProfileActivator` range test, which is not the dependency range
/// parser: the text is split on `,` (Java drops trailing empty pieces), each bound loses its
/// brackets, a missing upper bound is open, and versions compare on three numeric parts.
/// dubbo-test-check writes `<jdk>[17,</jdk>`, which Maven reads as 17 and later.
fn jdk_in_range(java: &str, range: &str) -> bool {
    let mut pieces: Vec<&str> = range.split(',').collect();
    while pieces.len() > 1 && pieces.last() == Some(&"") {
        pieces.pop();
    }
    let mut bounds: Vec<(String, bool)> = Vec::new();
    for p in pieces {
        if p.starts_with(['[', '(']) {
            bounds.push((p.replace(['[', '('], ""), p.starts_with('[')));
        } else if p.ends_with([']', ')']) {
            bounds.push((p.replace([']', ')'], ""), p.ends_with(']')));
        } else if p.is_empty() {
            bounds.push((String::new(), false));
        }
    }
    if bounds.len() < 2 {
        bounds.push(("99999999".into(), false));
    }
    let parts = |s: &str, split: &[char]| -> Option<[u64; 3]> {
        let mut out = [0; 3];
        for (slot, t) in out.iter_mut().zip(s.split(split)) {
            *slot = t.trim().parse().ok()?;
        }
        Some(out)
    };
    let kept: String = java
        .chars()
        .filter(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | '_'))
        .collect();
    let Some(value) = parts(&kept, &['.', '-', '_']) else {
        return false;
    };
    // Below (-1), at (0) or above (1) a bound; an open bound passes, a bound Maven
    // cannot read as numbers never matches.
    let relation = |(bound, closed): &(String, bool), left: bool| -> Option<i8> {
        if bound.is_empty() {
            return Some(if left { 1 } else { -1 });
        }
        let b = parts(bound, &['.'])?;
        Some(match value.cmp(&b) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Greater => 1,
            std::cmp::Ordering::Equal if !closed => {
                if left {
                    -1
                } else {
                    1
                }
            }
            std::cmp::Ordering::Equal => 0,
        })
    };
    match relation(&bounds[0], true) {
        Some(0) => true,
        Some(r) if r < 0 => false,
        Some(_) => relation(&bounds[1], false).is_some_and(|r| r <= 0),
        None => false,
    }
}

/// Whether a profile's `<activation>` conditions switch it on in a Maven build, as Maven 3.9
/// decides: every condition present must hold, and at least one must be present. `<jdk>` is
/// matched against [`JAVA_VERSION`] (a `[`/`(` range, else a prefix, `!` negating). `<property>`
/// is matched with no user properties set, so only `!name` or a `!value` holds. `<file>` is
/// checked in the build's own folder (`basedir`) and is off for a published POM. `<os>`
/// depends on the machine that builds, so a profile that names one stays off.
fn maven_activation(
    activation: Node<'_, '_>,
    basedir: Option<&Path>,
    user: &BTreeMap<String, String>,
) -> bool {
    let mut any = false;
    for c in activation.children().filter(Node::is_element) {
        let holds = match c.tag_name().name() {
            "activeByDefault" => continue,
            "jdk" => {
                let jdk = c.text().unwrap_or("").trim();
                let (negate, jdk) = match jdk.strip_prefix('!') {
                    Some(rest) => (true, rest.trim()),
                    None => (false, jdk),
                };
                let matched = if jdk.starts_with(['[', '(']) {
                    jdk_in_range(JAVA_VERSION, jdk)
                } else {
                    !jdk.is_empty() && JAVA_VERSION.starts_with(jdk)
                };
                matched != negate
            }
            "property" => {
                let name = text(c, "name").unwrap_or_default();
                let (negate, name) = match name.strip_prefix('!') {
                    Some(n) => (true, n.to_string()),
                    None => (false, name),
                };
                let set = user.get(&name);
                match text(c, "value").filter(|v| !v.is_empty()) {
                    Some(value) => match value.strip_prefix('!') {
                        Some(not) => set.is_none_or(|v| v != not),
                        None => set.is_some_and(|v| *v == value),
                    },
                    None => set.is_some() != negate,
                }
            }
            "file" => basedir.is_some_and(|b| file_activation(c, b)),
            _ => false,
        };
        if !holds {
            return false;
        }
        any = true;
    }
    any
}

/// A `<file>` activation in `basedir`: `<exists>` (read first) or `<missing>`, relative to the
/// module, `${basedir}` or `${project.basedir}` allowed in front (seata's distribution module
/// is on when `test-suite/test-new-version/pom.xml` exists). A path that names another
/// property, is absolute or climbs out with `..` does not hold.
fn file_activation(file: Node<'_, '_>, basedir: &Path) -> bool {
    let nonempty = |s: &String| !s.is_empty();
    let (path, want) = match (
        text(file, "exists").filter(nonempty),
        text(file, "missing").filter(nonempty),
    ) {
        (Some(p), _) => (p, true),
        (None, Some(p)) => (p, false),
        (None, None) => return false,
    };
    let path = ["${basedir}", "${project.basedir}"]
        .iter()
        .find_map(|b| path.strip_prefix(b))
        .map_or(path.as_str(), |rest| rest.trim_start_matches(['/', '\\']));
    let rel = Path::new(path);
    let plain = rel.components().all(|c| {
        matches!(
            c,
            std::path::Component::Normal(_) | std::path::Component::CurDir
        )
    });
    if path.is_empty() || path.contains("${") || !plain {
        return false;
    }
    basedir.join(rel).exists() == want
}

/// One `[a,b)` style interval; `None` bounds are open.
struct Interval {
    low: Option<(String, bool)>,
    high: Option<(String, bool)>,
}

impl Interval {
    fn contains(&self, v: &str) -> bool {
        let Some(pv) = parse_maven_version(v) else {
            return false;
        };
        let ok_low = self.low.as_ref().is_none_or(|(b, incl)| {
            parse_maven_version(b).is_some_and(|bv| if *incl { pv >= bv } else { pv > bv })
        });
        let ok_high = self.high.as_ref().is_none_or(|(b, incl)| {
            parse_maven_version(b).is_some_and(|bv| if *incl { pv <= bv } else { pv < bv })
        });
        ok_low && ok_high
    }

    /// `contains` in Gradle's version order.
    fn contains_gradle(&self, v: &str) -> bool {
        use std::cmp::Ordering::{Greater, Less};
        let ok_low = self.low.as_ref().is_none_or(|(b, incl)| {
            let o = gradle_cmp(v, b);
            o == Greater || (*incl && o != Less)
        });
        let ok_high = self.high.as_ref().is_none_or(|(b, incl)| {
            let o = gradle_cmp(v, b);
            o == Less || (*incl && o != Greater)
        });
        ok_low && ok_high
    }
}

/// Parse `[1.0,2.0)`, `[1.5,)`, `(,1.0]`, `[1.2]` and unions of them.
fn parse_ranges(spec: &str) -> Option<Vec<Interval>> {
    let mut out = Vec::new();
    let mut rest = spec.trim();
    while !rest.is_empty() {
        let open = rest.chars().next()?;
        if !matches!(open, '[' | '(') {
            return None;
        }
        let close_at = rest.find([']', ')'])?;
        let close = rest[close_at..].chars().next()?;
        let body = &rest[1..close_at];
        let bound = |s: &str, incl: bool| {
            let s = s.trim();
            (!s.is_empty()).then(|| (s.to_string(), incl))
        };
        let interval = match body.split_once(',') {
            Some((lo, hi)) => Interval {
                low: bound(lo, open == '['),
                high: bound(hi, close == ']'),
            },
            None => Interval {
                low: bound(body, true),
                high: bound(body, true),
            },
        };
        out.push(interval);
        rest = rest[close_at + 1..].trim_start_matches(',').trim();
    }
    (!out.is_empty()).then_some(out)
}

fn metadata_versions(xml: &str) -> Vec<String> {
    let Ok(doc) = Document::parse(xml) else {
        return Vec::new();
    };
    doc.descendants()
        .filter(|n| {
            n.tag_name().name() == "version"
                && n.parent()
                    .is_some_and(|p| p.tag_name().name() == "versions")
        })
        .filter_map(|n| n.text().map(|t| t.trim().to_string()))
        .collect()
}

/// The scope of a library's `compileOnlyApi` dependencies, read from Gradle module metadata:
/// on its consumers' compile classpaths (main and test), never on a runtime one.
const COMPILE_ONLY_API: &str = "compile-only-api";

/// Maven's scope of a transitive dependency (`child`) reached through one in `parent`
/// scope; `None` when it is not on any classpath.
fn propagate(parent: &str, child: &str) -> Option<String> {
    let scope = match (parent, child) {
        ("compile" | "provided", COMPILE_ONLY_API) => "provided",
        ("test", COMPILE_ONLY_API) => "test",
        (_, COMPILE_ONLY_API) => return None,
        (_, "test" | "provided" | "system" | "import") => return None,
        ("compile", "compile") => "compile",
        ("compile", "runtime") | ("runtime", "compile" | "runtime") => "runtime",
        ("provided", "compile" | "runtime") => "provided",
        ("test", "compile" | "runtime") => "test",
        // A scope Maven does not know is kept below a compile one and otherwise takes the
        // parent's: kudu-client 1.17.0 lists audience-annotations as `optional`, which still
        // wins mediation in hive's kudu handler.
        ("compile", other) => other,
        ("test" | "runtime" | "provided", _) => parent,
        _ => return None,
    };
    Some(scope.to_string())
}

/// How broad a scope is, for Maven's widening when one artifact is reached by several paths.
fn scope_rank(scope: &str) -> u8 {
    match scope {
        "compile" => 4,
        "runtime" => 3,
        "provided" => 2,
        "test" => 1,
        _ => 0,
    }
}

/// (dependency, depth, parent node, scope, inherited exclusions, root module index)
/// Group, artifact, type and classifier: what mediation compares.
type MgmtKey = (String, String, String, String);
type Pins = BTreeMap<MgmtKey, String>;

type Queue = VecDeque<(Dep, usize, String, String, Vec<(String, String)>, usize)>;

/// Queue an artifact's own dependencies in the scope they inherit (Maven's table): optional
/// and excluded ones are left out; a dependency's own test and provided dependencies are on
/// no classpath.
fn enqueue_children(
    eff: &Effective,
    scope: &str,
    exclusions: &[(String, String)],
    (depth, root_ix): (usize, usize),
    name: &str,
    queue: &mut Queue,
    (compile_only, platform_node): (bool, bool),
) {
    for child in &eff.deps {
        if child.optional {
            continue;
        }
        let child_scope = child.scope.clone().unwrap_or_else(|| "compile".into());
        // A compile classpath takes no runtime dependency at any depth: Gradle maps a POM's
        // `runtime` scope, and what only a `.module`'s runtime variant lists, to the runtime
        // classpath alone (archunit-junit5's engine raises JUnit only at test runtime).
        if compile_only && child_scope == "runtime" {
            continue;
        }
        // And a runtime classpath takes nothing a `.module` lists in its API variant alone
        // (log4j-api's bnd annotations are on zaproxy's compile classpath only).
        if !compile_only && child_scope == COMPILE_ONLY_API {
            continue;
        }
        let Some(next_scope) = propagate(scope, &child_scope) else {
            continue;
        };
        // A declared platform's own dependencies are never followed, but the platforms it
        // depends on are nodes of the graph: Gradle lists micronaut-platform's 73 nested BOMs
        // (micronaut-logging-bom, ...), each again a platform whose nested BOMs are listed.
        let nested_platform = platform_node && child.platform;
        let excluded = exclusions
            .iter()
            .any(|(g, a)| (g == "*" || *g == child.group) && (a == "*" || *a == child.artifact));
        if excluded && !nested_platform {
            continue;
        }
        let mut ex = exclusions.to_vec();
        ex.extend(child.exclusions.iter().cloned());
        let mut child = child.clone();
        // Any platform edge, a library's `.module` naming a BOM too, is the BOM's one node:
        // micronaut-validation's micronaut-core-bom 5.2.3 meets the 5.2.22 micronaut-platform
        // nests, and only the winner is listed.
        if nested_platform || child.platform {
            child.kind = Some("pom".to_string());
        }
        queue.push_back((child, depth + 1, name.to_string(), next_scope, ex, root_ix));
    }
}

/// Resolve the project in `dir` (its `pom.xml` and any `<modules>`).
///
/// # Errors
///
/// When `dir/pom.xml` cannot be read or parsed: failing closed.
pub fn resolve(dir: &Path, source: &dyn PomSource) -> Result<Resolution, String> {
    let (each, missing) = resolve_modules(dir, source)?;
    // Maven mediates each module on its own: one module's nearest version never hides another
    // module's (pooled, arthas's spring-boot starter took junit-jupiter-api 5.8.2 for every
    // module, hiding the 5.10.0 the others get). Distinct versions are all listed.
    let mut packages: Vec<ResolvedDep> = Vec::new();
    let mut at: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut graph = DepGraph::new("(root)");
    for (_, one, g) in each {
        for (from, to) in g.edges() {
            graph.add_edges(from, [to.to_string()]);
        }
        for p in one {
            match at.get(&(p.name.clone(), p.version.clone())) {
                Some(&i) => {
                    let seen = &mut packages[i];
                    seen.direct |= p.direct;
                    seen.dev &= p.dev;
                    if scope_rank(&p.scope) > scope_rank(&seen.scope) {
                        seen.scope.clone_from(&p.scope);
                    }
                }
                None => {
                    at.insert((p.name.clone(), p.version.clone()), packages.len());
                    packages.push(p);
                }
            }
        }
    }
    Ok(Resolution {
        packages,
        graph,
        missing,
    })
}

/// Each reactor module's own resolution (`group:artifact` and its packages), for comparing
/// with Maven's per-module `dependency:tree`. Not a stable API.
///
/// # Errors
///
/// As [`resolve`].
#[doc(hidden)]
pub fn resolve_each_module(
    dir: &Path,
    source: &dyn PomSource,
) -> Result<Vec<(String, Vec<ResolvedDep>)>, String> {
    let (each, _) = resolve_modules(dir, source)?;
    Ok(each.into_iter().map(|(m, p, _)| (m, p)).collect())
}

type ModuleResults = Vec<(String, Vec<ResolvedDep>, DepGraph)>;

fn resolve_modules(
    dir: &Path,
    source: &dyn PomSource,
) -> Result<(ModuleResults, Vec<String>), String> {
    let mut r = Resolver {
        source,
        cache: BTreeMap::new(),
        missing: BTreeSet::new(),
        gradle: false,
        bom_overrides: BTreeMap::new(),
        importing: false,
        reactor: BTreeMap::new(),
        ranges: BTreeMap::new(),
        candidates: BTreeMap::new(),
        chosen: BTreeMap::new(),
        loose: BTreeSet::new(),
        repo_ids: BTreeSet::new(),
        cli: MavenCli::read(dir),
        compile_only: false,
    };
    // Where each module lives, first, so the reactor can serve its own parents and BOMs.
    let mut stack = vec![dir.to_path_buf()];
    let mut seen_dirs = BTreeSet::new();
    while let Some(d) = stack.pop() {
        if !seen_dirs.insert(d.clone()) || seen_dirs.len() > 500 {
            continue;
        }
        let Ok(xml) = fleetreach_core::repofile::read_to_string(d.join("pom.xml")) else {
            continue;
        };
        let Ok(raw) = parse_pom_in(&xml, false, Some(&d), &r.cli) else {
            continue;
        };
        r.repo_ids.extend(raw.repositories.iter().cloned());
        for m in raw.modules.iter().rev() {
            stack.push(d.join(m));
        }
        r.reactor.entry(raw.artifact).or_default().push(d);
    }
    // The reactor: the root POM and every module below it, from local files.
    let mut modules: Vec<Effective> = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    let mut seen_dirs = BTreeSet::new();
    while let Some(d) = stack.pop() {
        if !seen_dirs.insert(d.clone()) || seen_dirs.len() > 500 {
            continue;
        }
        let path = d.join("pom.xml");
        let xml = fleetreach_core::repofile::read_to_string(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let eff = r
            .effective(&xml, Some(&d), 0)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        for m in eff.modules.iter().rev() {
            stack.push(d.join(m));
        }
        modules.push(eff);
    }
    let local: BTreeMap<(String, String), Effective> = modules
        .iter()
        .map(|m| ((m.group.clone(), m.artifact.clone()), m.clone()))
        .collect();

    let mut each = Vec::new();
    for module in &modules {
        let (one, g) = walk_within_ranges(&mut r, module, &local);
        each.push((format!("{}:{}", module.group, module.artifact), one, g));
    }
    Ok((each, r.missing.into_iter().collect()))
}

/// Resolve one POM text the way Gradle does: every version requested anywhere competes and the
/// highest wins. Each pass pins the winners, which can bring in new requests, until nothing
/// rises.
///
/// # Errors
///
/// When `xml` cannot be parsed.
/// Versions the Spring dependency-management plugin sets: its BOMs' managed versions and its
/// `dependency` entries. An artifact the build declares with a version of its own is managed
/// at that version instead (the plugin's `overriddenByDependencies`), for every path to it.
#[derive(Debug, Default)]
pub(crate) struct Enforced {
    pub boms: Vec<(String, String, String)>,
    pub versions: Vec<(String, String, String)>,
    pub keep: BTreeSet<(String, String)>,
    /// `enforcedPlatform(...)`: BOMs and versions forced over everything, `keep` included.
    pub strict_boms: Vec<(String, String, String)>,
    pub strict_versions: Vec<(String, String, String)>,
    /// `resolutionStrategy.eachDependency { ... useVersion(v) }`: the version every request
    /// a rule matches takes, a later rule overriding an earlier one.
    pub rules: Vec<VersionRule>,
    /// The dependency-management plugin applies: every version the project declares itself
    /// is managed on the classpaths that hold it, BOM-managed or not (conductor's test
    /// `jna:5.7.0` over Elasticsearch's 5.10.0).
    pub declared_manage: bool,
}

/// One `useVersion` branch of an `eachDependency` rule, with the conditions around it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VersionRule {
    pub conditions: Vec<RuleCondition>,
    pub version: String,
}

/// `requested.group == "g"`, `requested.name.startsWith("n")`, or the negation of one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleCondition {
    pub on_name: bool,
    pub prefix: bool,
    pub value: String,
    pub negated: bool,
}

impl VersionRule {
    pub(crate) fn matches(&self, group: &str, artifact: &str) -> bool {
        self.conditions.iter().all(|c| {
            let field = if c.on_name { artifact } else { group };
            let hit = if c.prefix {
                field.starts_with(&c.value)
            } else {
                field == c.value
            };
            hit != c.negated
        })
    }
}

pub(crate) fn resolve_gradle_module(
    xml: &str,
    source: &dyn PomSource,
    bom_overrides: &BTreeMap<String, String>,
    enforced: &Enforced,
    compile_only: bool,
) -> Result<Resolution, String> {
    const MAX_PASSES: usize = 32;
    let mut r = Resolver {
        source,
        cache: BTreeMap::new(),
        missing: BTreeSet::new(),
        gradle: true,
        bom_overrides: bom_overrides.clone(),
        importing: false,
        reactor: BTreeMap::new(),
        ranges: BTreeMap::new(),
        candidates: BTreeMap::new(),
        chosen: BTreeMap::new(),
        loose: BTreeSet::new(),
        repo_ids: BTreeSet::new(),
        cli: MavenCli::default(),
        compile_only,
    };
    let modules = vec![r.effective(xml, None, 0)?];
    let local = BTreeMap::new();
    let mut forced = Pins::new();
    let force = |r: &mut Resolver<'_>,
                 forced: &mut Pins,
                 boms: &[(String, String, String)],
                 versions: &[(String, String, String)]| {
        for (g, a, v) in boms {
            r.importing = !r.bom_overrides.is_empty();
            let bom = r.remote(g, a, v, 1);
            r.importing = false;
            let nested = bom.as_ref().map(|b| &b.nested_mgmt);
            for d in bom
                .iter()
                .flat_map(|b| b.mgmt.values())
                .filter(|d| nested.is_none_or(|n| !n.contains(&d.mgmt_key())))
            {
                if let Some(version) = d
                    .version
                    .as_ref()
                    .filter(|v| !v.starts_with(['[', '(']) && !v.ends_with('+'))
                {
                    forced.insert(d.mgmt_key(), version.clone());
                }
            }
        }
        for (g, a, v) in versions {
            forced.insert(
                (g.clone(), a.clone(), "jar".to_string(), String::new()),
                v.clone(),
            );
        }
    };
    force(&mut r, &mut forced, &enforced.boms, &enforced.versions);
    // The declared versions as this POM interpolates them; one declared as a range or a
    // dynamic version is left to conflict resolution.
    let declared: BTreeMap<(String, String), String> = modules[0]
        .deps
        .iter()
        .filter(|d| {
            enforced
                .keep
                .contains(&(d.group.clone(), d.artifact.clone()))
        })
        .filter_map(|d| Some(((d.group.clone(), d.artifact.clone()), d.version.clone()?)))
        .collect();
    forced.retain(|k, _| {
        declared
            .get(&(k.0.clone(), k.1.clone()))
            .is_none_or(|v| !v.starts_with(['[', '(']) && !v.contains(['+', '$']))
    });
    for (key, version) in forced.iter_mut() {
        if let Some(v) = declared.get(&(key.0.clone(), key.1.clone())) {
            version.clone_from(v);
        }
    }
    if enforced.declared_manage {
        for ((group, artifact), version) in &declared {
            if !version.starts_with(['[', '(']) && !version.contains(['+', '$']) {
                forced
                    .entry((
                        group.clone(),
                        artifact.clone(),
                        "jar".to_string(),
                        String::new(),
                    ))
                    .or_insert_with(|| version.clone());
            }
        }
    }
    force(
        &mut r,
        &mut forced,
        &enforced.strict_boms,
        &enforced.strict_versions,
    );
    // An `enforcedPlatform(...)` forces the platform itself too: kestra's jetty-bom 12.0.40
    // holds against the 12.1.10 a nested micronaut BOM asks for.
    for (g, a, v) in &enforced.strict_boms {
        forced.insert(
            (g.clone(), a.clone(), "pom".to_string(), String::new()),
            v.clone(),
        );
    }
    let mut pins = forced.clone();
    for _ in 0..MAX_PASSES {
        let mut requests = Pins::new();
        let (packages, graph) = walk(&mut r, &modules, &local, &pins, Some(&mut requests));
        let before = pins.len();
        let mut raised = false;
        for (key, version) in requests {
            if !forced.contains_key(&key) {
                raised |= raise(&mut pins, key, &version);
            }
        }
        // A rule sets the version of each request it matches; the walk shows which are met.
        for p in &packages {
            let Some((group, artifact)) = p.name.split_once(':') else {
                continue;
            };
            let Some(rule) = enforced
                .rules
                .iter()
                .rev()
                .find(|r| r.matches(group, artifact))
            else {
                continue;
            };
            let key = (
                group.to_string(),
                artifact.to_string(),
                "jar".to_string(),
                String::new(),
            );
            if forced.get(&key) != Some(&rule.version) {
                forced.insert(key.clone(), rule.version.clone());
                pins.insert(key, rule.version.clone());
                raised = true;
            }
        }
        if !raised && before == pins.len() {
            return Ok(Resolution {
                packages,
                graph,
                missing: r.missing.into_iter().collect(),
            });
        }
    }
    let (packages, graph) = walk(&mut r, &modules, &local, &pins, None);
    r.missing
        .insert("version conflicts did not settle".to_string());
    Ok(Resolution {
        packages,
        graph,
        missing: r.missing.into_iter().collect(),
    })
}

/// One module's walk where every selected version satisfies the ranges met on the way, as
/// Maven's `NearestVersionSelector` does: the nearest version outside a range loses to the
/// nearest version that satisfies them all, a range standing for its own pick (zipkin:
/// pulsar-client's bcprov 1.78.1 at depth 2 gives way to bcutil's `[1.81,1.82)`, so 1.81.1;
/// dolphinscheduler: aliyun tea 1.3.1, nearer than tea-openapi's `[1.1.14,2.0.0)` pick 1.4.3,
/// fits and stays). A conflict no version settles keeps nearest-wins.
fn walk_within_ranges(
    r: &mut Resolver<'_>,
    module: &Effective,
    local: &BTreeMap<(String, String), Effective>,
) -> (Vec<ResolvedDep>, DepGraph) {
    let mut pins = Pins::new();
    r.loose.clear();
    for _ in 0..8 {
        r.ranges.clear();
        r.candidates.clear();
        r.chosen.clear();
        let (packages, graph) = walk(r, std::slice::from_ref(module), local, &pins, None);
        let ranges = std::mem::take(&mut r.ranges);
        let mut changed = false;
        for (key, specs) in ranges {
            if pins.contains_key(&key) {
                continue;
            }
            let Some(chosen) = r.chosen.get(&key).cloned() else {
                continue;
            };
            let parsed: Vec<Vec<Interval>> = specs.iter().filter_map(|s| parse_ranges(s)).collect();
            let fits = |v: &str| parsed.iter().all(|rs| rs.iter().any(|i| i.contains(v)));
            if fits(&chosen) {
                continue;
            }
            let pick = r
                .candidates
                .get(&key)
                .and_then(|c| c.iter().find(|v| fits(v)).cloned());
            if let Some(v) = pick {
                pins.insert(key, v);
                changed = true;
            }
        }
        // A pin no occurrence of its own reached is placed at the nearest one instead, so a
        // package is never lost.
        for key in pins.keys() {
            if !r.chosen.contains_key(key) && r.loose.insert(key.clone()) {
                changed = true;
            }
        }
        if !changed {
            r.loose.clear();
            return (packages, graph);
        }
    }
    r.ranges.clear();
    let out = walk(r, std::slice::from_ref(module), local, &pins, None);
    r.loose.clear();
    out
}

/// Keep the higher of `version` and what `pins` holds for `key`, in Gradle's version order
/// (only Gradle resolution raises). True if it rose.
fn raise(pins: &mut Pins, key: MgmtKey, version: &str) -> bool {
    if version.trim().is_empty() {
        return false;
    }
    match pins.get(&key) {
        Some(old) if gradle_cmp(old, version) != std::cmp::Ordering::Less => false,
        _ => {
            pins.insert(key, version.to_string());
            true
        }
    }
}

/// An exclusion list that leaves out every dependency (`transitive = false`).
fn excludes_all(exclusions: &[(String, String)]) -> bool {
    exclusions.iter().any(|(g, a)| g == "*" && a == "*")
}

/// Gradle constraints count as requests for the artifacts they name: a module's own
/// `dependencyConstraints`, and for a platform (BOM) also its managed versions.
/// On a compile classpath, a constraint of the runtime variant alone is left out.
fn request_constraints(
    eff: &Effective,
    platform: bool,
    compile_only: bool,
    requests: Option<&mut Pins>,
) {
    let Some(requests) = requests else {
        return;
    };
    let managed = eff.mgmt.values().filter(|_| platform);
    let held = eff
        .constraints
        .iter()
        .filter(|c| !(compile_only && c.scope.as_deref() == Some("runtime")));
    for c in held.chain(managed) {
        if let Some(v) = c
            .version
            .as_ref()
            .filter(|v| !v.starts_with(['[', '(']) && !v.ends_with('+'))
        {
            raise(requests, c.mgmt_key(), v);
        }
    }
}

/// Maven reads a POM boolean as Java's `Boolean.parseBoolean`: `true` in any case.
fn maven_true(s: &str) -> bool {
    s.trim().eq_ignore_ascii_case("true")
}

/// The build's own module that `dep` names, when its version is the module's: Maven takes a
/// module from the reactor only at its exact version, and reads any other version from a
/// repository (easyexcel manages its own `easyexcel-support` module at the published 3.3.4).
/// An unknown or uninterpolated version still names the module.
fn sibling<'a>(
    local: &'a BTreeMap<(String, String), Effective>,
    dep: &Dep,
    version: Option<&str>,
) -> Option<&'a Effective> {
    let module = local.get(&dep.key())?;
    let Some(wanted) = version.filter(|v| !v.contains("${")) else {
        return Some(module);
    };
    let mut ignore = BTreeSet::new();
    let own = module
        .props
        .get("project.version")
        .map(|v| interpolate(v, &module.props, &mut ignore));
    match own {
        Some(own) if !own.contains("${") && own != wanted => None,
        _ => Some(module),
    }
}

/// Walk the dependency tree from `modules`. `pins` fix an artifact's version wherever it
/// appears; `requests`, when given, collects the highest version each artifact was asked for.
fn walk(
    r: &mut Resolver<'_>,
    modules: &[Effective],
    local: &BTreeMap<(String, String), Effective>,
    pins: &Pins,
    mut requests: Option<&mut Pins>,
) -> (Vec<ResolvedDep>, DepGraph) {
    const ROOT: &str = "(root)";
    let mut graph = DepGraph::new(ROOT);
    // Mediation is per group, artifact, type and classifier, as in Maven.
    let mut selected: BTreeMap<(String, String, String, String), ResolvedDep> = BTreeMap::new();
    let mut order: Vec<(String, String, String, String)> = Vec::new();
    // Each winner's own depth and path exclusions: Maven widens a winner's scope but keeps its
    // subtree (keycloak reaches guava first with `*` excluded, then at compile by grpc).
    let mut winners: BTreeMap<MgmtKey, (usize, Vec<(String, String)>)> = BTreeMap::new();
    // Gradle: the exclusions every path to a module so far shares. A dependency stays out
    // only when every path excludes it (isolating-the-domain: thymeleaf-spring5 excludes ognl
    // from thymeleaf, thymeleaf-extras-java8time does not, and ognl is on the classpath).
    let mut shared_exclusions: BTreeMap<MgmtKey, Vec<(String, String)>> = BTreeMap::new();
    // The widest scope of occurrences a range pin passed over before its winner.
    let mut skipped_scope: BTreeMap<MgmtKey, String> = BTreeMap::new();
    // (dependency, depth, parent node, scope, inherited exclusions, root management)
    let mut queue: Queue = VecDeque::new();
    // Sibling modules walked through so far, with the widest scope each was reached in.
    // Keyed by type and classifier too: keycloak's integration tests take a module as a `pom`
    // with every child excluded, and the same module's jar through keycloak-junit5.
    let mut through: BTreeMap<MgmtKey, String> = BTreeMap::new();
    // A sibling module is queued like any direct dependency, and its own dependencies follow
    // in its turn, a level below every direct one (nacos's adapter pins slf4j-api 1.7.26
    // below an inherited dependency on its nacos-common module, which brings 2.0.13).
    for (i, m) in modules.iter().enumerate() {
        for d in &m.deps {
            let scope = d.scope.clone().unwrap_or_else(|| "compile".into());
            if matches!(scope.as_str(), "system" | "import") {
                continue;
            }
            queue.push_back((
                d.clone(),
                0,
                ROOT.to_string(),
                scope,
                d.exclusions.clone(),
                i,
            ));
        }
    }
    // Maven's resolver manages and mediates by artifact (extension and classifier), Gradle
    // here by the declared type.
    let art_mgmt: Vec<BTreeMap<MgmtKey, &Dep>> = modules
        .iter()
        .map(|m| {
            let mut by_artifact = BTreeMap::new();
            for exact in [true, false] {
                for (k, d) in &m.mgmt {
                    if (d.artifact_key() == *k) == exact {
                        by_artifact.entry(d.artifact_key()).or_insert(d);
                    }
                }
            }
            by_artifact
        })
        .collect();
    let gradle = r.gradle;
    let mgmt_of = |root_ix: usize, key: &MgmtKey| -> Option<&Dep> {
        if gradle {
            modules[root_ix].mgmt.get(key)
        } else {
            art_mgmt[root_ix].get(key).copied()
        }
    };
    while let Some((dep, depth, parent, scope, mut exclusions, root_ix)) = queue.pop_front() {
        if r.compile_only && scope == "runtime" {
            continue;
        }
        let key = if r.gradle {
            dep.mgmt_key()
        } else {
            dep.artifact_key()
        };
        let name = format!("{}:{}", dep.group, dep.artifact);
        // Maven's resolver adds a managed entry's exclusions at every depth (its version only
        // below the direct ones), merged with the dependency's own: Spring Cloud's BOM keeps
        // archaius-core out of eureka-client, and dubbo's keeps audience-annotations out of a
        // zookeeper that lists exclusions of its own.
        if !r.gradle {
            if let Some(m) = mgmt_of(root_ix, &key) {
                exclusions.extend(m.exclusions.iter().cloned());
            }
        }
        graph.add_edges(&parent, [name.clone()]);
        // A direct dependency's version is its own (management already filled a missing one);
        // a transitive one takes the root's management first.
        let managed_version = modules[root_ix]
            .mgmt
            .get(&key)
            .and_then(|m| m.version.as_deref());
        let wanted = if depth == 0 {
            dep.version.as_deref()
        } else {
            managed_version.or(dep.version.as_deref())
        };
        if let Some(sibling) = sibling(local, &dep, wanted) {
            // A sibling module is part of the project, not a package: its dependencies join
            // this module's tree, mediated here. Walked through once per wider scope, which
            // also stops a cycle between modules. A nearer published version of the same
            // artifact already won mediation, and the module is not walked.
            if !r.gradle && selected.contains_key(&key) {
                continue;
            }
            let wider = through
                .get(&key)
                .is_none_or(|seen| scope_rank(&scope) > scope_rank(seen));
            if wider {
                through.insert(key.clone(), scope.clone());
                enqueue_children(
                    sibling,
                    &scope,
                    &exclusions,
                    (depth, root_ix),
                    &name,
                    &mut queue,
                    (r.compile_only, false),
                );
            }
            continue;
        }
        // A module met first holds its place in mediation: guava-testlib's own guava module
        // wins over the guava 32.0.0-jre that truth asks for further down.
        if !r.gradle && through.contains_key(&key) {
            continue;
        }
        if !r.gradle && !pins.contains_key(&key) {
            if let Some(w) = wanted.filter(|w| !w.contains("${")) {
                let is_range = w.trim_start().starts_with(['[', '(']);
                let seen = r.ranges.get(&key).is_some_and(|s| s.iter().any(|s| s == w));
                if is_range && !seen {
                    r.ranges.entry(key.clone()).or_default().push(w.to_string());
                }
                let candidate = if is_range {
                    (!seen)
                        .then(|| r.pick_version(&dep.group, &dep.artifact, w))
                        .flatten()
                } else {
                    Some(w.to_string())
                };
                if let Some(c) = candidate {
                    let list = r.candidates.entry(key.clone()).or_default();
                    if !list.contains(&c) {
                        list.push(c);
                    }
                }
            }
        }
        if let Some(requests) = requests.as_deref_mut() {
            let managed = mgmt_of(root_ix, &key);
            for version in [
                dep.version.as_ref(),
                managed.and_then(|m| m.version.as_ref()),
            ] {
                if let Some(v) = version.filter(|v| !v.starts_with(['[', '(']) && !v.ends_with('+'))
                {
                    raise(requests, key.clone(), v);
                } else if let Some(v) = version.filter(|v| r.gradle && v.ends_with('+')) {
                    // A prefix version is settled before conflict resolution: pygradle's
                    // `junit:4.+` is 4.13.2, which beats spock's 4.12.
                    if let Some(settled) = r.pick_version(&dep.group, &dep.artifact, v) {
                        raise(requests, key.clone(), &settled);
                    }
                }
            }
        }
        if let Some(existing) = selected.get_mut(&key) {
            // Nearest wins for the version; the scope widens to the broadest path
            // (compile > runtime > provided > test), and a widened artifact's own
            // dependencies are followed again in the wider scope. Maven's managed scope holds
            // on every path (seatunnel manages log4j as provided, under hadoop-auth too).
            let managed_scope = (depth > 0 && !r.gradle)
                .then(|| mgmt_of(root_ix, &key))
                .flatten()
                .and_then(|m| m.scope.clone())
                .filter(|s| s != "import");
            let scope = managed_scope.unwrap_or(scope);
            if !existing.direct && scope_rank(&scope) > scope_rank(&existing.scope) {
                existing.scope.clone_from(&scope);
                existing.dev = matches!(scope.as_str(), "test" | "provided");
                let version = existing.version.clone();
                let (depth, exclusions) = winners
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| (depth, exclusions.clone()));
                if let Some(eff) = r.remote(&dep.group, &dep.artifact, &version, 0) {
                    if !excludes_all(&exclusions) {
                        request_constraints(
                            &eff,
                            dep.platform,
                            r.compile_only,
                            requests.as_deref_mut(),
                        );
                    }
                    enqueue_children(
                        &eff,
                        &scope,
                        &exclusions,
                        (depth, root_ix),
                        &name,
                        &mut queue,
                        (
                            r.compile_only,
                            r.gradle && dep.kind.as_deref() == Some("pom"),
                        ),
                    );
                }
            }
            if let Some(seen) = shared_exclusions.get_mut(&key) {
                // What both exclude, wildcards included: `io.netty:*` on one path and
                // `io.netty:netty-codec` on the other leave netty-codec out on both.
                let covers = |set: &[(String, String)], (g, a): &(String, String)| {
                    set.iter()
                        .any(|(pg, pa)| (pg == "*" || pg == g) && (pa == "*" || pa == a))
                };
                let mut kept: Vec<(String, String)> = seen
                    .iter()
                    .filter(|e| covers(&exclusions, e))
                    .cloned()
                    .collect();
                for e in &exclusions {
                    if covers(seen, e) && !kept.contains(e) {
                        kept.push(e.clone());
                    }
                }
                // Narrower when something `seen` excluded is no longer excluded.
                let narrower = seen.iter().any(|e| !covers(&kept, e));
                if narrower {
                    seen.clone_from(&kept);
                    let (version, scope) = (existing.version.clone(), existing.scope.clone());
                    if let Some(eff) = r.remote(&dep.group, &dep.artifact, &version, 0) {
                        enqueue_children(
                            &eff,
                            &scope,
                            &kept,
                            (depth, root_ix),
                            &name,
                            &mut queue,
                            (
                                r.compile_only,
                                r.gradle && dep.kind.as_deref() == Some("pom"),
                            ),
                        );
                    }
                }
            }
            continue;
        }
        // The root's management sets transitive versions and scopes.
        let managed = (depth > 0).then(|| mgmt_of(root_ix, &key)).flatten();
        // A Maven range pin goes to the nearest occurrence that asks for the pinned version
        // itself, which keeps that node's own subtree and exclusions (seatunnel: vitess's
        // grpc-core 1.33.0 wins, not firestore's, which excludes grpc-api from it).
        if let Some(pin) = pins
            .get(&key)
            .filter(|_| !r.gradle && !r.loose.contains(&key))
        {
            let own = managed
                .and_then(|m| m.version.clone())
                .or(dep.version.clone())
                .and_then(|v| r.pick_version(&dep.group, &dep.artifact, &v));
            if own.as_ref() != Some(pin) {
                // Its scope still counts: Maven widens the winner over every occurrence.
                let s = match managed.and_then(|m| m.scope.clone()) {
                    Some(s) if depth > 0 && s != "import" => s,
                    _ => scope,
                };
                let wide = skipped_scope.entry(key).or_insert_with(|| s.clone());
                if scope_rank(&s) > scope_rank(wide) {
                    *wide = s;
                }
                continue;
            }
        }
        let declared = pins
            .get(&key)
            .cloned()
            .or_else(|| managed.and_then(|m| m.version.clone()))
            .or(dep.version.clone());
        let Some(declared) = declared else {
            r.missing
                .insert(format!("{name}: no version (not managed)"));
            continue;
        };
        // A property no POM in reach defines (its parent missing): never a version to list.
        if declared.contains("${") {
            r.missing.insert(format!(
                "{name}: version `{declared}` names an undefined property"
            ));
            continue;
        }
        let scope = match managed.and_then(|m| m.scope.clone()) {
            Some(s) if depth > 0 && s != "import" => s,
            _ => scope,
        };
        let scope = match skipped_scope.remove(&key) {
            Some(s) if scope_rank(&s) > scope_rank(&scope) => s,
            _ => scope,
        };
        let Some(mut version) = r.pick_version(&dep.group, &dep.artifact, &declared) else {
            continue;
        };
        if !r.gradle && declared.trim_start().starts_with(['[', '(']) {
            if let Some(v) = r.first_relocating(&dep.group, &dep.artifact, &declared) {
                version = v;
            }
        }
        // Maven resolves a relocated artifact (`<distributionManagement><relocation>`) as its
        // new coordinate; each source moves once, so a cycle stops. Gradle does not follow
        // relocations (real Gradle keeps `junit:junit-dep` and `mysql:mysql-connector-java`).
        if !r.gradle {
            let moved = r
                .remote(&dep.group, &dep.artifact, &version, 0)
                .and_then(|eff| eff.relocation);
            if let Some(to) = moved {
                // The resolver selects a relocated dependency again, now with its managed
                // scope, and a transitive `provided` or `test` one is left out: seatunnel
                // manages slf4j-log4j12 as provided, and 1.7.36 relocates to slf4j-reload4j.
                let own_scope = managed.and_then(|m| m.scope.as_deref());
                if depth > 0 && matches!(own_scope, Some("provided" | "test")) {
                    continue;
                }
                let from = (dep.group.clone(), dep.artifact.clone(), version.clone());
                // Every path relocates (linkis reaches slf4j-log4j12 by a test path and a
                // compile one, and Maven lists only slf4j-reload4j); a chain stops at 8 hops.
                if to != from && dep.hops < 8 {
                    let (g, a, v) = to;
                    let mut next = dep.clone();
                    next.group = g;
                    next.artifact = a;
                    next.version = Some(v);
                    next.hops = dep.hops + 1;
                    queue.push_front((next, depth, parent, scope, exclusions, root_ix));
                    continue;
                }
            }
        }
        selected.insert(
            key.clone(),
            ResolvedDep {
                name: name.clone(),
                version: version.clone(),
                direct: depth == 0,
                dev: matches!(scope.as_str(), "test" | "provided"),
                scope: scope.clone(),
            },
        );
        if r.gradle {
            shared_exclusions.insert(key.clone(), exclusions.clone());
        } else {
            r.chosen.insert(key.clone(), version.clone());
            winners.insert(key.clone(), (depth, exclusions.clone()));
        }
        order.push(key);
        let Some(eff) = r.remote(&dep.group, &dep.artifact, &version, 0) else {
            continue;
        };
        // `transitive = false` (or an exclude of everything) leaves out the module's
        // constraints as well as its dependencies (PlotSquared's FAWE pins Gson otherwise).
        if !excludes_all(&exclusions) {
            request_constraints(&eff, dep.platform, r.compile_only, requests.as_deref_mut());
        }
        enqueue_children(
            &eff,
            &scope,
            &exclusions,
            (depth, root_ix),
            &name,
            &mut queue,
            (
                r.compile_only,
                r.gradle && dep.kind.as_deref() == Some("pom"),
            ),
        );
    }
    let packages = order
        .into_iter()
        .filter_map(|k| selected.remove(&k))
        .collect();
    (packages, graph)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn gradle_cache_files_are_found_by_hash_folder_and_cannot_escape() {
        let root = std::env::temp_dir().join(format!("fr-gradle-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("org.acme").join("lib").join("1.0").join("3f2a");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("lib-1.0.pom"), "<project/>").unwrap();
        std::fs::write(dir.join("lib-1.0.module"), "{}").unwrap();
        std::fs::write(root.join("secret.pom"), "no").unwrap();
        let local = LocalRepositories {
            roots: Vec::new(),
            gradle_roots: vec![root.clone()],
        };
        assert_eq!(
            local.pom("org.acme", "lib", "1.0").as_deref(),
            Some("<project/>")
        );
        assert_eq!(
            local.module("org.acme", "lib", "1.0").as_deref(),
            Some("{}")
        );
        assert!(local.pom("org.acme", "lib", "2.0").is_none());
        assert!(local.pom("..", "..", "..").is_none());
        assert!(local.pom("org.acme/../..", "lib", "1.0").is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn repository_listings_are_read_by_plain_id_only() {
        let root = std::env::temp_dir().join(format!("fr-repo-meta-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("org").join("acme").join("lib");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("maven-metadata-redhat.xml"), "<metadata/>").unwrap();
        std::fs::write(root.join("org").join("maven-metadata-x.xml"), "no").unwrap();
        let local = LocalRepositories {
            roots: vec![root.clone()],
            gradle_roots: Vec::new(),
        };
        assert_eq!(
            local.repo_metadata("org.acme", "lib", "redhat").as_deref(),
            Some("<metadata/>")
        );
        assert!(local.repo_metadata("org.acme", "lib", "other").is_none());
        assert!(local.repo_metadata("org.acme", "lib", "../../x").is_none());
        assert!(local.repo_metadata("org.acme", "lib", "").is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// POMs in memory, keyed `g:a:v`.
    struct Mem(BTreeMap<String, String>);

    impl PomSource for Mem {
        fn pom(&self, g: &str, a: &str, v: &str) -> Option<String> {
            self.0.get(&format!("{g}:{a}:{v}")).cloned()
        }
        fn metadata(&self, g: &str, a: &str) -> Option<String> {
            self.0.get(&format!("{g}:{a}:metadata")).cloned()
        }
        fn repo_metadata(&self, g: &str, a: &str, id: &str) -> Option<String> {
            self.0.get(&format!("{g}:{a}:metadata-{id}")).cloned()
        }
    }

    fn pom(g: &str, a: &str, v: &str, body: &str) -> String {
        format!("<project><modelVersion>4.0.0</modelVersion><groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version>{body}</project>")
    }

    fn dep(g: &str, a: &str, v: &str, extra: &str) -> String {
        format!("<dependency><groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version>{extra}</dependency>")
    }

    fn project(dir_name: &str, body: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fr-mvn-{dir_name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pom.xml"), pom("com.acme", "app", "1.0", body)).unwrap();
        dir
    }

    fn rows(r: &Resolution) -> Vec<(String, String, bool, bool)> {
        r.packages
            .iter()
            .map(|p| (p.name.clone(), p.version.clone(), p.direct, p.dev))
            .collect()
    }

    #[test]
    fn nearest_wins_exclusions_optional_and_scopes() {
        let repo = Mem(BTreeMap::from([
            (
                "g:a:1".to_string(),
                pom(
                    "g",
                    "a",
                    "1",
                    &format!(
                        "<dependencies>{}{}{}</dependencies>",
                        dep("g", "c", "2", ""),
                        dep("g", "opt", "1", "<optional>true</optional>"),
                        dep("g", "t", "1", "<scope>test</scope>")
                    ),
                ),
            ),
            (
                "g:b:1".to_string(),
                pom(
                    "g",
                    "b",
                    "1",
                    &format!(
                        "<dependencies>{}{}</dependencies>",
                        dep("g", "c", "3", ""),
                        dep("g", "gone", "1", "")
                    ),
                ),
            ),
            ("g:c:2".to_string(), pom("g", "c", "2", "")),
            ("g:c:3".to_string(), pom("g", "c", "3", "")),
            ("g:junit:4".to_string(), pom("g", "junit", "4", "")),
        ]));
        let dir = project(
            "nearest",
            &format!(
                "<dependencies>{}{}{}</dependencies>",
                dep("g", "a", "1", ""),
                dep("g", "b", "1", "<exclusions><exclusion><groupId>g</groupId><artifactId>gone</artifactId></exclusion></exclusions>"),
                dep("g", "junit", "4", "<scope>test</scope>")
            ),
        );
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(
            rows(&r),
            vec![
                ("g:a".into(), "1".into(), true, false),
                ("g:b".into(), "1".into(), true, false),
                ("g:junit".into(), "4".into(), true, true),
                // c at depth 1 through a (declared first) wins over b's c:3.
                ("g:c".into(), "2".into(), false, false),
            ]
        );
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(r.graph.chain_to("g:c"), vec!["(root)", "g:a", "g:c"]);
    }

    #[test]
    fn parent_properties_management_and_bom_imports() {
        let repo = Mem(BTreeMap::from([
            (
                "com.acme:parent:5".to_string(),
                pom("com.acme", "parent", "5", &format!(
                    "<properties><lib.version>2.17.1</lib.version></properties>\
                     <dependencyManagement><dependencies>{}{}</dependencies></dependencyManagement>",
                    dep("org.apache.logging.log4j", "log4j-core", "${lib.version}", ""),
                    dep("org.bom", "bom", "1", "<type>pom</type><scope>import</scope>"))),
            ),
            ("org.bom:bom:1".to_string(), pom("org.bom", "bom", "1", &format!(
                "<dependencyManagement><dependencies>{}{}</dependencies></dependencyManagement>",
                dep("com.fasterxml.jackson.core", "jackson-databind", "2.9.8", ""),
                dep("org.apache.logging.log4j", "log4j-core", "2.0", "")))),
            ("org.apache.logging.log4j:log4j-core:2.17.1".to_string(), pom("org.apache.logging.log4j", "log4j-core", "2.17.1", "")),
            ("com.fasterxml.jackson.core:jackson-databind:2.9.8".to_string(), pom("com.fasterxml.jackson.core", "jackson-databind", "2.9.8", "")),
        ]));
        let dir = std::env::temp_dir().join(format!("fr-mvn-parent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("pom.xml"),
            "<project><parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>5</version><relativePath/></parent>\
             <artifactId>app</artifactId><dependencies>\
             <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId></dependency>\
             <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId></dependency>\
             </dependencies></project>",
        )
        .unwrap();
        let r = resolve(&dir, &repo).unwrap();
        // The parent's own management (from a property) wins over the BOM's.
        assert_eq!(
            rows(&r),
            vec![
                (
                    "org.apache.logging.log4j:log4j-core".into(),
                    "2.17.1".into(),
                    true,
                    false
                ),
                (
                    "com.fasterxml.jackson.core:jackson-databind".into(),
                    "2.9.8".into(),
                    true,
                    false
                ),
            ]
        );
    }

    #[test]
    fn a_test_jar_does_not_replace_the_jar_of_the_same_artifact() {
        let repo = Mem(BTreeMap::from([
            (
                "g:core:1".to_string(),
                pom(
                    "g",
                    "core",
                    "1",
                    &format!(
                        "<dependencies>{}{}</dependencies>",
                        dep("g", "api", "1", ""),
                        dep("g", "api", "1", "<type>test-jar</type><scope>test</scope>")
                    ),
                ),
            ),
            ("g:api:1".to_string(), pom("g", "api", "1", "")),
        ]));
        let dir = project(
            "testjar",
            &format!("<dependencies>{}</dependencies>", dep("g", "core", "1", "")),
        );
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(rows(&r)[1], ("g:api".into(), "1".into(), false, false));
    }

    #[test]
    fn root_management_overrides_transitive_versions() {
        let repo = Mem(BTreeMap::from([
            (
                "g:a:1".to_string(),
                pom(
                    "g",
                    "a",
                    "1",
                    &format!("<dependencies>{}</dependencies>", dep("g", "c", "1.0", "")),
                ),
            ),
            ("g:c:1.5".to_string(), pom("g", "c", "1.5", "")),
        ]));
        let dir = project("mgmt", &format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement><dependencies>{}</dependencies>",
            dep("g", "c", "1.5", ""), dep("g", "a", "1", "")));
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(rows(&r)[1], ("g:c".into(), "1.5".into(), false, false));
    }

    #[test]
    fn a_profile_adds_reactor_modules() {
        // dubbo builds dubbo-mcp only in a `<jdk>[17,)</jdk>` profile; a JDK 8 profile's
        // module is left out.
        let dir = project(
            "profile-modules",
            "<packaging>pom</packaging><modules><module>core</module></modules><profiles>\
                 <profile><id>new</id><activation><jdk>[17,)</jdk></activation>\
                 <modules><module>mcp</module></modules></profile>\
                 <profile><id>old</id><activation><jdk>1.8</jdk></activation>\
                 <modules><module>legacy</module></modules></profile></profiles>",
        );
        for (m, a) in [("core", "c"), ("mcp", "m"), ("legacy", "l")] {
            std::fs::create_dir_all(dir.join(m)).unwrap();
            std::fs::write(
                dir.join(m).join("pom.xml"),
                pom(
                    "com.acme",
                    m,
                    "1.0",
                    &format!("<dependencies>{}</dependencies>", dep("g", a, "1", "")),
                ),
            )
            .unwrap();
        }
        let repo = Mem(BTreeMap::from([
            ("g:c:1".to_string(), pom("g", "c", "1", "")),
            ("g:m:1".to_string(), pom("g", "m", "1", "")),
            ("g:l:1".to_string(), pom("g", "l", "1", "")),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        let mut got: Vec<_> = rows(&r).into_iter().map(|(n, _, _, _)| n).collect();
        got.sort();
        assert_eq!(got, ["g:c", "g:m"], "{:?}", r.missing);
    }

    #[test]
    fn each_reactor_module_mediates_its_own_versions() {
        // arthas: one module pins junit-jupiter-api 5.8.2, another reaches 5.10.0. Maven
        // builds each module apart, so both versions ship; one pooled walk kept only one.
        let dir = project(
            "per-module",
            "<packaging>pom</packaging><modules><module>a</module><module>b</module></modules>",
        );
        let deps = [
            ("a", dep("g", "api", "1", "")),
            ("b", dep("g", "lib", "1", "")),
        ];
        for (m, d) in deps {
            std::fs::create_dir_all(dir.join(m)).unwrap();
            std::fs::write(
                dir.join(m).join("pom.xml"),
                pom(
                    "com.acme",
                    m,
                    "1.0",
                    &format!("<dependencies>{d}</dependencies>"),
                ),
            )
            .unwrap();
        }
        let repo = Mem(BTreeMap::from([
            ("g:api:1".to_string(), pom("g", "api", "1", "")),
            ("g:api:2".to_string(), pom("g", "api", "2", "")),
            (
                "g:lib:1".to_string(),
                pom(
                    "g",
                    "lib",
                    "1",
                    &format!("<dependencies>{}</dependencies>", dep("g", "api", "2", "")),
                ),
            ),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        let mut got: Vec<_> = rows(&r).into_iter().map(|(n, v, d, _)| (n, v, d)).collect();
        got.sort();
        assert_eq!(
            got,
            [
                ("g:api".to_string(), "1".to_string(), true),
                ("g:api".to_string(), "2".to_string(), false),
                ("g:lib".to_string(), "1".to_string(), true),
            ],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn sibling_modules_are_walked_through_not_listed() {
        // nacos: the server depends on nacos-api, which depends on nacos-common. Both are
        // the project's own modules, so only their published dependencies are listed, and a
        // cycle between modules stops.
        let dir = project(
            "siblings",
            "<packaging>pom</packaging><modules><module>server</module><module>api</module>\
             <module>common</module></modules>",
        );
        let deps = [
            ("server", dep("com.acme", "api", "1.0", "")),
            ("api", dep("com.acme", "common", "1.0", "")),
            (
                "common",
                format!(
                    "{}{}",
                    dep("g", "lib", "1", ""),
                    dep("com.acme", "api", "1.0", "<scope>test</scope>")
                ),
            ),
        ];
        for (m, d) in deps {
            std::fs::create_dir_all(dir.join(m)).unwrap();
            std::fs::write(
                dir.join(m).join("pom.xml"),
                pom(
                    "com.acme",
                    m,
                    "1.0",
                    &format!("<dependencies>{d}</dependencies>"),
                ),
            )
            .unwrap();
        }
        let repo = Mem(BTreeMap::from([
            ("g:lib:1".to_string(), pom("g", "lib", "1", "")),
            // A published copy of a module must not stand in for the module itself.
            (
                "com.acme:api:1.0".to_string(),
                pom("com.acme", "api", "1.0", ""),
            ),
            (
                "com.acme:common:1.0".to_string(),
                pom("com.acme", "common", "1.0", ""),
            ),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(
            rows(&r),
            [("g:lib".to_string(), "1".to_string(), true, false)],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn a_nearer_version_outside_a_range_gives_way() {
        // zipkin: pulsar-client asks bcprov 1.78.1 at depth 2, its bcutil `[1.81,1.82)` at
        // depth 3; Maven selects 1.81.1, the range's pick.
        let dir = project(
            "range-wins",
            &format!(
                "<dependencies>{}{}</dependencies>",
                dep("g", "a", "1", ""),
                dep("g", "b", "1", "")
            ),
        );
        let deps = |d: String| format!("<dependencies>{d}</dependencies>");
        let repo = Mem(BTreeMap::from([
            (
                "g:a:1".to_string(),
                pom("g", "a", "1", &deps(dep("g", "x", "1", ""))),
            ),
            (
                "g:b:1".to_string(),
                pom("g", "b", "1", &deps(dep("g", "c", "1", ""))),
            ),
            (
                "g:c:1".to_string(),
                pom("g", "c", "1", &deps(dep("g", "x", "[2,3)", ""))),
            ),
            ("g:x:1".to_string(), pom("g", "x", "1", "")),
            ("g:x:2.5".to_string(), pom("g", "x", "2.5", "")),
            (
                "g:x:metadata".to_string(),
                "<metadata><versioning><versions><version>1</version><version>2</version>\
                 <version>2.5</version><version>3</version></versions></versioning></metadata>"
                    .to_string(),
            ),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        let x: Vec<_> = r.packages.iter().filter(|p| p.name == "g:x").collect();
        assert_eq!(x.len(), 1);
        assert_eq!(x[0].version, "2.5", "{:?}", r.missing);
        // The nearest version that fits wins over the range's own pick (dolphinscheduler:
        // aliyun tea 1.3.1 stays under tea-openapi's `[1.1.14,2.0.0)`).
        let mut repo = repo;
        repo.0.insert(
            "g:b:1".to_string(),
            pom(
                "g",
                "b",
                "1",
                &deps(format!(
                    "{}{}",
                    dep("g", "x", "2.2", ""),
                    dep("g", "c", "1", "")
                )),
            ),
        );
        repo.0
            .insert("g:x:2.2".to_string(), pom("g", "x", "2.2", ""));
        let r = resolve(&dir, &repo).unwrap();
        let x: Vec<_> = r.packages.iter().filter(|p| p.name == "g:x").collect();
        assert_eq!(x[0].version, "2.2", "{:?}", r.missing);
    }

    #[test]
    fn a_module_holds_its_place_in_mediation() {
        // guava-testlib: its own guava module, then truth asking guava 32.0.0-jre deeper.
        let dir = project(
            "module-mediates",
            "<packaging>pom</packaging><modules><module>testlib</module><module>core</module>\
             </modules>",
        );
        let modules = [
            (
                "testlib",
                format!(
                    "{}{}",
                    dep("com.acme", "core", "1.0", ""),
                    dep("g", "truth", "1", "")
                ),
            ),
            ("core", String::new()),
        ];
        for (m, d) in modules {
            std::fs::create_dir_all(dir.join(m)).unwrap();
            let body = format!("<dependencies>{d}</dependencies>");
            std::fs::write(
                dir.join(m).join("pom.xml"),
                pom("com.acme", m, "1.0", &body),
            )
            .unwrap();
        }
        let repo = Mem(BTreeMap::from([
            (
                "g:truth:1".to_string(),
                pom(
                    "g",
                    "truth",
                    "1",
                    &format!(
                        "<dependencies>{}</dependencies>",
                        dep("com.acme", "core", "0.9", "")
                    ),
                ),
            ),
            (
                "com.acme:core:0.9".to_string(),
                pom("com.acme", "core", "0.9", ""),
            ),
        ]));
        let each = resolve_each_module(&dir, &repo).unwrap();
        let testlib = each.iter().find(|(m, _)| m == "com.acme:testlib").unwrap();
        let names: Vec<_> = testlib.1.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["g:truth"], "{each:?}");
    }

    #[test]
    fn a_sibling_as_a_pom_and_as_a_jar_is_walked_for_each() {
        // keycloak's quarkus integration tests: the server-deployment module as a `pom` with
        // every child excluded, and its jar again through keycloak-junit5.
        let dir = project(
            "sibling-types",
            "<packaging>pom</packaging><modules><module>tests</module><module>junit</module>\
             <module>deploy</module></modules>",
        );
        let excl_all = "<type>pom</type><exclusions><exclusion><groupId>*</groupId>\
                        <artifactId>*</artifactId></exclusion></exclusions>";
        let modules = [
            (
                "tests",
                format!(
                    "{}{}",
                    dep("com.acme", "deploy", "1.0", excl_all),
                    dep("com.acme", "junit", "1.0", "")
                ),
            ),
            ("junit", dep("com.acme", "deploy", "1.0", "")),
            ("deploy", dep("g", "lib", "1", "")),
        ];
        for (m, d) in modules {
            std::fs::create_dir_all(dir.join(m)).unwrap();
            let body = format!("<dependencies>{d}</dependencies>");
            std::fs::write(
                dir.join(m).join("pom.xml"),
                pom("com.acme", m, "1.0", &body),
            )
            .unwrap();
        }
        let repo = Mem(BTreeMap::from([(
            "g:lib:1".to_string(),
            pom("g", "lib", "1", ""),
        )]));
        let each = resolve_each_module(&dir, &repo).unwrap();
        let tests = each.iter().find(|(m, _)| m == "com.acme:tests").unwrap();
        let names: Vec<_> = tests.1.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["g:lib"], "{each:?}");
    }

    #[test]
    fn a_range_reads_the_listings_of_declared_repositories() {
        // flink declares Red Hat's repository; `lang-tag [1.4.3,)` then picks
        // 1.7.0.redhat-00003, which only that listing has. Undeclared listings are not read.
        let listing = |vs: &[&str]| {
            let vs: String = vs
                .iter()
                .map(|v| format!("<version>{v}</version>"))
                .collect();
            format!("<metadata><versioning><versions>{vs}</versions></versioning></metadata>")
        };
        let body = |repos: &str| {
            format!(
                "{repos}<dependencies>{}</dependencies>",
                dep("g", "tag", "[1.4,)", "")
            )
        };
        let repo = Mem(BTreeMap::from([
            ("g:tag:metadata".to_string(), listing(&["1.4", "1.7"])),
            (
                "g:tag:metadata-redhat".to_string(),
                listing(&["1.7.0.redhat-3"]),
            ),
            ("g:tag:metadata-other".to_string(), listing(&["9"])),
            ("g:tag:1.7".to_string(), pom("g", "tag", "1.7", "")),
            (
                "g:tag:1.7.0.redhat-3".to_string(),
                pom("g", "tag", "1.7.0.redhat-3", ""),
            ),
            ("g:tag:9".to_string(), pom("g", "tag", "9", "")),
        ]));
        let declared = project(
            "repo-listing",
            &body("<repositories><repository><id>redhat</id><url>https://x</url></repository></repositories>"),
        );
        let r = resolve(&declared, &repo).unwrap();
        assert_eq!(r.packages[0].version, "1.7.0.redhat-3", "{:?}", r.missing);
        let plain = project("repo-listing-none", &body(""));
        assert_eq!(resolve(&plain, &repo).unwrap().packages[0].version, "1.7");
    }

    #[test]
    fn a_range_winner_keeps_its_own_subtree() {
        // seatunnel-dist: firestore brings grpc-core 1.52.1 with grpc-api excluded, and
        // grpc-netty's `[1.33.0]` makes vitess's grpc-core 1.33.0 win, with its grpc-api.
        let excl = "<exclusions><exclusion><groupId>g</groupId><artifactId>api</artifactId>\
                    </exclusion></exclusions>";
        let dir = project(
            "range-winner-subtree",
            &format!(
                "<dependencies>{}{}</dependencies>",
                dep("g", "firestore", "1", ""),
                dep("g", "vitess", "1", "")
            ),
        );
        let deps = |d: String| format!("<dependencies>{d}</dependencies>");
        let repo = Mem(BTreeMap::from([
            (
                "g:firestore:1".to_string(),
                pom("g", "firestore", "1", &deps(dep("g", "core", "2", excl))),
            ),
            (
                "g:vitess:1".to_string(),
                pom(
                    "g",
                    "vitess",
                    "1",
                    &deps(format!(
                        "{}{}",
                        dep("g", "core", "1", ""),
                        dep("g", "netty", "1", "")
                    )),
                ),
            ),
            (
                "g:netty:1".to_string(),
                pom("g", "netty", "1", &deps(dep("g", "core", "[1]", ""))),
            ),
            (
                "g:core:1".to_string(),
                pom("g", "core", "1", &deps(dep("g", "api", "1", ""))),
            ),
            (
                "g:core:2".to_string(),
                pom("g", "core", "2", &deps(dep("g", "api", "2", ""))),
            ),
            ("g:api:1".to_string(), pom("g", "api", "1", "")),
            ("g:api:2".to_string(), pom("g", "api", "2", "")),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        let mut names: Vec<_> = r
            .packages
            .iter()
            .map(|p| format!("{}:{}", p.name, p.version))
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "g:api:1",
                "g:core:1",
                "g:firestore:1",
                "g:netty:1",
                "g:vitess:1"
            ],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn a_widened_winner_keeps_its_own_exclusions() {
        // keycloak: guava first at test with every child excluded, then at compile through
        // grpc; Maven makes guava compile and lists none of its children.
        let excl_all = "<exclusions><exclusion><groupId>*</groupId><artifactId>*</artifactId>\
                        </exclusion></exclusions>";
        let dir = project(
            "widen-keeps-exclusions",
            &format!(
                "<dependencies>{}{}</dependencies>",
                dep("g", "server", "1", "<scope>test</scope>"),
                dep("g", "grpc", "1", "")
            ),
        );
        let deps = |d: String| format!("<dependencies>{d}</dependencies>");
        let repo = Mem(BTreeMap::from([
            (
                "g:server:1".to_string(),
                pom("g", "server", "1", &deps(dep("g", "guava", "1", excl_all))),
            ),
            (
                "g:grpc:1".to_string(),
                pom("g", "grpc", "1", &deps(dep("g", "mid", "1", ""))),
            ),
            (
                "g:mid:1".to_string(),
                pom("g", "mid", "1", &deps(dep("g", "guava", "1", ""))),
            ),
            (
                "g:guava:1".to_string(),
                pom("g", "guava", "1", &deps(dep("g", "j2objc", "1", ""))),
            ),
            ("g:j2objc:1".to_string(), pom("g", "j2objc", "1", "")),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        let names: Vec<_> = r
            .packages
            .iter()
            .map(|p| format!("{}:{}", p.name, p.scope))
            .collect();
        assert_eq!(
            names,
            [
                "g:server:test",
                "g:grpc:compile",
                "g:guava:compile",
                "g:mid:compile"
            ],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn a_range_stops_at_its_first_relocating_version() {
        // Sentinel: system-rules asks junit-dep `[4.9,)`; 4.11-beta-1 moves to junit, and the
        // project's junit 4.12 wins. Maven never reads 4.11.
        let dir = project(
            "range-relocates",
            &format!(
                "<dependencies>{}{}</dependencies>",
                dep("g", "junit", "4.12", ""),
                dep("g", "rules", "1", "")
            ),
        );
        let moved = "<distributionManagement><relocation><artifactId>junit</artifactId>\
                     </relocation></distributionManagement>";
        let repo = Mem(BTreeMap::from([
            ("g:junit:4.12".to_string(), pom("g", "junit", "4.12", "")),
            (
                "g:rules:1".to_string(),
                pom(
                    "g",
                    "rules",
                    "1",
                    &format!(
                        "<dependencies>{}</dependencies>",
                        dep("g", "dep", "[4.9,)", "")
                    ),
                ),
            ),
            ("g:dep:4.9".to_string(), pom("g", "dep", "4.9", "")),
            ("g:dep:4.10".to_string(), pom("g", "dep", "4.10", "")),
            (
                "g:dep:4.11-beta-1".to_string(),
                pom("g", "dep", "4.11-beta-1", moved),
            ),
            (
                "g:dep:metadata".to_string(),
                "<metadata><versioning><versions><version>4.9</version><version>4.10</version>\
                 <version>4.11-beta-1</version><version>4.11</version></versions></versioning>\
                 </metadata>"
                    .to_string(),
            ),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        let names: Vec<_> = r
            .packages
            .iter()
            .map(|p| format!("{}:{}", p.name, p.version))
            .collect();
        assert_eq!(names, ["g:junit:4.12", "g:rules:1"], "{:?}", r.missing);
    }

    #[test]
    fn a_module_named_with_a_property_is_a_sibling() {
        // flink: `flink-table-planner_${scala.binary.version}` is one of the build's modules,
        // and flink-avro depends on it as `flink-table-planner_2.12`.
        let dir = project(
            "named-by-property",
            "<packaging>pom</packaging><modules><module>planner</module><module>avro</module>\
             </modules>",
        );
        let modules = [
            (
                "planner",
                "planner_${sv}",
                format!(
                    "<properties><sv>2.12</sv></properties><dependencies>{}</dependencies>",
                    dep("g", "lib", "1", "")
                ),
            ),
            (
                "avro",
                "avro",
                format!(
                    "<dependencies>{}</dependencies>",
                    dep("com.acme", "planner_2.12", "1.0", "")
                ),
            ),
        ];
        for (d, a, body) in modules {
            std::fs::create_dir_all(dir.join(d)).unwrap();
            std::fs::write(
                dir.join(d).join("pom.xml"),
                pom("com.acme", a, "1.0", &body),
            )
            .unwrap();
        }
        let repo = Mem(BTreeMap::from([(
            "g:lib:1".to_string(),
            pom("g", "lib", "1", ""),
        )]));
        let each = resolve_each_module(&dir, &repo).unwrap();
        let avro = each.iter().find(|(m, _)| m == "com.acme:avro").unwrap();
        let names: Vec<_> = avro.1.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["g:lib"], "{each:?}");
    }

    #[test]
    fn a_bom_from_the_reactor_manages_the_build() {
        // dubbo's parent imports dubbo-dependencies-bom, one of its own modules at
        // `${revision}`: Maven reads it from the reactor, not a repository.
        let dir = project(
            "reactor-bom",
            "<packaging>pom</packaging><properties><revision>3.3.7</revision></properties>\
             <modules><module>bom</module><module>svc</module></modules>\
             <dependencyManagement><dependencies><dependency><groupId>com.acme</groupId>\
             <artifactId>bom</artifactId><version>${revision}</version><type>pom</type>\
             <scope>import</scope></dependency></dependencies></dependencyManagement>",
        );
        std::fs::create_dir_all(dir.join("bom")).unwrap();
        std::fs::write(
            dir.join("bom").join("pom.xml"),
            format!(
                "<project><groupId>com.acme</groupId><artifactId>bom</artifactId>\
                 <version>${{revision}}</version><packaging>pom</packaging>\
                 <properties><revision>3.3.7</revision></properties>\
                 <dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
                 </project>",
                dep("g", "lib", "2", "")
            ),
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("svc")).unwrap();
        std::fs::write(
            dir.join("svc").join("pom.xml"),
            "<project><parent><groupId>com.acme</groupId><artifactId>app</artifactId>\
             <version>1.0</version></parent><artifactId>svc</artifactId><dependencies>\
             <dependency><groupId>g</groupId><artifactId>lib</artifactId></dependency>\
             </dependencies></project>",
        )
        .unwrap();
        let repo = Mem(BTreeMap::from([(
            "g:lib:2".to_string(),
            pom("g", "lib", "2", ""),
        )]));
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(
            rows(&r),
            [("g:lib".to_string(), "2".to_string(), true, false)],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn another_version_of_a_module_comes_from_the_repository() {
        // easyexcel builds easyexcel-support 4.0.3 and manages it at the published 3.3.4:
        // Maven reads 3.3.4 from the repository and lists it, with its own dependencies.
        let dir = project(
            "module-other-version",
            &format!(
                "<packaging>pom</packaging><modules><module>support</module>\
                 <module>core</module></modules><dependencyManagement><dependencies>{}\
                 </dependencies></dependencyManagement>",
                dep("com.acme", "support", "0.9", "")
            ),
        );
        for (m, body) in [
            ("support", dep("g", "new", "1", "")),
            (
                "core",
                "<dependency><groupId>com.acme</groupId><artifactId>support</artifactId>\
                 </dependency>"
                    .to_string(),
            ),
        ] {
            std::fs::create_dir_all(dir.join(m)).unwrap();
            std::fs::write(
                dir.join(m).join("pom.xml"),
                format!(
                    "<project><parent><groupId>com.acme</groupId><artifactId>app</artifactId>\
                     <version>1.0</version></parent><artifactId>{m}</artifactId>\
                     <dependencies>{body}</dependencies></project>"
                ),
            )
            .unwrap();
        }
        let repo = Mem(BTreeMap::from([
            (
                "com.acme:support:0.9".to_string(),
                pom(
                    "com.acme",
                    "support",
                    "0.9",
                    &format!("<dependencies>{}</dependencies>", dep("g", "old", "1", "")),
                ),
            ),
            ("g:new:1".to_string(), pom("g", "new", "1", "")),
            ("g:old:1".to_string(), pom("g", "old", "1", "")),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(
            rows(&r),
            [
                ("g:new".to_string(), "1".to_string(), true, false),
                (
                    "com.acme:support".to_string(),
                    "0.9".to_string(),
                    true,
                    false
                ),
                ("g:old".to_string(), "1".to_string(), false, false),
            ],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn jdk_ranges_read_as_maven_reads_them() {
        for (range, on) in [
            ("[17,", true), // dubbo-test-check, no closing bracket
            ("[17,)", true),
            ("[9,)", true),
            ("[21,22)", true),
            ("(21.0.5,)", false),
            ("[1.8,9)", false),
            ("(,11]", false),
            ("[22,)", false),
            ("[x,)", false),
        ] {
            assert_eq!(jdk_in_range(JAVA_VERSION, range), on, "{range}");
        }
    }

    #[test]
    fn element_names_maven_reads_but_xml_does_not() {
        // hadoop-project 3.1.4: `<Xlint:-unchecked/>` in a compiler plugin's configuration.
        let xml = format!(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
             <build><plugins><plugin><configuration><compilerArguments><Xlint/>\
             <Xlint:-unchecked/><a:b>x</a:b></compilerArguments></configuration></plugin>\
             </plugins></build></project>",
            dep("g", "lib", "2", "")
        );
        let pom = parse_pom(&xml, false).unwrap();
        assert_eq!(pom.mgmt.len(), 1);
        // Still refused: a POM that is broken in another way, or only half there.
        assert!(parse_pom(
            "<project><artifactId>a</artifactId><Xlint:-u></project>",
            false
        )
        .is_err());
        assert!(parse_pom("<project><artifactId>a</artifactId>", false).is_err());
        assert!(rename_unreadable_elements("<project><a>1</a></project>").is_none());
    }

    #[test]
    fn a_plain_doctype_is_skipped_as_maven_does() {
        // oshi-core 6.1.1 and oshi-parent 6.1.1 start with `<!DOCTYPE project>`.
        let xml = "<?xml version=\"1.0\"?>\n<!DOCTYPE project>\n<project><artifactId>a\
                   </artifactId><version>1</version></project>";
        assert_eq!(parse_pom(xml, false).unwrap().artifact, "a");
        // Entities stay refused.
        let entities = "<!DOCTYPE project [<!ENTITY x \"y\">]><project><artifactId>&x;\
                        </artifactId></project>";
        assert!(parse_pom(entities, false).is_err());
    }

    #[test]
    fn own_dependencies_come_before_inherited_ones() {
        // seatunnel's clickhouse connector: its own clickhouse-jdbc brings httpcore 4.4.13,
        // and a dependency inherited from the parent brings 4.4.16 at the same depth.
        let dir = project(
            "own-first",
            &format!(
                "<packaging>pom</packaging><modules><module>c</module></modules>\
                 <dependencies>{}</dependencies>",
                dep("g", "p", "1", "")
            ),
        );
        std::fs::create_dir_all(dir.join("c")).unwrap();
        std::fs::write(
            dir.join("c").join("pom.xml"),
            format!(
                "<project><parent><groupId>com.acme</groupId><artifactId>app</artifactId>\
                 <version>1.0</version></parent><artifactId>c</artifactId>\
                 <dependencies>{}</dependencies></project>",
                dep("g", "jdbc", "1", "")
            ),
        )
        .unwrap();
        let with = |a: &str, v: &str| {
            pom(
                "g",
                a,
                "1",
                &format!("<dependencies>{}</dependencies>", dep("g", "core", v, "")),
            )
        };
        let repo = Mem(BTreeMap::from([
            ("g:p:1".to_string(), with("p", "2")),
            ("g:jdbc:1".to_string(), with("jdbc", "1")),
            ("g:core:1".to_string(), pom("g", "core", "1", "")),
            ("g:core:2".to_string(), pom("g", "core", "2", "")),
        ]));
        let each = resolve_each_module(&dir, &repo).unwrap();
        let c: Vec<(String, String)> = each
            .iter()
            .find(|(m, _)| m == "com.acme:c")
            .unwrap()
            .1
            .iter()
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();
        assert_eq!(
            c,
            [
                ("g:jdbc".to_string(), "1".to_string()),
                ("g:p".to_string(), "1".to_string()),
                ("g:core".to_string(), "1".to_string()),
            ]
        );
    }

    #[test]
    fn a_direct_dependency_beats_an_inherited_siblings() {
        // nacos: logger-adapter-impl declares nacos-common (a module, bringing slf4j-api 2),
        // and its child logback-adapter-12 pins slf4j-api 1 itself.
        let dir = project(
            "sibling-order",
            "<packaging>pom</packaging><modules><module>common</module>\
             <module>impl</module></modules>",
        );
        let child = |a: &str, parent: &str, body: &str| {
            format!(
                "<project><parent><groupId>com.acme</groupId><artifactId>{parent}</artifactId>\
                 <version>1.0</version></parent><artifactId>{a}</artifactId>{body}</project>"
            )
        };
        let common = format!("<dependencies>{}</dependencies>", dep("g", "lib", "2", ""));
        let imp = format!(
            "<packaging>pom</packaging><modules><module>adapter</module></modules>\
             <dependencies>{}</dependencies>",
            dep("com.acme", "common", "1.0", "")
        );
        let adapter = format!("<dependencies>{}</dependencies>", dep("g", "lib", "1", ""));
        for (path, xml) in [
            ("common", child("common", "app", &common)),
            ("impl", child("impl", "app", &imp)),
            ("impl/adapter", child("adapter", "impl", &adapter)),
        ] {
            std::fs::create_dir_all(dir.join(path)).unwrap();
            std::fs::write(dir.join(path).join("pom.xml"), xml).unwrap();
        }
        let repo = Mem(BTreeMap::from([
            ("g:lib:1".to_string(), pom("g", "lib", "1", "")),
            ("g:lib:2".to_string(), pom("g", "lib", "2", "")),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(
            rows(&r),
            [
                ("g:lib".to_string(), "2".to_string(), true, false),
                ("g:lib".to_string(), "1".to_string(), true, false),
            ],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn a_one_version_range_needs_no_metadata() {
        let dir = project(
            "one-version-range",
            &format!(
                "<dependencies>{}{}</dependencies>",
                dep("g", "a", "[2]", ""),
                dep("g", "b", "[1, 1]", "")
            ),
        );
        let repo = Mem(BTreeMap::from([
            ("g:a:2".to_string(), pom("g", "a", "2", "")),
            ("g:b:1".to_string(), pom("g", "b", "1", "")),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(
            rows(&r),
            [
                ("g:a".to_string(), "2".to_string(), true, false),
                ("g:b".to_string(), "1".to_string(), true, false),
            ],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn an_optional_flag_from_a_property() {
        // The Kubernetes client marks its Prometheus, AWS and Google clients
        // `<optional>${prometheus.client.optional}</optional>`, set in its parent.
        let dir = project(
            "optional-property",
            &format!("<dependencies>{}</dependencies>", dep("g", "a", "1", "")),
        );
        let repo = Mem(BTreeMap::from([
            (
                "g:par:1".to_string(),
                pom(
                    "g",
                    "par",
                    "1",
                    "<packaging>pom</packaging><properties><opt>True</opt></properties>",
                ),
            ),
            (
                "g:a:1".to_string(),
                format!(
                    "<project><parent><groupId>g</groupId><artifactId>par</artifactId>\
                     <version>1</version></parent><artifactId>a</artifactId>\
                     <dependencies>{}{}</dependencies></project>",
                    dep("g", "gone", "1", "<optional>${opt}</optional>"),
                    dep("g", "kept", "1", "<optional>${no.such}</optional>")
                ),
            ),
            ("g:gone:1".to_string(), pom("g", "gone", "1", "")),
            ("g:kept:1".to_string(), pom("g", "kept", "1", "")),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(
            rows(&r),
            [
                ("g:a".to_string(), "1".to_string(), true, false),
                ("g:kept".to_string(), "1".to_string(), false, false),
            ],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn managed_exclusions_prune_a_transitive_dependency() {
        let dir = project(
            "managed-exclusions",
            &format!(
                "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
                 <dependencies>{}</dependencies>",
                dep(
                    "g",
                    "b",
                    "1",
                    "<exclusions><exclusion><groupId>g</groupId><artifactId>gone</artifactId>\
                     </exclusion></exclusions>"
                ),
                dep("g", "a", "1", "")
            ),
        );
        let with = |a: &str, child: &str| {
            pom(
                "g",
                a,
                "1",
                &format!("<dependencies>{}</dependencies>", dep("g", child, "1", "")),
            )
        };
        let repo = Mem(BTreeMap::from([
            ("g:a:1".to_string(), with("a", "b")),
            ("g:b:1".to_string(), with("b", "gone")),
            ("g:gone:1".to_string(), pom("g", "gone", "1", "")),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(
            rows(&r),
            [
                ("g:a".to_string(), "1".to_string(), true, false),
                ("g:b".to_string(), "1".to_string(), false, false),
            ],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn managed_exclusions_join_a_direct_dependencys_own() {
        // dubbo's zookeeper starter excludes logback itself; the managed entry's
        // audience-annotations exclusion still applies.
        let excl = |a: &str| {
            format!("<exclusion><groupId>g</groupId><artifactId>{a}</artifactId></exclusion>")
        };
        let dir = project(
            "managed-exclusions-direct",
            &format!(
                "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
                 <dependencies>{}</dependencies>",
                dep(
                    "g",
                    "zk",
                    "1",
                    &format!("<exclusions>{}</exclusions>", excl("audience"))
                ),
                dep(
                    "g",
                    "zk",
                    "1",
                    &format!("<exclusions>{}</exclusions>", excl("logback"))
                )
            ),
        );
        let repo = Mem(BTreeMap::from([
            (
                "g:zk:1".to_string(),
                pom(
                    "g",
                    "zk",
                    "1",
                    &format!(
                        "<dependencies>{}{}{}</dependencies>",
                        dep("g", "audience", "1", ""),
                        dep("g", "logback", "1", ""),
                        dep("g", "jute", "1", "")
                    ),
                ),
            ),
            ("g:audience:1".to_string(), pom("g", "audience", "1", "")),
            ("g:logback:1".to_string(), pom("g", "logback", "1", "")),
            ("g:jute:1".to_string(), pom("g", "jute", "1", "")),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(
            rows(&r),
            [
                ("g:zk".to_string(), "1".to_string(), true, false),
                ("g:jute".to_string(), "1".to_string(), false, false),
            ],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn a_parents_import_beats_the_grandparents() {
        // dubbo's Boot 1 modules: the root imports a BOM managing Boot 2.7, their parent
        // imports Boot 1.5, and Maven tries the nearer import first.
        let import = |a: &str| {
            format!(
                "<dependencyManagement><dependencies><dependency><groupId>b</groupId>\
                 <artifactId>{a}</artifactId><version>1</version><type>pom</type>\
                 <scope>import</scope></dependency></dependencies></dependencyManagement>"
            )
        };
        let dir = project(
            "nearer-import",
            &format!(
                "<packaging>pom</packaging><modules><module>mid</module></modules>{}",
                import("new")
            ),
        );
        std::fs::create_dir_all(dir.join("mid").join("leaf")).unwrap();
        std::fs::write(
            dir.join("mid").join("pom.xml"),
            format!(
                "<project><parent><groupId>com.acme</groupId><artifactId>app</artifactId>\
                 <version>1.0</version></parent><artifactId>mid</artifactId>\
                 <packaging>pom</packaging><modules><module>leaf</module></modules>{}\
                 </project>",
                import("old")
            ),
        )
        .unwrap();
        std::fs::write(
            dir.join("mid").join("leaf").join("pom.xml"),
            "<project><parent><groupId>com.acme</groupId><artifactId>mid</artifactId>\
             <version>1.0</version></parent><artifactId>leaf</artifactId><dependencies>\
             <dependency><groupId>g</groupId><artifactId>lib</artifactId></dependency>\
             </dependencies></project>",
        )
        .unwrap();
        let bom = |a: &str, v: &str| {
            pom(
                "b",
                a,
                "1",
                &format!(
                    "<packaging>pom</packaging><dependencyManagement><dependencies>{}\
                     </dependencies></dependencyManagement>",
                    dep("g", "lib", v, "")
                ),
            )
        };
        let repo = Mem(BTreeMap::from([
            ("b:new:1".to_string(), bom("new", "2")),
            ("b:old:1".to_string(), bom("old", "1")),
            ("g:lib:1".to_string(), pom("g", "lib", "1", "")),
            ("g:lib:2".to_string(), pom("g", "lib", "2", "")),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(
            rows(&r),
            [("g:lib".to_string(), "1".to_string(), true, false)],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn a_test_jar_is_the_tests_classifier_jar() {
        // hudi manages hadoop-common's `tests` jar at 2.10.2; hadoop-minicluster asks the same
        // artifact as `<type>test-jar</type>` 2.10.0, which Maven manages and mediates as one.
        let dir = project(
            "test-jar",
            &format!(
                "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
                 <dependencies>{}{}</dependencies>",
                dep("g", "common", "2", "<classifier>tests</classifier>"),
                dep("g", "common", "2", "<classifier>tests</classifier>"),
                dep("g", "mini", "1", "")
            ),
        );
        let repo = Mem(BTreeMap::from([
            (
                "g:mini:1".to_string(),
                pom(
                    "g",
                    "mini",
                    "1",
                    &format!(
                        "<dependencies>{}</dependencies>",
                        dep("g", "common", "1", "<type>test-jar</type>")
                    ),
                ),
            ),
            ("g:common:1".to_string(), pom("g", "common", "1", "")),
            ("g:common:2".to_string(), pom("g", "common", "2", "")),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        let names: Vec<_> = r
            .packages
            .iter()
            .map(|p| format!("{}:{}", p.name, p.version))
            .collect();
        assert_eq!(names, ["g:common:2", "g:mini:1"], "{:?}", r.missing);
    }

    fn names_of(r: &Resolution) -> Vec<String> {
        r.packages
            .iter()
            .map(|p| format!("{}:{}", p.name, p.version))
            .collect()
    }

    #[test]
    fn an_exclusion_names_a_property() {
        // drill's JDBC driver excludes `${calcite.groupId}:calcite-core` from java-exec.
        let dir = project(
            "excl-prop",
            &format!(
                "<properties><cg>x</cg></properties><dependencies>{}</dependencies>",
                dep(
                    "g",
                    "lib",
                    "1",
                    "<exclusions><exclusion><groupId>${cg}</groupId>\
                     <artifactId>bad</artifactId></exclusion></exclusions>"
                )
            ),
        );
        let repo = Mem(BTreeMap::from([
            (
                "g:lib:1".to_string(),
                pom(
                    "g",
                    "lib",
                    "1",
                    &format!("<dependencies>{}</dependencies>", dep("x", "bad", "1", "")),
                ),
            ),
            ("x:bad:1".to_string(), pom("x", "bad", "1", "")),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(names_of(&r), ["g:lib:1"], "{:?}", r.missing);
    }

    #[test]
    fn an_unknown_scope_still_mediates() {
        // kudu-client 1.17.0 lists audience-annotations 0.13.0 as `optional`, a scope Maven does
        // not know: it stays in the tree and its nearer version beats a deeper 0.12.0.
        let dir = project(
            "odd-scope",
            &format!(
                "<dependencies>{}{}</dependencies>",
                dep("g", "client", "1", ""),
                dep("g", "deep", "1", "")
            ),
        );
        let one = |a: &str, child: String| {
            (
                format!("g:{a}:1"),
                pom(
                    "g",
                    a,
                    "1",
                    &format!("<dependencies>{child}</dependencies>"),
                ),
            )
        };
        let repo = Mem(BTreeMap::from([
            one("client", dep("g", "ann", "2", "<scope>optional</scope>")),
            one("deep", dep("g", "mid", "1", "")),
            one("mid", dep("g", "ann", "1", "")),
            ("g:ann:1".to_string(), pom("g", "ann", "1", "")),
            ("g:ann:2".to_string(), pom("g", "ann", "2", "")),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(
            names_of(&r),
            ["g:client:1", "g:deep:1", "g:ann:2", "g:mid:1"],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn a_relative_system_path_empties_a_published_pom() {
        // druid 1.2.6 lists tools.jar at `${project.basedir}/lib/...`: Maven rejects the model
        // and lists druid alone. An absolute or environment path keeps the dependencies.
        let dir = project(
            "system-path",
            &format!(
                "<dependencies>{}{}</dependencies>",
                dep("g", "bad", "1", ""),
                dep("g", "good", "1", "")
            ),
        );
        let with = |a: &str, path: &str| {
            let system = format!(
                "<dependency><groupId>com.sun</groupId><artifactId>tools</artifactId>\
                 <version>1</version><scope>system</scope><systemPath>{path}</systemPath>\
                 </dependency>"
            );
            (
                format!("g:{a}:1"),
                pom(
                    "g",
                    a,
                    "1",
                    &format!(
                        "<dependencies>{system}{}</dependencies>",
                        dep("g", &format!("{a}-child"), "1", "")
                    ),
                ),
            )
        };
        let repo = Mem(BTreeMap::from([
            with("bad", "${project.basedir}/lib/tools.jar"),
            with("good", "${java.home}/../lib/tools.jar"),
            ("g:bad-child:1".to_string(), pom("g", "bad-child", "1", "")),
            (
                "g:good-child:1".to_string(),
                pom("g", "good-child", "1", ""),
            ),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(
            names_of(&r),
            ["g:bad:1", "g:good:1", "g:good-child:1"],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn release_is_the_newest_metadatas_release() {
        // COLA's state machine asks junit-jupiter `RELEASE`; the metadata updated last names it.
        let dir = project(
            "meta-release",
            &format!(
                "<repositories><repository><id>other</id><url>https://example.invalid</url>\
                 </repository></repositories><dependencies>{}</dependencies>",
                dep("g", "j", "RELEASE", "")
            ),
        );
        let meta = |release: &str, updated: &str| {
            format!(
                "<metadata><versioning><release>{release}</release><versions>\
                 <version>{release}</version></versions><lastUpdated>{updated}</lastUpdated>\
                 </versioning></metadata>"
            )
        };
        let repo = Mem(BTreeMap::from([
            ("g:j:metadata".to_string(), meta("3", "20260102000000")),
            (
                "g:j:metadata-other".to_string(),
                meta("4", "20250101000000"),
            ),
            (
                "g:j:3".to_string(),
                pom(
                    "g",
                    "j",
                    "3",
                    &format!("<dependencies>{}</dependencies>", dep("g", "k", "1", "")),
                ),
            ),
            ("g:k:1".to_string(), pom("g", "k", "1", "")),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(names_of(&r), ["g:j:3", "g:k:1"], "{:?}", r.missing);
    }

    #[test]
    fn maven_config_profiles_and_properties_apply() {
        // spring-cloud-gateway's `.mvn/maven.config` says `-P spring`; `-D` sets user
        // properties, which win over the POM's and switch `<property>` profiles.
        let profile = |id: &str, activation: &str, a: &str| {
            format!(
                "<profile><id>{id}</id>{activation}<dependencies>{}</dependencies></profile>",
                dep("g", a, "${v}", "")
            )
        };
        let dir = project(
            "maven-config",
            &format!(
                "<properties><v>1</v></properties><profiles>{}{}{}{}{}</profiles>",
                profile("spring", "", "named"),
                profile("dflt", "<activation><activeByDefault>true</activeByDefault></activation>", "dflt"),
                profile("prop", "<activation><property><name>flag</name><value>yes</value></property></activation>", "prop"),
                profile("gone", "<activation><property><name>!absent</name></property></activation>", "gone"),
                profile("idle", "", "idle")
            ),
        );
        std::fs::create_dir_all(dir.join(".mvn")).unwrap();
        std::fs::write(
            dir.join(".mvn").join("maven.config"),
            "-T1C --no-transfer-progress\n# a comment -P idle\n-P spring,!gone\n-Dflag=yes -D v=2\n",
        )
        .unwrap();
        let repo = Mem(["named", "dflt", "prop", "gone", "idle"]
            .iter()
            .flat_map(|a| ["1", "2"].map(|v| (format!("g:{a}:{v}"), pom("g", a, v, ""))))
            .collect());
        let r = resolve(&dir, &repo).unwrap();
        let mut names: Vec<_> = r
            .packages
            .iter()
            .map(|p| format!("{}:{}", p.name, p.version))
            .collect();
        names.sort();
        assert_eq!(names, ["g:named:2", "g:prop:2"], "{:?}", r.missing);
        let cli = MavenCli::read(&dir);
        assert!(cli.on.contains("spring") && cli.off.contains("gone") && !cli.on.contains("idle"));
    }

    #[test]
    fn file_activation_is_checked_in_the_checkout() {
        // seata: `<exists>test-suite/test-new-version/pom.xml</exists>` with `!excludeTestModules`.
        let profile = |id: &str, cond: &str, a: &str| {
            format!(
                "<profile><id>{id}</id><activation><file>{cond}</file><property>\
                 <name>!skip</name></property></activation><dependencies>{}</dependencies>\
                 </profile>",
                dep("g", a, "1", "")
            )
        };
        let dir = project(
            "file-activation",
            &format!(
                "<profiles>{}{}{}{}{}</profiles>",
                profile("on", "<exists>suite/pom.xml</exists>", "exists"),
                profile("off", "<exists>${basedir}/nope.txt</exists>", "absent"),
                profile("gone", "<missing>nope.txt</missing>", "missing"),
                profile(
                    "up",
                    "<exists>../file-activation/suite/pom.xml</exists>",
                    "up"
                ),
                profile("prop", "<exists>${other}/suite/pom.xml</exists>", "prop")
            ),
        );
        std::fs::create_dir_all(dir.join("suite")).unwrap();
        std::fs::write(dir.join("suite").join("pom.xml"), "<project/>").unwrap();
        let repo = Mem(["exists", "absent", "missing", "up", "prop"]
            .iter()
            .map(|a| (format!("g:{a}:1"), pom("g", a, "1", "")))
            .collect());
        let r = resolve(&dir, &repo).unwrap();
        let names: Vec<_> = r.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["g:exists", "g:missing"], "{:?}", r.missing);
        // A published POM has no folder: its `<file>` profiles stay off.
        let xml = format!(
            "<project><artifactId>a</artifactId><profiles>{}</profiles></project>",
            profile("on", "<missing>nope.txt</missing>", "x")
        );
        assert!(parse_pom(&xml, false).unwrap().deps.is_empty());
    }

    #[test]
    fn profiles_switch_on_by_jdk_as_maven_decides() {
        // xmlunit-core 2.9.0 adds jakarta.xml.bind-api in a `<jdk>[9,)</jdk>` profile, which
        // Maven on a current JDK turns on. An activeByDefault profile then stays off, and
        // profiles for an old JDK, an OS, or a set property never apply.
        let profile = |id: &str, activation: &str, artifact: &str| {
            format!(
                "<profile><id>{id}</id><activation>{activation}</activation>\
                 <dependencies>{}</dependencies></profile>",
                dep("g", artifact, "1", "")
            )
        };
        let profiles = [
            profile("modern", "<jdk>[9,)</jdk>", "bind"),
            profile(
                "unset",
                "<property><name>!skipBind</name></property>",
                "unset",
            ),
            profile(
                "default",
                "<activeByDefault>true</activeByDefault>",
                "default",
            ),
            profile("old", "<jdk>1.8</jdk>", "old"),
            profile("notmodern", "<jdk>!21</jdk>", "notmodern"),
            profile(
                "os",
                "<jdk>[9,)</jdk><os><family>windows</family></os>",
                "os",
            ),
            profile("set", "<property><name>withExtra</name></property>", "set"),
        ]
        .concat();
        let mut map = BTreeMap::from([(
            "g:core:1".to_string(),
            pom(
                "g",
                "core",
                "1",
                &format!("<profiles>{profiles}</profiles>"),
            ),
        )]);
        for a in ["bind", "unset", "default", "old", "notmodern", "os", "set"] {
            map.insert(format!("g:{a}:1"), pom("g", a, "1", ""));
        }
        let repo = Mem(map);
        let dir = project(
            "jdk-profiles",
            &format!("<dependencies>{}</dependencies>", dep("g", "core", "1", "")),
        );
        let r = resolve(&dir, &repo).unwrap();
        let mut got: Vec<_> = rows(&r).into_iter().map(|(n, _, _, _)| n).collect();
        got.sort();
        assert_eq!(got, ["g:bind", "g:core", "g:unset"], "{:?}", r.missing);
    }

    #[test]
    fn a_child_property_sets_a_version_its_parent_manages() {
        // artemis-jakarta-client sets `jakarta.jms-api.version`, which artemis-pom's
        // management names: real Maven takes the child's 3.1.0, not the parent's 2.0.3.
        let repo = Mem(BTreeMap::from([
            (
                "g:parent:1".to_string(),
                pom(
                    "g",
                    "parent",
                    "1",
                    &format!(
                        "<properties><api.version>2.0.3</api.version></properties>\
                         <dependencyManagement><dependencies>{}</dependencies></dependencyManagement>\
                         <dependencies>{}</dependencies>",
                        dep("g", "api", "${api.version}", ""),
                        dep("g", "inherited", "${api.version}", "")
                    ),
                ),
            ),
            (
                "g:client:1".to_string(),
                "<project><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent>\
                 <artifactId>client</artifactId><properties><api.version>3.1.0</api.version></properties>\
                 <dependencies><dependency><groupId>g</groupId><artifactId>api</artifactId></dependency></dependencies></project>"
                    .to_string(),
            ),
            ("g:api:3.1.0".to_string(), pom("g", "api", "3.1.0", "")),
            ("g:inherited:3.1.0".to_string(), pom("g", "inherited", "3.1.0", "")),
        ]));
        let dir = project(
            "child-props",
            &format!(
                "<dependencies>{}</dependencies>",
                dep("g", "client", "1", "")
            ),
        );
        let r = resolve(&dir, &repo).unwrap();
        let mut got: Vec<_> = rows(&r)
            .into_iter()
            .map(|(n, v, _, _)| format!("{n}:{v}"))
            .collect();
        got.sort();
        assert_eq!(
            got,
            ["g:api:3.1.0", "g:client:1", "g:inherited:3.1.0"],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn an_undefined_property_is_not_listed_as_a_version() {
        let repo = Mem(BTreeMap::from([(
            "g:a:1".to_string(),
            pom(
                "g",
                "a",
                "1",
                &format!(
                    "<dependencies>{}</dependencies>",
                    dep("g", "b", "${nowhere}", "")
                ),
            ),
        )]));
        let dir = project(
            "undefined-prop",
            &format!("<dependencies>{}</dependencies>", dep("g", "a", "1", "")),
        );
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(rows(&r), [("g:a".into(), "1".into(), true, false)]);
        assert!(
            r.missing.iter().any(|m| m.contains("undefined property")),
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn relocated_artifacts_resolve_as_their_new_coordinate() {
        let moved = |g: &str, to: &str| {
            format!("<distributionManagement><relocation><groupId>{to}</groupId></relocation></distributionManagement><!--{g}-->")
        };
        let repo = Mem(BTreeMap::from([
            (
                "old:a:1".to_string(),
                pom("old", "a", "1", &moved("old", "new")),
            ),
            (
                "new:a:1".to_string(),
                pom(
                    "new",
                    "a",
                    "1",
                    &format!("<dependencies>{}</dependencies>", dep("g", "c", "1", "")),
                ),
            ),
            // A second path to the old coordinate relocates too (linkis: slf4j-log4j12).
            (
                "g:c:1".to_string(),
                pom(
                    "g",
                    "c",
                    "1",
                    &format!("<dependencies>{}</dependencies>", dep("old", "a", "1", "")),
                ),
            ),
            // A cycle: each moves to the other.
            (
                "x:loop:1".to_string(),
                pom("x", "loop", "1", &moved("x", "y")),
            ),
            (
                "y:loop:1".to_string(),
                pom("y", "loop", "1", &moved("y", "x")),
            ),
        ]));
        let dir = project(
            "relocation",
            &format!(
                "<dependencies>{}{}</dependencies>",
                dep("old", "a", "1", ""),
                dep("x", "loop", "1", "")
            ),
        );
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(
            rows(&r),
            [
                ("new:a".into(), "1".into(), true, false),
                ("x:loop".into(), "1".into(), true, false),
                ("g:c".into(), "1".into(), false, false),
            ]
        );
    }

    #[test]
    fn managed_provided_holds_on_every_path_and_drops_a_relocation() {
        // seatunnel manages log4j and slf4j-log4j12 as provided; hadoop-common brings both at
        // compile, and slf4j-log4j12 1.7.36 relocates to slf4j-reload4j.
        let managed = |a: &str| dep("g", a, "1", "<scope>provided</scope>");
        let dir = project(
            "managed-provided",
            &format!(
                "<dependencyManagement><dependencies>{}{}</dependencies>\
                 </dependencyManagement><dependencies>{}{}</dependencies>",
                managed("log4j"),
                managed("binding"),
                dep("g", "auth", "1", ""),
                dep("g", "common", "1", "")
            ),
        );
        let with = |a: &str, children: &[&str]| {
            let deps: String = children.iter().map(|c| dep("g", c, "1", "")).collect();
            pom("g", a, "1", &format!("<dependencies>{deps}</dependencies>"))
        };
        let repo = Mem(BTreeMap::from([
            ("g:auth:1".to_string(), with("auth", &["log4j"])),
            ("g:common:1".to_string(), with("common", &["mid"])),
            ("g:mid:1".to_string(), with("mid", &["log4j", "binding"])),
            ("g:log4j:1".to_string(), pom("g", "log4j", "1", "")),
            (
                "g:binding:1".to_string(),
                pom(
                    "g",
                    "binding",
                    "1",
                    "<distributionManagement><relocation><artifactId>reload</artifactId>\
                     </relocation></distributionManagement>",
                ),
            ),
            ("g:reload:1".to_string(), pom("g", "reload", "1", "")),
        ]));
        let r = resolve(&dir, &repo).unwrap();
        let got: Vec<(String, String)> = r
            .packages
            .iter()
            .map(|p| (p.name.clone(), p.scope.clone()))
            .collect();
        assert_eq!(
            got,
            [
                ("g:auth".to_string(), "compile".to_string()),
                ("g:common".to_string(), "compile".to_string()),
                ("g:log4j".to_string(), "provided".to_string()),
                ("g:mid".to_string(), "compile".to_string()),
            ],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn ranges_and_missing_poms_are_handled_honestly() {
        let repo = Mem(BTreeMap::from([
            ("g:r:metadata".to_string(), "<metadata><versioning><versions><version>1.0</version><version>1.9</version><version>2.0</version></versions></versioning></metadata>".to_string()),
            ("g:r:1.9".to_string(), pom("g", "r", "1.9", "")),
        ]));
        let dir = project(
            "ranges",
            &format!(
                "<dependencies>{}{}{}</dependencies>",
                dep("g", "r", "[1.0,2.0)", ""),
                dep("g", "absent", "1", ""),
                dep("g", "p", "${undefined.prop}", "")
            ),
        );
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(rows(&r)[0], ("g:r".into(), "1.9".into(), true, false));
        assert!(
            r.missing
                .iter()
                .any(|m| m.contains("g:absent:1: POM not available")),
            "{:?}",
            r.missing
        );
        assert!(
            r.missing.iter().any(|m| m.contains("${undefined.prop}")),
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn range_syntax() {
        let r = parse_ranges("[1.0,2.0)").unwrap();
        assert!(r[0].contains("1.5") && r[0].contains("1.0") && !r[0].contains("2.0"));
        let r = parse_ranges("(,1.0],[1.2,)").unwrap();
        assert!(r.iter().any(|i| i.contains("0.9")) && !r.iter().any(|i| i.contains("1.1")));
        assert!(parse_ranges("[1.5]").unwrap()[0].contains("1.5"));
        assert_eq!(propagate("compile", "runtime"), Some("runtime".into()));
        assert_eq!(propagate("compile", "test"), None);
        assert_eq!(propagate("test", "compile"), Some("test".into()));
        assert_eq!(
            propagate("compile", COMPILE_ONLY_API),
            Some("provided".into())
        );
        assert_eq!(propagate("test", COMPILE_ONLY_API), Some("test".into()));
        assert_eq!(propagate("compile", "optional"), Some("optional".into()));
        assert_eq!(propagate("provided", "optional"), Some("provided".into()));
        assert_eq!(propagate("runtime", COMPILE_ONLY_API), None);
    }
}
