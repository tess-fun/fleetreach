//! Read a Gradle build without running it: `gradle/libs.versions.toml` and the literal
//! declarations in `*.gradle` and `*.gradle.kts`, resolved through the POM resolver with
//! Gradle's rule that the highest requested version wins. Build scripts are programs, so
//! anything that is not a literal (a helper call, an undefined variable, a dynamic version) is
//! named in [`Resolution::missing`], and each build file is resolved alone, since two
//! subprojects can pin different versions.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::resolve::{resolve_gradle_module, PomSource, Resolution, ResolvedDep};

const SKIPPED_DIRS: &[&str] = &[".git", ".gradle", "build", "node_modules", "target", "out"];
const MAX_FILES: usize = 2000;
const MAX_FILE_BYTES: u64 = 4 << 20;

/// Whether `dir` is the root of a Gradle build.
#[must_use]
pub fn has_gradle_build(dir: &Path) -> bool {
    [
        "settings.gradle",
        "settings.gradle.kts",
        "build.gradle",
        "build.gradle.kts",
    ]
    .iter()
    .any(|f| dir.join(f).is_file())
}

/// Resolve every build file under `dir`, and catalog entries no build file names. An unused
/// entry still counts, as development only, since a convention plugin can reach it in ways not
/// read here.
#[must_use]
pub fn resolve_gradle(dir: &Path, source: &dyn PomSource) -> Resolution {
    let mut missing = BTreeSet::new();
    let scripts = build_scripts(dir, &mut missing);
    let mut vars = properties(&dir.join("gradle.properties"));
    let mut seen_twice = BTreeSet::new();
    for (_, text) in &scripts {
        script_variables(text, &mut vars, &mut seen_twice);
    }
    for name in seen_twice {
        vars.remove(&name);
    }
    let catalog = fleetreach_core::repofile::read_to_string(dir.join("gradle/libs.versions.toml"))
        .ok()
        .map_or_else(Catalog::default, |text| {
            Catalog::parse(&text).unwrap_or_else(|e| {
                missing.insert(format!("gradle/libs.versions.toml: {e}"));
                Catalog::default()
            })
        });
    let mut plugins = catalog.plugins.clone();
    // A convention plugin often applies Kotlin, with its version set on the plugin's library.
    if let Some(c) = catalog
        .libraries
        .values()
        .find(|c| c.artifact == "kotlin-gradle-plugin")
    {
        if let Some(version) = &c.version {
            plugins.insert(KOTLIN_JVM.to_string(), version.clone());
        }
    }
    for (_, text) in &scripts {
        for line in text.lines() {
            if let Some((id, Some(version))) = plugin_line(line.trim(), &catalog) {
                plugins.entry(id).or_insert(version);
            }
        }
    }
    let mut context = Context {
        vars,
        catalog,
        plugins,
        used: BTreeSet::new(),
    };
    let mut modules: Vec<Module> = Vec::new();
    for (file, text) in &scripts {
        let mut module = read_script(text, &mut context);
        // Build logic runs at build time and never ships.
        if file.starts_with("buildSrc/") || file.starts_with("build-logic/") {
            module.deps.iter_mut().for_each(|d| d.scope = "test");
        }
        for line in std::mem::take(&mut module.unread) {
            missing.insert(format!("{file}: {line}"));
        }
        modules.push(module);
    }
    let unused: Vec<Declared> = context
        .catalog
        .libraries
        .iter()
        .filter(|(alias, _)| !context.used.contains(*alias))
        .map(|(_, coordinate)| Declared {
            coordinate: coordinate.clone(),
            scope: "test",
        })
        .collect();
    if !unused.is_empty() {
        modules.push(Module {
            deps: unused,
            ..Module::default()
        });
    }
    for line in std::mem::take(&mut context.catalog.unread) {
        missing.insert(format!("gradle/libs.versions.toml: {line}"));
    }

    let mut graph = fleetreach_core::DepGraph::new("(root)");
    let mut packages: BTreeMap<(String, String), ResolvedDep> = BTreeMap::new();
    for module in &modules {
        if module.deps.is_empty() {
            continue;
        }
        match resolve_gradle_module(&module.to_pom(), source) {
            Ok(one) => {
                missing.extend(one.missing);
                for (from, to) in one.graph.edges() {
                    graph.add_edges(from, [to.to_string()]);
                }
                for p in one.packages {
                    packages
                        .entry((p.name.clone(), p.version.clone()))
                        .and_modify(|seen| {
                            seen.direct |= p.direct;
                            seen.dev &= p.dev;
                        })
                        .or_insert(p);
                }
            }
            Err(e) => {
                missing.insert(e);
            }
        }
    }
    Resolution {
        packages: packages.into_values().collect(),
        graph,
        missing: missing.into_iter().collect(),
    }
}

fn build_scripts(dir: &Path, missing: &mut BTreeSet<String>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                if !SKIPPED_DIRS.contains(&name.as_str()) {
                    stack.push(entry.path());
                }
                continue;
            }
            let script = name.ends_with(".gradle") || name.ends_with(".gradle.kts");
            if !kind.is_file() || !script || name.starts_with("settings.gradle") {
                continue;
            }
            let path = entry.path();
            let shown = path
                .strip_prefix(dir)
                .unwrap_or(&path)
                .display()
                .to_string();
            if out.len() >= MAX_FILES || entry.metadata().map_or(true, |m| m.len() > MAX_FILE_BYTES)
            {
                missing.insert(format!("{shown}: too large or too many to read"));
                continue;
            }
            match fleetreach_core::repofile::read_to_string(&path) {
                Ok(text) => out.push((shown, strip_comments(&text))),
                Err(e) => {
                    missing.insert(format!("{shown}: {e}"));
                }
            }
        }
    }
    out.sort();
    out
}

fn properties(path: &Path) -> BTreeMap<String, String> {
    let text = fleetreach_core::repofile::read_to_string(path).unwrap_or_default();
    text.lines()
        .filter(|l| !l.trim_start().starts_with(['#', '!']))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Remove `//` and `/* */` comments, leaving strings (a URL's `//`) alone.
fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut quote = None;
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                out.push(c);
                if c == '\\' {
                    out.extend(chars.next());
                } else if c == q || c == '\n' {
                    quote = None;
                }
            }
            None if c == '/' && chars.peek() == Some(&'/') => {
                while chars.peek().is_some_and(|n| *n != '\n') {
                    chars.next();
                }
            }
            None if c == '/' && chars.peek() == Some(&'*') => {
                chars.next();
                let mut last = ' ';
                for n in chars.by_ref() {
                    if n == '\n' {
                        out.push('\n');
                    }
                    if last == '*' && n == '/' {
                        break;
                    }
                    last = n;
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                }
                out.push(c);
            }
        }
    }
    out
}

/// `val x = "1"`, `def x = '1'`, `ext.x = '1'`, `x = '1'` and `extra["x"] = "1"`. A name given
/// two values is dropped, so a declaration using it is reported instead of guessed.
fn script_variables(text: &str, vars: &mut BTreeMap<String, String>, twice: &mut BTreeSet<String>) {
    for line in text.lines() {
        let mut l = line.trim();
        for prefix in [
            "final ", "const ", "val ", "var ", "def ", "String ", "project.", "ext.",
        ] {
            l = l.strip_prefix(prefix).unwrap_or(l).trim_start();
        }
        let Some((name, value)) = l.split_once('=') else {
            continue;
        };
        let name = name
            .trim()
            .trim_start_matches("extra[")
            .trim_start_matches("ext[")
            .trim_end_matches(']')
            .trim_matches(['"', '\''])
            .split(':')
            .next()
            .unwrap_or_default()
            .trim();
        let plain = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-');
        let Some((value, tail)) = quoted(value.trim()) else {
            continue;
        };
        if !plain || !tail.trim().is_empty() || value.contains('$') {
            continue;
        }
        match vars.get(name) {
            Some(known) if known != value => {
                twice.insert(name.to_string());
            }
            _ => {
                vars.insert(name.to_string(), value.to_string());
            }
        }
    }
}

/// The string at the start of `text` and what follows it.
fn quoted(text: &str) -> Option<(&str, &str)> {
    let q = text.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let end = text[1..].find(q)? + 1;
    Some((&text[1..end], &text[end + 1..]))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Coordinate {
    group: String,
    artifact: String,
    version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Declared {
    coordinate: Coordinate,
    scope: &'static str,
}

#[derive(Debug, Default)]
struct Module {
    deps: Vec<Declared>,
    platforms: Vec<Coordinate>,
    constraints: Vec<Coordinate>,
    unread: Vec<String>,
}

impl Module {
    /// The module as a POM, so BOM imports and versions go through the resolver.
    fn to_pom(&self) -> String {
        let xml = |text: &str| {
            text.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        };
        let dep = |c: &Coordinate, extra: &str| {
            let version = c
                .version
                .as_ref()
                .map(|v| format!("<version>{}</version>", xml(v)))
                .unwrap_or_default();
            format!(
                "<dependency><groupId>{}</groupId><artifactId>{}</artifactId>{version}{extra}</dependency>",
                xml(&c.group),
                xml(&c.artifact)
            )
        };
        let mut managed = String::new();
        for p in &self.platforms {
            managed.push_str(&dep(p, "<type>pom</type><scope>import</scope>"));
        }
        for c in &self.constraints {
            managed.push_str(&dep(c, ""));
        }
        let mut deps = String::new();
        for d in &self.deps {
            deps.push_str(&dep(&d.coordinate, &format!("<scope>{}</scope>", d.scope)));
        }
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>gradle</groupId>\
             <artifactId>build</artifactId><version>0</version>\
             <dependencyManagement><dependencies>{managed}</dependencies></dependencyManagement>\
             <dependencies>{deps}</dependencies></project>"
        )
    }
}

#[derive(Debug, Default)]
struct Catalog {
    /// `a-b.c` as written, to its coordinate.
    libraries: BTreeMap<String, Coordinate>,
    bundles: BTreeMap<String, Vec<String>>,
    /// Plugin id to version.
    plugins: BTreeMap<String, String>,
    /// Plugin alias to id.
    plugin_aliases: BTreeMap<String, String>,
    unread: Vec<String>,
}

fn accessor(alias: &str) -> String {
    alias.replace(['-', '_'], ".")
}

impl Catalog {
    fn parse(text: &str) -> Result<Catalog, String> {
        let doc: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut catalog = Catalog::default();
        let versions = doc.get("versions");
        let table = |key: &str| doc.get(key).and_then(toml::Value::as_table);
        for (alias, entry) in table("libraries").into_iter().flatten() {
            match library(entry, versions) {
                Ok(coordinate) => {
                    catalog.libraries.insert(alias.clone(), coordinate);
                }
                Err(e) => catalog.unread.push(format!("library `{alias}`: {e}")),
            }
        }
        for (alias, members) in table("bundles").into_iter().flatten() {
            let members = members.as_array().into_iter().flatten();
            let members = members.filter_map(toml::Value::as_str).map(str::to_string);
            catalog.bundles.insert(alias.clone(), members.collect());
        }
        for (alias, entry) in table("plugins").into_iter().flatten() {
            let (id, version) = match entry.as_str() {
                Some(text) => match text.split_once(':') {
                    Some((id, version)) => (id.to_string(), Some(version.to_string())),
                    None => (text.to_string(), None),
                },
                None => {
                    let id = entry.get("id").and_then(toml::Value::as_str);
                    let version = entry.get("version");
                    let version = version.and_then(|v| catalog_version(v, versions).ok());
                    (id.unwrap_or_default().to_string(), version)
                }
            };
            catalog.plugin_aliases.insert(accessor(alias), id.clone());
            if let Some(version) = version {
                catalog.plugins.insert(id, version);
            }
        }
        Ok(catalog)
    }
}

const SPRING_BOOT: &str = "org.springframework.boot";
const KOTLIN_JVM: &str = "org.jetbrains.kotlin.jvm";

/// The plugin a line applies, with its version when the line gives one: `id 'x' version '1'`,
/// `id("x") version "1"`, `kotlin("jvm") version "1"` or `alias(libs.plugins.x)`.
fn plugin_line(line: &str, catalog: &Catalog) -> Option<(String, Option<String>)> {
    if let Some(alias) = line.strip_prefix("alias(libs.plugins.") {
        let alias = alias.split(')').next()?;
        return Some((catalog.plugin_aliases.get(alias)?.clone(), None));
    }
    let (id, rest) = if let Some(rest) = line.strip_prefix("kotlin(") {
        let (short, tail) = quoted(rest.trim())?;
        (format!("org.jetbrains.kotlin.{short}"), tail)
    } else {
        let rest = line.strip_prefix("id")?;
        let rest = rest.trim_start().trim_start_matches('(').trim_start();
        let (id, tail) = quoted(rest)?;
        (id.to_string(), tail)
    };
    let rest = rest.trim_start().trim_start_matches(')').trim_start();
    let version = rest
        .strip_prefix("version")
        .and_then(|v| quoted(v.trim_start()))
        .map(|(v, _)| v.to_string());
    Some((id, version))
}

/// `"g:a:v"`, `{ module = "g:a", version = ... }` or `{ group, name, version }`, where a version
/// is a string, `{ ref = "x" }`, `version.ref = "x"` or rich (`strictly`, `require`, `prefer`).
fn library(entry: &toml::Value, versions: Option<&toml::Value>) -> Result<Coordinate, String> {
    if let Some(text) = entry.as_str() {
        return coordinate(text, &BTreeMap::new());
    }
    let text = |key: &str| entry.get(key).and_then(toml::Value::as_str);
    let (group, artifact) = match (text("module"), text("group"), text("name")) {
        (Some(module), _, _) => module
            .split_once(':')
            .ok_or_else(|| format!("module `{module}` is not group:name"))?,
        (None, Some(group), Some(name)) => (group, name),
        _ => return Err("names no module".to_string()),
    };
    let version = match entry.get("version") {
        None => None,
        Some(v) => Some(catalog_version(v, versions)?),
    };
    Ok(Coordinate {
        group: group.to_string(),
        artifact: artifact.to_string(),
        version: version.map(|v| version_text(&v)).transpose()?,
    })
}

fn catalog_version(value: &toml::Value, versions: Option<&toml::Value>) -> Result<String, String> {
    if let Some(version) = value.as_str() {
        return Ok(version.to_string());
    }
    if let Some(name) = value.get("ref").and_then(toml::Value::as_str) {
        let target = versions
            .and_then(|v| v.get(name))
            .ok_or_else(|| format!("version.ref `{name}` is not defined"))?;
        return catalog_version(target, None);
    }
    ["strictly", "require", "prefer"]
        .iter()
        .find_map(|k| value.get(*k).and_then(toml::Value::as_str))
        .map(str::to_string)
        .ok_or_else(|| "has no usable version".to_string())
}

/// A version as the resolver spells it. `1.+` and `latest.release` depend on what is published
/// on the day, so they are reported rather than picked.
fn version_text(version: &str) -> Result<String, String> {
    let v = version.trim();
    if v.ends_with('+') || v.starts_with("latest.") {
        return Err(format!("dynamic version `{v}`"));
    }
    // Gradle writes an excluded bound with the bracket reversed: `[1.0,2.0[`.
    let mut out = v.to_string();
    if out.starts_with(']') {
        out.replace_range(0..1, "(");
    }
    if out.starts_with(['[', '(']) && out.ends_with('[') {
        out.pop();
        out.push(')');
    }
    Ok(out)
}

fn coordinate(text: &str, vars: &BTreeMap<String, String>) -> Result<Coordinate, String> {
    let expanded = expand(text, vars)?;
    let plain = expanded.split('@').next().unwrap_or_default();
    let mut parts = plain.split(':');
    let (Some(group), Some(artifact)) = (parts.next(), parts.next()) else {
        return Err(format!("`{text}` is not group:name:version"));
    };
    if group.is_empty() || artifact.is_empty() {
        return Err(format!("`{text}` is not group:name:version"));
    }
    let version = parts.next().filter(|v| !v.is_empty());
    Ok(Coordinate {
        group: group.to_string(),
        artifact: artifact.to_string(),
        version: version.map(version_text).transpose()?,
    })
}

/// Replace `$name` and `${name}`, or fail naming the text.
fn expand(text: &str, vars: &BTreeMap<String, String>) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let (name, tail) = if let Some(inner) = after.strip_prefix('{') {
            let end = inner.find('}').ok_or(format!("`{text}` is computed"))?;
            (&inner[..end], &inner[end + 1..])
        } else {
            let end = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
                .unwrap_or(after.len());
            (&after[..end], &after[end..])
        };
        let name = name.trim();
        let short = [
            "rootProject.ext.",
            "project.ext.",
            "rootProject.",
            "project.",
            "ext.",
        ]
        .iter()
        .find_map(|p| name.strip_prefix(p))
        .unwrap_or(name);
        let value = vars
            .get(name)
            .or_else(|| vars.get(short))
            .ok_or_else(|| format!("`{text}` is computed"))?;
        out.push_str(value);
        rest = tail;
    }
    out.push_str(rest);
    Ok(out)
}

struct Context {
    vars: BTreeMap<String, String>,
    catalog: Catalog,
    /// Plugin id to the version any script or the catalog gives it.
    plugins: BTreeMap<String, String>,
    /// Catalog aliases some build file names.
    used: BTreeSet<String>,
}

impl Context {
    /// The aliases a `libs.a.b` accessor names: one library, or a bundle's members.
    fn aliases(&self, path: &str) -> Vec<String> {
        if let Some(bundle) = path.strip_prefix("bundles.") {
            let found = self
                .catalog
                .bundles
                .iter()
                .find(|(a, _)| accessor(a) == bundle);
            return found
                .map(|(_, members)| members.clone())
                .unwrap_or_default();
        }
        self.catalog
            .libraries
            .keys()
            .filter(|a| accessor(a) == path)
            .cloned()
            .collect()
    }
}

fn scope_of(configuration: &str) -> &'static str {
    let lower = configuration.to_ascii_lowercase();
    if lower.contains("test") {
        "test"
    } else if lower.contains("compileonly")
        || lower.contains("annotationprocessor")
        || lower.starts_with("kapt")
        || lower.starts_with("ksp")
    {
        "provided"
    } else if lower.contains("runtimeonly") || lower == "runtime" {
        "runtime"
    } else {
        "compile"
    }
}

fn is_configuration(name: &str) -> bool {
    const NAMES: &[&str] = &["api", "implementation", "compile", "runtime", "kapt", "ksp"];
    const ENDINGS: &[&str] = &[
        "Api",
        "Implementation",
        "Compile",
        "Runtime",
        "CompileOnly",
        "CompileOnlyApi",
        "RuntimeOnly",
        "AnnotationProcessor",
    ];
    NAMES.contains(&name)
        || name == "compileOnly"
        || name == "compileOnlyApi"
        || name == "runtimeOnly"
        || name == "annotationProcessor"
        || name.starts_with("kapt")
        || name.starts_with("ksp")
        || ENDINGS.iter().any(|e| name.ends_with(e))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Block {
    Dependencies,
    Constraints,
    Other,
}

fn read_script(text: &str, context: &mut Context) -> Module {
    let mut module = Module::default();
    let mut blocks: Vec<Block> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let current = blocks.last().copied();
        if !matches!(current, Some(Block::Dependencies | Block::Constraints)) {
            apply_plugin(trimmed, context, &mut module);
        }
        let opens = trimmed.ends_with('{') || trimmed.contains('{');
        let word: String = trimmed
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let after_word = trimmed[word.len()..].trim_start();
        let new_block = if word == "dependencies" && after_word.starts_with('{') {
            Some(Block::Dependencies)
        } else if word == "constraints"
            && after_word.starts_with('{')
            && current == Some(Block::Dependencies)
        {
            Some(Block::Constraints)
        } else {
            None
        };
        if let Some(block) = new_block {
            // A one-liner: `dependencies { implementation 'g:a:1' }`.
            let inner = after_word[1..].trim();
            if let Some(body) = inner.strip_suffix('}') {
                read_entry(body.trim(), block, context, &mut module);
                continue;
            }
            blocks.push(block);
            read_entry(inner, block, context, &mut module);
            continue;
        }
        if let Some(block @ (Block::Dependencies | Block::Constraints)) = current {
            if opens || !trimmed.starts_with('}') {
                read_entry(trimmed, block, context, &mut module);
            }
        }
        for c in code_only(line).chars() {
            match c {
                '{' => blocks.push(Block::Other),
                '}' => {
                    blocks.pop();
                }
                _ => {}
            }
        }
    }
    module
}

/// The dependencies a plugin brings: Spring Boot's BOM and Kotlin's standard library.
fn apply_plugin(line: &str, context: &Context, module: &mut Module) {
    let Some((id, _)) = plugin_line(line, &context.catalog) else {
        return;
    };
    let Some(version) = context.plugins.get(&id) else {
        return;
    };
    if id == SPRING_BOOT {
        module.platforms.push(Coordinate {
            group: "org.springframework.boot".to_string(),
            artifact: "spring-boot-dependencies".to_string(),
            version: Some(version.clone()),
        });
    } else if id == KOTLIN_JVM {
        module.deps.push(Declared {
            coordinate: Coordinate {
                group: "org.jetbrains.kotlin".to_string(),
                artifact: "kotlin-stdlib".to_string(),
                version: Some(version.clone()),
            },
            scope: "compile",
        });
    }
}

/// `line` without its strings, so a brace in one does not count.
fn code_only(line: &str) -> String {
    let mut out = String::new();
    let mut quote = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) if c == '\\' => {
                chars.next();
                let _: char = q;
            }
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            None => out.push(c),
        }
    }
    out
}

/// One statement of a `dependencies` or `constraints` block.
fn read_entry(line: &str, block: Block, context: &mut Context, module: &mut Module) {
    if line.is_empty() || line == "{" {
        return;
    }
    let unquoted = line.trim_start_matches(['"', '\'']);
    let name: String = unquoted
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name == "classpath" || name == "exclude" || name == "because" {
        return;
    }
    let rest = unquoted[name.len()..]
        .trim_start_matches(['"', '\''])
        .trim();
    // A custom configuration (`checkstyle`, `developmentOnly`) is off the runtime classpath.
    let scope = if is_configuration(&name) {
        scope_of(&name)
    } else if rest.trim_start_matches('(').starts_with(['"', '\'']) || rest.contains("libs.") {
        "test"
    } else {
        module
            .unread
            .push(format!("`{line}` is not a plain declaration"));
        return;
    };
    read_values(rest, scope, block, context, module);
}

fn read_values(
    text: &str,
    scope: &'static str,
    block: Block,
    context: &mut Context,
    module: &mut Module,
) {
    let mut rest = text.trim().trim_start_matches('(').trim();
    let whole = text.trim();
    let add = |module: &mut Module, c: Coordinate, platform: bool| {
        if platform {
            module.platforms.push(c);
        } else if block == Block::Constraints {
            module.constraints.push(c);
        } else {
            module.deps.push(Declared {
                coordinate: c,
                scope,
            });
        }
    };
    let mut platform = false;
    for prefix in ["enforcedPlatform(", "platform(", "testFixtures("] {
        if let Some(inner) = rest.strip_prefix(prefix) {
            platform = prefix != "testFixtures(";
            rest = inner.trim();
            break;
        }
    }
    let local = [
        "project(",
        "project ",
        "files(",
        "files ",
        "fileTree(",
        "gradleApi(",
        "gradleTestKit(",
        "localGroovy(",
        "sourceSets",
        "dependencies.",
    ];
    if local.iter().any(|p| rest.starts_with(p)) {
        return;
    }
    if rest.starts_with("group") {
        let field = |key: &str| {
            let at = rest.find(key)? + key.len();
            let tail = rest[at..]
                .trim_start()
                .strip_prefix([':', '='])?
                .trim_start();
            quoted(tail).map(|(value, _)| value)
        };
        if let (Some(g), Some(a)) = (field("group"), field("name")) {
            let literal = format!("{g}:{a}:{}", field("version").unwrap_or_default());
            match coordinate(&literal, &context.vars) {
                Ok(c) => add(module, c, platform),
                Err(e) => module.unread.push(e),
            }
            return;
        }
    }
    if let Some(path) = rest.strip_prefix("libs.") {
        let end = path
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
            .unwrap_or(path.len());
        let path = path[..end]
            .trim_end_matches(".get")
            .trim_end_matches(".asProvider");
        let aliases = context.aliases(path);
        if aliases.is_empty() {
            module
                .unread
                .push(format!("`libs.{path}` is not in the catalog"));
        }
        for alias in aliases {
            match context.catalog.libraries.get(&alias).cloned() {
                Some(c) => add(module, c, platform),
                None => module
                    .unread
                    .push(format!("`{alias}` is not in the catalog")),
            }
            context.used.insert(alias);
        }
        return;
    }
    if let Some(inner) = rest.strip_prefix("kotlin(") {
        let Some((short, tail)) = quoted(inner.trim()) else {
            module.unread.push(format!("`{whole}` is computed"));
            return;
        };
        let version = tail
            .trim_start()
            .strip_prefix(',')
            .and_then(|t| quoted(t.trim()))
            .map(|(v, _)| v)
            .or(context.plugins.get(KOTLIN_JVM).map(String::as_str));
        match version {
            Some(v) => add(
                module,
                Coordinate {
                    group: "org.jetbrains.kotlin".to_string(),
                    artifact: format!("kotlin-{short}"),
                    version: Some(v.to_string()),
                },
                platform,
            ),
            None => module.unread.push(format!(
                "`{whole}` takes its version from the Kotlin plugin"
            )),
        }
        return;
    }
    // One or more literals: `implementation 'g:a:1', 'g:b:2'`.
    let mut any = false;
    while let Some((value, tail)) = quoted(rest) {
        any = true;
        match coordinate(value, &context.vars) {
            Ok(c) => add(module, c, platform),
            Err(e) => module.unread.push(e),
        }
        match tail.trim_start().strip_prefix(',') {
            Some(next) => rest = next.trim_start(),
            None => break,
        }
    }
    if !any {
        module.unread.push(format!("`{whole}` is computed"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn context(toml: &str, vars: &[(&str, &str)]) -> Context {
        Context {
            vars: vars
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            catalog: Catalog::parse(toml).unwrap(),
            plugins: BTreeMap::new(),
            used: BTreeSet::new(),
        }
    }

    fn rows(m: &Module) -> Vec<(String, &'static str)> {
        m.deps
            .iter()
            .map(|d| {
                let c = &d.coordinate;
                let v = c.version.as_deref().unwrap_or("-");
                (format!("{}:{}:{v}", c.group, c.artifact), d.scope)
            })
            .collect()
    }

    #[test]
    fn reads_groovy_and_kotlin_declarations() {
        let script = strip_comments(
            r#"
buildscript { dependencies { classpath 'g:plugin:1' } }
dependencies {
    implementation 'g:a:1.0'            // a comment
    api("g:b:2.0") { exclude group: 'x', module: 'y' }
    /* implementation 'g:gone:1' */
    testImplementation "g:c:$cVersion"
    runtimeOnly group: 'g', name: 'd', version: '4.0'
    compileOnly(group = "g", name = "e", version = "5.0")
    implementation project(':sibling')
    implementation(files("libs/x.jar"))
    implementation platform('g:bom:1.0')
    implementation 'g:managed'
    "implementation"("g:f:6.0")
    kapt 'g:h:7.0', 'g:i:8.0'
    implementation "g:j:${unknown}"
    implementation 'g:k:1.+'
    implementation someHelper('x')
    helper()
    checkstyle 'g:tool:1.0'
    constraints {
        implementation('g:pinned:9.0') { because 'CVE' }
    }
}
"#,
        );
        let mut c = context("", &[("cVersion", "3.0")]);
        let m = read_script(&script, &mut c);
        assert_eq!(
            rows(&m),
            [
                ("g:a:1.0".to_string(), "compile"),
                ("g:b:2.0".to_string(), "compile"),
                ("g:c:3.0".to_string(), "test"),
                ("g:d:4.0".to_string(), "runtime"),
                ("g:e:5.0".to_string(), "provided"),
                ("g:managed:-".to_string(), "compile"),
                ("g:f:6.0".to_string(), "compile"),
                ("g:h:7.0".to_string(), "provided"),
                ("g:i:8.0".to_string(), "provided"),
                ("g:tool:1.0".to_string(), "test"),
            ]
        );
        assert_eq!(m.platforms.len(), 1);
        assert_eq!(m.constraints[0].artifact, "pinned");
        assert_eq!(m.unread.len(), 4, "{:?}", m.unread);
    }

    #[test]
    fn reads_every_catalog_form() {
        let toml = r#"
[versions]
x = "1.0"
rich = { strictly = "2.0" }
[libraries]
plain = "g:plain:0.1"
a-b = { module = "g:ab", version.ref = "x" }
c_d = { group = "g", name = "cd", version = { ref = "rich" } }
e = { module = "g:e", version = "3.0" }
nov = { module = "g:nov" }
[bundles]
set = ["a-b", "e"]
"#;
        let mut c = context(toml, &[]);
        let script = "dependencies {\n  implementation(libs.a.b)\n  testImplementation libs.c.d\n  api(libs.bundles.set)\n  implementation(platform(libs.plain))\n  implementation(libs.missing)\n}\n";
        let m = read_script(script, &mut c);
        assert_eq!(
            rows(&m),
            [
                ("g:ab:1.0".to_string(), "compile"),
                ("g:cd:2.0".to_string(), "test"),
                ("g:ab:1.0".to_string(), "compile"),
                ("g:e:3.0".to_string(), "compile"),
            ]
        );
        assert_eq!(m.platforms[0].artifact, "plain");
        assert_eq!(m.unread, ["`libs.missing` is not in the catalog"]);
        assert!(!c.used.contains("nov"));
    }

    #[test]
    fn plugins_bring_their_boms_and_libraries() {
        let toml = "[plugins]\nboot = { id = \"org.springframework.boot\", version = \"3.2.0\" }\n";
        let catalog = Catalog::parse(toml).unwrap();
        assert_eq!(
            plugin_line("alias(libs.plugins.boot)", &catalog),
            Some(("org.springframework.boot".to_string(), None))
        );
        for line in ["id 'g.x' version '1.0'", "id(\"g.x\") version \"1.0\""] {
            assert_eq!(
                plugin_line(line, &catalog),
                Some(("g.x".to_string(), Some("1.0".to_string())))
            );
        }
        assert_eq!(
            plugin_line("kotlin(\"jvm\") version \"2.0.0\"", &catalog)
                .unwrap()
                .0,
            KOTLIN_JVM
        );

        let mut c = context(toml, &[]);
        c.plugins = c.catalog.plugins.clone();
        c.plugins
            .insert(KOTLIN_JVM.to_string(), "2.0.0".to_string());
        let m = read_script(
            "plugins {\n  alias(libs.plugins.boot)\n  kotlin(\"jvm\")\n}\ndependencies {\n  testImplementation(kotlin(\"test\"))\n}\n",
            &mut c,
        );
        assert_eq!(m.platforms[0].version.as_deref(), Some("3.2.0"));
        assert_eq!(
            rows(&m),
            [
                (
                    "org.jetbrains.kotlin:kotlin-stdlib:2.0.0".to_string(),
                    "compile"
                ),
                ("org.jetbrains.kotlin:kotlin-test:2.0.0".to_string(), "test"),
            ]
        );
    }

    #[test]
    fn variables_with_two_values_are_not_guessed() {
        let mut vars = BTreeMap::new();
        let mut twice = BTreeSet::new();
        script_variables(
            "val a = \"1\"\next.b = '2'\ndef c = '3'\nc = '4'\nd = compute()\n",
            &mut vars,
            &mut twice,
        );
        assert_eq!(vars["a"], "1");
        assert_eq!(vars["b"], "2");
        assert!(twice.contains("c"));
        assert!(!vars.contains_key("d"));
    }

    #[test]
    fn gradle_ranges_become_maven_ranges() {
        assert_eq!(version_text("[1.0,2.0[").unwrap(), "[1.0,2.0)");
        assert_eq!(version_text("]1.0,2.0]").unwrap(), "(1.0,2.0]");
        assert!(version_text("1.+").is_err());
        assert!(version_text("latest.release").is_err());
    }

    /// POMs in memory, keyed `g:a:v`.
    struct Mem(BTreeMap<String, String>);

    impl PomSource for Mem {
        fn pom(&self, g: &str, a: &str, v: &str) -> Option<String> {
            self.0.get(&format!("{g}:{a}:{v}")).cloned()
        }
        fn metadata(&self, _: &str, _: &str) -> Option<String> {
            None
        }
    }

    fn pom(a: &str, v: &str, deps: &[(&str, &str)]) -> (String, String) {
        let deps: String = deps
            .iter()
            .map(|(a, v)| {
                format!("<dependency><groupId>g</groupId><artifactId>{a}</artifactId><version>{v}</version></dependency>")
            })
            .collect();
        (
            format!("g:{a}:{v}"),
            format!("<project><groupId>g</groupId><artifactId>{a}</artifactId><version>{v}</version><dependencies>{deps}</dependencies></project>"),
        )
    }

    fn tree(tag: &str, files: &[(&str, &str)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fr-gradle-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (file, text) in files {
            let path = dir.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        dir
    }

    fn versions(r: &Resolution, name: &str) -> Vec<String> {
        r.packages
            .iter()
            .filter(|p| p.name == name)
            .map(|p| p.version.clone())
            .collect()
    }

    #[test]
    fn the_highest_version_wins_where_maven_would_take_the_nearest() {
        // Maven keeps `c` at 1.0, nearest. Gradle takes 2.0, which then brings `d`.
        let repo = Mem(BTreeMap::from([
            pom("a", "1", &[("b", "1")]),
            pom("b", "1", &[("c", "2.0")]),
            pom("c", "1.0", &[]),
            pom("c", "2.0", &[("d", "1")]),
            pom("d", "1", &[]),
        ]));
        let dir = tree(
            "highest",
            &[(
                "build.gradle",
                "dependencies {\n  implementation 'g:c:1.0'\n  implementation 'g:a:1'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:c"), ["2.0"]);
        assert_eq!(versions(&r, "g:d"), ["1"]);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
    }

    #[test]
    fn subprojects_resolve_alone_so_a_lower_version_stays_visible() {
        let repo = Mem(BTreeMap::from([pom("c", "1.0", &[]), pom("c", "2.0", &[])]));
        let dir = tree(
            "subprojects",
            &[
                ("settings.gradle", ""),
                (
                    "one/build.gradle",
                    "dependencies { implementation 'g:c:1.0' }\n",
                ),
                (
                    "two/build.gradle",
                    "dependencies { implementation 'g:c:2.0' }\n",
                ),
            ],
        );
        assert_eq!(
            versions(&resolve_gradle(&dir, &repo), "g:c"),
            ["1.0", "2.0"]
        );
    }

    #[test]
    fn unused_catalog_entries_and_build_logic_are_development_only() {
        let repo = Mem(BTreeMap::from([
            pom("a", "1", &[]),
            pom("b", "1", &[]),
            pom("c", "1", &[]),
        ]));
        let dir = tree(
            "dev",
            &[
                (
                    "gradle/libs.versions.toml",
                    "[libraries]\na = \"g:a:1\"\nb = \"g:b:1\"\n",
                ),
                ("build.gradle", "dependencies { implementation(libs.a) }\n"),
                (
                    "buildSrc/build.gradle",
                    "dependencies { implementation 'g:c:1' }\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        let dev = |name: &str| r.packages.iter().find(|p| p.name == name).unwrap().dev;
        assert!(!dev("g:a"));
        assert!(dev("g:b"));
        assert!(dev("g:c"));
    }

    #[test]
    fn a_comment_marker_in_a_string_is_not_a_comment() {
        let out = strip_comments("url = \"https://x\" // gone\n/* a\nb */ c\n");
        assert_eq!(out, "url = \"https://x\" \n\n c\n");
    }
}
