//! Read a Gradle build without running it: `gradle/libs.versions.toml` and the literal
//! declarations in `*.gradle` and `*.gradle.kts`, resolved through the POM resolver with
//! Gradle's rule that the highest requested version wins. Build scripts are programs, so
//! anything that is not a literal (a helper call, an undefined variable, a dynamic version) is
//! named in [`Resolution::missing`], and each build file is resolved alone, since two
//! subprojects can pin different versions.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::resolve::{resolve_gradle_module, Enforced, PomSource, Resolution, ResolvedDep};

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
    let mut aliases = Vec::new();
    for (_, text) in &build_constants(dir) {
        kotlin_constants(text, &mut vars, &mut seen_twice);
    }
    let mut entries = Vec::new();
    for (_, text) in &scripts {
        script_variables(text, &mut vars, &mut seen_twice, &mut aliases);
        map_entries(text, &mut entries);
        set_calls(text, &mut entries);
    }
    // `val v = extra["k"] as String` and `extra["k"] = Versions.K` name another variable,
    // known once every literal is read.
    for (name, key) in aliases {
        if let Some(value) = vars.get(&key).cloned() {
            match vars.get(&name) {
                Some(known) if *known != value => {
                    seen_twice.insert(name);
                }
                _ => {
                    vars.insert(name, value);
                }
            }
        }
    }
    // `lib = [ "k": "g:a:${v}" ]` entries, as `lib.k`, once the versions they name are known.
    for (name, template) in entries {
        let Ok(value) = expand(&template, &vars) else {
            continue;
        };
        match vars.get(&name) {
            Some(known) if *known != value => {
                seen_twice.insert(name);
            }
            _ => {
                vars.insert(name, value);
            }
        }
    }
    for name in seen_twice {
        vars.remove(&name);
    }
    let mut doc =
        match fleetreach_core::repofile::read_to_string(dir.join("gradle/libs.versions.toml")) {
            Ok(text) => toml::from_str::<toml::Table>(&text).unwrap_or_else(|e| {
                missing.insert(format!("gradle/libs.versions.toml: {e}"));
                toml::Table::new()
            }),
            Err(_) => toml::Table::new(),
        };
    // A catalog can also be declared in the settings script; its entries join the file's.
    for name in ["settings.gradle", "settings.gradle.kts"] {
        if let Ok(text) = fleetreach_core::repofile::read_to_string(dir.join(name)) {
            for (section, entries) in settings_catalog(&text) {
                let slot = doc
                    .entry(section)
                    .or_insert_with(|| toml::Value::Table(toml::Table::new()));
                if let Some(table) = slot.as_table_mut() {
                    for (key, entry) in entries {
                        table.entry(key).or_insert(entry);
                    }
                }
            }
        }
    }
    let catalog = Catalog::from_doc(&toml::Value::Table(doc));
    for (alias, version) in &catalog.versions {
        vars.entry(format!("libs.versions.{alias}"))
            .or_insert_with(|| version.clone());
    }
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
            let line = line.trim();
            if let Some((id, Some(version))) = plugin_line(line, &catalog) {
                plugins.entry(id).or_insert(version);
            }
            // `buildscript { dependencies { classpath "g:a:v" } }` puts a plugin on the
            // build's classpath at that version; `apply plugin:` then applies it.
            if let Some((id, version)) = classpath_plugin(line, &vars) {
                plugins.entry(id.to_string()).or_insert(version);
            }
        }
    }
    let mut extended_by = BTreeMap::new();
    for (_, text) in &scripts {
        for line in text.lines() {
            extends_from(line.trim(), &mut extended_by);
        }
    }
    let mut context = Context {
        vars,
        catalog,
        plugins,
        used: BTreeSet::new(),
        extended_by,
        spring_dm: scripts
            .iter()
            .any(|(_, t)| t.contains("io.spring.dependency-management")),
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
    // The root build's `subprojects { }` and `allprojects { }` apply to every other build file
    // (BOM imports and versions there are how most multi-project builds manage versions).
    if let Some(root) = scripts
        .iter()
        .position(|(f, _)| f == "build.gradle" || f == "build.gradle.kts")
    {
        let shared = std::mem::take(&mut modules[root].shared);
        for (i, (file, _)) in scripts.iter().enumerate() {
            if i == root || file.starts_with("buildSrc/") || file.starts_with("build-logic/") {
                continue;
            }
            let module = &mut modules[i];
            module.shared_from = Some(module.platforms.len());
            module.platforms.extend_from_slice(&shared.platforms);
            module.constraints.extend_from_slice(&shared.constraints);
            module.deps.extend_from_slice(&shared.deps);
            module
                .project_platforms
                .extend_from_slice(&shared.project_platforms);
        }
    }
    // `platform(project(":p"))` takes the platform project's versions, by its default path.
    let by_path: BTreeMap<String, usize> = scripts
        .iter()
        .enumerate()
        .filter_map(|(i, (file, _))| {
            let dir = Path::new(file).parent()?.to_str()?;
            Some((format!(":{}", dir.replace('/', ":")), i))
        })
        .collect();
    let managed: Vec<(Vec<Coordinate>, Vec<Coordinate>)> = modules
        .iter()
        .map(|m| {
            let (mut platforms, mut constraints) = (Vec::new(), Vec::new());
            for (path, strict) in &m.project_platforms {
                if let Some(&i) = by_path.get(path) {
                    // `enforcedPlatform(project(...))` forces what the platform project sets.
                    let mark = |c: &Coordinate| Coordinate {
                        strict: c.strict || *strict,
                        ..c.clone()
                    };
                    platforms.extend(modules[i].platforms.iter().map(mark));
                    constraints.extend(modules[i].constraints.iter().map(mark));
                } else {
                    missing.insert(format!(
                        "platform project `{path}` is not a build file here"
                    ));
                }
            }
            (platforms, constraints)
        })
        .collect();
    for (module, (platforms, constraints)) in modules.iter_mut().zip(managed) {
        module.platforms.extend(platforms);
        module.constraints.extend(constraints);
    }
    let unused: Vec<Declared> = context
        .catalog
        .libraries
        .iter()
        .filter(|(alias, _)| !context.used.contains(*alias))
        .map(|(_, coordinate)| Declared {
            coordinate: coordinate.clone(),
            scope: "test",
            exclusions: Vec::new(),
            pom: false,
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

    // The Spring dependency-management plugin (also applied by Spring Boot's) lets a project
    // property override the same-named property of an imported BOM.
    let spring = scripts.iter().any(|(_, t)| {
        t.contains("io.spring.dependency-management") || t.contains("org.springframework.boot")
    });
    let bom_overrides = if spring {
        context.vars.clone()
    } else {
        BTreeMap::new()
    };
    let mut graph = fleetreach_core::DepGraph::new("(root)");
    let mut packages: BTreeMap<(String, String), ResolvedDep> = BTreeMap::new();
    for module in &modules {
        if module.deps.is_empty() {
            continue;
        }
        // Gradle resolves each configuration on its own, so a test dependency cannot raise a
        // version on the main classpath. Resolve the main classpath first; what only the full
        // (test) resolution adds is test-only.
        let has_test = module.deps.iter().any(|d| d.scope == "test");
        let has_main = module.deps.iter().any(|d| d.scope != "test");
        let mut main = BTreeSet::new();
        let passes: &[bool] = match (has_main, has_test) {
            (true, true) => &[true, false],
            _ => &[false],
        };
        for &main_only in passes {
            match resolve_gradle_module(
                &module.to_pom(main_only),
                source,
                &bom_overrides,
                &module.enforced(),
            ) {
                Ok(one) => {
                    missing.extend(one.missing);
                    for (from, to) in one.graph.edges() {
                        graph.add_edges(from, [to.to_string()]);
                    }
                    for mut p in one.packages {
                        let key = (p.name.clone(), p.version.clone());
                        if main_only {
                            main.insert(key.clone());
                        } else if passes.len() > 1 && !main.contains(&key) {
                            p.dev = true;
                        }
                        packages
                            .entry(key)
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
/// two values is dropped, so a declaration using it is reported instead of guessed. A value
/// naming another variable (`extra["k"] as String`, `property("k")`, `Versions.K`) goes to
/// `aliases`, resolved once every literal is known.
fn script_variables(
    text: &str,
    vars: &mut BTreeMap<String, String>,
    twice: &mut BTreeSet<String>,
    aliases: &mut Vec<(String, String)>,
) {
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
        if plain {
            if let Some(v) = property_default(value, vars) {
                match vars.get(name) {
                    Some(known) if *known != v => {
                        twice.insert(name.to_string());
                    }
                    _ => {
                        vars.insert(name.to_string(), v);
                    }
                }
                continue;
            }
        }
        let Some((value, tail)) = quoted(value.trim()) else {
            if plain {
                if let Some(key) = variable_reference(value) {
                    aliases.push((name.to_string(), key));
                }
            }
            continue;
        };
        // A lone trailing comma is an entry of a Groovy list: `libraries = [ v = '1.0', ... ]`.
        let tail = tail.trim();
        if !plain || !(tail.is_empty() || tail == ",") || value.contains('$') {
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

/// `set('k', "v")`, `ext.set("k", "v")` or `extra.set("k", "v")` in an `ext` block: the
/// spelling for a property name with dots or dashes, as a BOM override (`grpc-java.version`).
fn set_calls(text: &str, out: &mut Vec<(String, String)>) {
    for line in text.lines() {
        let l = line.trim();
        let Some(rest) = ["set(", "ext.set(", "extra.set(", "project.ext.set("]
            .iter()
            .find_map(|p| l.strip_prefix(p))
        else {
            continue;
        };
        let Some((name, tail)) = quoted(rest.trim_start()) else {
            continue;
        };
        let Some(tail) = tail.trim_start().strip_prefix(',') else {
            continue;
        };
        let Some((value, end)) = quoted(tail.trim_start()) else {
            continue;
        };
        if end.trim() == ")" {
            out.push((name.to_string(), value.to_string()));
        }
    }
}

/// The entries of Groovy map literals, `name = [ "key": "value", ... ]` over several lines (as
/// `ext.libraries = [...]` builds keep coordinates), as `name.key` and the value as written.
fn map_entries(text: &str, out: &mut Vec<(String, String)>) {
    let mut current: Option<String> = None;
    for line in text.lines() {
        let mut l = line.trim();
        if let Some(name) = &current {
            if l.starts_with(']') {
                current = None;
                continue;
            }
            let l = l.trim_end_matches(',').trim();
            let (key, value) = if let Some((key, tail)) = quoted(l) {
                let Some(value) = tail.trim_start().strip_prefix(':') else {
                    continue;
                };
                (key, value.trim())
            } else {
                let Some((key, value)) = l.split_once(':') else {
                    continue;
                };
                let key = key.trim();
                if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    continue;
                }
                (key, value.trim())
            };
            if let Some((value, tail)) = quoted(value) {
                if tail.trim().is_empty() {
                    out.push((format!("{name}.{key}"), value.to_string()));
                }
            }
            continue;
        }
        for prefix in ["project.ext.", "ext.", "def ", "final "] {
            l = l.strip_prefix(prefix).unwrap_or(l).trim_start();
        }
        let Some((name, open)) = l.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let plain = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if plain && open.trim() == "[" {
            current = Some(name.to_string());
        }
    }
}

/// `lib["k"]` or `lib['k']` as the variable `lib.k`.
fn map_reference(text: &str) -> Option<String> {
    let plain =
        |map: &str| !map.is_empty() && map.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    // Groovy also reads a map entry as `NAME."k"` or `NAME.'k'`.
    if let Some(at) = text.find(".\"").or_else(|| text.find(".'")) {
        let (map, key) = (&text[..at], &text[at + 1..]);
        let (key, tail) = quoted(key)?;
        return (plain(map) && tail.trim().is_empty()).then(|| format!("{map}.{key}"));
    }
    let (map, key) = text.split_once('[')?;
    let (key, tail) = quoted(key.trim())?;
    (plain(map) && tail.trim() == "]").then(|| format!("{map}.{key}"))
}

/// The variable an unquoted value names: `extra["k"]`, `ext["k"]`, `ext.k`, `property("k")`,
/// `findProperty("k")` (each with an optional `as String`, `!!` or `.toString()`), or a plain
/// dotted name such as `Versions.KOTLIN`.
fn variable_reference(value: &str) -> Option<String> {
    let mut v = value.trim();
    for suffix in [" as String?", " as String", "!!", ".toString()", ".get()"] {
        v = v.strip_suffix(suffix).unwrap_or(v).trim_end();
    }
    for prefix in ["rootProject.", "project."] {
        v = v.strip_prefix(prefix).unwrap_or(v);
    }
    for call in ["extra[", "ext[", "property(", "findProperty("] {
        if let Some(inner) = v.strip_prefix(call) {
            let (key, tail) = quoted(inner.trim())?;
            return matches!(tail.trim(), "]" | ")").then(|| key.to_string());
        }
    }
    let v = v.strip_prefix("ext.").unwrap_or(v);
    let plain = !v.is_empty()
        && v.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.');
    plain.then(|| v.to_string())
}

/// Kotlin files of `buildSrc` and `build-logic`, where builds keep version constants.
fn build_constants(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = ["buildSrc", "build-logic"]
        .iter()
        .map(|d| dir.join(d))
        .collect();
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name().to_string_lossy().to_string();
            if kind.is_dir() {
                if !SKIPPED_DIRS.contains(&name.as_str()) {
                    stack.push(entry.path());
                }
            } else if kind.is_file()
                && name.ends_with(".kt")
                && out.len() < MAX_FILES
                && entry.metadata().is_ok_and(|m| m.len() <= MAX_FILE_BYTES)
            {
                if let Ok(text) = fleetreach_core::repofile::read_to_string(entry.path()) {
                    out.push((entry.path(), strip_comments(&text)));
                }
            }
        }
    }
    out.sort();
    out
}

/// `const val K = "1"` inside `object Versions { }`, as `Versions.K`.
fn kotlin_constants(text: &str, vars: &mut BTreeMap<String, String>, twice: &mut BTreeSet<String>) {
    let mut objects: Vec<(String, usize)> = Vec::new();
    let mut depth = 0usize;
    for line in text.lines() {
        let t = line.trim();
        let word = |p: &str| -> Option<String> {
            let rest = t.strip_prefix(p)?.trim_start();
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            (!name.is_empty()).then_some(name)
        };
        if let Some(name) = word("object ").or_else(|| word("internal object ")) {
            objects.push((name, depth));
        }
        if let Some(rest) = t
            .strip_prefix("const val ")
            .or_else(|| t.strip_prefix("internal const val "))
        {
            if let (Some((name, value)), Some((object, _))) = (rest.split_once('='), objects.last())
            {
                let name = name.split(':').next().unwrap_or_default().trim();
                if let Some((value, tail)) = quoted(value.trim()) {
                    if tail.trim().is_empty() && !value.contains('$') {
                        let key = format!("{object}.{name}");
                        match vars.get(&key) {
                            Some(known) if known != value => {
                                twice.insert(key);
                            }
                            _ => {
                                vars.insert(key, value.to_string());
                            }
                        }
                    }
                }
            }
        }
        for c in code_only(line).chars() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth = depth.saturating_sub(1);
                    while objects.last().is_some_and(|(_, d)| *d >= depth) {
                        objects.pop();
                    }
                }
                _ => {}
            }
        }
    }
}

/// The string at the start of `text` and what follows it.
fn quoted(text: &str) -> Option<(&str, &str)> {
    let q = text.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    // A Groovy `${...}` may hold quotes of its own (`"${lib["x"]}"`): skip over it.
    let bytes = text.as_bytes();
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'$' if q == '"' && bytes.get(i + 1) == Some(&b'{') => {
                i += text[i..].find('}')? + 1;
            }
            b if b == q as u8 => return Some((&text[1..i], &text[i + 1..])),
            _ => i += 1,
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Coordinate {
    group: String,
    artifact: String,
    version: Option<String>,
    /// Managed by the Spring dependency-management plugin (`mavenBom`, `dependency`, Spring
    /// Boot's BOM): its versions win over conflict resolution, as `eachDependency` sets them.
    enforced: bool,
    /// From an `enforcedPlatform(...)`: its versions win over every request, a version the
    /// build declares itself included.
    strict: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Declared {
    coordinate: Coordinate,
    scope: &'static str,
    /// `exclude(group = "g", module = "a")` in the declaration's block; `*` for a part left out.
    exclusions: Vec<(String, String)>,
    /// A `platform(...)`: Gradle lists the BOM itself as a module of the configuration.
    pom: bool,
}

#[derive(Debug, Default)]
struct Module {
    deps: Vec<Declared>,
    platforms: Vec<Coordinate>,
    constraints: Vec<Coordinate>,
    unread: Vec<String>,
    /// What a `subprojects { }`, `allprojects { }` or `configure(subprojects...) { }` block
    /// declares: the root build applies it to every other build file.
    shared: Shared,
    /// `platform(project(":p"))`: another build file's constraints and platforms manage this
    /// one (a `java-platform` project), by Gradle project path.
    project_platforms: Vec<(String, bool)>,
    /// Where the root's shared platforms start in `platforms`: they are applied before this
    /// file's own, so a later import here overrides them.
    shared_from: Option<usize>,
}

#[derive(Debug, Default)]
struct Shared {
    deps: Vec<Declared>,
    platforms: Vec<Coordinate>,
    constraints: Vec<Coordinate>,
    project_platforms: Vec<(String, bool)>,
}

impl Module {
    /// The module as a POM, so BOM imports and versions go through the resolver.
    /// What the Spring dependency-management plugin sets for this build file.
    fn enforced(&self) -> Enforced {
        let triple = |c: &Coordinate| {
            c.version
                .clone()
                .map(|v| (c.group.clone(), c.artifact.clone(), v))
        };
        // The Spring plugin's later imports override earlier ones: the root's shared block
        // runs before this file.
        let from = self.shared_from.unwrap_or(self.platforms.len());
        let (own, shared) = self.platforms.split_at(from);
        Enforced {
            boms: shared
                .iter()
                .chain(own)
                .filter(|c| c.enforced)
                .filter_map(triple)
                .collect(),
            versions: self
                .constraints
                .iter()
                .filter(|c| c.enforced)
                .filter_map(triple)
                .collect(),
            keep: self
                .deps
                .iter()
                .filter(|d| d.coordinate.version.is_some())
                .map(|d| (d.coordinate.group.clone(), d.coordinate.artifact.clone()))
                .collect(),
            strict_boms: shared
                .iter()
                .chain(own)
                .filter(|c| c.strict)
                .filter_map(triple)
                .collect(),
            strict_versions: self
                .constraints
                .iter()
                .filter(|c| c.strict)
                .filter_map(triple)
                .collect(),
        }
    }

    /// The build file as a POM; with `main_only`, without its test dependencies.
    fn to_pom(&self, main_only: bool) -> String {
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
        let kept: Vec<&Declared> = self
            .deps
            .iter()
            .filter(|d| !main_only || d.scope != "test")
            .collect();
        // Gradle drops a module's dependency only when every edge to it excludes it, so an
        // artifact declared twice keeps just the exclusions all its declarations share.
        let mut shared_exclusions: BTreeMap<(&str, &str), Vec<(String, String)>> = BTreeMap::new();
        for d in &kept {
            let key = (d.coordinate.group.as_str(), d.coordinate.artifact.as_str());
            shared_exclusions
                .entry(key)
                .and_modify(|common| common.retain(|e| d.exclusions.contains(e)))
                .or_insert_with(|| d.exclusions.clone());
        }
        for d in kept {
            let mut extra = format!("<scope>{}</scope>", d.scope);
            if d.pom {
                // A platform's own dependencies are constraints to Gradle, never followed.
                extra.push_str(
                    "<type>pom</type><exclusions><exclusion><groupId>*</groupId>\
                     <artifactId>*</artifactId></exclusion></exclusions>",
                );
            }
            let exclusions = shared_exclusions
                .get(&(d.coordinate.group.as_str(), d.coordinate.artifact.as_str()))
                .map_or(&d.exclusions, |e| e);
            if !exclusions.is_empty() {
                extra.push_str("<exclusions>");
                for (g, a) in exclusions {
                    extra.push_str(&format!(
                        "<exclusion><groupId>{}</groupId><artifactId>{}</artifactId></exclusion>",
                        xml(g),
                        xml(a)
                    ));
                }
                extra.push_str("</exclusions>");
            }
            deps.push_str(&dep(&d.coordinate, &extra));
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
    /// `[versions]` by accessor, as scripts name them: `libs.versions.<accessor>`.
    versions: BTreeMap<String, String>,
    unread: Vec<String>,
}

fn accessor(alias: &str) -> String {
    alias.replace(['-', '_'], ".")
}

impl Catalog {
    #[cfg(test)]
    fn parse(text: &str) -> Result<Catalog, String> {
        let doc: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
        Ok(Catalog::from_doc(&doc))
    }

    fn from_doc(doc: &toml::Value) -> Catalog {
        let mut catalog = Catalog::default();
        let versions = doc.get("versions");
        let table = |key: &str| doc.get(key).and_then(toml::Value::as_table);
        for (alias, entry) in table("versions").into_iter().flatten() {
            if let Ok(version) = catalog_version(entry, None) {
                catalog.versions.insert(accessor(alias), version);
            }
        }
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
        catalog
    }
}

/// The `libs` catalog a settings script declares (`versionCatalogs { create("libs") { ... } }`,
/// or `.register('libs')`), as `libs.versions.toml` sections: `version`, `library` (with
/// `version` or `versionRef`, or a `g:a:v` string), `bundle` and `plugin`, in Groovy or Kotlin.
fn settings_catalog(text: &str) -> Vec<(&'static str, toml::Table)> {
    let mut versions = toml::Table::new();
    let mut libraries = toml::Table::new();
    let mut bundles = toml::Table::new();
    let mut plugins = toml::Table::new();
    let mut inside = false;
    let s = |v: &str| toml::Value::String(v.to_string());
    for line in text.lines() {
        let line = line.trim();
        if line.contains("versionCatalogs") || line.contains("create(\"libs\")") {
            inside = true;
        }
        if !inside {
            continue;
        }
        let words = strings(line);
        let reference = line.contains("versionRef");
        let keyword: String = line.chars().take_while(char::is_ascii_alphabetic).collect();
        let version = |at: usize| -> Option<toml::Value> {
            let v = words.get(at)?;
            Some(if reference {
                let mut t = toml::Table::new();
                t.insert("ref".to_string(), s(v));
                toml::Value::Table(t)
            } else {
                s(v)
            })
        };
        match (keyword.as_str(), words.len()) {
            ("version", 2..) => {
                versions.insert(words[0].clone(), s(&words[1]));
            }
            ("library", 2) => {
                libraries.insert(words[0].clone(), s(&words[1]));
            }
            ("library", 3..) => {
                let mut t = toml::Table::new();
                t.insert(
                    "module".to_string(),
                    s(&format!("{}:{}", words[1], words[2])),
                );
                if let Some(v) = version(3) {
                    t.insert("version".to_string(), v);
                }
                libraries.insert(words[0].clone(), toml::Value::Table(t));
            }
            ("bundle", 2..) => {
                let members = words[1..].iter().map(|m| s(m)).collect();
                bundles.insert(words[0].clone(), toml::Value::Array(members));
            }
            ("plugin", 2..) => {
                let mut t = toml::Table::new();
                t.insert("id".to_string(), s(&words[1]));
                if let Some(v) = version(2) {
                    t.insert("version".to_string(), v);
                }
                plugins.insert(words[0].clone(), toml::Value::Table(t));
            }
            _ => {}
        }
    }
    vec![
        ("versions", versions),
        ("libraries", libraries),
        ("bundles", bundles),
        ("plugins", plugins),
    ]
}

/// The quoted strings of a line, up to a `//` comment.
fn strings(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    loop {
        let quote = rest.find(['"', '\'']);
        let comment = rest.find("//");
        match (quote, comment) {
            (Some(q), c) if c.is_none_or(|c| q < c) => match quoted(&rest[q..]) {
                Some((value, tail)) => {
                    out.push(value.to_string());
                    rest = tail;
                }
                None => break,
            },
            _ => break,
        }
    }
    out
}

const SPRING_BOOT: &str = "org.springframework.boot";

/// The plugin id and version a buildscript `classpath` line brings, for the plugins whose
/// dependencies the reader adds.
fn classpath_plugin(line: &str, vars: &BTreeMap<String, String>) -> Option<(&'static str, String)> {
    let rest = line.strip_prefix("classpath")?;
    let rest = rest.trim_start().trim_start_matches('(').trim_start();
    let (text, _) = quoted(rest)?;
    let c = coordinate(text, vars).ok()?;
    let id = match (c.group.as_str(), c.artifact.as_str()) {
        ("org.springframework.boot", "spring-boot-gradle-plugin") => SPRING_BOOT,
        ("org.jetbrains.kotlin", "kotlin-gradle-plugin") => KOTLIN_JVM,
        _ => return None,
    };
    Some((id, c.version?))
}
const KOTLIN_JVM: &str = "org.jetbrains.kotlin.jvm";

/// The plugin a line applies, with its version when the line gives one: `id 'x' version '1'`,
/// `id("x") version "1"`, `kotlin("jvm") version "1"` or `alias(libs.plugins.x)`.
fn plugin_line(line: &str, catalog: &Catalog) -> Option<(String, Option<String>)> {
    if let Some(alias) = line.strip_prefix("alias(libs.plugins.") {
        let alias = alias.split(')').next()?;
        return Some((catalog.plugin_aliases.get(alias)?.clone(), None));
    }
    // `apply plugin: 'x'` or `apply(plugin = "x")`, which never carry a version.
    if let Some(rest) = line
        .strip_prefix("apply plugin:")
        .or_else(|| line.strip_prefix("apply(plugin ="))
        .or_else(|| line.strip_prefix("apply(plugin:"))
    {
        let (id, _) = quoted(rest.trim())?;
        let id = if id == "kotlin" { KOTLIN_JVM } else { id };
        return Some((id.to_string(), None));
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
    let version = rest.strip_prefix("version").and_then(|v| {
        let v = v.trim_start().trim_start_matches('(').trim_start();
        match quoted(v) {
            Some((v, _)) => Some(v.to_string()),
            // `version libs.versions.x.get()`
            None => {
                let name = v.trim_end();
                let name = name
                    .strip_suffix(".get())")
                    .or_else(|| name.strip_suffix(".get()"));
                let name = name.unwrap_or(v).trim_end_matches(')').trim_end();
                let name = name.strip_prefix("libs.versions.")?;
                catalog.versions.get(name).cloned()
            }
        }
    });
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
        enforced: false,
        strict: false,
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
        enforced: false,
        strict: false,
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
        let name = name.strip_suffix(".get()").unwrap_or(name);
        let keyed = map_reference(name);
        let name = keyed.as_deref().unwrap_or(name);
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
    /// `testImplementation.extendsFrom testShadow`: a custom configuration to the standard one
    /// that takes it in, so it gets that one's scope.
    extended_by: BTreeMap<String, String>,
    /// Some script applies the Spring dependency-management plugin.
    spring_dm: bool,
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

/// Fold a rich version block into its declaration, so `api("g:a") { version { require("1.0") } }`
/// over several lines reads as `api("g:a:1.0")`: `strictly` first, then `require`, then
/// `prefer`. A declaration that already has a version, or a block naming none, is left alone.
fn fold_rich_versions(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let folded = (|| {
            let code = line.trim();
            let open = code.strip_suffix('{')?.trim_end();
            let (head, call) = open.split_once('(')?;
            let call = call.strip_suffix(')')?;
            if head.is_empty() || !head.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return None;
            }
            let (coord, tail) = quoted(call.trim())?;
            if !tail.trim().is_empty() || coord.matches(':').count() != 1 {
                return None;
            }
            // The block's lines, by brace depth.
            let mut depth = 0i32;
            let mut end = i;
            for (j, l) in lines.iter().enumerate().skip(i) {
                let code = code_only(l);
                depth += code.matches('{').count() as i32 - code.matches('}').count() as i32;
                if depth <= 0 {
                    end = j;
                    break;
                }
            }
            if end == i || end - i > 40 {
                return None;
            }
            let body = &lines[i + 1..end];
            let version = ["strictly(", "require(", "prefer("].iter().find_map(|k| {
                body.iter().find_map(|l| {
                    let at = l.find(k)? + k.len();
                    quoted(l[at..].trim()).map(|(v, _)| v.to_string())
                })
            })?;
            let indent = &line[..line.len() - line.trim_start().len()];
            Some((format!("{indent}{head}(\"{coord}:{version}\")"), end))
        })();
        match folded {
            Some((joined, end)) => {
                out.push_str(&joined);
                out.push('\n');
                // Keep the line count, so nothing else shifts.
                for _ in i + 1..=end {
                    out.push('\n');
                }
                i = end + 1;
            }
            None => {
                out.push_str(line);
                out.push('\n');
                i += 1;
            }
        }
    }
    out
}

/// `a.extendsFrom b, c`, `a.extendsFrom(b)` or `configurations.a.extendsFrom(b)`: each custom
/// configuration named, to the standard one `a` that takes it in.
fn extends_from(line: &str, out: &mut BTreeMap<String, String>) {
    let line = line.strip_prefix("configurations.").unwrap_or(line);
    let Some((target, sources)) = line.split_once(".extendsFrom") else {
        return;
    };
    let target = target.trim().trim_end_matches(".get()");
    if !is_configuration(target) {
        return;
    }
    let sources = sources.trim().trim_start_matches('(');
    let sources = sources.split(')').next().unwrap_or_default();
    for source in sources.split(',') {
        let source = source.trim();
        let source = source.strip_prefix("configurations.").unwrap_or(source);
        let plain = !source.is_empty()
            && source
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
        if plain && !is_configuration(source) {
            out.insert(source.to_string(), target.to_string());
        }
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
    /// The Spring plugin's `dependencyManagement { }`: `imports { mavenBom ... }` and
    /// `dependencies { dependency ... }` manage versions.
    Management,
    ManagedVersions,
    /// `subprojects { }`, `allprojects { }`, `configure(subprojects...) { }`.
    Shared,
    /// An `if`/`else` branch a default build takes (no `-D` or `-P` flags): read as the
    /// block around it.
    Taken,
    Other,
}

fn read_script(text: &str, context: &mut Context) -> Module {
    let mut module = Module::default();
    let mut blocks: Vec<Block> = Vec::new();
    let text = fold_rich_versions(text);
    let mut open_deps: Option<OpenDeps> = None;
    // Open branches the default build decides: (block depth inside, taken), and the last
    // one closed, for an `else` on the next line.
    let mut branches: Vec<(usize, bool)> = Vec::new();
    let mut closed_branch: Option<bool> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        let current = blocks.iter().rev().find(|b| **b != Block::Taken).copied();
        let in_deps = matches!(current, Some(Block::Dependencies | Block::Constraints));
        let is_else = trimmed
            .trim_start_matches('}')
            .trim_start()
            .strip_prefix("else")
            .is_some_and(|r| r.trim_start().starts_with('{'));
        let decided = if is_else {
            let closing = if trimmed.starts_with('}') {
                branches
                    .last()
                    .filter(|(d, _)| *d == blocks.len())
                    .map(|b| b.1)
            } else {
                closed_branch
            };
            closing.map(|taken| !taken)
        } else if in_deps {
            if_condition(trimmed).and_then(|c| condition(c, &context.vars))
        } else {
            None
        };
        closed_branch = None;
        let shared = blocks.contains(&Block::Shared);
        let before = (
            module.deps.len(),
            module.platforms.len(),
            module.constraints.len(),
            module.project_platforms.len(),
        );
        if decided.is_none() {
            read_line(trimmed, current, &blocks, context, &mut module);
        }
        // `implementation("g:a:1") { exclude(...) }`: the block's excludes belong to the
        // declarations its opening line made, here and in the shared copy.
        if let Some(open) = &open_deps {
            if blocks.len() >= open.depth {
                if let Some(ex) = exclusion(trimmed) {
                    for i in open.deps.clone() {
                        module.deps[i].exclusions.push(ex.clone());
                    }
                    for i in open.shared.clone() {
                        module.shared.deps[i].exclusions.push(ex.clone());
                    }
                }
            } else {
                open_deps = None;
            }
        }
        let shared_before = module.shared.deps.len();
        if shared {
            module
                .shared
                .deps
                .extend_from_slice(&module.deps[before.0..]);
            module
                .shared
                .platforms
                .extend_from_slice(&module.platforms[before.1..]);
            module
                .shared
                .constraints
                .extend_from_slice(&module.constraints[before.2..]);
            module
                .shared
                .project_platforms
                .extend_from_slice(&module.project_platforms[before.3..]);
        }
        let word: String = trimmed
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let after_word = trimmed[word.len()..].trim_start();
        let new_block = if word == "dependencies"
            && after_word.starts_with('{')
            && blocks.contains(&Block::Management)
        {
            Some(Block::ManagedVersions)
        } else if word == "dependencies" && after_word.starts_with('{') {
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
            if inner.strip_suffix('}').is_some() {
                continue;
            }
            blocks.push(block);
            continue;
        }
        let marks = if word == "dependencyManagement" {
            Some(Block::Management)
        } else if matches!(word.as_str(), "subprojects" | "allprojects")
            || (word == "configure"
                && (after_word.starts_with("(subprojects")
                    || after_word.starts_with("(allprojects")))
        {
            Some(Block::Shared)
        } else {
            None
        };
        let depth = blocks.len();
        let code = code_only(line);
        for c in code.chars() {
            match c {
                '{' => blocks.push(Block::Other),
                '}' => {
                    blocks.pop();
                }
                _ => {}
            }
        }
        if let Some(taken) = decided {
            if is_else && trimmed.starts_with('}') {
                branches.pop();
            }
            if blocks.len() > depth || (is_else && trimmed.starts_with('}')) {
                if let Some(last) = blocks.last_mut() {
                    *last = if taken { Block::Taken } else { Block::Other };
                }
                branches.push((blocks.len(), taken));
            }
        }
        while let Some(&(d, taken)) = branches.last() {
            if blocks.len() >= d {
                break;
            }
            branches.pop();
            closed_branch = Some(taken);
        }
        if module.deps.len() > before.0 {
            let added = before.0..module.deps.len();
            let shared_added = shared_before..module.shared.deps.len();
            // A one-line block: `implementation('g:a:1') { exclude group: 'x' }`.
            if let Some((_, inner)) = trimmed.split_once('{') {
                for part in inner.split([';', '}']) {
                    if let Some(ex) = exclusion(part.trim()) {
                        for i in added.clone() {
                            module.deps[i].exclusions.push(ex.clone());
                        }
                        for i in shared_added.clone() {
                            module.shared.deps[i].exclusions.push(ex.clone());
                        }
                    }
                }
            }
            open_deps = (blocks.len() > depth).then_some(OpenDeps {
                deps: added,
                shared: shared_added,
                depth: blocks.len(),
            });
        }
        if let Some(mark) = marks {
            if blocks.len() > depth {
                if let Some(last) = blocks.last_mut() {
                    *last = mark;
                }
            }
        }
    }
    module
}

/// The condition of `if (cond) {`.
fn if_condition(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("if")?.trim_start().strip_prefix('(')?;
    let body = rest
        .trim_end()
        .strip_suffix('{')?
        .trim_end()
        .strip_suffix(')')?;
    Some(body.trim())
}

/// A condition a default build decides from what is read: `NAME == 'x'`, `NAME != 'x'`,
/// `NAME.equals('x')`, `hasProperty('k')` and `!` of these. `None` for anything else.
fn condition(cond: &str, vars: &BTreeMap<String, String>) -> Option<bool> {
    let c = cond.trim();
    if c.contains("&&") || c.contains("||") {
        return None;
    }
    if let Some(inner) = c.strip_prefix('!') {
        if !inner.starts_with('=') {
            return condition(inner, vars).map(|b| !b);
        }
    }
    if let Some(inner) = c.strip_prefix('(').and_then(|i| i.strip_suffix(')')) {
        return condition(inner, vars);
    }
    let value = |side: &str| -> Option<String> {
        let side = side.trim();
        if let Some((v, tail)) = quoted(side) {
            return tail.trim().is_empty().then(|| v.to_string());
        }
        vars.get(side).cloned()
    };
    for (op, equal) in [("==", true), ("!=", false)] {
        if let Some((left, right)) = c.split_once(op) {
            return Some((value(left)? == value(right)?) == equal);
        }
    }
    if let Some((left, right)) = c.split_once(".equals(") {
        let right = right.strip_suffix(')')?;
        return Some(value(left)? == value(right)?);
    }
    if let Some(v) = vars.get(c) {
        return match v.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        };
    }
    for call in ["project.hasProperty(", "hasProperty("] {
        if let Some(inner) = c.strip_prefix(call) {
            let (key, tail) = quoted(inner)?;
            return (tail.trim() == ")").then(|| vars.contains_key(key));
        }
    }
    None
}

/// `System.properties['k'] ?: 'd'`, `System.getProperty('k', 'd')` or
/// `findProperty('k') ?: 'd'`: the value a default build sees (no `-D` flags; a `-P` property
/// only from what is read).
fn property_default(value: &str, vars: &BTreeMap<String, String>) -> Option<String> {
    let v = value.trim();
    let v = v
        .strip_prefix('(')
        .and_then(|i| i.strip_suffix(')'))
        .unwrap_or(v)
        .trim();
    if let Some(inner) = v.strip_prefix("System.getProperty(") {
        let (_, tail) = quoted(inner.trim_start())?;
        let tail = tail.trim_start().strip_prefix(',')?;
        let (default, end) = quoted(tail.trim_start())?;
        return (end.trim() == ")").then(|| default.to_string());
    }
    // `providers.gradleProperty("k").map { ... }.getOrElse(false)`: the default when unset.
    for (prefix, settable) in [
        ("providers.gradleProperty(", true),
        ("providers.systemProperty(", false),
    ] {
        if let Some(inner) = v.strip_prefix(prefix) {
            let (key, _) = quoted(inner)?;
            if settable && vars.contains_key(key) {
                return None;
            }
            let default = v.rsplit_once(".getOrElse(")?.1.strip_suffix(')')?.trim();
            return match quoted(default) {
                Some((d, tail)) if tail.trim().is_empty() => Some(d.to_string()),
                _ => matches!(default, "true" | "false").then(|| default.to_string()),
            };
        }
    }
    let (call, default) = v.split_once("?:")?;
    let (default, tail) = quoted(default.trim())?;
    if !tail.trim().is_empty() {
        return None;
    }
    let call = call.trim();
    for prefix in ["System.properties[", "System.getProperty("] {
        if let Some(inner) = call.strip_prefix(prefix) {
            let (_, tail) = quoted(inner)?;
            return matches!(tail.trim(), "]" | ")").then(|| default.to_string());
        }
    }
    for prefix in ["project.findProperty(", "findProperty("] {
        if let Some(inner) = call.strip_prefix(prefix) {
            let (key, tail) = quoted(inner)?;
            if tail.trim() != ")" {
                return None;
            }
            return Some(
                vars.get(key)
                    .cloned()
                    .unwrap_or_else(|| default.to_string()),
            );
        }
    }
    None
}

/// Declarations whose block is still open, and the block depth inside it.
struct OpenDeps {
    deps: std::ops::Range<usize>,
    shared: std::ops::Range<usize>,
    depth: usize,
}

/// `exclude group: 'g', module: 'a'`, `exclude(group = "g")` or `exclude(module: "a")`, with
/// `*` for the part left out. `transitive = false` (`isTransitive = false`) excludes everything.
fn exclusion(line: &str) -> Option<(String, String)> {
    let flag: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    if matches!(
        flag.as_str(),
        "transitive=false" | "isTransitive=false" | "transitivefalse"
    ) {
        return Some(("*".to_string(), "*".to_string()));
    }
    let rest = line.strip_prefix("exclude")?;
    if !rest.starts_with([' ', '(']) {
        return None;
    }
    let value = |key: &str| {
        let at = rest.find(key)?;
        let tail = rest[at + key.len()..].trim_start();
        let tail = tail.strip_prefix([':', '='])?;
        quoted(tail.trim_start()).map(|(v, _)| v.to_string())
    };
    let (group, module) = (value("group"), value("module"));
    if group.is_none() && module.is_none() {
        return None;
    }
    Some((
        group.unwrap_or_else(|| "*".to_string()),
        module.unwrap_or_else(|| "*".to_string()),
    ))
}

/// One line of a build script, read by the block it sits in.
fn read_line(
    trimmed: &str,
    current: Option<Block>,
    blocks: &[Block],
    context: &mut Context,
    module: &mut Module,
) {
    match current {
        Some(block @ (Block::Dependencies | Block::Constraints)) => {
            // `constraints {` opens a block; only what follows its brace is an entry.
            if let Some(after) = trimmed.strip_prefix("constraints") {
                if let Some(inner) = after.trim_start().strip_prefix('{') {
                    let inner = inner.trim();
                    let body = inner.strip_suffix('}').unwrap_or(inner);
                    read_entry(body.trim(), Block::Constraints, context, module);
                    return;
                }
            }
            if trimmed.contains('{') || !trimmed.starts_with('}') {
                read_entry(trimmed, block, context, module);
            }
            return;
        }
        Some(Block::ManagedVersions) => {
            // `dependency 'g:a:1'` or `dependency("g:a:1")`; `dependencySet` is not read.
            if let Some(rest) = trimmed.strip_prefix("dependency") {
                if rest.starts_with([' ', '(']) {
                    let before = module.constraints.len();
                    read_values(rest, "compile", Block::Constraints, context, module);
                    for c in &mut module.constraints[before..] {
                        c.enforced = true;
                    }
                }
            }
            return;
        }
        _ => {}
    }
    apply_plugin(trimmed, context, module);
    if blocks.contains(&Block::Management) {
        if let Some(rest) = trimmed.strip_prefix("mavenBom") {
            let inner = rest.trim().trim_start_matches('(');
            let inner = inner.trim_end().trim_end_matches(')');
            let before = module.platforms.len();
            let listed = module.deps.len();
            read_values(
                &format!("platform({inner})"),
                "compile",
                Block::Dependencies,
                context,
                module,
            );
            // The plugin manages versions with it; it is not a dependency.
            module.deps.truncate(listed);
            for c in &mut module.platforms[before..] {
                c.enforced = true;
            }
        }
    }
    // `dependencies { implementation 'g:a:1' }` on one line.
    let word: String = trimmed
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    let after_word = trimmed[word.len()..].trim_start();
    if word == "dependencies" && !blocks.contains(&Block::Management) {
        if let Some(inner) = after_word.strip_prefix('{') {
            let inner = inner.trim();
            let body = inner.strip_suffix('}').unwrap_or(inner);
            read_entry(body.trim(), Block::Dependencies, context, module);
        }
    }
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
        // Spring Boot applies its BOM through the dependency-management plugin.
        module.platforms.push(Coordinate {
            group: "org.springframework.boot".to_string(),
            artifact: "spring-boot-dependencies".to_string(),
            version: Some(version.clone()),
            enforced: context.spring_dm,
            strict: false,
        });
    } else if id == KOTLIN_JVM {
        module.deps.push(Declared {
            coordinate: Coordinate {
                group: "org.jetbrains.kotlin".to_string(),
                artifact: "kotlin-stdlib".to_string(),
                version: Some(version.clone()),
                enforced: false,
                strict: false,
            },
            scope: "compile",
            exclusions: Vec::new(),
            pom: false,
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
    // `testImplementation lib.h2` or `api(lib['x'])`: a map entry or variable holding a
    // coordinate, read as that string.
    let bare = rest.trim_start_matches('(').trim_end_matches(')').trim();
    let resolved = (!bare.starts_with("libs.") && !bare.is_empty())
        .then(|| map_reference(bare).unwrap_or_else(|| bare.to_string()))
        .and_then(|key| context.vars.get(&key))
        .filter(|v| v.contains(':'))
        .map(|v| format!("\"{v}\""));
    let rest = resolved.as_deref().unwrap_or(rest);
    let declared = rest.trim_start_matches('(').trim_start();
    // A platform manages versions whichever configuration carries it (Spring Framework's
    // `dependencyManagement(enforcedPlatform(...))`).
    let a_platform = declared.starts_with("platform(") || declared.starts_with("enforcedPlatform(");
    let scope = if is_configuration(&name) {
        scope_of(&name)
    } else if let Some(target) = context.extended_by.get(&name) {
        scope_of(target)
    } else if a_platform
        || declared.starts_with(['"', '\''])
        || declared.starts_with("group:")
        || declared.starts_with("group =")
        || rest.contains("libs.")
    {
        "test"
    } else {
        module
            .unread
            .push(format!("`{line}` is not a plain declaration"));
        return;
    };
    read_values(rest, scope, block, context, module);
}

/// `read_declaration`, with what an `enforcedPlatform(...)` adds marked strict.
fn read_values(
    text: &str,
    scope: &'static str,
    block: Block,
    context: &mut Context,
    module: &mut Module,
) {
    let before = module.platforms.len();
    read_declaration(text, scope, block, context, module);
    if text
        .trim()
        .trim_start_matches('(')
        .trim_start()
        .starts_with("enforcedPlatform(")
    {
        for c in &mut module.platforms[before..] {
            c.strict = true;
        }
    }
}

fn read_declaration(
    text: &str,
    scope: &'static str,
    block: Block,
    context: &mut Context,
    module: &mut Module,
) {
    // `cond ? "g:a:1" : "g:a:2"`, when a default build decides `cond`.
    if let Some((cond, branches)) = text.trim().trim_start_matches('(').split_once(" ? ") {
        if let Some((yes, no)) = branches.split_once(" : ") {
            let no = no.trim().trim_end_matches(')').trim();
            if let Some(taken) = condition(cond, &context.vars) {
                let pick = if taken { yes.trim() } else { no };
                if quoted(pick).is_some_and(|(_, tail)| tail.trim().is_empty()) {
                    read_values(pick, scope, block, context, module);
                    return;
                }
            }
        }
    }
    let mut rest = text.trim().trim_start_matches('(').trim();
    let whole = text.trim();
    let add = |module: &mut Module, c: Coordinate, platform: bool| {
        if platform {
            if c.version.is_some() && block == Block::Dependencies {
                module.deps.push(Declared {
                    coordinate: c.clone(),
                    scope,
                    exclusions: Vec::new(),
                    pom: true,
                });
            }
            module.platforms.push(c);
        } else if block == Block::Constraints {
            // A constraint without a version (a `because` only) manages nothing.
            if c.version.is_some() {
                module.constraints.push(c);
            }
        } else {
            module.deps.push(Declared {
                coordinate: c,
                scope,
                exclusions: Vec::new(),
                pom: false,
            });
        }
    };
    // ForgeGradle's `fg.deobf("g:a:v")` remaps the jar; the coordinate is the dependency.
    if let Some(inner) = rest.strip_prefix("fg.deobf(") {
        rest = inner.trim();
    }
    let mut platform = false;
    let mut strict = false;
    for prefix in ["enforcedPlatform(", "platform(", "testFixtures("] {
        if let Some(inner) = rest.strip_prefix(prefix) {
            platform = prefix != "testFixtures(";
            strict = prefix == "enforcedPlatform(";
            rest = inner.trim();
            break;
        }
    }
    if platform {
        // `project(":p")`, `project(path: ":p")`, `dependencies.project(path = ":p")`.
        let project = rest.strip_prefix("dependencies.").unwrap_or(rest);
        if let Some(path) = project
            .strip_prefix("project(")
            .or_else(|| project.strip_prefix("project "))
            .map(|p| {
                let p = p.trim_start();
                p.strip_prefix("path").map_or(p, |q| {
                    q.trim_start().trim_start_matches([':', '=']).trim_start()
                })
            })
            .and_then(|p| quoted(p))
            .map(|(p, _)| p)
        {
            module.project_platforms.push((path.to_string(), strict));
            return;
        }
        // The Spring Boot plugin's BOM, at the version the plugin is declared with (even one
        // declared `apply false`).
        if rest.starts_with("SpringBootPlugin.BOM_COORDINATES") {
            if let Some(version) = context.plugins.get(SPRING_BOOT) {
                let c = Coordinate {
                    group: "org.springframework.boot".to_string(),
                    artifact: "spring-boot-dependencies".to_string(),
                    version: Some(version.clone()),
                    enforced: false,
                    strict: false,
                };
                if block == Block::Dependencies {
                    module.deps.push(Declared {
                        coordinate: c.clone(),
                        scope,
                        exclusions: Vec::new(),
                        pom: true,
                    });
                }
                module.platforms.push(c);
                return;
            }
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
                    enforced: false,
                    strict: false,
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
            extended_by: BTreeMap::new(),
            spring_dm: false,
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
                ("g:bom:1.0".to_string(), "compile"),
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
                ("g:plain:0.1".to_string(), "compile"),
            ]
        );
        assert_eq!(m.platforms[0].artifact, "plain");
        assert_eq!(m.unread, ["`libs.missing` is not in the catalog"]);
        assert!(!c.used.contains("nov"));
    }

    #[test]
    fn buildscript_classpath_versions_plugins_applied_by_name() {
        let mut vars = BTreeMap::new();
        vars.insert("bootVersion".to_string(), "4.0.0".to_string());
        assert_eq!(
            classpath_plugin(
                "classpath \"org.springframework.boot:spring-boot-gradle-plugin:$bootVersion\"",
                &vars
            ),
            Some((SPRING_BOOT, "4.0.0".to_string()))
        );
        assert_eq!(
            classpath_plugin(
                "classpath(\"org.jetbrains.kotlin:kotlin-gradle-plugin:2.1.0\")",
                &vars
            ),
            Some((KOTLIN_JVM, "2.1.0".to_string()))
        );
        assert_eq!(
            classpath_plugin("classpath 'org.gretty:gretty:4.1.10'", &vars),
            None
        );
        let catalog = Catalog::default();
        for (line, id) in [
            ("apply plugin: 'org.springframework.boot'", SPRING_BOOT),
            ("apply(plugin = \"org.springframework.boot\")", SPRING_BOOT),
            ("apply plugin: 'kotlin'", KOTLIN_JVM),
        ] {
            assert_eq!(plugin_line(line, &catalog), Some((id.to_string(), None)));
        }
        let mut c = context("", &[]);
        c.plugins
            .insert(SPRING_BOOT.to_string(), "4.0.0".to_string());
        let m = read_script("apply plugin: 'org.springframework.boot'\n", &mut c);
        assert_eq!(m.platforms[0].artifact, "spring-boot-dependencies");
        assert_eq!(m.platforms[0].version.as_deref(), Some("4.0.0"));
    }

    #[test]
    fn plugins_bring_their_boms_and_libraries() {
        let toml = "[plugins]\nboot = { id = \"org.springframework.boot\", version = \"3.2.0\" }\n";
        let catalog = Catalog::parse(toml).unwrap();
        assert_eq!(
            plugin_line("alias(libs.plugins.boot)", &catalog),
            Some(("org.springframework.boot".to_string(), None))
        );
        let catalog = Catalog::parse(&format!("{toml}[versions]\nmy-x = \"1.0\"\n")).unwrap();
        for line in [
            "id 'g.x' version '1.0'",
            "id(\"g.x\") version \"1.0\"",
            "id(\"g.x\") version libs.versions.my.x.get()",
            "id(\"g.x\") version(libs.versions.my.x.get())",
        ] {
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
            &mut Vec::new(),
        );
        assert_eq!(vars["a"], "1");
        assert_eq!(vars["b"], "2");
        assert!(twice.contains("c"));
        assert!(!vars.contains_key("d"));
    }

    #[test]
    fn groovy_list_entries_are_variables() {
        let mut vars = BTreeMap::new();
        script_variables(
            "libraries = [\n    springVersion = '5.3.39',\n    pair = '1', '2'\n]\n",
            &mut vars,
            &mut BTreeSet::new(),
            &mut Vec::new(),
        );
        assert_eq!(vars["springVersion"], "5.3.39");
        assert!(!vars.contains_key("pair"));
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
        fn module(&self, g: &str, a: &str, v: &str) -> Option<String> {
            self.0.get(&format!("{g}:{a}:{v}.module")).cloned()
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
    fn exclusions_in_a_declaration_block_prune_its_tree() {
        assert_eq!(
            exclusion("exclude group: 'g', module: 'x'"),
            Some(("g".to_string(), "x".to_string()))
        );
        assert_eq!(
            exclusion("exclude(module = \"x\")"),
            Some(("*".to_string(), "x".to_string()))
        );
        assert_eq!(exclusion("excludeRules()"), None);
        for line in [
            "isTransitive = false",
            "transitive = false",
            "transitive false",
        ] {
            assert_eq!(exclusion(line), Some(("*".to_string(), "*".to_string())));
        }
        assert_eq!(exclusion("isTransitive = true"), None);
        let repo = Mem(BTreeMap::from([
            pom("a", "1", &[("x", "1"), ("y", "1")]),
            pom("b", "1", &[("x", "1"), ("y", "1")]),
            pom("x", "1", &[]),
            pom("y", "1", &[]),
        ]));
        let dir = tree(
            "exclusions",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "dependencies {\n    api(\"g:a:1\") {\n        exclude(group = \"g\", module = \"x\")\n    }\n}\n",
                ),
                (
                    "sub/build.gradle",
                    "dependencies {\n    implementation('g:b:1') { exclude group: 'g', module: 'y' }\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        let mut names: Vec<_> = r.packages.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        // `x` comes only through `b` and `y` only through `a`.
        assert_eq!(names, ["g:a", "g:b", "g:x", "g:y"], "{:?}", r.missing);
        let dir = tree(
            "exclusions-one",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "dependencies {\n    api(\"g:a:1\") {\n        exclude(group = \"g\", module = \"x\")\n    }\n    api 'g:y:1'\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(versions(&r, "g:x").is_empty(), "{:?}", r.packages);
        // Declared again without the block, `a` keeps its dependencies.
        let dir = tree(
            "exclusions-twice",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "dependencies {\n    testImplementation 'g:a:1'\n    agent('g:a:1') { transitive = false }\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:x"), ["1"], "{:?}", r.packages);
    }

    #[test]
    fn gradle_keeps_a_relocation_pom_and_adds_its_target() {
        let repo = Mem(BTreeMap::from([
            (
                "old:a:1".to_string(),
                "<project><groupId>old</groupId><artifactId>a</artifactId><version>1</version>\
                 <distributionManagement><relocation><groupId>g</groupId></relocation>\
                 </distributionManagement></project>"
                    .to_string(),
            ),
            pom("a", "1", &[]),
            pom("a", "2", &[]),
            pom("b", "1", &[("a", "2")]),
        ]));
        let dir = tree(
            "relocation",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "dependencies {\n    implementation 'old:a:1'\n    implementation 'g:b:1'\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "old:a"), ["1"], "{:?}", r.missing);
        // The target competes with other requests: the highest wins.
        assert_eq!(versions(&r, "g:a"), ["2"], "{:?}", r.missing);
    }

    #[test]
    fn a_test_dependency_does_not_raise_the_main_classpath() {
        // Gradle resolves `compileClasspath` without test dependencies: `x` stays 1 there,
        // and 2 is on the test classpath only.
        let repo = Mem(BTreeMap::from([
            pom("a", "1", &[("x", "1")]),
            pom("x", "1", &[]),
            pom("x", "2", &[]),
        ]));
        let dir = tree(
            "main-vs-test",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "dependencies {\n    implementation 'g:a:1'\n    testImplementation 'g:x:2'\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        let x: Vec<_> = r
            .packages
            .iter()
            .filter(|p| p.name == "g:x")
            .map(|p| (p.version.as_str(), p.dev))
            .collect();
        assert_eq!(x, [("1", false), ("2", true)], "{:?}", r.missing);
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
    fn module_metadata_redirects_and_constrains() {
        let marker = "<!-- do_not_remove: published-with-gradle-metadata -->";
        let gradle_pom = |a: &str, v: &str| {
            (
                format!("g:{a}:{v}"),
                format!("<project>{marker}<groupId>g</groupId><artifactId>{a}</artifactId><version>{v}</version></project>"),
            )
        };
        let module = |a: &str, v: &str, body: &str| {
            (
                format!("g:{a}:{v}.module"),
                format!(r#"{{"formatVersion":"1.1","variants":[{body}]}}"#),
            )
        };
        let runtime = r#""attributes":{"org.gradle.usage":"java-runtime","org.gradle.category":"library","org.jetbrains.kotlin.platform.type":"jvm"}"#;
        let repo = Mem(BTreeMap::from([
            gradle_pom("kmp", "1.0"),
            module(
                "kmp",
                "1.0",
                &format!(
                    r#"{{"name":"jvmRuntimeElements",{runtime},"available-at":{{"group":"g","module":"kmp-jvm","version":"1.0"}}}}"#
                ),
            ),
            gradle_pom("kmp-jvm", "1.0"),
            module(
                "kmp-jvm",
                "1.0",
                &format!(
                    r#"{{"name":"jvmRuntimeElements",{runtime},"dependencies":[
                {{"group":"g","module":"dep","version":{{"requires":"1.0"}}}},
                {{"group":"g","module":"bom","version":{{"requires":"1.0"}},"attributes":{{"org.gradle.category":"platform"}}}}]}}"#
                ),
            ),
            gradle_pom("bom", "1.0"),
            module(
                "bom",
                "1.0",
                r#"{"name":"platformRuntimeElements","attributes":{"org.gradle.usage":"java-runtime","org.gradle.category":"platform"},
                "dependencyConstraints":[{"group":"g","module":"dep","version":{"requires":"2.0"}}]}"#,
            ),
            pom("dep", "1.0", &[]),
            pom("dep", "2.0", &[]),
            // A BOM with only module metadata, imported by the build: its constraints manage.
            gradle_pom("bom2", "1.0"),
            module(
                "bom2",
                "1.0",
                r#"{"name":"platformRuntimeElements","attributes":{"org.gradle.usage":"java-runtime","org.gradle.category":"platform"},
                "dependencyConstraints":[{"group":"g","module":"unversioned","version":{"requires":"3.0"}}]}"#,
            ),
            pom("unversioned", "3.0", &[]),
            // Published with metadata, but the file is not there: the POM is read.
            gradle_pom("nomod", "1.0"),
        ]));
        let dir = tree(
            "module-metadata",
            &[(
                "build.gradle",
                "dependencies {\n  implementation 'g:kmp:1.0'\n  implementation 'g:nomod:1.0'\n  implementation platform('g:bom2:1.0')\n  implementation 'g:unversioned'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:kmp-jvm"), ["1.0"]);
        assert_eq!(versions(&r, "g:bom"), ["1.0"]);
        assert_eq!(versions(&r, "g:dep"), ["2.0"]);
        assert_eq!(versions(&r, "g:nomod"), ["1.0"]);
        assert_eq!(versions(&r, "g:unversioned"), ["3.0"]);
        assert_eq!(
            r.missing,
            ["g:nomod:1.0: Gradle module metadata not available, read the POM instead"]
        );
    }

    #[test]
    fn a_root_blocks_boms_and_versions_reach_every_subproject() {
        // A BOM managing g:a, imported in the root's `configure(subprojects...)` through the
        // Spring plugin with its version in `extra`, a managed version for g:b, and Kotlin's
        // version as a buildSrc constant.
        let bom = (
            "g:bom:4.1.1".to_string(),
            "<project><groupId>g</groupId><artifactId>bom</artifactId><version>4.1.1</version>\
             <packaging>pom</packaging><dependencyManagement><dependencies>\
             <dependency><groupId>g</groupId><artifactId>a</artifactId><version>3.0</version></dependency>\
             </dependencies></dependencyManagement></project>"
                .to_string(),
        );
        let repo = Mem(BTreeMap::from([
            bom,
            pom("a", "3.0", &[]),
            pom("b", "2.0", &[]),
            pom("k", "2.2.20", &[]),
        ]));
        let dir = tree(
            "shared-blocks",
            &[
                ("settings.gradle.kts", ""),
                (
                    "build.gradle.kts",
                    "allprojects {\n    extra[\"sb.version\"] = \"4.1.1\"\n}\n\
                     configure(subprojects.filterNot { it in skipped }) {\n\
                     \x20   val sbVersion = extra[\"sb.version\"] as String\n\
                     \x20   dependencyManagement {\n\
                     \x20       imports {\n\
                     \x20           mavenBom(\"g:bom:$sbVersion\")\n\
                     \x20       }\n\
                     \x20       dependencies {\n\
                     \x20           dependency(\"g:b:2.0\")\n\
                     \x20       }\n\
                     \x20   }\n\
                     \x20   dependencies {\n\
                     \x20       implementation(\"g:k:${Versions.KOTLIN}\")\n\
                     \x20   }\n\
                     }\n",
                ),
                (
                    "buildSrc/src/main/kotlin/Versions.kt",
                    "object Versions {\n    const val KOTLIN = \"2.2.20\"\n}\n",
                ),
                (
                    "lib/build.gradle.kts",
                    "dependencies {\n    api(\"g:a\")\n    implementation(\"g:b\")\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:a"), ["3.0"], "{:?}", r.missing);
        assert_eq!(versions(&r, "g:b"), ["2.0"], "{:?}", r.missing);
        assert_eq!(versions(&r, "g:k"), ["2.2.20"], "{:?}", r.missing);
    }

    #[test]
    fn a_platform_project_manages_the_projects_that_import_it() {
        // halo's shape: a `java-platform` project imports the Spring Boot plugin's BOM (the
        // plugin declared `apply false` with its version in the catalog) and constrains g:c;
        // another project takes both through `platform(project(...))`.
        let bom = (
            "org.springframework.boot:spring-boot-dependencies:3.5.0".to_string(),
            "<project><groupId>org.springframework.boot</groupId>\
             <artifactId>spring-boot-dependencies</artifactId><version>3.5.0</version>\
             <packaging>pom</packaging><dependencyManagement><dependencies>\
             <dependency><groupId>g</groupId><artifactId>a</artifactId><version>3.0</version></dependency>\
             </dependencies></dependencyManagement></project>"
                .to_string(),
        );
        let repo = Mem(BTreeMap::from([
            bom,
            pom("a", "3.0", &[]),
            pom("c", "1.5", &[]),
        ]));
        let dir = tree(
            "platform-project",
            &[
                ("settings.gradle", "include 'platform:app', 'api'\n"),
                (
                    "gradle/libs.versions.toml",
                    "[plugins]\nspring-boot = { id = \"org.springframework.boot\", version = \"3.5.0\" }\n",
                ),
                (
                    "platform/app/build.gradle",
                    "plugins {\n    id 'java-platform'\n    alias(libs.plugins.spring.boot) apply false\n}\n\
                     dependencies {\n    api platform(SpringBootPlugin.BOM_COORDINATES)\n\
                     \x20   constraints {\n        api 'g:c:1.5'\n    }\n}\n",
                ),
                (
                    "api/build.gradle",
                    "dependencies {\n    api platform(project(':platform:app'))\n\
                     \x20   api 'g:a'\n    api 'g:c'\n}\n",
                ),
                (
                    "build.gradle",
                    "configure(allprojects - project(':platform:app')) {\n\
                     \x20   dependencies {\n\
                     \x20       dependencyManagement(enforcedPlatform(dependencies.project(path: \":platform:app\")))\n\
                     \x20   }\n}\n",
                ),
                ("web/build.gradle", "dependencies {\n    api 'g:c'\n}\n"),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:a"), ["3.0"], "{:?}", r.missing);
        assert_eq!(versions(&r, "g:c"), ["1.5"], "{:?}", r.missing);
        assert!(
            !r.missing.iter().any(|m| m.contains("not managed")),
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn groovy_map_entries_name_coordinates() {
        let repo = Mem(BTreeMap::from([
            pom("a", "3.5.19", &[]),
            pom("b", "2.0", &[]),
            pom("c", "1.4", &[]),
            pom("d", "6.1", &[]),
        ]));
        let dir = tree(
            "groovy-maps",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "buildscript {\n    ext {\n        libraries = [\n            aVersion = '3.5.19',\n        ]\n\
                     \x20       lib = [\n            \"a\"      : \"g:a:${aVersion}\",\n\
                     \x20           'b-x'    : 'g:b:2.0',\n            c: \"g:c:1.4\",\n\
                     \x20           \"junit\": \"g:d:6.1\",\n        ]\n    }\n}\n\
                     dependencies {\n    implementation lib.a\n    api(lib['b-x'])\n\
                     \x20   testImplementation \"${lib.'c'}\"\n    testImplementation \"${lib[\"junit\"]}\"\n\
                     \x20   implementation \"${lib.\"b-x\"}\"\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        for (name, want) in [
            ("g:a", "3.5.19"),
            ("g:b", "2.0"),
            ("g:c", "1.4"),
            ("g:d", "6.1"),
        ] {
            assert_eq!(versions(&r, name), [want], "{name} {:?}", r.missing);
        }
    }

    #[test]
    fn forge_deobf_wraps_a_plain_coordinate() {
        let mut context = context("", &[("project.blockUI_version", "1.0.9"), ("v", "2.1")]);
        let module = read_script(
            "dependencies {\n    implementation(fg.deobf(\"com.ldtteam:blockui:${project.blockUI_version}\")){\n\
             \x20       transitive = false\n    }\n    compileOnly fg.deobf(\"g:x:$v:universal\")\n}\n",
            &mut context,
        );
        let got: Vec<String> = module
            .deps
            .iter()
            .map(|d| {
                format!(
                    "{}:{}",
                    d.coordinate.artifact,
                    d.coordinate.version.as_deref().unwrap_or("-")
                )
            })
            .collect();
        assert_eq!(got, ["blockui:1.0.9", "x:2.1"], "{:?}", module.unread);
    }

    #[test]
    fn rich_version_blocks_fold_into_their_declaration() {
        let text = "constraints {\n    api(\"g:a\") {\n        version {\n            require(\"3.8.0\")\n\
                    \x20           reject(\"[3.2.1]\")\n        }\n    }\n\
                    \x20   api(\"g:b\") {\n        version { strictly(\"3.0.0\") }\n    }\n\
                    \x20   api(\"g:c:2.26.1\") {\n        because(\"CVE\")\n    }\n\
                    \x20   api(\"g:d\") {\n        because(\"no version\")\n    }\n}\n";
        let folded = fold_rich_versions(text);
        assert_eq!(folded.lines().count(), text.lines().count());
        assert!(folded.contains("api(\"g:a:3.8.0\")"), "{folded}");
        assert!(folded.contains("api(\"g:b:3.0.0\")"), "{folded}");
        assert!(folded.contains("api(\"g:c:2.26.1\") {"), "{folded}");
        assert!(folded.contains("api(\"g:d\") {"), "{folded}");
        let mut context = context("", &[]);
        let module = read_script(&format!("dependencies {{\n{text}}}\n"), &mut context);
        let mut got: Vec<String> = module
            .constraints
            .iter()
            .map(|c| format!("{}:{}", c.artifact, c.version.as_deref().unwrap_or("-")))
            .collect();
        got.sort();
        assert_eq!(got, ["a:3.8.0", "b:3.0.0", "c:2.26.1"]);
    }

    #[test]
    fn custom_configurations_take_the_scope_that_extends_them() {
        let mut map = BTreeMap::new();
        for line in [
            "testImplementation.extendsFrom testShadow",
            "implementation.extendsFrom(shade, bundled)",
            "configurations.compileOnly.get().extendsFrom(configurations.provided)",
            "foo.extendsFrom bar",
        ] {
            extends_from(line, &mut map);
        }
        assert_eq!(map["testShadow"], "testImplementation");
        assert_eq!(map["shade"], "implementation");
        assert_eq!(map["bundled"], "implementation");
        assert_eq!(map["provided"], "compileOnly");
        assert!(!map.contains_key("bar"));

        let repo = Mem(BTreeMap::from([
            pom("j", "4.13", &[]),
            pom("s", "3.2", &[]),
        ]));
        let dir = tree(
            "custom-configurations",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "configurations {\n    implementation.extendsFrom shade\n}\n\
                     dependencies {\n    shade group: 'g', name: 's', version: '3.2'\n\
                     \x20   testShadow group: 'g', name: 'j', version: '4.13'\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:s"), ["3.2"], "{:?}", r.missing);
        assert_eq!(versions(&r, "g:j"), ["4.13"], "{:?}", r.missing);
        let s = r.packages.iter().find(|p| p.name == "g:s").unwrap();
        assert!(!s.dev);
    }

    #[test]
    fn a_catalog_in_the_settings_script_is_read() {
        let repo = Mem(BTreeMap::from([
            pom("a", "3.4.9", &[]),
            pom("b", "0.4.1", &[]),
            pom("c", "1.2", &[]),
            pom("k", "2.0", &[]),
        ]));
        let dir = tree(
            "settings-catalog",
            &[
                (
                    "settings.gradle",
                    "rootProject.name = 'x'\n\
                     dependencyResolutionManagement.versionCatalogs.register('libs') {\n\
                     \x20   version 'av', '3.4.9'\n\
                     \x20   library 'a-lib', 'g', 'a' versionRef 'av' // a comment 'quoted'\n\
                     \x20   library 'b', 'g', 'b' version '0.4.1'\n\
                     \x20   library 'c', 'g:c:1.2'\n\
                     \x20   bundle 'utils', ['b', 'c']\n}\n",
                ),
                (
                    "build.gradle.kts",
                    "dependencies {\n    implementation(libs.a.lib)\n    implementation(libs.bundles.utils)\n}\n",
                ),
                (
                    "other/settings.gradle.kts",
                    "dependencyResolutionManagement {\n  versionCatalogs {\n    create(\"libs\") {\n\
                     \x20     library(\"k\", \"g\", \"k\").version(\"2.0\")\n    }\n  }\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:a"), ["3.4.9"], "{:?}", r.missing);
        assert_eq!(versions(&r, "g:b"), ["0.4.1"], "{:?}", r.missing);
        assert_eq!(versions(&r, "g:c"), ["1.2"], "{:?}", r.missing);
        let kotlin = settings_catalog(
            "versionCatalogs {\n create(\"libs\") {\n  library(\"k\", \"g\", \"k\").version(\"2.0\")\n\
             \x20 plugin(\"p\", \"g.p\").versionRef(\"pv\")\n }\n}\n",
        );
        assert_eq!(kotlin[1].1["k"]["module"].as_str(), Some("g:k"));
        assert_eq!(kotlin[1].1["k"]["version"].as_str(), Some("2.0"));
        assert_eq!(kotlin[3].1["p"]["version"]["ref"].as_str(), Some("pv"));
    }

    #[test]
    fn a_declared_platform_is_listed_without_its_dependencies() {
        let repo = Mem(BTreeMap::from([
            pom("chain", "1", &[("x", "1")]),
            pom("x", "1", &[]),
        ]));
        let dir = tree(
            "platform-listed",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "dependencies {\n    implementation platform('g:chain:1')\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        let names: Vec<_> = r.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["g:chain"], "{:?}", r.missing);
    }

    #[test]
    fn spring_managed_versions_beat_conflict_resolution() {
        let bom = |name: &str, x: &str| {
            (
                format!("g:{name}:1"),
                format!(
                    "<project><groupId>g</groupId><artifactId>{name}</artifactId><version>1</version>\
                     <dependencyManagement><dependencies><dependency><groupId>g</groupId>\
                     <artifactId>x</artifactId><version>{x}</version></dependency></dependencies>\
                     </dependencyManagement></project>"
                ),
            )
        };
        let repo = Mem(BTreeMap::from([
            bom("bom", "1"),
            bom("later", "3"),
            pom("a", "1", &[("x", "2")]),
            pom("x", "1", &[]),
            pom("x", "2", &[]),
            pom("x", "3", &[]),
            pom("y", "1", &[("x", "2")]),
        ]));
        let script = |imports: &str, deps: &str| {
            format!(
                "plugins {{ id 'io.spring.dependency-management' version '1.1.7' }}\n\
                 dependencyManagement {{\n    imports {{\n{imports}    }}\n}}\n\
                 dependencies {{\n{deps}}}\n"
            )
        };
        let one = |tag: &str, text: &str| {
            let dir = tree(tag, &[("settings.gradle", ""), ("build.gradle", text)]);
            versions(&resolve_gradle(&dir, &repo), "g:x")
        };
        // `a` asks for x 2; the BOM's 1 wins, as the plugin sets it.
        assert_eq!(
            one(
                "spring-enforced",
                &script(
                    "        mavenBom 'g:bom:1'\n",
                    "    implementation 'g:a:1'\n"
                )
            ),
            ["1"]
        );
        // A later import overrides an earlier one.
        assert_eq!(
            one(
                "spring-later",
                &script(
                    "        mavenBom 'g:bom:1'\n        mavenBom 'g:later:1'\n",
                    "    implementation 'g:a:1'\n"
                )
            ),
            ["3"]
        );
        // A version the build declares itself is kept.
        assert_eq!(
            one(
                "spring-own",
                &script(
                    "        mavenBom 'g:bom:1'\n",
                    "    implementation 'g:a:1'\n    implementation 'g:x:2'\n"
                )
            ),
            ["2"]
        );
        // `enforcedPlatform` forces its version, over one the build declares too.
        assert_eq!(
            one(
                "enforced-platform",
                "dependencies {\n    implementation enforcedPlatform('g:bom:1')\n    implementation 'g:a:1'\n\
                 \x20   implementation 'g:x:2'\n}\n"
            ),
            ["1"]
        );
        // A plain platform only requests: the highest wins.
        assert_eq!(
            one(
                "platform-highest",
                "dependencies {\n    implementation platform('g:bom:1')\n    implementation 'g:a:1'\n}\n"
            ),
            ["2"]
        );
    }

    #[test]
    fn default_build_branches_are_read() {
        let mut vars = BTreeMap::new();
        vars.insert("fromProps".to_string(), "yes".to_string());
        assert_eq!(
            property_default("System.properties['e'] ?: ''", &vars).as_deref(),
            Some("")
        );
        assert_eq!(
            property_default("System.getProperty(\"e\", \"x\")", &vars).as_deref(),
            Some("x")
        );
        assert_eq!(
            property_default("findProperty('fromProps') ?: 'no'", &vars).as_deref(),
            Some("yes")
        );
        assert_eq!(
            property_default("(findProperty('k') ?: 'no')", &vars).as_deref(),
            Some("no")
        );
        assert_eq!(property_default("System.getenv('E') ?: 'x'", &vars), None);
        assert_eq!(
            property_default(
                "providers.gradleProperty(\"toolchainVersion\").map { (it as int) < 21 }.getOrElse(false)",
                &vars
            )
            .as_deref(),
            Some("false")
        );
        assert_eq!(
            property_default(
                "providers.gradleProperty('fromProps').getOrElse('x')",
                &vars
            ),
            None
        );
        vars.insert("old".to_string(), "false".to_string());
        assert_eq!(condition("old", &vars), Some(false));
        let mut c = context("", &[("old", "false")]);
        let m = read_script(
            "dependencies {\n    api(old ? \"g:j:9\" : \"g:j:10\")\n}\n",
            &mut c,
        );
        assert_eq!(rows(&m), [("g:j:10".to_string(), "compile")]);
        vars.insert("e".to_string(), String::new());
        assert_eq!(condition("e == 'true'", &vars), Some(false));
        assert_eq!(condition("!(e != 'true')", &vars), Some(false));
        assert_eq!(condition("hasProperty(\"fromProps\")", &vars), Some(true));
        assert_eq!(condition("project.hasProperty('nope')", &vars), Some(false));
        assert_eq!(condition("e == 'true' && x", &vars), None);
        assert_eq!(
            condition("JavaVersion.current().isJava9Compatible()", &vars),
            None
        );

        let repo = Mem(BTreeMap::from([
            pom("a", "1", &[]),
            pom("b", "1", &[]),
            pom("c", "1", &[]),
            pom("d", "1", &[]),
        ]));
        let dir = tree(
            "branches",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "def enterprise = System.properties['enterprise'] ?: ''\n\
                     dependencies {\n    if (enterprise == 'true') {\n        implementation 'g:a:1'\n\
                     \x20   } else {\n        implementation 'g:b:1'\n    }\n\
                     \x20   if (hasProperty('nope')) {\n        implementation 'g:c:1'\n    }\n\
                     \x20   else {\n        implementation 'g:d:1'\n    }\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        let mut names: Vec<_> = r.packages.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["g:b", "g:d"], "{:?}", r.missing);
        assert!(
            r.missing.iter().all(|m| !m.contains("plain declaration")),
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn set_calls_name_dotted_properties() {
        let mut out = Vec::new();
        set_calls(
            "ext {\n  set('grpc-java.version', \"$grpcVersion\")\n  extra.set(\"a-b\", \"1\")\n  set(x)\n}\n",
            &mut out,
        );
        assert_eq!(
            out,
            [
                ("grpc-java.version".to_string(), "$grpcVersion".to_string()),
                ("a-b".to_string(), "1".to_string())
            ]
        );
    }

    #[test]
    fn a_project_property_overrides_the_bom_property_of_that_name() {
        let bom = |name: &str| {
            (
                format!("g:{name}:1"),
                format!(
                    "<project><groupId>g</groupId><artifactId>{name}</artifactId><version>1</version>\
                     <packaging>pom</packaging><properties><a.version>1.0</a.version></properties>\
                     <dependencyManagement><dependencies>\
                     <dependency><groupId>g</groupId><artifactId>a</artifactId><version>${{a.version}}</version></dependency>\
                     </dependencies></dependencyManagement></project>"
                ),
            )
        };
        let repo = Mem(BTreeMap::from([
            bom("bom"),
            pom("a", "1.0", &[]),
            pom("a", "2.0", &[]),
        ]));
        let script = |plugin: &str| {
            format!(
                "plugins {{\n    id '{plugin}' version '1.1.7'\n}}\next['a.version'] = '2.0'\n\
                 dependencyManagement {{\n    imports {{\n        mavenBom 'g:bom:1'\n    }}\n}}\n\
                 dependencies {{\n    implementation 'g:a'\n}}\n"
            )
        };
        for (plugin, want) in [
            ("io.spring.dependency-management", "2.0"),
            ("other.plugin", "1.0"),
        ] {
            let dir = tree(
                &format!("bom-override-{want}"),
                &[("settings.gradle", ""), ("build.gradle", &script(plugin))],
            );
            let r = resolve_gradle(&dir, &repo);
            assert_eq!(versions(&r, "g:a"), [want], "{plugin} {:?}", r.missing);
        }
    }

    #[test]
    fn variable_references_name_another_variable() {
        for (value, key) in [
            ("extra[\"sb.version\"] as String", Some("sb.version")),
            ("rootProject.ext['v']", Some("v")),
            ("property(\"kotlinVersion\")!!", Some("kotlinVersion")),
            ("Versions.KOTLIN", Some("Versions.KOTLIN")),
            ("compute()", None),
            ("\"1.0\"", None),
        ] {
            assert_eq!(variable_reference(value).as_deref(), key, "{value}");
        }
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
