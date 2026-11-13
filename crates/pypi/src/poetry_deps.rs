//! Poetry's `[tool.poetry.dependencies]` as PEP 508 requirement lines, for a Poetry project
//! with no `poetry.lock` (spec 16, row 9).
//!
//! Poetry writes constraints in its own syntax: `^1.2` (up to the next leftmost non-zero
//! part), `~1.2.3` (up to the next minor), `1.2.*`, a bare version (exact), or PEP 440
//! operators, joined with `,`. Each is written out as PEP 440 specifiers, and a table's
//! `python` and `markers` keys become environment markers. Optional dependencies are left
//! out unless an extra asks for them, `python` itself is not a package, and git, path and URL
//! entries are written as `name @ ...` so the reader names them as not from the package
//! index. A constraint with `||` has no PEP 440 form and is left out by name.

/// The runtime dependencies of a parsed `pyproject.toml`'s `[tool.poetry]` table, plus the
/// optional ones that `extras` name in `[tool.poetry.extras]`, one requirement per line.
pub(crate) fn requirement_lines(pyproject: &toml::Value, extras: &[String]) -> Vec<String> {
    let Some(poetry) = pyproject.get("tool").and_then(|t| t.get("poetry")) else {
        return Vec::new();
    };
    let Some(deps) = poetry.get("dependencies").and_then(toml::Value::as_table) else {
        return Vec::new();
    };
    let wanted: Vec<String> = extras
        .iter()
        .filter_map(|e| poetry.get("extras")?.get(e)?.as_array())
        .flatten()
        .filter_map(toml::Value::as_str)
        .map(|name| name.to_ascii_lowercase())
        .collect();
    let mut lines = Vec::new();
    for (name, spec) in deps {
        if name.eq_ignore_ascii_case("python") {
            continue;
        }
        let asked = wanted.contains(&name.to_ascii_lowercase());
        match spec {
            toml::Value::Array(entries) => {
                for entry in entries {
                    lines.extend(line(name, entry, asked));
                }
            }
            other => lines.extend(line(name, other, asked)),
        }
    }
    lines
}

/// One dependency entry as a requirement line; `None` when it is optional and not asked for.
fn line(name: &str, spec: &toml::Value, asked: bool) -> Option<String> {
    let (constraint, table) = match spec {
        toml::Value::String(s) => (Some(s.as_str()), None),
        toml::Value::Table(t) => (t.get("version").and_then(toml::Value::as_str), Some(t)),
        _ => return Some(format!("{name} (not understood)")),
    };
    let key = |k: &str| table.and_then(|t| t.get(k));
    if key("optional").and_then(toml::Value::as_bool) == Some(true) && !asked {
        return None;
    }
    let extras: Vec<&str> = key("extras")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .collect();
    let head = if extras.is_empty() {
        name.to_string()
    } else {
        format!("{name}[{}]", extras.join(","))
    };
    // Not from the package index: the reader names these and leaves them out.
    for source in ["git", "url", "path", "file"] {
        if let Some(at) = key(source).and_then(toml::Value::as_str) {
            let at = if source == "git" && !at.starts_with("git+") {
                format!("git+{at}")
            } else {
                at.to_string()
            };
            return Some(format!("{head} @ {at}"));
        }
    }
    let Some(specifiers) = constraint.map_or(Some(String::new()), pep440) else {
        return Some(format!(
            "{head} (Poetry constraint {:?} has no PEP 440 form)",
            constraint.unwrap_or_default()
        ));
    };
    let mut markers: Vec<String> = Vec::new();
    if let Some(python) = key("python").and_then(toml::Value::as_str) {
        match pep440(python) {
            Some(clauses) if !clauses.is_empty() => markers.push(python_marker(&clauses)),
            Some(_) => {}
            None => {
                return Some(format!(
                    "{head} (Poetry python {python:?} has no PEP 508 form)"
                ))
            }
        }
    }
    if let Some(m) = key("markers").and_then(toml::Value::as_str) {
        markers.push(format!("({m})"));
    }
    let mut out = head;
    if !specifiers.is_empty() {
        out.push(' ');
        out.push_str(&specifiers);
    }
    if !markers.is_empty() {
        out.push_str(" ; ");
        out.push_str(&markers.join(" and "));
    }
    Some(out)
}

/// A Poetry constraint as PEP 440 specifiers (`""` for any version); `None` for `||`.
pub(crate) fn pep440(constraint: &str) -> Option<String> {
    let constraint = constraint.trim();
    if constraint.contains("||") {
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    for part in constraint
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        if part == "*" {
            continue;
        }
        if let Some(v) = part.strip_prefix('^') {
            let v = v.trim();
            out.push(format!(">={v}"));
            out.push(format!("<{}", caret_upper(v)?));
        } else if let Some(v) = part.strip_prefix("~=") {
            out.push(format!("~={}", v.trim()));
        } else if let Some(v) = part.strip_prefix('~') {
            let v = v.trim();
            out.push(format!(">={v}"));
            out.push(format!("<{}", tilde_upper(v)?));
        } else if let Some(op) = ["==", "!=", ">=", "<=", ">", "<"]
            .into_iter()
            .find(|op| part.starts_with(op))
        {
            out.push(format!("{op}{}", part[op.len()..].trim()));
        } else if let Some(v) = part.strip_prefix('=') {
            out.push(format!("=={}", v.trim()));
        } else {
            out.push(format!("=={part}"));
        }
    }
    Some(out.join(","))
}

/// The numeric release parts at the front of a version (`1.2.3b1` -> `[1, 2, 3]`).
fn release(v: &str) -> Option<Vec<u64>> {
    let mut parts = Vec::new();
    for piece in v.split('.') {
        let digits: String = piece.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            break;
        }
        parts.push(digits.parse().ok()?);
        if digits.len() != piece.len() {
            break;
        }
    }
    (!parts.is_empty()).then_some(parts)
}

/// `^`: the next version up at the leftmost non-zero part (the last part if all are zero).
fn caret_upper(v: &str) -> Option<String> {
    let parts = release(v)?;
    let i = parts
        .iter()
        .position(|&p| p != 0)
        .unwrap_or(parts.len() - 1);
    Some(bumped(&parts, i))
}

/// `~`: the next minor, or the next major when only a major is given.
fn tilde_upper(v: &str) -> Option<String> {
    let parts = release(v)?;
    Some(bumped(&parts, usize::from(parts.len() > 1)))
}

fn bumped(parts: &[u64], i: usize) -> String {
    let mut up: Vec<String> = parts[..i].iter().map(u64::to_string).collect();
    up.push((parts[i] + 1).to_string());
    up.join(".")
}

/// PEP 440 clauses on the interpreter as a marker: `python_version` for `major.minor`
/// bounds, `python_full_version` for longer ones; a wildcard compares the line.
fn python_marker(clauses: &str) -> String {
    let parts: Vec<String> = clauses
        .split(',')
        .map(|clause| {
            let op_len = clause.find(|c: char| c.is_ascii_digit()).unwrap_or(0);
            let (op, version) = clause.split_at(op_len);
            let version = version.trim_end_matches(".*");
            let field = if version.split('.').count() > 2 {
                "python_full_version"
            } else {
                "python_version"
            };
            format!("{field} {op} \"{version}\"")
        })
        .collect();
    format!("({})", parts.join(" and "))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn constraints_follow_poetry_rules() {
        let cases = [
            ("^1.2.3", ">=1.2.3,<2"),
            ("^1.2", ">=1.2,<2"),
            ("^0.2.3", ">=0.2.3,<0.3"),
            ("^0.0.3", ">=0.0.3,<0.0.4"),
            ("^0.0", ">=0.0,<0.1"),
            ("^0", ">=0,<1"),
            ("~1.2.3", ">=1.2.3,<1.3"),
            ("~1.2", ">=1.2,<1.3"),
            ("~1", ">=1,<2"),
            ("~=1.2", "~=1.2"),
            ("1.2.*", "==1.2.*"),
            ("1.2.3", "==1.2.3"),
            ("=1.2.3", "==1.2.3"),
            (">= 1.2, < 1.5", ">=1.2,<1.5"),
            ("*", ""),
            ("^2.0.0b1", ">=2.0.0b1,<3"),
        ];
        for (poetry, pep) in cases {
            assert_eq!(pep440(poetry).as_deref(), Some(pep), "{poetry}");
        }
        assert_eq!(pep440("^1.0 || ^2.0"), None);
    }

    #[test]
    fn tables_become_requirement_lines() {
        let doc: toml::Value = toml::from_str(
            r#"
[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.31"
uvicorn = { version = "^0.30", extras = ["standard"] }
numpy = [
  { version = "^1.24", python = "<3.12" },
  { version = "^2.0", python = ">=3.12" },
]
pywin32 = { version = "306", markers = "sys_platform == 'win32'" }
boto3 = { version = "^1.34", optional = true }
mylib = { git = "https://github.com/acme/mylib.git", tag = "v1" }
local = { path = "../local" }
odd = "^1 || ^2"

[tool.poetry.extras]
aws = ["boto3"]
"#,
        )
        .unwrap();
        let lines = requirement_lines(&doc, &[]);
        assert_eq!(
            lines,
            [
                "local @ ../local",
                "mylib @ git+https://github.com/acme/mylib.git",
                "numpy >=1.24,<2 ; (python_version < \"3.12\")",
                "numpy >=2.0,<3 ; (python_version >= \"3.12\")",
                "odd (Poetry constraint \"^1 || ^2\" has no PEP 440 form)",
                "pywin32 ==306 ; (sys_platform == 'win32')",
                "requests >=2.31,<3",
                "uvicorn[standard] >=0.30,<0.31",
            ]
        );
        let with_aws = requirement_lines(&doc, &["aws".to_string()]);
        assert!(with_aws.contains(&"boto3 >=1.34,<2".to_string()));
    }
}
