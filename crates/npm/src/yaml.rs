//! A minimal YAML tree for the lockfile readers, built with `saphyr` with scalar
//! resolution turned off: every scalar stays the exact text the package manager wrote, so
//! a version such as `1.10` is never read back as the float `1.1`.

use saphyr::{Yaml, YamlLoader};

/// A YAML node with string scalars only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Node {
    Str(String),
    Map(Vec<(String, Node)>),
    Seq(Vec<Node>),
    Null,
}

impl Node {
    pub fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Node::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Node::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The entries of a mapping; empty for anything else (an absent or `{}` section).
    pub fn entries(&self) -> &[(String, Node)] {
        match self {
            Node::Map(entries) => entries,
            _ => &[],
        }
    }

    /// `self[key]` as a string.
    pub fn str_at(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Node::as_str)
    }
}

/// Parse every document in `text`.
pub(crate) fn parse(text: &str) -> Result<Vec<Node>, String> {
    let mut parser = saphyr_parser::Parser::new_from_str(text);
    let mut loader: YamlLoader<'_, Yaml<'_>> = YamlLoader::default();
    loader.early_parse(false);
    parser.load(&mut loader, true).map_err(|e| e.to_string())?;
    if let Some(e) = loader.error() {
        return Err(e.to_string());
    }
    Ok(loader.into_documents().iter().map(convert).collect())
}

fn convert(y: &Yaml<'_>) -> Node {
    match y {
        Yaml::Representation(s, _, _) => Node::Str(s.to_string()),
        Yaml::Value(v) => match v {
            saphyr::Scalar::Null => Node::Null,
            saphyr::Scalar::String(s) => Node::Str(s.to_string()),
            saphyr::Scalar::Boolean(b) => Node::Str(b.to_string()),
            saphyr::Scalar::Integer(i) => Node::Str(i.to_string()),
            saphyr::Scalar::FloatingPoint(f) => Node::Str(f.to_string()),
        },
        Yaml::Sequence(items) => Node::Seq(items.iter().map(convert).collect()),
        Yaml::Mapping(map) => Node::Map(
            map.iter()
                .filter_map(|(k, v)| match convert(k) {
                    Node::Str(key) => Some((key, convert(v))),
                    _ => None,
                })
                .collect(),
        ),
        Yaml::Tagged(_, inner) => convert(inner),
        _ => Node::Null,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn scalars_keep_their_text() {
        let docs = parse("a: 1.10\nb: '9.0'\nc: {integrity: sha512-x}\nd: ~\n").unwrap();
        let doc = &docs[0];
        assert_eq!(doc.str_at("a"), Some("1.10"));
        assert_eq!(doc.str_at("b"), Some("9.0"));
        assert_eq!(doc.get("c").unwrap().str_at("integrity"), Some("sha512-x"));
        assert_eq!(doc.str_at("d"), Some("~"));
    }

    #[test]
    fn multiple_documents() {
        let docs = parse("---\na: 1\n---\nb: 2\n").unwrap();
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[1].str_at("b"), Some("2"));
    }
}
