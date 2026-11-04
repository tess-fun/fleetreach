//! CycloneDX XML, written from the JSON BOM so the two forms cannot disagree. The schema fixes
//! the order of elements, so each is written by name rather than by walking the tree.

use serde_json::Value;

/// Rewrite a BOM from [`to_cyclonedx`](crate::to_cyclonedx) as XML.
///
/// # Errors
///
/// If `bom` is not JSON.
pub fn to_cyclonedx_xml(bom: &str) -> Result<String, serde_json::Error> {
    let bom: Value = serde_json::from_str(bom)?;
    let mut x = Xml::default();
    x.out
        .push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let namespace = format!(
        "http://cyclonedx.org/schema/bom/{}",
        text(&bom, "specVersion")
    );
    let version = bom["version"].to_string();
    x.open(
        "bom",
        &[
            ("xmlns", namespace.as_str()),
            ("serialNumber", text(&bom, "serialNumber")),
            ("version", version.as_str()),
        ],
    );
    metadata(&mut x, &bom["metadata"]);
    x.open("components", &[]);
    for c in list(&bom, "components") {
        component(&mut x, c);
    }
    x.close("components");
    x.open("dependencies", &[]);
    for d in list(&bom, "dependencies") {
        x.open("dependency", &[("ref", text(d, "ref"))]);
        for on in list(d, "dependsOn") {
            x.empty("dependency", &[("ref", on.as_str().unwrap_or_default())]);
        }
        x.close("dependency");
    }
    x.close("dependencies");
    x.open("compositions", &[]);
    for c in list(&bom, "compositions") {
        x.open("composition", &[]);
        x.leaf("aggregate", text(c, "aggregate"));
        for (section, item) in [("assemblies", "assembly"), ("dependencies", "dependency")] {
            x.open(section, &[]);
            for r in list(c, section) {
                x.empty(item, &[("ref", r.as_str().unwrap_or_default())]);
            }
            x.close(section);
        }
        x.close("composition");
    }
    x.close("compositions");
    if bom.get("vulnerabilities").is_some() {
        x.open("vulnerabilities", &[]);
        for v in list(&bom, "vulnerabilities") {
            vulnerability(&mut x, v);
        }
        x.close("vulnerabilities");
    }
    x.close("bom");
    Ok(x.out)
}

fn metadata(x: &mut Xml, m: &Value) {
    x.open("metadata", &[]);
    x.optional(m, "timestamp");
    x.open("tools", &[]);
    x.open("components", &[]);
    for tool in list(&m["tools"], "components") {
        component(x, tool);
    }
    x.close("components");
    x.close("tools");
    component(x, &m["component"]);
    x.close("metadata");
}

fn component(x: &mut Xml, c: &Value) {
    let mut attributes = vec![("type", text(c, "type"))];
    if c.get("bom-ref").is_some() {
        attributes.push(("bom-ref", text(c, "bom-ref")));
    }
    x.open("component", &attributes);
    x.leaf("name", text(c, "name"));
    x.optional(c, "version");
    x.optional(c, "scope");
    if c.get("hashes").is_some() {
        x.open("hashes", &[]);
        for h in list(c, "hashes") {
            x.leaf_with("hash", &[("alg", text(h, "alg"))], text(h, "content"));
        }
        x.close("hashes");
    }
    if c.get("licenses").is_some() {
        x.open("licenses", &[]);
        for l in list(c, "licenses") {
            if l.get("expression").is_some() {
                x.leaf("expression", text(l, "expression"));
            } else {
                x.open("license", &[]);
                x.leaf("name", text(&l["license"], "name"));
                x.close("license");
            }
        }
        x.close("licenses");
    }
    x.optional(c, "purl");
    if c.get("externalReferences").is_some() {
        x.open("externalReferences", &[]);
        for r in list(c, "externalReferences") {
            x.open("reference", &[("type", text(r, "type"))]);
            x.leaf("url", text(r, "url"));
            x.close("reference");
        }
        x.close("externalReferences");
    }
    properties(x, c);
    x.close("component");
}

fn properties(x: &mut Xml, owner: &Value) {
    if owner.get("properties").is_none() {
        return;
    }
    x.open("properties", &[]);
    for p in list(owner, "properties") {
        x.leaf_with("property", &[("name", text(p, "name"))], text(p, "value"));
    }
    x.close("properties");
}

fn source(x: &mut Xml, s: &Value) {
    x.open("source", &[]);
    x.leaf("name", text(s, "name"));
    x.leaf("url", text(s, "url"));
    x.close("source");
}

fn vulnerability(x: &mut Xml, v: &Value) {
    x.open("vulnerability", &[("bom-ref", text(v, "bom-ref"))]);
    x.leaf("id", text(v, "id"));
    source(x, &v["source"]);
    if v.get("references").is_some() {
        x.open("references", &[]);
        for r in list(v, "references") {
            x.open("reference", &[]);
            x.leaf("id", text(r, "id"));
            source(x, &r["source"]);
            x.close("reference");
        }
        x.close("references");
    }
    x.open("ratings", &[]);
    for r in list(v, "ratings") {
        x.open("rating", &[]);
        if let Some(score) = r.get("score") {
            x.leaf("score", &score.to_string());
        }
        x.optional(r, "severity");
        x.optional(r, "method");
        x.optional(r, "vector");
        x.close("rating");
    }
    x.close("ratings");
    x.leaf("description", text(v, "description"));
    let analysis = &v["analysis"];
    x.open("analysis", &[]);
    x.leaf("state", text(analysis, "state"));
    x.optional(analysis, "justification");
    x.optional(analysis, "detail");
    x.close("analysis");
    x.open("affects", &[]);
    for a in list(v, "affects") {
        x.open("target", &[]);
        x.leaf("ref", text(a, "ref"));
        x.close("target");
    }
    x.close("affects");
    properties(x, v);
    x.close("vulnerability");
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn list<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// The document so far and the current depth.
#[derive(Default)]
struct Xml {
    out: String,
    depth: usize,
}

impl Xml {
    fn start(&mut self, name: &str, attributes: &[(&str, &str)]) {
        self.out.push_str(&"  ".repeat(self.depth));
        self.out.push('<');
        self.out.push_str(name);
        for (key, value) in attributes {
            self.out.push(' ');
            self.out.push_str(key);
            self.out.push_str("=\"");
            self.out.push_str(&escape(value));
            self.out.push('"');
        }
    }

    fn open(&mut self, name: &str, attributes: &[(&str, &str)]) {
        self.start(name, attributes);
        self.out.push_str(">\n");
        self.depth += 1;
    }

    fn close(&mut self, name: &str) {
        self.depth -= 1;
        self.out.push_str(&"  ".repeat(self.depth));
        self.out.push_str("</");
        self.out.push_str(name);
        self.out.push_str(">\n");
    }

    fn empty(&mut self, name: &str, attributes: &[(&str, &str)]) {
        self.start(name, attributes);
        self.out.push_str("/>\n");
    }

    fn leaf_with(&mut self, name: &str, attributes: &[(&str, &str)], value: &str) {
        self.start(name, attributes);
        self.out.push('>');
        self.out.push_str(&escape(value));
        self.out.push_str("</");
        self.out.push_str(name);
        self.out.push_str(">\n");
    }

    fn leaf(&mut self, name: &str, value: &str) {
        self.leaf_with(name, &[], value);
    }

    fn optional(&mut self, owner: &Value, key: &str) {
        if let Some(value) = owner.get(key).and_then(Value::as_str) {
            self.leaf(key, value);
        }
    }
}

/// Escape markup and drop the control characters XML 1.0 cannot carry at all.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if u32::from(c) < 0x20 || matches!(c, '\u{fffe}' | '\u{ffff}') => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn writes_elements_in_schema_order_and_escapes_text() {
        let bom = serde_json::json!({
            "specVersion": "1.7", "serialNumber": "urn:uuid:1", "version": 1,
            "metadata": {
                "tools": { "components": [
                    { "type": "application", "name": "fleetreach", "version": "1" }] },
                "component": { "type": "application", "bom-ref": "repo:a", "name": "a<b" },
            },
            "components": [{
                "type": "library", "bom-ref": "pkg:npm/a@1", "name": "a", "version": "1",
                "purl": "pkg:npm/a@1", "scope": "required",
                "hashes": [{ "alg": "SHA-1", "content": "ab" }],
                "licenses": [{ "license": { "name": "R&D\u{1}" } }],
            }],
            "dependencies": [{ "ref": "repo:a", "dependsOn": ["pkg:npm/a@1"] }],
            "compositions": [{ "aggregate": "complete",
                "assemblies": ["repo:a"], "dependencies": ["repo:a"] }],
        });
        let xml = to_cyclonedx_xml(&bom.to_string()).unwrap();
        assert!(xml.contains("xmlns=\"http://cyclonedx.org/schema/bom/1.7\""));
        assert!(xml.contains("<name>a&lt;b</name>"));
        assert!(xml.contains("<name>R&amp;D</name>"));
        assert!(xml.contains("<hash alg=\"SHA-1\">ab</hash>"));
        let order: Vec<usize> = [
            "<name>a</name>",
            "<scope>",
            "<hashes>",
            "<licenses>",
            "<purl>",
        ]
        .iter()
        .map(|tag| xml.find(tag).unwrap())
        .collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{xml}");
    }
}
