//! One sink record against one graph.

use fleetreach_sinks::record::{SinkRecord, Verdict as RecordKind};

use crate::graph::{Analysis, Witness};

/// What the graph says about a record. Only `NotReached` is a claim of absence, and it means
/// "no path in this graph", with [`Limits`] saying what the graph could not see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Reached(Box<Witness>),
    NotReached(Limits),
    Unknown(Why),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Reached methods using reflection on data no constant gives.
    pub open_reflection: usize,
    /// Reached `invokedynamic` sites with an unknown bootstrap.
    pub open_dynamic: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The inputs gave no entry point, so nothing was analyzed.
    NoEntryPoints,
    /// Some classes could not be read, so a path may be missing.
    PartialRead,
    /// The record has no sinks to look for.
    NoSinks,
    /// None of the record's sinks is in the installed code: the flaw may sit elsewhere in
    /// this version.
    SinkAbsent,
    /// The record may not support "not reached": unreviewed, or reached by name.
    RecordCannotSay,
}

/// Judge one record. A witness always counts, whatever the record's status: a path is a path.
#[must_use]
pub fn judge(record: &SinkRecord, analysis: &Analysis<'_>, partial: bool) -> Verdict {
    if analysis.roots == 0 {
        return Verdict::Unknown(Why::NoEntryPoints);
    }
    if record.verdict != RecordKind::Sinks {
        return Verdict::Unknown(Why::NoSinks);
    }
    let mut present = false;
    for sink in &record.sinks {
        let descriptor = sink.descriptor.as_deref();
        if let Some(witness) = analysis.witness(&sink.class, &sink.method, descriptor) {
            return Verdict::Reached(Box::new(witness));
        }
        present |= analysis.has_method(&sink.class, &sink.method, descriptor);
    }
    if !present {
        return Verdict::Unknown(Why::SinkAbsent);
    }
    if partial {
        return Verdict::Unknown(Why::PartialRead);
    }
    if !record.supports_not_reached() {
        return Verdict::Unknown(Why::RecordCannotSay);
    }
    Verdict::NotReached(Limits {
        open_reflection: analysis.open_reflection.len(),
        open_dynamic: analysis.open_dynamic,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use fleetreach_sinks::record::{Evidence, Review, Sink, Status, SCHEMA};

    use super::*;
    use crate::classpath::ClassPath;
    use crate::graph::analyze;
    use crate::model::{Class, Method, Role};

    fn record(class: &str) -> SinkRecord {
        SinkRecord {
            schema: SCHEMA.into(),
            id: "GHSA-aaaa-bbbb-cccc".into(),
            aliases: vec![],
            ecosystem: "Maven".into(),
            packages: vec!["a:b".into()],
            status: Status::Reviewed,
            verdict: RecordKind::Sinks,
            sinks: vec![Sink {
                class: class.into(),
                method: "sink".into(),
                descriptor: None,
            }],
            gadgets: vec![],
            reached_by_name: false,
            evidence: Evidence::default(),
            review: Some(Review {
                by: "ann".into(),
                date: "2026-11-06".into(),
                note: None,
            }),
            note: None,
        }
    }

    /// An app with one method, and a library class holding an unreached `sink`.
    fn classpath() -> ClassPath {
        let mut cp = ClassPath::default();
        let add = |cp: &mut ClassPath, name: &str, method: &str, role| {
            let method = Method {
                name: cp.names.intern(method),
                desc: cp.names.intern("()V"),
                ..Method::default()
            };
            let class = Class {
                name: cp.names.intern(name),
                superclass: None,
                interfaces: vec![],
                is_interface: false,
                is_abstract: false,
                role,
                methods: vec![method],
                annotations: vec![],
                annotation_refs: vec![],
            };
            cp.by_name.insert(class.name, cp.classes.len());
            cp.classes.push(class);
        };
        add(&mut cp, "app/Main", "main", Role::App);
        add(&mut cp, "lib/Flawed", "sink", Role::Dependency);
        cp
    }

    #[test]
    fn a_reviewed_record_can_say_not_reached() {
        let cp = classpath();
        let a = analyze(&cp);
        let v = judge(&record("lib.Flawed"), &a, false);
        assert!(matches!(v, Verdict::NotReached(_)), "{v:?}");
    }

    #[test]
    fn a_sink_absent_from_the_jar_is_unknown() {
        let cp = classpath();
        let a = analyze(&cp);
        let v = judge(&record("lib.Missing"), &a, false);
        assert_eq!(v, Verdict::Unknown(Why::SinkAbsent));
    }

    #[test]
    fn reached_by_name_and_proposed_records_cannot_say_not_reached() {
        let cp = classpath();
        let a = analyze(&cp);
        let mut r = record("lib.Flawed");
        r.reached_by_name = true;
        assert_eq!(judge(&r, &a, false), Verdict::Unknown(Why::RecordCannotSay));
        let mut r = record("lib.Flawed");
        r.status = Status::Proposed;
        r.review = None;
        assert_eq!(judge(&r, &a, false), Verdict::Unknown(Why::RecordCannotSay));
    }

    #[test]
    fn a_partial_read_cannot_say_not_reached() {
        let cp = classpath();
        let a = analyze(&cp);
        let v = judge(&record("lib.Flawed"), &a, true);
        assert_eq!(v, Verdict::Unknown(Why::PartialRead));
    }

    #[test]
    fn a_witness_counts_for_any_record() {
        let cp = classpath();
        let a = analyze(&cp);
        let mut r = record("app.Main");
        r.sinks[0].method = "main".into();
        r.status = Status::Proposed;
        r.review = None;
        r.reached_by_name = true;
        assert!(matches!(judge(&r, &a, false), Verdict::Reached(_)));
    }

    #[test]
    fn nothing_to_analyze_is_unknown() {
        let cp = ClassPath::default();
        let a = analyze(&cp);
        let v = judge(&record("lib.Flawed"), &a, false);
        assert_eq!(v, Verdict::Unknown(Why::NoEntryPoints));
    }
}
