//! One sink record against one graph, as for the JVM.

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
    /// Reached methods calling reflection by name.
    pub open_reflection: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The inputs gave no entry point, so nothing was analyzed.
    NoEntryPoints,
    /// Some assemblies could not be read, so a path may be missing.
    PartialRead,
    /// The record has no sinks to look for.
    NoSinks,
    /// None of the record's sinks is in the installed assemblies: the flaw may sit elsewhere
    /// in this version.
    SinkAbsent,
    /// The record may not support "not reached": unreviewed, or reached by name.
    RecordCannotSay,
}

/// Judge one record. A witness always counts, whatever the record's status: a path is a path.
#[must_use]
pub fn judge(record: &SinkRecord, analysis: &Analysis<'_>, partial: bool) -> Verdict {
    judge_in(record, analysis, partial, &|_| true)
}

/// [`judge`], looking for the sinks only in the assemblies whose name `keep` accepts: those
/// of the record's packages, where the caller knows them.
#[must_use]
pub fn judge_in(
    record: &SinkRecord,
    analysis: &Analysis<'_>,
    partial: bool,
    keep: &dyn Fn(&str) -> bool,
) -> Verdict {
    if analysis.roots == 0 {
        return Verdict::Unknown(Why::NoEntryPoints);
    }
    if record.verdict != RecordKind::Sinks {
        return Verdict::Unknown(Why::NoSinks);
    }
    let mut present = false;
    for sink in &record.sinks {
        if let Some(witness) = analysis.witness_in(&sink.class, &sink.method, keep) {
            return Verdict::Reached(Box::new(witness));
        }
        present |= analysis.has_method_in(&sink.class, &sink.method, keep);
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
    })
}
