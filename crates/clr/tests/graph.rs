//! `tests/graphapp.dll` and `graphlib.dll` are built from `tests/graph-src` (see its project
//! files). Each `Lib.Via*.Mark` method stands for one rule of the graph.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fleetreach_clr::graph::{analyze, analyze_with, Role, Root};
use fleetreach_clr::verdict::{judge, Verdict, Why};
use fleetreach_clr::{read, Assembly};
use fleetreach_sinks::record::{
    Evidence, Review, Sink, SinkRecord, Status, Verdict as Kind, SCHEMA,
};

fn inputs() -> Vec<(Assembly, Role)> {
    vec![
        (read(include_bytes!("graphapp.dll")).unwrap(), Role::App),
        (
            read(include_bytes!("graphlib.dll")).unwrap(),
            Role::Dependency,
        ),
    ]
}

#[test]
fn each_route_reaches_its_mark() {
    let inputs = inputs();
    let a = analyze(&inputs);
    for via in [
        "ViaCircle",
        "ViaOutside",
        "ViaGeneric",
        "ViaExplicit",
        "ViaStruct",
        "ViaAttribute",
        "ViaString",
    ] {
        assert!(
            a.witness(&format!("Lib.{via}"), "Mark").is_some(),
            "{via} not reached"
        );
    }
    assert!(a.has_method("Lib.Unreached", "Mark"));
    assert!(
        a.witness("Lib.Unreached", "Mark").is_none(),
        "a type nothing makes is no dispatch target"
    );
    assert!(a.open_reflection.iter().any(|s| s == "Lib.Loader::Load"));
}

#[test]
fn a_witness_starts_at_the_service_and_follows_calls() {
    let inputs = inputs();
    let a = analyze(&inputs);
    let w = a.witness("Lib.ViaCircle", "Mark").unwrap();
    assert_eq!(w.root, Root::AppCode);
    let steps: Vec<String> = w
        .steps
        .iter()
        .map(|s| format!("{}::{}", s.type_name, s.method))
        .collect();
    assert_eq!(
        steps,
        [
            "App.Program::Main",
            "Lib.Shapes::Total",
            "Lib.Circle::Area",
            "Lib.ViaCircle::Mark"
        ]
    );
}

#[test]
fn configuration_names_make_types() {
    let inputs = inputs();
    let a = analyze_with(&inputs, &["Lib.Square, graphlib".to_string()]);
    assert!(a.witness("Lib.Unreached", "Mark").is_some());
}

fn record(class: &str) -> SinkRecord {
    SinkRecord {
        schema: SCHEMA.into(),
        id: "GHSA-aaaa-bbbb-cccc".into(),
        aliases: vec![],
        ecosystem: "NuGet".into(),
        packages: vec!["graphlib".into()],
        status: Status::Reviewed,
        verdict: Kind::Sinks,
        sinks: vec![Sink {
            class: class.into(),
            method: "Mark".into(),
            descriptor: None,
        }],
        gadgets: vec![],
        reached_by_name: false,
        evidence: Evidence::default(),
        review: Some(Review {
            by: "ann".into(),
            date: "2026-11-13".into(),
            note: None,
        }),
        note: None,
    }
}

#[test]
fn verdicts_follow_the_jvm_rules() {
    let inputs = inputs();
    let a = analyze(&inputs);
    assert!(matches!(
        judge(&record("Lib.Unreached"), &a, false),
        Verdict::NotReached(l) if l.open_reflection >= 1
    ));
    assert!(matches!(
        judge(&record("Lib.ViaString"), &a, false),
        Verdict::Reached(_)
    ));
    assert_eq!(
        judge(&record("Lib.Missing"), &a, false),
        Verdict::Unknown(Why::SinkAbsent)
    );
    assert_eq!(
        judge(&record("Lib.Unreached"), &a, true),
        Verdict::Unknown(Why::PartialRead)
    );
    let mut by_name = record("Lib.Unreached");
    by_name.reached_by_name = true;
    assert_eq!(
        judge(&by_name, &a, false),
        Verdict::Unknown(Why::RecordCannotSay)
    );
    let mut proposed = record("Lib.Unreached");
    proposed.status = Status::Proposed;
    proposed.review = None;
    assert_eq!(
        judge(&proposed, &a, false),
        Verdict::Unknown(Why::RecordCannotSay)
    );

    let lib_only = vec![(
        read(include_bytes!("graphlib.dll")).unwrap(),
        Role::Dependency,
    )];
    let none = analyze(&lib_only);
    assert_eq!(
        judge(&record("Lib.Unreached"), &none, false),
        Verdict::Unknown(Why::NoEntryPoints)
    );
}
