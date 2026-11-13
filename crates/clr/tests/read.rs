//! `tests/fixture.dll` is built from `tests/fixture-src` (see its project file).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fleetreach_clr::{read, Assembly, Invoke, Op, Target};

const FIXTURE: &[u8] = include_bytes!("fixture.dll");

fn method<'a>(a: &'a Assembly, ty: &str, name: &str) -> &'a [Op] {
    let t = a.types.iter().find(|t| t.full_name == ty).expect(ty);
    let m = t.methods.iter().find(|m| m.name == name).expect(name);
    &m.body.as_ref().expect("a body").1
}

fn call(kind: Invoke, ty: &str, name: &str) -> Op {
    Op::Invoke {
        kind,
        target: Target {
            type_name: ty.to_string(),
            name: name.to_string(),
        },
    }
}

#[test]
fn types_methods_and_ops_are_named_as_reflection_names_them() {
    let a = read(FIXTURE).unwrap();
    assert_eq!(a.name, "fixture");
    assert!(a.references.iter().any(|r| r == "netstandard"));
    let pricer = a
        .types
        .iter()
        .find(|t| t.full_name == "Acme.Billing.Pricer")
        .unwrap();
    assert_eq!(pricer.extends.as_deref(), Some("System.Object"));
    assert_eq!(pricer.interfaces, ["Acme.Billing.IPricer"]);
    let iface = a
        .types
        .iter()
        .find(|t| t.full_name == "Acme.Billing.IPricer")
        .unwrap();
    assert!(
        iface.methods[0].body.is_none(),
        "an interface method has no body"
    );

    assert_eq!(
        method(&a, "Acme.Billing.Pricer", "Price"),
        [
            Op::StaticField("Acme.Billing.Pricer".to_string()),
            call(
                Invoke::CallVirt,
                "System.Collections.Generic.Dictionary`2",
                "TryGetValue"
            ),
            call(Invoke::Call, "Acme.Billing.Pricer", "Fallback"),
        ]
    );
    assert_eq!(
        method(&a, "Acme.Billing.Loader", "Find"),
        [
            Op::Str("Acme.Billing.Pricer".to_string()),
            call(Invoke::Call, "System.Type", "GetType"),
            Op::TypeToken("Acme.Billing.Pricer".to_string()),
            call(Invoke::Call, "System.Type", "GetTypeFromHandle"),
        ]
    );
    let lambda = "Acme.Billing.Pricer+Cache+<>c__DisplayClass0_0";
    assert_eq!(
        method(&a, "Acme.Billing.Pricer+Cache", "Make"),
        [
            call(Invoke::NewObj, lambda, ".ctor"),
            call(Invoke::LdFtn, lambda, "<Make>b__0"),
            call(Invoke::NewObj, "System.Func`2", ".ctor"),
        ]
    );
    // A generic method's call through a MethodSpec-free MemberRef on a generic instance.
    assert_eq!(
        method(&a, "Acme.Billing.Loader", "One")[1],
        call(Invoke::CallVirt, "System.Collections.Generic.List`1", "Add")
    );
}

#[test]
fn a_damaged_file_is_an_error_never_a_panic() {
    for len in 0..FIXTURE.len() {
        let _ = read(&FIXTURE[..len]);
    }
    let mut bytes = FIXTURE.to_vec();
    for at in 0..bytes.len() {
        let was = bytes[at];
        for value in [0x00, 0xFF, was ^ 0x01, was ^ 0x80] {
            bytes[at] = value;
            let _ = read(&bytes);
        }
        bytes[at] = was;
    }
    assert!(read(b"MZ").is_err());
    assert!(read(b"not a pe file").is_err());
}
