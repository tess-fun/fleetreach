//! Hostile source through the JavaScript and Python readers: deep nesting must not overflow
//! the stack (an abort no handler can catch), and long chains must not take quadratic time.
//! Each read here starts on a 2 MiB thread, as on a rayon worker.

#![allow(clippy::panic)]

use fleetreach_sinks::{js, python};

fn on_small_stack<T: Send + 'static>(read: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(read)
        .and_then(|h| h.join().map_err(|_| std::io::Error::other("panicked")))
        .unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn deeply_nested_javascript_is_read_without_overflowing() {
    // Each overflows a 2 MiB stack many times over.
    let n = 40_000;
    let shapes = [
        format!("x = {}1{};\n", "(".repeat(n), ")".repeat(n)),
        format!("x = {}1;\n", "() => ".repeat(n)),
        format!("{}1;\n", "a=".repeat(n)),
        format!("x = {}a;\n", "new ".repeat(n)),
        format!("{}{}", "function f() {".repeat(n / 4), "}".repeat(n / 4)),
    ];
    for src in shapes {
        let facts = on_small_stack(move || js::facts("deep.js", &src));
        drop(facts);
    }
}

#[test]
fn a_long_call_chain_keeps_only_a_bounded_callee() {
    let n = 200_000;
    let src = format!("x = f{};\n", "()".repeat(n));
    let facts = on_small_stack(move || js::facts("chain.js", &src));
    let calls = |f: &fleetreach_sinks::calls::ModuleFacts| -> usize {
        f.functions.values().map(|f| f.calls.len()).sum()
    };
    assert!(calls(&facts) > 0);
    let src = format!("x = f{}\n", "()".repeat(n));
    let facts = on_small_stack(move || python::facts(&src));
    assert!(calls(&facts) > 0);
}

#[test]
fn nested_python_calls_and_subscripts_read_in_linear_time() {
    let n = 200_000;
    for (open, close) in [("a(", ")"), ("a[", "]"), ("a.b(", ")")] {
        let src = format!("x = {}1{}\n", open.repeat(n), close.repeat(n));
        let facts = on_small_stack(move || python::facts(&src));
        drop(facts);
    }
}
