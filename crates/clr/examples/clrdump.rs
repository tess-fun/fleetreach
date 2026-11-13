//! Print every method of each assembly given and the ops the call graph sees, one per line,
//! in the format of the `System.Reflection.Metadata` oracle (docs/differential/clr).
#![allow(clippy::print_stdout)]

use std::io::Write;

use fleetreach_clr::{Invoke, Op};

fn main() {
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for path in std::env::args().skip(1) {
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                let _ = writeln!(out, "E {path} {e}");
                continue;
            }
        };
        let assembly = match fleetreach_clr::read(&bytes) {
            Ok(a) => a,
            Err(e) => {
                let _ = writeln!(out, "E {path} {e}");
                continue;
            }
        };
        let _ = writeln!(out, "A {path} {}", assembly.name);
        for t in &assembly.types {
            for m in &t.methods {
                match &m.body {
                    None => {
                        let _ = writeln!(out, "M {}::{} -", t.full_name, m.name);
                    }
                    Some((size, ops)) => {
                        let _ = writeln!(out, "M {}::{} {size}", t.full_name, m.name);
                        for op in ops {
                            let _ = writeln!(out, " {}", line(op));
                        }
                    }
                }
            }
        }
    }
    let _ = out.flush();
}

fn line(op: &Op) -> String {
    match op {
        Op::Invoke { kind, target } => {
            let kind = match kind {
                Invoke::Call => "call",
                Invoke::CallVirt => "callvirt",
                Invoke::NewObj => "newobj",
                Invoke::LdFtn => "ldftn",
                Invoke::LdVirtFtn => "ldvirtftn",
                Invoke::Jmp => "jmp",
            };
            format!("{kind} {}::{}", target.type_name, target.name)
        }
        Op::Str(s) => format!("ldstr {}", s.encode_utf16().count()),
        Op::TypeToken(t) => format!("ldtoken T {t}"),
        Op::MethodToken(m) => format!("ldtoken M {}::{}", m.type_name, m.name),
        Op::FieldToken(t) => format!("ldtoken F {t}"),
        Op::StaticField(t) => format!("sfld {t}"),
    }
}
