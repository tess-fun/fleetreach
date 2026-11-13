//! Hostile sources through the Python and JavaScript fact readers: crafted shapes (deep
//! nesting, long lines, unterminated strings) and mutated real files. Each read runs on a
//! thread with a 2 MiB stack, as a rayon worker has, so a stack overflow shows up as an abort.
//!
//! `srcattack shapes` runs the crafted shapes, printing the time of each;
//! `srcattack mutate ROUNDS SEED FILE...` damages real `.py`/`.js` files and reads each copy.
#![allow(clippy::print_stdout, clippy::print_stderr, clippy::unwrap_used)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

use fleetreach_sinks::{js, python};

fn read(name: &str, src: String) -> Duration {
    let is_py = name.ends_with(".py");
    let path = name.to_string();
    let handle = std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(move || {
            let start = Instant::now();
            let ok = catch_unwind(AssertUnwindSafe(|| {
                if is_py {
                    let _ = python::facts(&src);
                    let _ = python::functions(&path, &src);
                } else {
                    let _ = js::facts(&path, &src);
                    let _ = js::functions(&path, &src);
                }
            }));
            (start.elapsed(), ok.is_ok())
        })
        .unwrap();
    let (took, ok) = handle.join().unwrap();
    if !ok {
        println!("PANIC {name}");
    }
    took
}

fn shapes() -> Vec<(String, String)> {
    // within the 2 MiB file cap; SRCATTACK_N shrinks the shapes to find the depth that breaks
    let n: usize = std::env::var("SRCATTACK_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1 << 20);
    let mut v = Vec::new();
    for (ext, open, close) in [
        ("py", "(", ")"),
        ("py", "[", "]"),
        ("js", "(", ")"),
        ("js", "[", "]"),
        ("js", "{", "}"),
    ] {
        v.push((
            format!("nest-{open}.{ext}"),
            format!("x = {}1{}\n", open.repeat(n / 2), close.repeat(n / 2)),
        ));
    }
    v.push(("unary.js".into(), format!("x = {}1;\n", "-".repeat(n))));
    v.push(("not.py".into(), format!("x = {}1\n", "not ".repeat(n / 4))));
    v.push(("binop.js".into(), format!("x = 1{};\n", "+1".repeat(n / 2))));
    v.push(("binop.py".into(), format!("x = 1{}\n", "+1".repeat(n / 2))));
    v.push(("attr.py".into(), format!("x = a{}\n", ".b".repeat(n / 2))));
    v.push(("attr.js".into(), format!("x = a{};\n", ".b".repeat(n / 2))));
    v.push(("call.py".into(), format!("x = f{}\n", "()".repeat(n / 2))));
    v.push(("call.js".into(), format!("x = f{};\n", "()".repeat(n / 2))));
    v.push((
        "lambda.py".into(),
        format!("x = {}1\n", "lambda: ".repeat(n / 8)),
    ));
    v.push((
        "arrow.js".into(),
        format!("x = {}1;\n", "() => ".repeat(n / 6)),
    ));
    v.push((
        "ternary.js".into(),
        format!("x = {}1;\n", "a?b:".repeat(n / 4)),
    ));
    v.push(("assign.js".into(), format!("{}1;\n", "a=".repeat(n / 2))));
    v.push(("exp.js".into(), format!("x = 2{};\n", "**2".repeat(n / 3))));
    v.push(("new.js".into(), format!("x = {}a;\n", "new ".repeat(n / 4))));
    v.push((
        "typeof.js".into(),
        format!("x = {}a;\n", "typeof ".repeat(n / 7)),
    ));
    v.push(("not.js".into(), format!("x = {}a;\n", "!".repeat(n))));
    v.push((
        "comma.js".into(),
        format!("x = (1{});\n", ",1".repeat(n / 2)),
    ));
    v.push(("and.js".into(), format!("x = a{};\n", "&&a".repeat(n / 3))));
    v.push((
        "index.js".into(),
        format!("x = a{};\n", "[0]".repeat(n / 3)),
    ));
    v.push((
        "ifelse.js".into(),
        format!("{}x;\n", "if(a);else ".repeat(n / 11)),
    ));
    v.push(("label.js".into(), format!("{}x;\n", "a:".repeat(n / 2))));
    v.push((
        "callnest.py".into(),
        format!("x = {}1{}\n", "a(".repeat(n / 4), ")".repeat(n / 4)),
    ));
    v.push((
        "callnest.js".into(),
        format!("x = {}1{};\n", "a(".repeat(n / 4), ")".repeat(n / 4)),
    ));
    v.push((
        "subscript.py".into(),
        format!("x = {}1{}\n", "a[".repeat(n / 4), "]".repeat(n / 4)),
    ));
    v.push(("assign.py".into(), format!("{}1\n", "a=".repeat(n / 2))));
    v.push(("index.py".into(), format!("x = a{}\n", "[0]".repeat(n / 3))));
    v.push(("pow.py".into(), format!("x = 2{}\n", "**2".repeat(n / 3))));
    v.push((
        "ternary.py".into(),
        format!("x = 1{}\n", " if a else 1".repeat(n / 12)),
    ));
    v.push((
        "func.js".into(),
        format!("{}{}", "function f() {".repeat(n / 16), "}".repeat(n / 16)),
    ));
    let mut py = String::new();
    for i in 0..4000 {
        py.push_str(&" ".repeat(i));
        py.push_str("if x:\n");
    }
    v.push(("indent.py".into(), py));
    let mut defs = String::new();
    for i in 0..3000 {
        defs.push_str(&" ".repeat(i * 4));
        defs.push_str(&format!("def f{i}():\n"));
    }
    v.push(("defs.py".into(), defs));
    v.push(("tq.py".into(), "\"\"\"".repeat(n / 3)));
    v.push(("quote.py".into(), format!("x = '{}", "\\".repeat(n))));
    v.push((
        "template.js".into(),
        format!("x = `{}`;", "${`".repeat(n / 8)),
    ));
    v.push(("regex.js".into(), format!("x = /{}/;", "(".repeat(n / 2))));
    v.push(("lines.py".into(), "\n".repeat(n * 2 - 1)));
    v.push(("imports.py".into(), "import a\n".repeat(n / 9)));
    v.push(("imports.js".into(), "import a from 'a';\n".repeat(n / 19)));
    v.push((
        "class.py".into(),
        (0..20000)
            .map(|i| format!("class C{i}(C{}): pass\n", i + 1))
            .collect(),
    ));
    v.push((
        "decorators.py".into(),
        format!("{}def f(): pass\n", "@d\n".repeat(n / 3)),
    ));
    v
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

const TOKENS: &[&str] = &[
    "(",
    ")",
    "[",
    "]",
    "{",
    "}",
    "\"",
    "'",
    "\"\"\"",
    "`",
    "${",
    "\n",
    "    ",
    "\\",
    "#",
    "//",
    "/*",
    "*/",
    ":",
    "def ",
    "class ",
    "import ",
    "from ",
    "=>",
    "function ",
    "lambda ",
    "@",
    "async ",
    "\u{feff}",
    "\r",
];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("shapes") => {
            // Each shape in a child process: a stack overflow aborts the whole process.
            let me = std::env::current_exe().unwrap();
            for (name, _) in shapes() {
                let out = std::process::Command::new(&me)
                    .args(["one", &name])
                    .output()
                    .unwrap();
                let text = String::from_utf8_lossy(&out.stdout);
                match out.status.code() {
                    Some(0) => print!("{text}"),
                    code => println!("ABORT {name} ({code:?})"),
                }
            }
        }
        Some("one") => {
            let want = &args[1];
            for (name, src) in shapes() {
                if &name == want {
                    let took = read(&name, src);
                    println!("{took:>12?} {name}");
                }
            }
        }
        Some("mutate") => {
            let rounds: usize = args[1].parse().unwrap();
            let seed: u64 = args[2].parse().unwrap();
            let files: Vec<(String, String)> = args[3..]
                .iter()
                .filter_map(|f| std::fs::read_to_string(f).ok().map(|s| (f.clone(), s)))
                .collect();
            std::panic::set_hook(Box::new(|_| {}));
            let mut slowest = (Duration::ZERO, String::new());
            let mut runs = 0;
            for round in 0..rounds {
                for (fi, (name, src)) in files.iter().enumerate() {
                    let mut rng =
                        Rng(
                            (seed ^ ((round as u64) << 20) ^ fi as u64 ^ 0x9e37_79b9_7f4a_7c15) | 1,
                        );
                    let mut s: Vec<char> = src.chars().collect();
                    for _ in 0..=rng.below(8) {
                        let at = rng.below(s.len() + 1);
                        match rng.below(3) {
                            0 => {
                                let t = TOKENS[rng.below(TOKENS.len())];
                                s.splice(at..at, t.chars());
                            }
                            1 => {
                                let end = (at + rng.below(64)).min(s.len());
                                s.drain(at..end);
                            }
                            _ => {
                                if !s.is_empty() {
                                    let from = rng.below(s.len());
                                    let end = (from + rng.below(200)).min(s.len());
                                    let block: Vec<char> = s[from..end].to_vec();
                                    s.splice(at..at, block);
                                }
                            }
                        }
                    }
                    let text: String = s.into_iter().collect();
                    let took = read(name, text);
                    runs += 1;
                    if took > slowest.0 {
                        slowest = (took, format!("{name} round {round}"));
                    }
                    if took > Duration::from_secs(1) {
                        println!("SLOW {took:?} {name} seed={seed} round={round}");
                    }
                }
            }
            println!("{runs} runs, slowest {:?} ({})", slowest.0, slowest.1);
        }
        _ => eprintln!("usage: srcattack shapes | srcattack mutate ROUNDS SEED FILE..."),
    }
}
