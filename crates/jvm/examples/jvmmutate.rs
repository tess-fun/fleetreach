//! Mutate real class files and read each copy: no panic, no read slower than a second. A
//! stand-in for libFuzzer where it cannot build (macOS without the C++ headers).
//!
//! `jvmmutate ROUNDS SEED WORKDIR FILE.class...`: each round damages every class one of
//! several ways (bit flips, a run of 0xFF or 0x00, a random 32-bit word, truncation, a copied
//! block), writes it alone into WORKDIR, loads that directory and builds the graph. Prints each
//! failure with the seed and round that made it and the panic message, keeps the bytes in
//! `WORKDIR.panics/SEED-ROUND-N.class`, and prints a count at the end.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use fleetreach_jvm::classpath::{load, Input};
use fleetreach_jvm::graph::analyze;
use fleetreach_jvm::model::Role;

/// The last panic's message and place.
static LAST: Mutex<String> = Mutex::new(String::new());

/// xorshift64*: enough to spread the damage, and repeatable from the seed.
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
            usize::try_from(self.next() % n as u64).unwrap_or(0)
        }
    }
}

fn damage(bytes: &mut Vec<u8>, rng: &mut Rng) {
    let len = bytes.len();
    if len == 0 {
        return;
    }
    match rng.below(6) {
        0 => {
            for _ in 0..=rng.below(16) {
                let i = rng.below(len);
                bytes[i] ^= 1 << rng.below(8);
            }
        }
        1 | 2 => {
            let at = rng.below(len);
            let n = (1 + rng.below(8)).min(len - at);
            let v = if rng.below(2) == 0 { 0xFF } else { 0x00 };
            bytes[at..at + n].fill(v);
        }
        3 => {
            let at = rng.below(len.saturating_sub(4));
            let word = u32::try_from(rng.next() & 0xFFFF_FFFF).unwrap_or(0);
            let end = (at + 4).min(len);
            bytes[at..end].copy_from_slice(&word.to_be_bytes()[..end - at]);
        }
        4 => bytes.truncate(rng.below(len)),
        _ => {
            let from = rng.below(len);
            let to = rng.below(len);
            let n = (1 + rng.below(256)).min(len - from).min(len - to);
            let block = bytes[from..from + n].to_vec();
            bytes[to..to + n].copy_from_slice(&block);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [rounds, seed, work, files @ ..] = args.as_slice() else {
        eprintln!("usage: jvmmutate ROUNDS SEED WORKDIR FILE.class...");
        std::process::exit(2);
    };
    let rounds: usize = rounds.parse().unwrap_or(1);
    let seed: u64 = seed.parse().unwrap_or(1);
    let work = PathBuf::from(work);
    if std::fs::create_dir_all(&work).is_err() {
        eprintln!("cannot create {}", work.display());
        std::process::exit(2);
    }
    let target = work.join("Damaged.class");
    let originals: Vec<(String, Vec<u8>)> = files
        .iter()
        .filter_map(|f| std::fs::read(f).ok().map(|b| (f.clone(), b)))
        .collect();
    std::panic::set_hook(Box::new(|info| {
        if let Ok(mut last) = LAST.lock() {
            *last = info.to_string().replace('\n', " ");
        }
    }));
    let (mut runs, mut read_ok, mut failures) = (0usize, 0usize, 0usize);
    let mut slowest = Duration::ZERO;
    for round in 0..rounds {
        for (fi, (name, original)) in originals.iter().enumerate() {
            let case_seed = seed
                ^ (u64::try_from(round).unwrap_or(0) << 20)
                ^ u64::try_from(fi).unwrap_or(0)
                ^ 0x9e37_79b9_7f4a_7c15;
            let mut rng = Rng(case_seed | 1);
            let mut bytes = original.clone();
            for _ in 0..=rng.below(3) {
                damage(&mut bytes, &mut rng);
            }
            if std::fs::write(&target, &bytes).is_err() {
                eprintln!("cannot write {}", target.display());
                std::process::exit(2);
            }
            runs += 1;
            let start = Instant::now();
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let inputs = [Input {
                    path: work.clone(),
                    role: Role::App,
                }];
                match load(&inputs) {
                    Ok(cp) => {
                        let read = cp.unread.is_empty();
                        let _ = analyze(&cp).reached();
                        read
                    }
                    Err(_) => false,
                }
            }));
            let took = start.elapsed();
            slowest = slowest.max(took);
            match outcome {
                Ok(true) => read_ok += 1,
                Ok(false) => {}
                Err(_) => {
                    failures += 1;
                    let why = LAST.lock().map(|l| l.clone()).unwrap_or_default();
                    println!("PANIC {name} seed={seed} round={round}: {why}");
                    // Beside the work directory: anything in it is loaded with the next case.
                    let kept = work.with_extension("panics");
                    let _ = std::fs::create_dir_all(&kept);
                    let _ = std::fs::write(kept.join(format!("{seed}-{round}-{fi}.class")), &bytes);
                }
            }
            if took > Duration::from_secs(1) {
                failures += 1;
                println!("SLOW {took:?} {name} seed={seed} round={round}");
            }
        }
    }
    println!("{runs} runs, {read_ok} still read, {failures} failures, slowest {slowest:?}");
}
