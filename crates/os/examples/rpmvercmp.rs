//! Compare rpm version pairs (`a<TAB>b` per line on stdin) with the comparator, printing
//! `-1`, `0` or `1` per line: the format of rpm's `rpm.vercmp`, for the differential against
//! rpm itself (spec 16, row 10).

use std::io::{BufRead, Write};

use fleetreach_os::RpmVersion;

fn main() -> std::io::Result<()> {
    let stdin = std::io::stdin().lock();
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for line in stdin.lines() {
        let line = line?;
        let (a, b) = line.split_once('\t').unwrap_or((&line, ""));
        let verdict = match (RpmVersion::parse(a), RpmVersion::parse(b)) {
            (Some(a), Some(b)) => match a.cmp(&b) {
                std::cmp::Ordering::Less => "-1",
                std::cmp::Ordering::Equal => "0",
                std::cmp::Ordering::Greater => "1",
            },
            _ => "unparsed",
        };
        writeln!(out, "{verdict}")?;
    }
    out.flush()
}
