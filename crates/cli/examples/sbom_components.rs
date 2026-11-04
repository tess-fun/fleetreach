//! Prints what fleetreach reads from an SBOM, for `docs/differential/sbom_formats.py`.

fn main() {
    for path in std::env::args().skip(1) {
        match fleetreach_cli::sbom_input::read(std::path::Path::new(&path)) {
            Ok(input) => {
                for (ecosystem, packages) in &input.packages {
                    for p in packages {
                        println!("{ecosystem:?} {} {}", p.name, p.version);
                    }
                }
                for line in &input.unrouted {
                    println!("unrouted {line}");
                }
            }
            Err(e) => println!("error {e}"),
        }
    }
}
