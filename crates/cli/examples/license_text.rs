//! Prints what fleetreach detects in each package directory, for
//! `docs/differential/license_text.py`: a JSON line per directory.

fn main() {
    let detector = fleetreach_cli::licensetext::Detector::new();
    for dir in std::env::args().skip(1) {
        let found = detector.dir(std::path::Path::new(&dir));
        let (ids, unrecognized) = found.map_or((Vec::new(), Vec::new()), |d| {
            (d.ids.into_iter().collect(), d.unrecognized)
        });
        let line = serde_json::json!({"dir": dir, "ids": ids, "unrecognized": unrecognized});
        println!("{line}");
    }
}
