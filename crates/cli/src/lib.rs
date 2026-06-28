//! `fleetreach-cli` library: config loading, fleet orchestration, report
//! assembly + exit-code logic, and the command surface.
//!
//! The pipeline lives in the library (typed, testable). The command layer —
//! argument parsing ([`cli`]), the `scan` runner ([`scan`]), the `vex`
//! subcommands ([`vex`]), and DB/provenance plumbing ([`db`]) — also lives here,
//! so `main.rs` is a thin shell that just parses and dispatches.

pub mod assemble;
pub mod cli;
pub mod config;
pub mod db;
pub mod diff;
pub mod enrich;
pub mod npm_reach;
pub mod orchestrate;
pub mod reach;
pub mod resolve;
pub mod scan;
pub mod static_reach;
pub mod vex;

pub use assemble::{
    assemble, build_report, combine_baseline, drop_phantom, exit_code, retain_min_epss, retain_new,
    retain_reachable, Assembled, GateConfig, SuppressedOccurrence, Suppression,
};
pub use config::{Config, ConfigError};
pub use orchestrate::{scan_fleet, ScanData, Toolchain};
