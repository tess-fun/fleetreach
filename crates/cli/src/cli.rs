//! The command-line surface: the clap command tree, the shared value-enums it
//! parses into, and the top-level dispatch. The thin binary calls
//! [`Cli::try_parse`] then [`dispatch`]; the per-command logic lives in
//! [`crate::scan`] and [`crate::vex`].

use clap::{Parser, Subcommand, ValueEnum};
use fleetreach_core::Severity;
use fleetreach_report as report;

use crate::diff::DiffArgs;
use crate::scan::ScanArgs;
use crate::vex::{VexCheckArgs, VexVerifyArgs};

#[derive(Parser)]
#[command(
    name = "fleetreach",
    version,
    about = "Fleet-native dependency security audit across 12 ecosystems"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
// `ScanArgs` is far larger than the VEX subcommands; boxing the variant fights
// clap's `Args` derive, so accept the size skew on this top-level command enum.
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Scan the fleet for advisories.
    Scan(ScanArgs),
    /// Compare two saved JSON reports: new vs. fixed vs. still-open findings.
    Diff(DiffArgs),
    /// Operate on OpenVEX documents (drift gate, witness verification).
    #[command(subcommand)]
    Vex(VexCommand),
}

#[derive(Subcommand)]
enum VexCommand {
    /// Fail when a committed OpenVEX document has drifted from a fresh scan (§10).
    Check(VexCheckArgs),
    /// Re-derive each machine `not_affected` witness against current source (§9.2).
    Verify(VexVerifyArgs),
}

/// Run the parsed command, returning the process exit code (§8).
pub fn dispatch(cli: Cli) -> u8 {
    match cli.command {
        Commands::Scan(args) => crate::scan::run_scan(args),
        Commands::Diff(args) => crate::diff::run_diff(args),
        Commands::Vex(VexCommand::Check(args)) => crate::vex::run_vex_check(args),
        Commands::Vex(VexCommand::Verify(args)) => crate::vex::run_vex_verify(args),
    }
}

/// A could-not-scan failure (exit `2`): config/DB/render error — loud, never clean.
pub(crate) fn fail(message: &str) -> u8 {
    eprintln!("error: {message}");
    2
}

/// A usage error (exit `3`), distinct from could-not-scan (`2`); used for the
/// fail-closed VEX author/timestamp/consent checks.
pub(crate) fn usage_fail(message: &str) -> u8 {
    eprintln!("error: {message}");
    3
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ReachMode {
    /// Grep the repo's own source for affected-function names (zero-build).
    Heuristic,
    /// Sound call-graph reachability over the compiled crate closure.
    Static,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum BuildSandbox {
    /// Confine if a mechanism is available, else warn and run unconfined.
    Auto,
    /// Never confine — run the build with full user privileges.
    Off,
    /// Confine, or refuse to build (→ Unknown) if no mechanism is available.
    Require,
}

impl From<BuildSandbox> for fleetreach_reach::SandboxPolicy {
    fn from(b: BuildSandbox) -> Self {
        match b {
            BuildSandbox::Auto => fleetreach_reach::SandboxPolicy::Auto,
            BuildSandbox::Off => fleetreach_reach::SandboxPolicy::Off,
            BuildSandbox::Require => fleetreach_reach::SandboxPolicy::Require,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Format {
    Table,
    Json,
    /// SARIF 2.1.0 for GitHub code scanning.
    Sarif,
    /// Blast-radius view: advisories ranked by repos affected.
    Impact,
    /// Blast view: blast radius split into direct vs transitive reach, with a fix-path
    /// hint (manifest / upstream / mixed).
    Blast,
    /// Package-impact view: vulnerable dependencies ranked by fleet reach (which one
    /// bump clears the most), with the direct/transitive split and advisory count.
    Packages,
    /// The package-impact rollup as JSON (the `packages` view, machine-readable).
    PackagesJson,
    /// Fix-first view: advisories ranked by remediation priority
    /// (KEV, then severity, then blast radius).
    FixFirst,
    /// Remediation view: the actionable fix queue — batched dependency bumps,
    /// reachability-gated, fix-first-ordered.
    Remediation,
    /// The remediation fix queue as JSON (the `remediation` view, machine-readable).
    RemediationJson,
    /// OpenVEX 0.2.0 suppression document (§14).
    Vex,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum VexScopeArg {
    Runtime,
    Build,
}

impl From<VexScopeArg> for report::VexScope {
    fn from(s: VexScopeArg) -> Self {
        match s {
            VexScopeArg::Runtime => report::VexScope::Runtime,
            VexScopeArg::Build => report::VexScope::Build,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum SeverityArg {
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}
