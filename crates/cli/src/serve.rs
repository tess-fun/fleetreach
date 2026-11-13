//! `fleetreach serve`: its arguments, and the server when built with the `serve` feature
//! (see [`crate::server`]).

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use clap::Args;

#[derive(Args)]
pub struct ServeArgs {
    /// The directory `scan --history-dir` writes
    #[arg(long)]
    pub(crate) history_dir: PathBuf,
    /// fleet.toml: its `[settings.sla]` sets deadlines, and decisions go to its triage directory
    #[arg(short, long, default_value = "./fleet.toml")]
    pub(crate) config: PathBuf,
    /// The address to listen on; anything but a loopback address needs --trust-proxy
    #[arg(long, default_value = "127.0.0.1:8484")]
    pub(crate) listen: SocketAddr,
    /// A reverse proxy's address (repeatable): only requests from these are served, and the
    /// reviewer is the identity header they send
    #[arg(long = "trust-proxy", value_name = "IP")]
    pub(crate) trust_proxy: Vec<IpAddr>,
    /// The header in which a trusted proxy names the signed-in user
    #[arg(long, default_value = "X-Forwarded-User")]
    pub(crate) identity_header: String,
    /// Who records decisions when there is no proxy (default: git's user.name, else $USER)
    #[arg(long)]
    pub(crate) by: Option<String>,
    /// The overview page's title
    #[arg(long, default_value = "Fleet security report")]
    pub(crate) title: String,
}

pub fn run_serve(args: ServeArgs) -> u8 {
    #[cfg(feature = "serve")]
    {
        crate::server::run(args)
    }
    #[cfg(not(feature = "serve"))]
    {
        let _ = args;
        crate::cli::fail(
            "this fleetreach was built without the `serve` feature; install a release binary, \
             or build with `cargo install fleetreach-cli --features serve`",
        )
    }
}
