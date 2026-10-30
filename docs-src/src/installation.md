# Installation

## Prebuilt binaries

Every [GitHub release](https://github.com/tess-fun/fleetreach/releases) carries binaries
built with the `network` feature for:

| Platform | Archive |
|----------|---------|
| Linux x86-64 (glibc 2.35+) | `fleetreach-<version>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux ARM64 (glibc 2.35+) | `fleetreach-<version>-aarch64-unknown-linux-gnu.tar.gz` |
| macOS Apple silicon | `fleetreach-<version>-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `fleetreach-<version>-x86_64-apple-darwin.tar.gz` |
| Windows x86-64 | `fleetreach-<version>-x86_64-pc-windows-msvc.zip` |

Each release also has a `SHA256SUMS` file and signed build-provenance attestations
(`gh attestation verify <archive> --repo tess-fun/fleetreach`).

The install script picks the right archive, checks its SHA-256 and installs it to
`~/.local/bin` (override with `--to <dir>` or `FLEETREACH_INSTALL_DIR`; pin a version with
`--version <x.y.z>`):

```sh
curl -fsSL https://raw.githubusercontent.com/tess-fun/fleetreach/main/scripts/install.sh | sh
```

## Homebrew

```sh
brew install tess-fun/tap/fleetreach
```

## Container image

`ghcr.io/tess-fun/fleetreach` (linux/amd64 and linux/arm64) includes `git` for fleet
sources and runs as a non-root user. Mount your fleet on `/work` and a volume on `/cache` so
OSV exports, checkouts and NVD answers persist between runs:

```sh
docker run --rm -v "$PWD:/work" -v fleetreach-cache:/cache \
  ghcr.io/tess-fun/fleetreach scan -c fleet.toml
```

## From crates.io

```sh
cargo install fleetreach-cli --features network
```

This installs the `fleetreach` binary with network support (advisory-DB fetch
plus KEV/EPSS/NVD enrichment).

## The `network` feature

The default build is **pure-Rust** — no vendored-C TLS stack. It has no network
support and expects a local advisory-db clone passed with `--db <PATH>`. The
opt-in `network` feature adds advisory-DB fetch and KEV/EPSS/NVD enrichment
(pulling a `rustls` TLS stack).

- Install **with** `--features network` for the usual fetch-on-run behavior.
- Omit it for a minimal, dependency-light, offline (`--db`) build.

## From source

```sh
git clone https://github.com/tess-fun/fleetreach
cd fleetreach
cargo install --path crates/cli --features network
```

## Minimum supported Rust version

The MSRV is **1.89**, driven by the whole dependency closure (not just
`rustsec`) and verified in CI.

## Static reachability (optional)

The `--reachability=static` mode needs a separately built nightly driver
(`fleetreach-reach-driver`). It links `rustc_private`, so it is not published to
crates.io — build it from the repository when you want sound static
reachability. See [Reachability](./reachability.md).
