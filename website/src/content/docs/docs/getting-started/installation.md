---
title: Install fleetreach
description: Install fleetreach with the install script, Homebrew, cargo or the container image. Prebuilt binaries for Linux, macOS and Windows, with checksums and attestations.
sidebar:
  label: Installation
---

fleetreach is a single binary. Install it with any of the methods below; all of them give
the build with network support (advisory download, KEV, EPSS and NVD enrichment).

## Install script (Linux and macOS)

The script picks the right archive for your machine, checks its SHA-256 and installs it to
`~/.local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/tess-fun/fleetreach/main/scripts/install.sh | sh
```

Pass `--to <dir>` (or set `FLEETREACH_INSTALL_DIR`) to install elsewhere and
`--version <x.y.z>` to pin a release.

## Homebrew

```sh
brew install tess-fun/tap/fleetreach
```

## cargo

```sh
cargo install fleetreach-cli --features network
```

The minimum supported Rust version is 1.89.

## Container image

`ghcr.io/tess-fun/fleetreach` (linux/amd64 and linux/arm64) includes `git` for fleet
sources and runs as a non-root user. Mount your fleet on `/work` and a volume on `/cache` so
downloads persist between runs:

```sh
docker run --rm -v "$PWD:/work" -v fleetreach-cache:/cache \
  ghcr.io/tess-fun/fleetreach scan -c fleet.toml
```

## Prebuilt binaries

Every [GitHub release](https://github.com/tess-fun/fleetreach/releases) has archives for:

| Platform | Archive |
|----------|---------|
| Linux x86-64 (glibc 2.35+) | `fleetreach-<version>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux ARM64 (glibc 2.35+) | `fleetreach-<version>-aarch64-unknown-linux-gnu.tar.gz` |
| macOS Apple silicon | `fleetreach-<version>-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `fleetreach-<version>-x86_64-apple-darwin.tar.gz` |
| Windows x86-64 | `fleetreach-<version>-x86_64-pc-windows-msvc.zip` |

Each release has a `SHA256SUMS` file and signed build provenance:

```sh
gh attestation verify fleetreach-<version>-x86_64-unknown-linux-gnu.tar.gz --repo tess-fun/fleetreach
```

## The offline build

The default `cargo install fleetreach-cli` (without `--features network`) is pure Rust with
no TLS stack and no network code. It reads a local RustSec clone (`--db <path>`) and OSV
exports you provide (`--osv-dir <dir>`), which suits air-gapped environments. See
[Run offline or air-gapped](/fleetreach/docs/guides/run-offline-or-air-gapped/).

## Check it works

```sh
fleetreach --version
```

Next: [run your first scan](/fleetreach/docs/getting-started/first-scan/).
