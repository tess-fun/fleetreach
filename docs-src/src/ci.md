# CI integration

## GitHub Action

The bundled composite action installs fleetreach, scans the repo, and uploads
findings to the Security tab as SARIF:

```yaml
name: audit
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "0 6 * * *"  # daily, so newly-published advisories surface

permissions:
  contents: read
  security-events: write  # required to upload SARIF

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: tess-fun/fleetreach@v1
        with:
          # rank by real-world exploit risk and flag never-built optional deps
          args: "--enrich --resolve-features"
```

`with.args` is forwarded to `fleetreach scan`. By default the action generates a
`fleet.toml` that scans the current repo; pass `config:` to point at your own.

## Gating

The exit code is the CI contract (see [Quickstart](./quickstart.md)). Tune what
trips a failure:

- `--fail-on <severity>` — floor a finding must reach to gate (default `low`;
  Unknown always counts, fail-closed).
- `--fail-on-warnings` — also gate on supply-chain warnings.
- `--fail-on-kev` / `--min-epss 0.5` — gate on real-world exploit risk (needs
  `--enrich`).
- `--require-full-coverage`: exit 2 if any source was only partly read (a
  `pom.xml` without a resolved graph, a `bun.lockb`).

## Drift gating with `diff`

Save a baseline report and compare against it so only *new* findings fail the
build:

```sh
fleetreach scan -c fleet.toml -f json > current.json
fleetreach diff baseline.json current.json --fail-on high
```

`diff` is pure (no scanning, DB, or network — just two JSON files). The exit code
mirrors `scan`: `1` when a *new* finding trips the gate. `--exit-zero` makes it
report-only.

## SARIF and suppression

`-f sarif` emits SARIF 2.1.0. A machine-sound `not_affected` (a static
`NotReachable` verdict or a phantom optional dependency) carries a
`suppressions[]` entry so GitHub's Security tab greys it out rather than alerting.
fleetreach can also emit and consume **OpenVEX** (`-f vex`) for cross-tool
suppression with Grype and Trivy.

## Resolving the real build

With `--resolve-features` (needs the repo's buildable source), each finding is
marked built vs. a phantom `Cargo.lock`-only optional dependency that is never
compiled; the table flags those with `⚠ not in default build`. Default scans
stay lockfile-only and portable.

## Dev and build dependencies

Where the lockfile records it, each finding says whether the package is only
installed for development: npm `"dev": true`, uv dependency groups, poetry
`groups`/`category`, Pipfile `[dev-packages]`, and composer `packages-dev`. A
package counts as dev only if no runtime dependency (including extras) reaches
it. The table marks those `(dev only)`, JSON carries `"scope": "dev"`, and
`--ignore-dev-deps` drops them. A dev finding still gates by default: a
vulnerable linter or test runner runs in CI with your credentials.
