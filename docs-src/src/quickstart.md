# Quickstart

## 1. Describe your fleet

Create a `fleet.toml` listing the repositories to scan:

```toml
[[repo]]
id   = "core-lib"
path = "../core-lib"            # repo root; Cargo.lock located within

[[repo]]
id   = "services"
path = "../services"
glob = true                     # discover **/Cargo.lock under the tree

[[repo]]
id        = "web-frontend"
path      = "../web-frontend"   # a package-lock.json repo
ecosystem = "npm"               # optional; auto-detected from the manifests
```

The ecosystem is auto-detected from each repo's manifests, so `ecosystem = …` is
usually optional. See the full [configuration reference](./configuration.md).

## 2. Scan

```sh
fleetreach scan -c fleet.toml          # human table (default)
fleetreach scan -c fleet.toml -f json  # machine payload, clean for | jq
fleetreach scan -c fleet.toml -f sarif # SARIF 2.1.0 for code scanning
```

A mixed-ecosystem fleet (Rust, Go, npm, and any of the toolchain-free feeders)
folds into one unified, blast-radius-ranked report.

## 3. Read the result

The default table lists each advisory with its severity, the repos it hits, and
a fix hint. From there, the [report views](./views.md) reshape the same findings
to answer specific questions:

- `-f impact` — which fix clears the most repos?
- `-f blast` — split each advisory's reach into direct vs transitive.
- `-f packages` — which dependency is my biggest fleet liability?
- `-f remediation` — the batched fix queue: what to bump, in what order.

## Exit codes (the CI contract)

Evaluated top-down, first match wins:

| Code | Meaning |
|------|---------|
| `3`  | Usage / argument error. |
| `2`  | Could not complete a trustworthy scan (bad config, DB unloadable, a repo errored). |
| `1`  | Trustworthy scan; a finding tripped the gate (`--fail-on`). |
| `0`  | Trustworthy scan; nothing met the failure threshold. |

The tool never exits `0` unless it completed a scan it can stand behind.
