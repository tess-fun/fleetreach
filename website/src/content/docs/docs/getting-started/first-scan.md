---
title: Run your first scan
description: Describe your repositories in fleet.toml, run fleetreach scan, and read the fleet-wide report. Takes about a minute, with real output at every step.
sidebar:
  label: First scan
---

A scan needs one file, `fleet.toml`, that lists your repositories. fleetreach finds the
lockfiles in each one, downloads the advisory data it needs, and prints one report for all
of them.

## 1. List your repos

```toml title="fleet.toml"
[[repo]]
id   = "payments-api"
path = "../payments-api"

[[repo]]
id   = "checkout-web"
path = "../checkout-web"

[[repo]]
id   = "platform"
path = "../platform"
glob = true          # a monorepo: also scan lockfiles below the root
```

`path` is the repo's root on disk. Every ecosystem fleetreach finds there is scanned, so a
repo with a `Cargo.lock`, a `package-lock.json` and GitHub workflows is read in full. To
scan a whole GitHub or GitLab organisation without cloning it yourself, see
[Scan a GitHub or GitLab org](/fleetreach/docs/guides/scan-a-github-or-gitlab-org/).

To list repos by URL instead of by path, use a source: fleetreach clones only the
lockfiles it needs into its cache, so `fleet.toml` holds no local paths.

```toml title="fleet.toml"
[[source]]
kind = "git"
urls = ["https://github.com/acme/payments-api", "https://github.com/acme/checkout-web"]
```

Run `fleetreach scan --sync` to clone or refresh them.

**Just one repo?** Run `fleetreach scan` anywhere inside it without a `fleet.toml`: the
git work tree around the current directory is scanned as a one-repo fleet, named after
its directory, with lockfiles below the root included. `fleetreach scan --repo <dir>` does
the same for any directory.

## 2. Scan

```sh
fleetreach scan
```

`scan` reads `./fleet.toml` by default (`-c` names another). The first run downloads the
osv.dev exports the fleet needs into `~/.cache/fleetreach/` and the RustSec database; later
runs reuse them and refresh them every few hours.

On the demo fleet used throughout these docs (nine repos in Rust, npm, Python, Go, Ruby,
Java and GitHub Actions), the summary line and the first rows look like this:

<!-- run: fleetreach scan 2>&1 | head -n 14 -->
```console
$ fleetreach scan 2>&1 | head -n 14
note: 1 source(s) scanned with incomplete coverage (findings outside what was read were never matched):
  data-pipeline: requirements.txt [partial] every requirement is pinned, but nothing shows the file lists the full transitive set (no pip-compile or uv header, `# via` annotations or hashes); dependencies of these packages may be missing
note: SSVC decisions not computed: no exploitation data: run with --enrich, or --kev-file offline
Scanned 9 repo(s) (0 errored): 211 vulns, 1 warning(s); max severity critical. Incomplete coverage: 1 source(s) in 1 repo(s).
┌───────────────┬─────────────────────┬──────────────────────────────────────────────────────────────────────────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Severity      ┆ Advisory            ┆ Title                                                                    ┆ Locations                                                                                                              │
╞═══════════════╪═════════════════════╪══════════════════════════════════════════════════════════════════════════╪════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╡
│ critical      ┆ GHSA-353f-x4gh-cqq8 ┆ Nokogiri patches vendored libxml2 to resolve mu…                         ┆ billing/nokogiri@1.16.2 → 1.18.9 (direct)                                                                              │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ critical      ┆ GHSA-6q48-6c7w-9gw2 ┆ certifi bundles emSign root CAs with compromise…                         ┆ data-pipeline/certifi@2022.9.24 → 2026.10.18 (direct)                                                                  │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ critical 9.0  ┆ GHSA-7rjr-3q55-vv33 ┆ Incomplete fix for Apache Log4j vulnerability                            ┆ partner-api/org.apache.logging.log4j:log4j-core@2.14.1 → 2.16.0 (direct)                                               │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ critical 10.0 ┆ GHSA-jfh8-c2jp-5v3q ┆ Remote code injection in Log4j                                           ┆ partner-api/org.apache.logging.log4j:log4j-core@2.14.1 → 2.15.0 (direct)                                               │
```
<!-- /run -->

Each row is one advisory in one repo, with the installed version, the version that fixes
it and whether the package is a direct or transitive dependency. The `note` lines on stderr
name anything not read in full: here `data-pipeline` has a `requirements.txt` with pinned
versions but no sign of which resolver wrote it, so fleetreach cannot be sure it lists every
transitive package. See [Coverage](/fleetreach/docs/concepts/coverage-and-fail-closed/).

## 3. Ask the fleet question

The same findings, ranked by how many repos one fix clears:

<!-- run: fleetreach scan -f remediation | head -n 16 -->
```console
$ fleetreach scan -f remediation | head -n 16
┌────┬───────────────────────────────────────────────────────────────────┬───────────────┬─────────────────────┬───────┬─────────┬─────────┬────────────────────────┐
│ #  ┆ Action                                                            ┆ Severity      ┆ Resolves            ┆ Repos ┆ Reach   ┆ Exploit ┆ Bump risk              │
╞════╪═══════════════════════════════════════════════════════════════════╪═══════════════╪═════════════════════╪═══════╪═════════╪═════════╪════════════════════════╡
│ 1  ┆ bump org.apache.logging.log4j:log4j-core 2.14.1 → 2.25.4          ┆ critical 10.0 ┆ 8 advisories        ┆ 1     ┆ unknown ┆ -       ┆ low                    │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2  ┆ bump smallvec 1.6.0 → 1.6.1                                       ┆ critical 9.8  ┆ RUSTSEC-2021-0003   ┆ 1     ┆ unknown ┆ -       ┆ low                    │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 3  ┆ bump nokogiri 1.16.2 → 1.19.4                                     ┆ critical 7.8  ┆ 16 advisories       ┆ 1     ┆ unknown ┆ -       ┆ low                    │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 4  ┆ bump certifi 2022.9.24 → 2026.10.18 (breaking)                    ┆ critical 7.5  ┆ 4 advisories        ┆ 1     ┆ unknown ┆ -       ┆ high · 1 on 2026.10.23 │
│    ┆   or 2022.12.7 on 2022.x (1 repo, 3 left open)                    ┆               ┆                     ┆       ┆         ┆         ┆                        │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 5  ┆ bump minimist 1.2.5 → 1.2.6                                       ┆ critical      ┆ GHSA-xvch-5gv4-984h ┆ 1     ┆ unknown ┆ -       ┆ low                    │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 6  ┆ bump urllib3 1.26.12 → 2.8.0 (breaking)                           ┆ high 8.1      ┆ 10 advisories       ┆ 2     ┆ unknown ┆ -       ┆ high                   │
│    ┆   or 1.26.19 on 1.x (2 repos, 7 left open)                        ┆               ┆                     ┆       ┆         ┆         ┆                        │
```
<!-- /run -->

Each row is one dependency bump with every advisory it clears and every repo it touches.
Read the [report views](/fleetreach/docs/getting-started/reading-the-report/) to see what
else the same scan answers.

## 4. Use it in CI

The exit code is the contract: `0` clean, `1` a finding met `--fail-on`, `2` the scan could
not be completed (so it is never mistaken for clean), `3` a usage error.

```sh
fleetreach scan --fail-on high -f sarif > fleetreach.sarif
```

See [GitHub Actions](/fleetreach/docs/integrations/github-actions/) and
[GitLab CI](/fleetreach/docs/integrations/gitlab-ci/) for ready-made pipelines.
