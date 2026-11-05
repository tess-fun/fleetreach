---
title: What is fleetreach?
description: fleetreach audits the dependencies of many repositories in one pass, across 12 ecosystems, and ranks the fixes that clear the most repos first.
sidebar:
  label: Overview
---

fleetreach is a command-line tool that audits the dependencies of many repositories at
once and tells you which single fix clears the most of them. It reads lockfiles in 12
ecosystems and [container images](/fleetreach/docs/ecosystems/container-images/), matches them against public advisory data (RustSec, [OSV](https://osv.dev) and distro feeds),
and gives one deduplicated, ranked report for the whole fleet. It is one binary: no server,
no database to run, no SBOM pipeline to wire up.

## The fleet question

Single-project scanners answer "is this repo vulnerable?". A team that owns fifty repos has
a different question: **which one fix clears the most repos, and in what order do we work?**

fleetreach answers it by correlating advisories across repos. In the demo fleet these docs
use (nine repos of a made-up company, Acme), the package rollup puts the shared dependencies
first, because one bump clears them everywhere:

<!-- run: fleetreach scan -f packages | head -n 12 -->
```console
$ fleetreach scan -f packages | head -n 12
┌───────┬────────┬────────────┬────────────┬──────────┬──────────┬─────────┬─────────────────────────────────────────────────────┐
│ Repos ┆ Direct ┆ Transitive ┆ Advisories ┆ Severity ┆ Fix      ┆ Exploit ┆ Package                                             │
╞═══════╪════════╪════════════╪════════════╪══════════╪══════════╪═════════╪═════════════════════════════════════════════════════╡
│ 2     ┆ 2      ┆ 0          ┆ 25         ┆ high     ┆ manifest ┆ -       ┆ axios (npm)                                         │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ 10         ┆ high     ┆ manifest ┆ -       ┆ urllib3 (pypi)                                      │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ 6          ┆ high     ┆ manifest ┆ -       ┆ lodash (npm)                                        │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ 1          ┆ high     ┆ manifest ┆ -       ┆ regex                                               │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ 4          ┆ medium   ┆ manifest ┆ -       ┆ requests (pypi)                                     │
```
<!-- /run -->

## What you can do with it

| Task | Command | Guide |
|------|---------|-------|
| See which fix clears the most repos | `scan -f impact`, `-f packages` | [Find the fix that clears the most repos](/fleetreach/docs/guides/find-the-fix-that-clears-the-most-repos/) |
| Get a batched fix queue | `scan -f remediation` | [Plan and apply fixes](/fleetreach/docs/guides/plan-and-apply-fixes/) |
| Open verified fix pull requests | `fix plan`, `fix apply --open-pr` | [Plan and apply fixes](/fleetreach/docs/guides/plan-and-apply-fixes/) |
| Prioritise by exploitation and exposure | `--enrich`, `-f ssvc` | [Prioritise with KEV, EPSS and SSVC](/fleetreach/docs/guides/prioritise-with-kev-epss-and-ssvc/) |
| Ask "are we exposed to X anywhere?" | `scan --why <package>` | [Trace why a package is there](/fleetreach/docs/guides/trace-why-a-package-is-there/) |
| Write an SBOM per repo | `sbom` | [Generate SBOMs](/fleetreach/docs/guides/generate-sboms/) |
| Enforce a license policy | `licenses` | [Enforce a license policy](/fleetreach/docs/guides/enforce-a-license-policy/) |
| Track trends, SLAs and time to fix | `scan --history-dir`, `history` | [Track history and SLAs](/fleetreach/docs/guides/track-history-and-slas/) |
| Tell owners what changed | `notify` | [Send notifications](/fleetreach/docs/guides/send-notifications/) |
| Scan a whole GitHub or GitLab org | `[[source]]`, `fleet sync` | [Scan a GitHub or GitLab org](/fleetreach/docs/guides/scan-a-github-or-gitlab-org/) |
| Gate CI | `--fail-on`, `diff`, SARIF | [GitHub Actions](/fleetreach/docs/integrations/github-actions/) |

## What it is not

- **Not an advisory database.** It reads RustSec and OSV (which aggregates GitHub
  advisories, PyPA, RubyGems, Go and others), plus CISA KEV and FIRST EPSS when you ask.
- **Not a host or cluster scanner.** It reads [container images](/fleetreach/docs/ecosystems/container-images/),
  not running machines. Pair it with [Trivy](/fleetreach/docs/integrations/trivy-and-grype/)
  for VMs and Kubernetes.
- **Not a server.** If you want a hosted portfolio, it writes the SBOMs
  [Dependency-Track](/fleetreach/docs/integrations/dependency-track/) ingests.

## It fails closed

A falsely clean report is the worst thing a security tool can print, so fleetreach never
exits `0` unless it completed a scan it can stand behind. A repo it cannot read is an
errored gap, a source it read only in part is labelled with its
[coverage](/fleetreach/docs/concepts/coverage-and-fail-closed/), and an advisory with no
severity still fails the gate.

## Next

- [Install fleetreach](/fleetreach/docs/getting-started/installation/)
- [Run your first scan](/fleetreach/docs/getting-started/first-scan/)
