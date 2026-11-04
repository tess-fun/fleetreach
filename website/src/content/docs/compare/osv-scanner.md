---
title: fleetreach vs osv-scanner
description: "An honest comparison of fleetreach and Google's osv-scanner (v2.7): both read lockfiles against OSV, but osv-scanner checks one project tree and container images, while fleetreach correlates a whole fleet of repositories."
sidebar:
  order: 1
---

*Checked against osv-scanner v2.7.0 and its documentation in November 2026. Corrections
welcome: [open an issue](https://github.com/tess-fun/fleetreach/issues).*

Both tools read lockfiles and match them against [OSV](https://osv.dev) data, without
running package managers. They differ in what they are for.

| | fleetreach | osv-scanner |
|---|---|---|
| Unit of work | a fleet: many repos, local or discovered from a GitHub, GitLab, Bitbucket, Azure DevOps or Gitea org | one directory tree (`-r` recurses) or one image |
| Main answer | which fix clears the most repos, who owns it, what changed | which vulnerable packages this tree has |
| Container images | no | yes (`scan image`) |
| Reachability | npm and Python import graphs; sound Rust call graph; Go via govulncheck | Go call analysis by default; Rust experimental |
| KEV, EPSS, SSVC | yes, all three | not in its docs |
| VEX | writes OpenVEX | planned |
| SBOM | writes CycloneDX 1.7 and SPDX 2.3; reads both | reads SPDX and CycloneDX; writes SPDX 2.3, CycloneDX 1.4/1.5 |
| Fixes | lock-only bumps on branches, re-scanned, opened as PRs or MRs | `fix` edits npm and Maven files locally (experimental) |
| History, SLAs, notifications | yes | no |
| Unreadable sources | fail closed: errored repo or coverage label, exit 2 | reported per file |
| License | MIT or Apache-2.0 | Apache-2.0 |

**Choose osv-scanner** to scan a single project or a container image in CI, or if you want
Google-maintained tooling with image support.

**Choose fleetreach** when the question is about many repositories at once: ranking fixes
across them, owners, SLAs and verified fix pull requests.

**Use both**: osv-scanner on images, fleetreach across the source repos. They read the same
advisory data.

Sources: [osv-scanner on GitHub](https://github.com/google/osv-scanner),
[scan source](https://google.github.io/osv-scanner/usage/scan-source),
[output formats](https://google.github.io/osv-scanner/output),
[guided remediation](https://google.github.io/osv-scanner/experimental/guided-remediation/).
