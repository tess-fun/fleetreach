---
title: FAQ
description: "Common questions about fleetreach: how it differs from per-repo scanners, what it sends over the network, whether it runs code, how it handles monorepos, private registries and air-gapped networks."
---

## How is this different from osv-scanner, Trivy or Dependabot?

Those answer "is this repo vulnerable?", one repo at a time. fleetreach scans every repo in
one run and answers fleet questions: which fix clears the most repos, who owns each finding,
what is new since last night, and which version the fleet already trusts. See
[Compare](/fleetreach/compare/osv-scanner/).

## Does it run code from the repos it scans?

No, by default. It reads lockfiles and manifests and runs no package manager, install script
or build. The two exceptions are opt-in and named: `--reachability=static` and Go's
`govulncheck` compile code, and both need `--allow-untrusted-builds`. `fix apply` runs
lock-only updates with scripts disabled.

## What does it send over the network?

In a network build: advisory downloads (osv.dev, RustSec, KEV, EPSS), and only when asked,
package names and versions to deps.dev (`--release-age`, `licenses --fetch`), CVE ids to NVD,
artifact coordinates to Maven Central or your mirror (`--maven-fetch`), and forge API calls
for `[[source]]`. Never your source code. `--offline` refuses all of it, and the default
`cargo install` build has no network code at all.

## Is there a server or a database?

No. One binary, files in and files out. History is a directory of gzipped JSON you can
commit or cache. The HTML report is one static file.

## Does it work on monorepos?

Yes. `glob = true` scans every lockfile below the root (to `glob_max_depth`), and a polyglot
repo is scanned in every ecosystem it has, workflows included.

## What if a repo uses a format it cannot read?

It says so. The repo is an errored gap, or the source is labelled partial or direct-only,
and the run exits 2 with `--require-full-coverage`. It never reports a repo clean that it did
not read. See [Coverage and failing closed](/fleetreach/docs/concepts/coverage-and-fail-closed/).

## Does it work with private registries and mirrors?

Lockfiles already pin exact versions, so private packages are read like any other (and
matched if an advisory names them). Maven uses your `settings.xml` mirror. With `--signals`,
add your registries to `[settings.signals] registries` so they are not flagged.

## Can I run it in an air-gapped network?

Yes. Sync advisory data on a connected machine and carry it across. See
[Run offline or air-gapped](/fleetreach/docs/guides/run-offline-or-air-gapped/).

## How accurate is it?

Each ecosystem's version comparator is checked against the ecosystem's own implementation
over hundreds of thousands of version pairs, and matching against real lockfiles at 100%
recall. See [Accuracy and validation](/fleetreach/docs/concepts/accuracy/).

## Does it scan container images?

No. Use Trivy or Grype for images; fleetreach's OpenVEX output quiets the same proven
non-issues there. See [Trivy and Grype](/fleetreach/docs/integrations/trivy-and-grype/).

## What does it cost, and what is the license?

Free and open source, dual-licensed MIT or Apache-2.0.

## Why "fleetreach"?

It shows how far each vulnerability *reaches* across your *fleet* of repositories, and, for
Rust, whether vulnerable code is reached at all.
