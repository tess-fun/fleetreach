---
title: Trace why a package is there
description: Find every repo that uses a package, in any ecosystem, and the dependency chain that pulls it in, with fleetreach scan --why. Answers "are we exposed to X anywhere?".
sidebar:
  order: 2
---

`fleetreach scan --why <package>` lists every repo whose dependency tree contains the
package, in every ecosystem, with its version, whether it is direct or transitive, and the
chain that pulls it in. It is the fastest answer to "are we exposed to X anywhere?" when a
new advisory lands.

## Find a package across the fleet

<!-- run: fleetreach scan --why log4j-core -->
```console
$ fleetreach scan --why log4j-core
partner-api — org.apache.logging.log4j:log4j-core 2.14.1 (maven, direct):
  partner-api → org.apache.logging.log4j:log4j-core
```
<!-- /run -->

The name matches the full package name or its last segment, case-insensitively, so
`log4j-core` finds `org.apache.logging.log4j:log4j-core` and `grpc` finds
`google.golang.org/grpc`.

## See the chain for a transitive package

<!-- run: fleetreach scan --why qs -->
```console
$ fleetreach scan --why qs
admin-dashboard — qs 6.7.0 (npm, transitive):
  admin-dashboard → express → qs
```
<!-- /run -->

`qs` is not in `admin-dashboard`'s `package.json`; `express` brings it in, so the fix is an
`express` bump.

For Rust, every route is listed, including several versions of one crate:

<!-- run: fleetreach scan --why time -->
```console
$ fleetreach scan --why time
payments-api — time 0.1.45 (transitive):
  payments-api → chrono → time
ledger-svc — time 0.1.45 (transitive):
  ledger-svc → chrono → time
ledger-svc — time 0.2.7 (direct):
  ledger-svc → time
```
<!-- /run -->

## Exit codes

`0` when the package is in at least one tree, `2` when it is in none, so a script can ask:

```sh
if fleetreach scan --why log4j-core >/dev/null 2>&1; then echo "exposed"; fi
```

`--why` reads lockfiles only. It needs no advisory data and no network.

## Related

- [Incident response](/fleetreach/use-cases/incident-response/): from "a CVE dropped" to a
  list of repos and fixes.
