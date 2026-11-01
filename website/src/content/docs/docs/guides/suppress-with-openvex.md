---
title: Suppress with OpenVEX
description: Write OpenVEX statements for findings proven not to affect you, keep human-reviewed exceptions in one document, and share them with Trivy and Grype.
sidebar:
  order: 13
---

`-f vex` writes an [OpenVEX](https://openvex.dev) 0.2.0 document. By default it states
`not_affected` only for the sound signals: a function proven unreachable by static analysis,
or a dependency that is never compiled. Reviewed exceptions from `[[settings.ignore]]` are
included as human assertions unless you pass `--vex-only-sound`.

```sh
fleetreach scan -f vex --vex-author "security@acme.example" > fleet.vex.json
```

Trivy and Grype both read OpenVEX, so the same statements quiet the same findings in their
reports:

```sh
trivy image --vex fleet.vex.json ghcr.io/acme/payments-api:latest
grype ghcr.io/acme/payments-api:latest --vex fleet.vex.json
```

## Ignoring a finding by hand

```toml title="fleet.toml"
[[settings.ignore]]
id     = "RUSTSEC-2020-0071"
reason = "dev-dependency only, not in any shipped path"   # required
```

An ignore without a reason is rejected, and one that no longer matches anything is reported
as stale, so the list cannot rot quietly.

## Keep VEX honest over time

`fleetreach vex` checks a published VEX document against a new scan (drift) and verifies
the witness chains behind `not_affected` statements. Pin `--vex-timestamp`, `--vex-id` and
`--vex-version` to make documents reproducible.
