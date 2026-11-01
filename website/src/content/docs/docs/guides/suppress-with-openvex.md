---
title: Suppress with OpenVEX
description: Write OpenVEX statements for findings proven not to affect you, keep human-reviewed exceptions in one document, and share them with Trivy and Grype.
sidebar:
  order: 13
---

`-f vex` writes an [OpenVEX](https://openvex.dev) 0.2.0 document with one statement per
finding:

- `not_affected` for the sound signals: a function proven unreachable by static analysis, or
  a dependency that is never compiled;
- `not_affected` for reviewed exceptions, `[[settings.vex_assertion]]` and
  `[[settings.ignore]]`, marked as human assertions (`--vex-only-sound` leaves them out);
- `under_investigation` for everything else, saying why it is undecided;
- `fixed` as well, with `--vex-include-fixed`.

```sh
fleetreach scan -f vex --vex-author "security@acme.example" > fleet.vex.json
```

The demo fleet has one reviewed exception in its `fleet.toml`:

```toml
[[settings.vex_assertion]]
id            = "RUSTSEC-2020-0071"
repo          = "ledger-svc"
justification = "vulnerable_code_not_in_execute_path"
reason        = "ledger-svc never formats local time; it only uses UTC timestamps"
approved_by   = "security@acme.example"
```

It gives the only `not_affected` statements in the document, one per copy of `time` in
ledger-svc; every other finding is still open:

<!-- run: fleetreach scan -f vex --vex-author security@acme.example | jq '[.statements[].status] | group_by(.) | map({(.[0]): length}) | add' -->
```console
$ fleetreach scan -f vex --vex-author security@acme.example | jq '[.statements[].status] | group_by(.) | map({(.[0]): length}) | add'
{
  "not_affected": 2,
  "under_investigation": 257
}
```
<!-- /run -->

<!-- run: fleetreach scan -f vex --vex-author security@acme.example | jq '[.statements[] | select(.status == "not_affected")][0]' -->
```console
$ fleetreach scan -f vex --vex-author security@acme.example | jq '[.statements[] | select(.status == "not_affected")][0]'
{
  "vulnerability": {
    "name": "RUSTSEC-2020-0071",
    "aliases": [
      "CVE-2020-26235",
      "GHSA-wcg3-cvx6-7396"
    ]
  },
  "products": [
    {
      "@id": "urn:fleetreach:product:ledger-svc"
    },
    {
      "@id": "pkg:cargo/time@0.1.45"
    }
  ],
  "subcomponents": [
    {
      "@id": "pkg:cargo/time@0.1.45"
    }
  ],
  "status": "not_affected",
  "justification": "vulnerable_code_not_in_execute_path",
  "status_notes": "role=Human Assertion; approved_by=security@acme.example"
}
```
<!-- /run -->

The assertion is scoped to ledger-svc, so the same advisory in payments-api stays open, and
it is removed from ledger-svc's findings in every other report.

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
