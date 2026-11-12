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

## CSAF and CycloneDX VEX

The same statements come in two more formats, for tools and portals that read those instead:

- `-f csaf-vex` writes a [CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html)
  document of the VEX profile. Each repo is a product, each package a component with its
  purl, and each component in a repo a `default_component_of` relationship. A package every
  repo gives the same status is also named on its own, so a scan of a single directory, which
  has no product to match, still finds it. Advisories that share a CVE share one entry.
- `sbom --report report.json --separate-vex` writes `<repo>.vex.cdx.json` beside each
  CycloneDX SBOM: the findings of a saved scan, pointing at the SBOM's components by
  BOM-Link (`urn:cdx:<serial>/1#<component>`), for tools that apply VEX to an SBOM.

<!-- run: fleetreach scan -f csaf-vex --vex-author security@acme.example | jq '.vulnerabilities[] | select(.cve == "CVE-2020-26235") | {product_status, flags}' -->
```console
$ fleetreach scan -f csaf-vex --vex-author security@acme.example | jq '.vulnerabilities[] | select(.cve == "CVE-2020-26235") | {product_status, flags}'
{
  "product_status": {
    "known_not_affected": [
      "FR-COMPONENT-5:FR-PRODUCT-6",
      "FR-COMPONENT-6",
      "FR-COMPONENT-6:FR-PRODUCT-6"
    ],
    "under_investigation": [
      "FR-COMPONENT-5:FR-PRODUCT-9"
    ]
  },
  "flags": [
    {
      "label": "vulnerable_code_not_in_execute_path",
      "product_ids": [
        "FR-COMPONENT-5:FR-PRODUCT-6",
        "FR-COMPONENT-6",
        "FR-COMPONENT-6:FR-PRODUCT-6"
      ]
    }
  ]
}
```
<!-- /run -->

CSAF needs a publisher namespace, a URL that names who wrote the document. It comes from
`--csaf-namespace`, else `[settings.vex] namespace`, else the domain of an email address given
as `--vex-author`. `--csaf-publisher` sets the publisher category (`vendor` by default; `user`
for a fleet assessing software it runs but did not write). CSAF names a published file after its
`document.tracking.id`, so save it as `<id>.json` (`--vex-id` sets the id; by default it is
`fleetreach-vex-` and a content hash).

A saved report keeps the findings a person set aside under `set_aside`, with the reason and the
approver, so `--separate-vex` writes them as `not_affected` with that reason as the detail. An
accepted risk stays `exploitable`, with the response `will_not_fix`.

```sh
fleetreach scan -f json > report.json
fleetreach sbom --report report.json --separate-vex -o sbom/
trivy sbom --vex sbom/ledger-svc.vex.cdx.json sbom/ledger-svc.cdx.json
```

### Which tools apply which format

Checked with Trivy 0.73.0 and Grype v0.121.1 on Alpine 3.16, Debian 12 and Rocky Linux 9
images and on the demo's Rust service (`docs/differential/vex_consumers.py`):

| Format | Trivy | Grype |
|---|---|---|
| OpenVEX (`-f vex`) | applied | applied |
| CSAF (`-f csaf-vex`) | applied | not applied |
| CycloneDX (`--separate-vex`) | applied, with `trivy sbom` | does not read CycloneDX VEX |

Grype matches a CSAF product only by its exact package URL, with the architecture and release
qualifiers its own scan writes, so use OpenVEX with Grype. Trivy 0.73 stops on a CSAF entry
that has no CVE id; `--csaf-cve-only` leaves those advisories out and says how many.

### Images

An image is a product too (`urn:fleetreach:product:<id>`, or under `[settings.vex] product_id_base`), and an
OS finding names each binary package its source package built, at the version installed. Trivy
and Grype spell some distributions differently (Rocky Linux is `rocky` to both; Oracle Linux
is `oracle` to Trivy and `ol` to Grype), and a consumer matches only when type, namespace and
name agree, so each package is named in every spelling. An epoch is the `epoch` qualifier, and
a Debian package is also named with the epoch in its version, as Grype writes it.

## Reading VEX documents

`scan --vex FILE` sets findings aside on a VEX document someone else wrote: a supplier's
statements on their package, a platform team's document for the services it runs, or a
document fleetreach wrote earlier. It reads OpenVEX, CycloneDX VEX and CSAF VEX, and may be
given more than once. List the ones every run should read in `fleet.toml`:

```toml title="fleet.toml"
[settings.vex]
files = ["vex/vendor.openvex.json", "vex/platform.csaf.json"]
```

How far a statement reaches depends on what it names:

- A statement whose product is one of your repos (its VEX product id,
  `urn:fleetreach:product:<id>`, or the `repo:<id>` an SBOM names it by) applies to that repo
  only, and the packages it names are that repo's. This is how fleetreach's own documents
  read back: each sets aside exactly what the assertion behind it did.
- A statement whose product is a package (`pkg:npm/foo@1.2.3`) and no repo applies to that
  package, at that version, in every repo.
- A statement about another product, such as a vendor's platform, holds no package of yours
  and sets nothing aside.

`not_affected` and `fixed` set findings aside (in CycloneDX, `not_affected`, `false_positive`
and `resolved`; in CSAF, `known_not_affected`, `fixed` and `first_fixed`). For one
vulnerability and package the latest statement wins, so a later `affected` undoes an earlier
`not_affected`, and on a tie the finding stays. A `not_affected` statement with neither a
justification nor an impact statement makes the whole document unusable, and a document that
cannot be used is named in a warning and changes nothing.

A finding set aside this way is under `set_aside` in the JSON report, and it becomes a
`not_affected` statement in the VEX fleetreach writes, with the file as its approver.

### Signed documents

With a key, a document applies only when that key signed it. Sign with `cosign sign-blob`; a
signature or bundle beside the file is found by its name:

```sh
cosign sign-blob --key cosign.key --output-signature fleet.vex.json.sig fleet.vex.json   # cosign 2
cosign sign-blob --key cosign.key --bundle fleet.vex.json.sigstore.json fleet.vex.json   # cosign 3
fleetreach scan --vex fleet.vex.json --vex-key cosign.pub
```

fleetreach checks the ECDSA P-256 signature itself, offline; it does not look the signature
up in a transparency log. A file with no signature, or one no named key made, is refused
with a warning. `[settings.vex] keys` names keys for every run. Keyless signatures are not
checked. For VEX attached to images, see
[VEX attached to images](/fleetreach/docs/ecosystems/container-images/#vex-attached-to-images).

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
