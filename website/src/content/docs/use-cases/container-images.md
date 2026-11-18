---
title: Secure container images
description: Scan container images on 20+ Linux distributions alongside the code that builds them. OS packages, Go and Rust binaries, jars and gems inside, base-image and layer attribution, vendor VEX and end-of-life warnings, in the same fix queue as your repos.
sidebar:
  order: 3
---

**The problem.** The app's lockfile is clean, but the image it ships in carries an OS from
two years ago, a Go binary someone copied in, and a jar nobody declared. The image scanner
and the code scanner report separately, in different formats, to different people.

**With fleetreach**, an image is one more entry in the fleet, with an owner and an exposure
like a repo:

```toml title="fleet.toml"
[[image]]
id = "storefront-web"
reference = "docker://ghcr.io/acme/storefront-web:main"   # or path = "image.tar"
owner = "team-storefront"
exposure = "open"
```

```sh
fleetreach scan --image app.tar                          # one image, no config
fleetreach scan -c fleet.toml -f remediation --enrich    # images and repos, one queue
```

## One queue for the app and its OS

The demo's `storefront-web` is the checkout-web service on Alpine 3.18. Its npm packages,
the GitHub Action that builds it and its Alpine packages are ranked together, and each OS
fix names the exact package revision Alpine ships:

<!-- run: fleetreach scan -c ecosystems/images.toml -f remediation --enrich | head -n 13 -->
```console
$ fleetreach scan -c ecosystems/images.toml -f remediation --enrich | head -n 13
┌────┬──────────────┬──────────────────────────────────────────────────────────┬──────────────┬───────────────────────┬───────┬─────────┬──────────────┬───────────┐
│ #  ┆ SSVC         ┆ Action                                                   ┆ Severity     ┆ Resolves              ┆ Repos ┆ Reach   ┆ Exploit      ┆ Bump risk │
╞════╪══════════════╪══════════════════════════════════════════════════════════╪══════════════╪═══════════════════════╪═══════╪═════════╪══════════════╪═══════════╡
│ 1  ┆ out-of-cycle ┆ bump tj-actions/changed-files 44.0.0 → 46.0.1 (breaking) ┆ high 8.6     ┆ GHSA-mrrh-fwg8-r2c3   ┆ 1     ┆ unknown ┆ KEV EPSS 72% ┆ high      │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┤
│ 2  ┆ scheduled    ┆ bump minimist 1.2.5 → 1.2.6                              ┆ critical     ┆ GHSA-xvch-5gv4-984h   ┆ 2     ┆ unknown ┆ EPSS 5%      ┆ low       │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┤
│ 3  ┆ scheduled    ┆ bump alpine/curl 8.3.0-r.0 → 8.12.0-r.0                  ┆ critical 9.8 ┆ 17 advisories         ┆ 1     ┆ unknown ┆ -            ┆ low       │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┤
│ 4  ┆ scheduled    ┆ bump alpine/expat 2.5.0-r.1 → 2.7.0-r.0                  ┆ critical 9.8 ┆ 8 advisories          ┆ 1     ┆ unknown ┆ -            ┆ low       │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┤
│ 5  ┆ scheduled    ┆ bump alpine/openssl 3.1.3-r.0 → 3.1.8-r.0                ┆ critical 9.1 ┆ 12 advisories         ┆ 1     ┆ unknown ┆ -            ┆ low       │
├╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┤
```
<!-- /run -->

## Releases past their end of life

An image on a release its distribution no longer supports gets a warning, from a bundled
endoflife.date snapshot, so it works offline:

<!-- run: fleetreach scan -c ecosystems/images.toml | tail -n 5 -->
```console
$ fleetreach scan -c ecosystems/images.toml | tail -n 5
┌──────────────┬───────────────────────┬─────────────────────────────────────────────┐
│ Kind         ┆ Advisory              ┆ Locations                                   │
╞══════════════╪═══════════════════════╪═════════════════════════════════════════════╡
│ unmaintained ┆ EOL-alpine-linux-3.18 ┆ storefront-web/alpine-linux@3.18.0 (direct) │
└──────────────┴───────────────────────┴─────────────────────────────────────────────┘
```
<!-- /run -->

## What it reads

- **OS packages** on Debian, Ubuntu, Alpine, Wolfi, Chainguard, Red Hat and UBI,
  AlmaLinux, Rocky, CentOS, Fedora, SUSE, Azure Linux, Amazon Linux, Oracle Linux, Photon,
  Bottlerocket, Root and more, each compared by its own package manager's rules (checked
  against dpkg, apk-tools and rpm on 1.7 million pairs).
- **Vendor VEX**: Red Hat and SUSE CSAF statuses, so a CVE the vendor marks not affected is
  not reported.
- **Language packages inside**: Go and Rust binaries, jars, gems and the app's own lockfiles.
- **Layers and base images**: each finding names the layer that added it, and a rollup
  shows which base image the most findings come from.
- **Any source**: `docker save` tarballs, OCI layouts, unpacked root filesystems, or
  `docker://` references pulled from a registry into a digest-checked cache.

On 217 public images, every difference from Trivy and Grype is explained in the
[image differential](/fleetreach/docs/concepts/image-differential/).

See [Container images](/fleetreach/docs/ecosystems/container-images/).
