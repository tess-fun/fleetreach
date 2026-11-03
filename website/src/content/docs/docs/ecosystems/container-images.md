---
title: Container images
description: Scan container images for vulnerable OS packages (Debian, Ubuntu, Alpine, Wolfi, Chainguard and more) and the language packages inside them, offline and without running the image.
sidebar:
  order: 13
---

| | |
|---|---|
| Reads | a `docker save` or OCI-layout tarball, an OCI-layout directory, or a root filesystem (a directory or a tarball of one) |
| OS packages | dpkg `status` and distroless `status.d`; apk `installed` |
| Advisory data | the osv.dev distro exports: Debian, Ubuntu (and Ubuntu Pro), Alpine, Wolfi, Chainguard, MinimOS, Alpaquita and BellSoft, Echo, CleanStart, Root |
| Version rules | dpkg's (`dpkg --compare-versions`) and apk-tools' (`apk version -t`) |

Name images in `fleet.toml`, next to repos:

```toml
[[image]]
id = "api"
path = "images/api.tar"     # docker save api:latest -o images/api.tar
platform = "linux/arm64"    # optional: which image of a multi-platform OCI index
distro = "Debian:12"        # optional: override /etc/os-release
owner = "team-api"          # optional: the same context fields as [[repo]]
```

Or pass them on the command line. With only `--image`, no `fleet.toml` is needed:

```console
$ docker save api:latest -o api.tar
$ fleetreach scan --image api.tar
```

An image's findings carry its `id` as their repo, so they rank, dedupe, gate and show in every
output format with the rest of the fleet. Package names are `<distro>/<source package>`
(`debian/openssl`), the package-URL namespace and name.

## How it reads an image

Nothing in the image is run, and nothing is pulled: fleetreach reads the archive you give it.
Layers are merged in order with OCI whiteouts (`.wh.<name>` and the opaque `.wh..wh..opq`),
symlinks are followed inside the image only, and every layer named by its digest is checked
against that digest. Only the files that matter are kept in memory: the package databases,
`/etc/os-release`, and language lockfiles and package metadata.

The distribution comes from `/etc/os-release`. Debian, Ubuntu (an LTS release also takes the
Ubuntu Pro export when its packages carry `+esm` versions), Alpine (`3.20.10` matches as
`v3.20`), Wolfi, Chainguard, MinimOS, Alpaquita, Echo and CleanStart are recognized, and Root's
patched packages (`root.io` versions) take Root's own advisories first. Distroless images are
Debian, read from `/var/lib/dpkg/status.d`.

Advisories name **source** packages, so each installed binary package is matched under its
source: `libssl3` as `openssl`. The finding's dependency path shows both, with the real
installed version: `Debian 12 > openssl 3.0.17-1~deb12u2 > libssl3`.

## Unfixed and unimportant advisories

Debian and Ubuntu track many CVEs with no fix yet. They are reported, never dropped, with
`no fix yet` and the tracker's urgency in the title (`[Debian 12: no fix yet; urgency low]`).
An advisory fixed only in another release line says so. Pass `--distro-ignore-unimportant`
to drop the ones Debian marks `unimportant` and Ubuntu rates `negligible`.

## Language packages in the image

Lockfiles in the image (`package-lock.json`, `poetry.lock`, `Gemfile.lock`, `go.mod`, ...) are
scanned by the same matchers as repositories. Installed Python packages (`*.dist-info`) and
npm packages (`node_modules/*/package.json`) with no lockfile beside them are matched too.
Files that belong to an OS package are skipped, so Debian's `python3-requests` is reported
once, as the Debian package. Java archives and installed gems are not read yet; when an image
has them, the scan says so as a coverage gap.

## Advisory data

Distro exports are fetched one distribution at a time, never all at once: Chainguard's is
over a gigabyte. Where osv.dev publishes a per-release export (`Debian:12`, `Alpine:v3.20`,
`Ubuntu:24.04:LTS`), only that is fetched; otherwise the whole distribution's.

```console
$ fleetreach db sync                          # what fleet.toml's repos and images need
$ fleetreach db sync --distros Debian:12,Wolfi
```

In network builds a scan keeps the exports it needs fresh in `~/.cache/fleetreach/osv/`.
Offline, lay them out in `--osv-dir` as `<dir>/Debian_12/all.zip` (or `<dir>/Debian:12/`).

## Fail-closed

- An image that cannot be read, or whose distro export is missing, is an errored target
  (exit 2), never clean.
- An unknown distribution or release, an unreadable package database, or a release the
  export has no records for is a coverage gap: reported in every format, and exit 2 under
  `--require-full-coverage`.
- An image with no OS at all (a `scratch` image with one static binary) has no OS packages to
  match, which is not a gap.

## Validation

Both comparators were checked against the real tools in Docker, over pairs drawn from the
osv.dev distro exports: 619,997 pairs against dpkg 1.21.23 and 619,999 against apk-tools 2.14
(Alpine and Wolfi agree), with no disagreement. The 15 versions in the exports that apk itself
rejects are rejected here too. The installed packages read from debian:12-slim, ubuntu:24.04,
python:3.12-slim, alpine:3.20, node:20-alpine, Chainguard's wolfi-base and the two distroless
Debian images equal what `dpkg-query -W` and `apk info -v` list. The findings on 11 real
images, older releases included, equal an independent evaluation of the same exports that
uses the real tools for every version comparison. See
[Accuracy and validation](/fleetreach/docs/concepts/accuracy/).
