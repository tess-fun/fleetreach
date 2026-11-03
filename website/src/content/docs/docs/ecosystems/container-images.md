---
title: Container images
description: Scan container images for vulnerable OS packages (Debian, Ubuntu, Alpine, Wolfi, Chainguard, Red Hat, AlmaLinux, Rocky, SUSE, Azure Linux and more) and the language packages inside them, offline and without running the image.
sidebar:
  order: 13
---

| | |
|---|---|
| Reads | a `docker save` or OCI-layout tarball, an OCI-layout directory, or a root filesystem (a directory or a tarball of one) |
| OS packages | dpkg `status` and distroless `status.d`; apk `installed`; the rpm database (SQLite, Berkeley DB or NDB) |
| Advisory data | the osv.dev distro exports: Debian, Ubuntu (and Ubuntu Pro), Alpine, Wolfi, Chainguard, MinimOS, Alpaquita and BellSoft, Echo, CleanStart, Root, Red Hat, AlmaLinux, Rocky Linux, openSUSE, SUSE, Azure Linux, Mageia, openEuler |
| Version rules | dpkg's (`dpkg --compare-versions`), apk-tools' (`apk version -t`) and rpm's (`rpm.vercmp`) |

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

rpm-based images are recognized too: Red Hat Enterprise Linux and UBI (matched against the
release's BaseOS, AppStream and CRB repositories), AlmaLinux, Rocky Linux, openSUSE Leap,
Leap Micro and Tumbleweed, SUSE Linux Enterprise 15 (its Basesystem and Server Applications
modules, the optional modules such as Containers, Python 3 and Public Cloud, and LTSS), SLE
Micro and SUSE Linux Micro, Azure Linux 3 and CBL-Mariner 2, Mageia and
openEuler. CentOS and Fedora have no advisories to match, so their images are a coverage gap:
they are not matched against Red Hat's records, whose versions and backports are not theirs.

Amazon Linux, Oracle Linux and Photon OS publish no advisories to osv.dev, so fleetreach reads
their vendors' own feeds and converts them to OSV records, cached beside the osv.dev exports:

| Distribution | Releases | Feed | Advisory ids |
|---|---|---|---|
| Amazon Linux | 2, 2023 | the core repository's `updateinfo.xml` (what `yum updateinfo` reads) | ALAS |
| Oracle Linux | 7, 8, 9, 10 | Oracle's OVAL definitions | ELSA |
| Photon OS | 3.0, 4.0, 5.0 | VMware's CVE metadata | CVE |

These advisories name binary packages, and findings link the vendor's advisory page. Oracle
publishes separate fixes for each module stream (`nodejs:18`, `php:7.4`); such an advisory
matches only packages built for that stream, read from the package's modularity label or,
for an older build without one, from the stream `/etc/dnf/modules.d` enables. A feed whose
shape fleetreach does not recognize fails the sync rather than load partly. Results equal
`yum updateinfo` on Amazon Linux 2 and `dnf updateinfo` on Amazon Linux 2023 and Oracle
Linux 8. One known difference: Oracle's OVAL leaves out a few reissued ELSAs, so dnf can name
an advisory fleetreach does not, while the same CVEs are reported under the reissue's id.

The rpm database is read without `rpm` and without a database library, in whichever of rpm's
three formats the image uses: SQLite (`rpmdb.sqlite`, with its write-ahead log applied; RHEL 9
and later, Fedora, Azure Linux), Berkeley DB (`Packages`; RHEL 7 and 8, Amazon Linux 2) or NDB
(`Packages.db`; SUSE). Both `/usr/lib/sysimage/rpm` and `/var/lib/rpm` are read: an empty
database in one (Oracle Linux 9 ships a stray one) gives way to the one with packages, and two
that disagree are a coverage gap.

Advisories name **source** packages, so each installed binary package is matched under its
source: `libssl3` as `openssl`. The finding's dependency path shows both, with the real
installed version: `Debian 12 > openssl 3.0.17-1~deb12u2 > libssl3`. Red Hat and AlmaLinux
are the exception: their advisories name binary packages (`openssl-libs`), so there each
binary is matched on its own (`redhat/openssl-libs`). Vendor VEX statuses (Red Hat, SUSE)
name binaries too; they are looked up by the binary's name under its source package.

## Unfixed and unimportant advisories

Debian and Ubuntu track many CVEs with no fix yet. They are reported, never dropped, with
`no fix yet` and the tracker's urgency in the title (`[Debian 12: no fix yet; urgency low]`).
An advisory fixed only in another release line says so. Pass `--distro-ignore-unimportant`
to drop the ones Debian marks `unimportant` and Ubuntu rates `negligible`.

Red Hat's open CVEs are not in osv.dev, which carries only its fixes (RHSAs). They come from
Red Hat's CSAF VEX instead, indexed with `db sync --source csaf:redhat` (a 415 MB download
that takes several minutes, so a scan never starts it) or `db import --csaf` from a local
copy of the archive. The first scan of a RHEL image after that turns the index into a
per-release export, which later scans reuse until the index changes. Where the release's own
advisories do not name a CVE for a package, the VEX entry applies:

- CVEs Red Hat lists as affected, will not fix, fix deferred, out of support scope or under
  investigation are findings marked `no fix yet` with that status
  (`[Red Hat enterprise_linux 9 baseos: no fix yet; status will not fix]`);
- fixes on the release's main stream that osv.dev has not imported yet are reported with
  their fixed version (extended update support streams are not the release's).

Red Hat lists open CVEs under the source package (`python-requests`), so a binary package
(`python3-requests`) also takes its source package's open statuses, unless Red Hat says
something about the binary itself: a binary listed as not affected stays clean, and a fix
for the source package never stands in for its binaries. Trivy matches by binary name only,
so fleetreach reports somewhat more on RHEL images (19 more on UBI 8.8, 2 more on UBI 9,
with every one of Trivy's findings also reported). Entries for a module stream (`php:7.3`)
match only packages from that stream. Without the index, a RHEL image is a coverage gap that
names the command.

SUSE's open CVEs come the same way, from SUSE's CSAF VEX: `db sync --source csaf:suse` (a
526 MB download that expands to 19 GB of JSON; indexing takes about 15 minutes and 10 GB of
memory) or `db import --csaf csaf-vex.tar.bz2 --provider suse`. It covers openSUSE Leap,
Leap Micro and Tumbleweed, SUSE Linux Enterprise Server 15 (with LTSS), SLE Micro and SUSE
Linux Micro. SUSE's VEX names binary packages (`libdw1`) while osv.dev's SUSE records name
source packages (`elfutils`), so each binary is looked up by its own name, and a binary built
at a version of its own (`libreadline7` 7.0 from `bash` 4.4) is compared with that version.
Two SUSE conventions shape the result:

- SUSE marks a fix `recommended`, but also recommends the current build of a package it
  still lists as affected. A `known_affected` or `known_not_affected` status for the same
  package wins over the recommendation.
- SUSE's update advisories name every CVE the update refers to, including ones it did not
  fix (SUSE-SU-2025:4092-1 names CVE-2025-1372, which SUSE still lists as affected). So a
  SUSE open status applies unless the release's own records find the package affected.

openSUSE Leap 15.x is built from SUSE Linux Enterprise 15 SPx, and its own VEX entries stop
once the release reaches its end of life. A fix SUSE ships for the matching SLE service pack
is reported against Leap as `fixed only in another line`; SLE's open statuses are not
borrowed, as they are not SUSE's word about Leap. Leap Micro borrows from SLE Micro the same
way. Validated against OpenSCAP evaluating SUSE's own OVAL: on the SLES BCI 15.6 image,
fleetreach reports all 238 CVEs the OVAL finds, plus 1 open status from the newer VEX.
Without the index, a SUSE image is a coverage gap that names the command.

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

The comparators were checked against the real tools in Docker, over pairs drawn from the
osv.dev distro exports: 619,997 pairs against dpkg 1.21.23, 619,999 against apk-tools 2.14
(Alpine and Wolfi agree) and 538,780 against rpm 4.20 (`rpm.vercmp`, the exports of eight rpm
distributions plus the installed versions of 18 images), with no disagreement. The 15 versions in the exports that apk itself
rejects are rejected here too. The installed packages read from debian:12-slim, ubuntu:24.04,
python:3.12-slim, alpine:3.20, node:20-alpine, Chainguard's wolfi-base and the two distroless
Debian images equal what `dpkg-query -W` and `apk info -v` list, and the rpm databases of 18
images (all three formats, from CentOS 7 to Fedora 41) equal `rpm -qa`, field by field. The
findings on 11 real dpkg and apk images, older releases included, equal an independent
evaluation of the same exports that uses the real tools for every version comparison; so do
the 1,130 findings on 12 rpm images (AlmaLinux 8 and 9, Rocky 8 and 9, UBI 8 and 9, Azure
Linux 3, CBL-Mariner 2, openSUSE Leap 15.5 and 15.6), with rpm deciding every comparison. See
[Accuracy and validation](/fleetreach/docs/concepts/accuracy/).
