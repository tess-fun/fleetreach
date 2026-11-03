---
title: Container images
description: Scan container images for vulnerable OS packages (Debian, Ubuntu, Alpine, Wolfi, Chainguard, Red Hat, AlmaLinux, Rocky, SUSE, Azure Linux and more) and the language packages inside them, offline and without running the image.
sidebar:
  order: 13
---

| | |
|---|---|
| Reads | a `docker save` or OCI-layout tarball, an OCI-layout directory, or a root filesystem (a directory or a tarball of one) |
| OS packages | dpkg `status` and distroless `status.d`; apk `installed`; the rpm database (SQLite, Berkeley DB or NDB); Bottlerocket's application inventory |
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
openEuler. AlmaLinux's export also holds bug fix and enhancement advisories (ALBA, ALEA);
those that name no CVE fix no vulnerability and are not reported.

CentOS Linux 6, 7 and 8 rebuilt Red Hat Enterprise Linux and published no advisories, so their
images are matched against Red Hat's records for the release they rebuilt, with Red Hat's open
statuses (`csaf:redhat`), as Grype and Trivy do. Unlike those tools, fleetreach reports a Red
Hat fix as fixed only when CentOS shipped it: a bundled list of the highest build of each
package in each release's final repositories (vault.centos.org, which no longer changes)
decides, and a fix CentOS never built, such as every RHEL 8 fix after CentOS 8 ended in 2021,
is reported as fixed only in another line. CentOS's rebranded builds
(`4.2.5-83.el7.centos.2` for Red Hat's `4.2.5-83.el7_9.2`) are read as the build they
rebuilt. Equal to Grype v0.121.1 on CentOS 7 and 8 images in every vulnerability and package
pair both report, apart from those Red Hat fixes CentOS 8 never shipped (557 pairs Grype
calls fixed). CentOS Stream is built ahead of RHEL, so Red Hat's records are not about its
builds; its images are a coverage gap.

Amazon Linux, Oracle Linux, Photon OS, Fedora and Bottlerocket publish no advisories to osv.dev, so
fleetreach reads their vendors' own feeds and converts them to OSV records, cached beside the
osv.dev exports:

| Distribution | Releases | Feed | Advisory ids |
|---|---|---|---|
| Amazon Linux | 2, 2023 | the core repository's `updateinfo.xml` (what `yum updateinfo` reads) | ALAS |
| Oracle Linux | 7, 8, 9, 10 | Oracle's OVAL definitions | ELSA |
| Photon OS | 3.0, 4.0, 5.0 | VMware's CVE metadata | CVE |
| Fedora | 41 and later | the updates repository's `updateinfo.xml.zst` (what `dnf updateinfo` reads), security updates only, from the archive once a release leaves the mirrors | FEDORA (Bodhi) |
| CBL-Mariner | 2.0, over its osv.dev records | Microsoft's OVAL (`cbl-mariner-2.0-oval.xml`) | CVE |
| Bottlerocket | every variant and version | `advisories.bottlerocket.aws/updateinfo.xml.gz` | BRSA, GHSA |

These advisories name binary packages, and findings link the vendor's advisory page. Oracle
publishes separate fixes for each module stream (`nodejs:18`, `php:7.4`); such an advisory
matches only packages built for that stream, read from the package's modularity label or,
for an older build without one, from the stream `/etc/dnf/modules.d` enables. A feed whose
shape fleetreach does not recognize fails the sync rather than load partly. Results equal
`yum updateinfo` on Amazon Linux 2 and `dnf updateinfo` on Amazon Linux 2023, Oracle
Linux 8 and Fedora 43. Fedora's updates name their CVEs only in the titles of the Red Hat
Bugzilla bugs they close, and those are what fleetreach reports; Fedora 40 and older are a
coverage gap. Microsoft stopped sending CBL-Mariner 2.0 to OSV in April 2026 while its OVAL ran
on to May, so the OVAL (`db sync --distros "Azure Linux:2::oval"`) is read over osv.dev's
records: where it names a CVE for a package, including "Not Applicable", it is the word that
counts. One known difference: Oracle's OVAL leaves out a few reissued ELSAs, so dnf can name
an advisory fleetreach does not, while the same CVEs are reported under the reissue's id.

Bottlerocket is a host OS rather than a container image, and it ships no rpm database: scan its
root filesystem (for example the root partition of a release image, extracted) with `--image
<dir>`, and its packages are read from `/usr/share/bottlerocket/application-inventory.json`.
Versions keep their epoch: Bottlerocket's older advisories give the OS release as the package
version (`0:1.19.0`), and packages that moved to upstream versions took epoch 1, so dropping the
epoch would read every installed package as older than those fixes. Since the packages were
renamed with a `bottlerocket-` prefix, the advisories list both names
(`bottlerocket-kernel-6.12` and `kernel-6.12`) and both are matched. Validated on Bottlerocket
1.66.0 and 1.68.1 (aws-k8s-1.33): equal to the whole feed evaluated with rpm's comparator (330
and 0), and every one of Trivy 0.73.0's 200 findings on 1.66.0 is reported; the other 130 are
kernel advisories of 2026-10-26 that Trivy's data does not have yet.

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

AlmaLinux and Rocky Linux rebuild RHEL from the same sources, so their scans take Red Hat's
open statuses and "not affected" for the matching RHEL release the same way, titled with
`Red Hat status` (`[Rocky Linux 9: no fix yet; Red Hat status affected]`). Red Hat's fix
versions are not borrowed: they are Red Hat's builds, and the rebuild's own advisories carry
its fixes. Without the index, an AlmaLinux or Rocky image is a coverage gap that names the
command.

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

## Module streams

Red Hat Enterprise Linux 8 and 9, AlmaLinux and Rocky Linux ship some software as module
streams (`php:7.4`, `nodejs:18`, `postgresql:12`), each with its own advisories. osv.dev's
records for these distributions do not say which stream an advisory is for, so fleetreach
reads it from the advisory's title (`php:8.0 security update`,
`virt:rhel and virt-devel:rhel security update`) when its fix is a module build, and matches
it only against packages from that stream, known from each package's modularity label. Three
consequences follow dnf's own behavior:

- an advisory for another stream is not reported (php:7.4 is not "fixed in 8.0.30"), and it
  does not hide Red Hat's open status for the installed stream;
- a non-module fix (perl 5.26's `5.26.3-419.el8`) never applies to a module build, since dnf
  hides non-module packages of a name a stream provides;
- a fix built once per module context (two builds of `perl-Data-Dumper-2.174-440`) is
  compared by its version and release, so the installed context's build counts as fixed.

An advisory whose title names no stream is matched as before. Checked against `dnf
updateinfo list --security` inside Rocky Linux 8 and 9 and AlmaLinux 8 images with php,
nodejs, ruby, perl and postgresql streams installed: the cross-stream findings (46 on Rocky
8, 100 on AlmaLinux 8) are gone and every dnf row is reported, apart from dnf listing a newer
stream's advisory that `dnf upgrade` would not install.

## End-of-life releases

A release past the end of its standard support gets fewer and fewer advisories, so matching
it finds less than is there. Each image whose release is past that date gets an
`unmaintained` warning, from a snapshot of [endoflife.date](https://endoflife.date) bundled
with fleetreach (no network needed), and the fleet's warnings group images on the same
release (`EOL-amazon-linux-2`):

```text
Amazon Linux 2 reached the end of its standard support on 2026-06-30 (endoflife.date): the
vendor publishes no more security fixes for it
```

Where the vendor sells extended support (Debian ELTS, Ubuntu Pro, Red Hat ELS, SUSE LTSS), the
warning gives its end date instead. It covers Debian, Ubuntu, Alpine, Red Hat Enterprise
Linux, AlmaLinux, Rocky Linux, Oracle Linux, CentOS Linux and Stream, Fedora, Amazon Linux,
openSUSE Leap, SUSE Linux Enterprise Server, SUSE Linux Micro, Photon OS and Mageia; rolling
releases have no end of life. The scan date is the clock, or `SOURCE_DATE_EPOCH` when set. A
warning does not change the exit code.

## Language packages in the image

Lockfiles in the image (`package-lock.json`, `poetry.lock`, `Gemfile.lock`, `go.mod`, ...) are
scanned by the same matchers as repositories. Installed Python packages (`*.dist-info`) and
npm packages (`node_modules/*/package.json`) with no lockfile beside them are matched too.
Files that belong to an OS package are skipped, so Debian's `python3-requests` is reported
once, as the Debian package. Installed gems (`specifications/*.gemspec`) are matched as
RubyGems.

Java archives (`.jar`, `.war`, `.ear`, `.par`, `.kar`, `.jpi`, `.hpi`) are opened, along with
the archives nested in them, and matched as Maven packages. Nothing in them is run. Each is
identified by the best evidence it holds:

1. `META-INF/maven/**/pom.properties` gives exact coordinates, one for each library a shaded
   jar holds.
2. A file name such as `spring-core-5.3.20.jar` gives the artifact and version. The group comes
   from the advisory data: the coordinate with that artifact name that the archive's OSGi
   bundle name or class packages point to.
3. For a file name with no version, such as Tomcat's `catalina.jar`, the OSGi headers in
   `META-INF/MANIFEST.MF` name the bundle and version.

An archive none of these can place is a coverage gap, never a guess. Fleetreach has no
checksum index of Maven Central, so a jar that was renamed and has no metadata stays a gap
where a tool with such an index could name it.

## Images in a registry

A network build pulls images itself, with no Docker daemon:

```bash
fleetreach scan --image docker://ghcr.io/acme/api@sha256:5bd5ab35814f86783561603ebb35d5d5d99006dcdcd5c3f828ea1afb4c12d159
```

```toml
[[image]]
id = "api"
ref = "ghcr.io/acme/api:1.4"
platform = "linux/arm64"
```

References read as Docker reads them, so `debian:12` is on Docker Hub. A multi-platform image
is scanned for `platform`, or `linux/amd64` when none is given. Prefer a digest: a tag can
move, so its result holds only for the digest the report records under `provenance.images`.

Every manifest and blob is checked against its digest, and anything that does not match is an
errored target. Blobs are kept in `~/.cache/fleetreach/images`, once however many images share
them, and a digest pulled before scans with `--offline` or in a build without network support.
A tag needs the registry, so `--offline` refuses one. Nothing removes old blobs: delete the
directory to reclaim the space.

Logins come from Docker's config (`$DOCKER_CONFIG/config.json` or `~/.docker/config.json`):
`credHelpers`, then `auths`, then `credsStore`, running `docker-credential-<name>` as Docker does.
A login goes to the registry and to a token service on the registry's own domain, over TLS.
Redirects to blob storage never carry it, and plain HTTP is refused except on this machine.

## VEX attached to images

A publisher can attach an OpenVEX document to an image with `cosign attest --type openvex`.
`--vex-oci` reads what is attached to an image pulled from a registry, as OCI 1.1 referrers, the
referrers tag, or cosign's `.att` tag, on the image and on its multi-platform index.

```bash
fleetreach scan --image docker://ghcr.io/org/app@sha256:... --vex-oci-key cosign.pub
```

An attachment is not part of the image's digest, so anyone who can push to the repository can
add one to an image you pinned long ago. So a document sets findings aside only when a key you
named with `--vex-oci-key` signed it. With `--vex-oci` alone, documents are listed and change
nothing. `--vex-oci-unsigned` accepts every document, which is what Trivy's `--vex oci` does:
use it only for a repository whose push access you trust. Keyless signatures are not checked, so
they count as unsigned. A document whose in-toto subject is another image is always refused.

A statement applies to the image (`pkg:oci/app@sha256:...`), to a subcomponent of the image, or
to a package named as the product. Purl versions must be the installed version. For one
vulnerability and package the latest statement decides, so a later `affected` undoes an earlier
`not_affected`, and on a tie the finding stays. Only `not_affected`, with a justification or an
impact statement, and `fixed` set a finding aside. An advisory covering several CVEs needs a
statement for each, and a source package needs one for each binary: if `ssl_client` is still
open, a statement on the `busybox` binary leaves the `busybox` finding standing.

Every document read is in the report's `provenance.images[].vex`, with the key that verified it,
why it was refused, and how many occurrences it set aside. Failing to read attachments is a
warning and the findings stand. `--offline` uses what the last online scan found.

## Layers and base images

Each finding in an image carries a `layer` in the JSON report: its position, its digest, the
build step that made it, and `base: true` when it belongs to the base image. For an OS package
that is the layer where the package first appeared at its installed version; for a language
package, the layer that wrote its lockfile, metadata or archive. A finding on several binaries
of one source package takes the highest of their layers, since replacing the ones below would
leave that one.

The base image ends at its `CMD`: the last `CMD` in the image's history with a layer above it,
the rule Trivy uses. An image with no such `CMD`, including a base image itself, has no base.
`org.opencontainers.image.base.name` gives the base's name when the image declares it.

Images built on the same layers are one entry in the report's `base_images`, with a fingerprint
of those layers, the images, the findings in its layers counted once, and `fixable`, how many
of them have a fix. Those are what rebuilding on a current base can clear; the rest wait for the
distribution. The table view ends with the same summary:

```text
Base images
  Debian 10 (d3d01b10c925): 2 image(s), 123 finding(s) in its layers; rebuilding on a current base clears the 123 with a fix
```

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
