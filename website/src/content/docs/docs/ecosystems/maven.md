---
title: Maven and Gradle (Java)
description: "Scan Java projects across a fleet: gradle.lockfile, or pom.xml resolved like Maven does (parents, BOMs, mediation, exclusions) without running Maven, through your Artifactory or Nexus mirror."
sidebar:
  order: 8
---

| | |
|---|---|
| Reads | `gradle.lockfile`, else `pom.xml` (resolved) |
| Advisory data | osv.dev `Maven` export |
| Version rules | Maven `ComparableVersion` |

Advisories come from the osv.dev `Maven` export, kept fresh in `~/.cache/fleetreach/osv/` (or read from `--osv-dir`, or `--maven-vuln-db=file://<path>`). Fetch it ahead of time with `fleetreach db sync`.

It runs no package manager and no install or build script, so it is safe to point at any repository and needs no `--allow-untrusted-builds`. Without advisory data for the ecosystem, the repo is an errored gap, never clean.

## pom.xml resolved without Maven

fleetreach resolves the dependency graph the way Maven would: the parent chain, properties,
`dependencyManagement` with imported BOMs, profiles active by default, nearest-wins
mediation with scope widening, exclusions, optional dependencies, version ranges and
multi-module reactors. POMs come from `~/.m2/repository` and fleetreach's cache;
`--maven-fetch` downloads missing ones through your mirror. See
[Use a Maven mirror](/fleetreach/docs/guides/use-a-maven-mirror/).

Anything that cannot be resolved makes the source partial coverage, with the items named.
On a Spring Boot 2.7 project every one of 85 artifacts matched `mvn dependency:list`.

The comparator agrees with Apache Maven's `ComparableVersion` on over 710,000 version pairs.
