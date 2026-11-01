---
title: Use a Maven mirror
description: Resolve pom.xml dependency graphs through your Artifactory or Nexus mirror of Maven Central, with credentials from settings.xml and environment variables.
sidebar:
  order: 15
---

fleetreach resolves `pom.xml` the way Maven does (parents, properties, imported BOMs,
nearest-wins mediation, exclusions), without running Maven. POMs come from your local
repository (`~/.m2/repository`) and fleetreach's cache. `--maven-fetch` downloads the
missing ones, and goes through your mirror when `~/.m2/settings.xml` names one:

```xml title="~/.m2/settings.xml"
<settings>
  <mirrors>
    <mirror>
      <id>corp</id>
      <mirrorOf>central</mirrorOf>
      <url>https://artifactory.example.com/maven-remote</url>
    </mirror>
  </mirrors>
  <servers>
    <server>
      <id>corp</id>
      <username>${env.ARTIFACTORY_USER}</username>
      <password>${env.ARTIFACTORY_TOKEN}</password>
    </server>
  </servers>
</settings>
```

```sh
fleetreach scan --maven-fetch -v      # -v names the mirror in use
fleetreach scan --maven-fetch --maven-settings ci-settings.xml
```

The mirror is chosen as Maven chooses it: one naming `central` first, then `*` or
`external:*`, with `!central` excluding it. Credentials are sent to the mirror only, never
across a redirect.

A mirror that is configured but cannot be used stops the scan with exit 2 instead of
falling back to Maven Central: plain HTTP, a password encrypted with `settings-security.xml`
(use `${env.NAME}` instead), or an unset variable. `sbom` and `licenses` take the same flags.

Anything that cannot be resolved (a missing POM, an undefined property) makes the source
`partial` coverage, with the items named; what did resolve is still matched.
