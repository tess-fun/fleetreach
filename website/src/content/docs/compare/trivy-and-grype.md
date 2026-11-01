---
title: fleetreach vs Trivy and Grype
description: "An honest comparison of fleetreach with Aqua's Trivy (v0.76) and Anchore's Grype (v0.121): image and filesystem scanners versus a fleet-wide source dependency audit, and how they share OpenVEX."
sidebar:
  order: 2
---

*Checked against Trivy v0.76.1 and Grype v0.121.0 and their documentation in November 2026.*

Trivy and Grype are excellent at scanning container images, filesystems and SBOMs, one
target per run. fleetreach scans the source repositories those images are built from, all
of them in one run.

| | fleetreach | Trivy | Grype |
|---|---|---|---|
| Targets | many repos, or a GitHub or GitLab org | image, filesystem, one git repo, VM, Kubernetes | image, directory, SBOM |
| OS packages in images | no | yes | yes |
| Fleet ranking and owners | yes | no | no |
| Reachability | yes (see [Check reachability](/fleetreach/docs/guides/check-reachability/)) | no | no |
| KEV / EPSS / SSVC | yes / yes / yes | not documented | KEV and EPSS as enrichment / no |
| VEX | writes OpenVEX | reads OpenVEX, CycloneDX VEX, CSAF | reads OpenVEX |
| SBOM | writes CycloneDX, SPDX | writes CycloneDX, SPDX; scans SBOMs | scans SBOMs; writes CycloneDX |
| Fix pull requests | yes, verified | no | no |
| Advisory data | OSV, RustSec | vendor feeds, GHSA and others | vendor feeds, GHSA, NVD and others |
| License | MIT or Apache-2.0 | Apache-2.0 | Apache-2.0 |

**Choose Trivy or Grype** for container images and operating-system packages, which
fleetreach does not scan.

**Choose fleetreach** for the source side across many repos.

**Use them together.** fleetreach's OpenVEX statements (`-f vex`) quiet the same proven
non-issues in Trivy (`--vex`) and Grype (`--vex`), and its SBOMs scan in both. See
[Trivy and Grype](/fleetreach/docs/integrations/trivy-and-grype/).

Sources: [Trivy](https://github.com/aquasecurity/trivy),
[Trivy VEX](https://trivy.dev/latest/docs/supply-chain/vex/),
[Grype](https://github.com/anchore/grype),
[Grype data sources](https://oss.anchore.com/docs/reference/grype/data-sources/).
