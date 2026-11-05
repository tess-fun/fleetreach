---
title: fleetreach vs Trivy and Grype
description: "An honest comparison of fleetreach with Aqua's Trivy (v0.76) and Anchore's Grype (v0.121): single-target scanners versus a fleet-wide audit of repos and images, and how they share OpenVEX."
sidebar:
  order: 2
---

*Checked against Trivy v0.76.1 and Grype v0.121.0 and their documentation in November 2026.*

Trivy and Grype are excellent at scanning container images, filesystems and SBOMs, one
target per run. fleetreach scans images too, along with the source repositories they are
built from, all of them in one run and in one ranked report.

| | fleetreach | Trivy | Grype |
|---|---|---|---|
| Targets | many repos and images, or a GitHub, GitLab, Bitbucket, Azure DevOps or Gitea org | image, filesystem, one git repo, VM, Kubernetes | image, directory, SBOM |
| OS packages in images | yes ([compared on 217 images](/fleetreach/docs/concepts/image-differential/)) | yes | yes |
| Fleet ranking and owners | yes | no | no |
| Reachability | yes (see [Check reachability](/fleetreach/docs/guides/check-reachability/)) | no | no |
| KEV / EPSS / SSVC | yes / yes / yes | not documented | KEV and EPSS as enrichment / no |
| VEX | writes OpenVEX; reads it from images in a registry | reads OpenVEX, CycloneDX VEX, CSAF | reads OpenVEX |
| SBOM | writes CycloneDX, SPDX; scans SBOMs | writes CycloneDX, SPDX; scans SBOMs | scans SBOMs; writes CycloneDX |
| Fix pull requests | yes, verified | no | no |
| Advisory data | OSV, RustSec, vendor feeds | vendor feeds, GHSA and others | vendor feeds, GHSA, NVD and others |
| License | MIT or Apache-2.0 | Apache-2.0 | Apache-2.0 |

**Choose Trivy or Grype** to scan one target per run, or, with Trivy, VMs and Kubernetes
clusters, which fleetreach does not scan.

**Choose fleetreach** for many repos and images at once.

**Use them together.** fleetreach's OpenVEX statements (`-f vex`) quiet the same proven
non-issues in Trivy (`--vex`) and Grype (`--vex`), and its SBOMs scan in both. See
[Trivy and Grype](/fleetreach/docs/integrations/trivy-and-grype/).

Sources: [Trivy](https://github.com/aquasecurity/trivy),
[Trivy VEX](https://trivy.dev/latest/docs/supply-chain/vex/),
[Grype](https://github.com/anchore/grype),
[Grype data sources](https://oss.anchore.com/docs/reference/grype/data-sources/).
