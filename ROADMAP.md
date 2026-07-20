# DockSec Roadmap

This is the directional plan for DockSec. Priorities are shaped by user feedback, so
if an item here matters to you (or something is missing), say so in an
[issue](https://github.com/OWASP/DockSec/issues) or in the
[#project-docksec](https://owasp.slack.com/archives/C0APXGCUW7M) channel on OWASP Slack.

Dates are intentionally absent: items ship when they are ready. Recently completed work
moves to the [CHANGELOG](CHANGELOG.md).

## Near term

- **Registry / remote image scanning.** Scan images in a registry (Artifactory, Harbor,
  ECR, Docker Hub) without a local Docker daemon, using Trivy's remote scanning and the
  standard registry auth environment variables. Unblocks daemonless CI runners.
- **Repo-level configuration file.** A committed `.docksec.yml` for severity, fail-on
  threshold, report formats, output directory, disabled rules, and provider settings,
  so a team's policy lives in the repo instead of per-developer flags.
- **Dockerfile lint findings as first-class findings.** Parse Hadolint output into
  structured findings with mapped severities so they participate in `--fail-on`,
  `--json`, SARIF, and the reports like image vulnerabilities already do.
- **CI templates beyond GitHub Actions.** Copy-paste examples for Jenkins, GitLab CI,
  and Azure Pipelines built on the existing exit codes and `--json` output.
- **Official container image.** `docker run ghcr.io/owasp/docksec ...` with Trivy and
  Hadolint baked in, published multi-arch on each release, for zero-install evaluation
  and air-gapped deployment.
- **Line-anchored AI findings.** Structured AI output (line, severity, issue, fix) so
  AI findings can appear in SARIF regions and PR annotations, not just as prose.
- **Versioned JSON output contract.** A `schema_version` field and a published JSON
  Schema so automation built on `--json` cannot break silently.
- **Faster compose scans.** Scan services in parallel instead of serially.

## Later

- **Kubernetes manifest and Helm chart scanning**, using the same static-rule approach
  as compose scanning.
- **Policy packs.** Named profiles that map findings to compliance frameworks such as
  the CIS Docker Benchmark and NIST SP 800-190.
- **Trend tracking.** Persist scores and finding counts per image over time and report
  deltas ("3 new, 5 fixed since last scan").
- **Pull request comment mode** for the GitHub Action (summary comment with the Quick
  take).
- **SPDX SBOM export** alongside the existing CycloneDX support.
- **Bundled offline vulnerability database** for true air-gap installs (today
  `--offline` relies on a previously downloaded Trivy DB).

## Recently shipped

See the [CHANGELOG](CHANGELOG.md). Highlights from 2026.7.4/2026.7.5: secret redaction
before AI analysis, auditable waiver files, digest-keyed scan caching with TTL, a slim
scan-only install, tuned compose rules, and an overhauled HTML report.
