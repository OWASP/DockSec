# DockSec Roadmap

This is the directional plan for DockSec. Priorities are shaped by user feedback, so
if an item here matters to you (or something is missing), say so in an
[issue](https://github.com/OWASP/DockSec/issues) or in the
[#project-docksec](https://owasp.slack.com/archives/C0APXGCUW7M) channel on OWASP Slack.

Dates are intentionally absent: items ship when they are ready. Completed work moves to
the [CHANGELOG](CHANGELOG.md).

## Near term

- **Registry / remote image scanning.** Scan images in a registry (Artifactory, Harbor,
  ECR, Docker Hub) without a local Docker daemon, using Trivy's remote scanning and the
  standard registry auth environment variables. Unblocks daemonless CI runners.
- **Scan history and trend tracking.** Persist scores and finding counts per target over
  time, and report the delta on each run ("3 new, 5 fixed since last scan"). Turns a
  point-in-time scanner into a posture tracker.
- **Audit log.** An append-only NDJSON record of what a run detected and changed, for
  change-control evidence in regulated environments.
- **Pull request comment mode** for the GitHub Action: post the priority tiers and any
  exploit chains as a comment, using a two-stage workflow so a fork PR cannot inject
  comment content.
- **Faster compose scans.** Scan services in parallel instead of serially.
- **Versioned JSON output contract.** A `schema_version` field and a published JSON
  Schema so automation built on `--json` cannot break silently. (`score_version` is
  already emitted for the scoring model specifically.)

## Later

- **Policy packs.** Named profiles that map findings to compliance frameworks such as
  the CIS Docker Benchmark and NIST SP 800-190, carried through into SARIF rule metadata.
- **A bundled offline advisory database.** Today `--offline` relies on a previously
  downloaded Trivy database, so air-gapped use carries a precondition.
- **Reachability signal.** Whether a vulnerable package is actually on the
  `CMD`/`ENTRYPOINT` path, rather than a build-stage artifact that never ships.
- **Exploit chains beyond Compose.** Chains spanning a Dockerfile and a compose file,
  and eventually Kubernetes manifests - the differentiator there would be cross-resource
  chain analysis, not the detection itself.
- **SPDX SBOM export** alongside the existing CycloneDX support.
- **A documentation site**, once there is enough material to warrant one.

## Recently shipped

See the [CHANGELOG](CHANGELOG.md) for detail. The headline changes since 2026.8.19:

- **Dockerfile findings are first-class.** Hadolint and Trivy's config scanner both run
  and produce structured findings, so Dockerfile issues participate in `--fail-on`,
  `--json`, SARIF and the reports. CI could previously pass on a root-user Dockerfile
  shipping a plaintext credential.
- **EPSS priority tiers.** Every CVE is ranked by severity combined with exploitation
  likelihood: `Fix Now`, `Fix Soon`, `Monitor`, `Low Priority`. Only CVE IDs are sent,
  and `--offline` or `--no-epss` disables the lookup entirely.
- **Cross-service exploit chains.** Separate findings that combine into one attack path
  are reported as a chain, with the services involved and the single change that breaks
  it. Rule-based, so it works offline and without an API key.
- **The AI pass analyses the scan.** It now receives the CVE list, the Dockerfile
  misconfigurations with line numbers, and the compose topology, and returns typed
  findings rather than free text.
- **`--fix`.** Applies the mechanical subset of the suggested Dockerfile changes, keeps
  a `.bak`, re-scans, and reports the delta. Refuses to edit a dirty working tree.
- **Scan completeness.** A scan that could not complete says so, and
  `--incomplete-policy fail` exits non-zero rather than reporting a clean result.
- **Deterministic scoring.** Identical inputs always produce an identical score; the
  model is no longer asked for one.
- **The container image works and is published** to `ghcr.io/owasp/docksec`, multi-arch,
  with build provenance attestation. The previous image shipped without Trivy.
- **Documentation**: a page per compose rule, CI guides for Jenkins, GitLab, Azure
  Pipelines and pre-commit, and a 15-minute evaluation guide.
