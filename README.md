<div align="center">

[![OWASP](https://img.shields.io/badge/Lab-blue?&label=level&style=for-the-badge)](https://owasp.org/DockSec/) [![OWASP](https://img.shields.io/badge/Code-blue?label=type&style=for-the-badge)](https://owasp.org/DockSec/) [![project-docksec](https://img.shields.io/badge/%23project--docksec-blue?label=slack&logoColor=white&style=for-the-badge)](https://owasp.slack.com/archives/C0APXGCUW7M) [![Build Status](https://img.shields.io/github/actions/workflow/status/OWASP/DockSec/python-app.yml?branch=main&style=for-the-badge&label=Build&color=blue)](https://github.com/OWASP/DockSec/actions)
<br>[![OpenSSF Best Practices](https://img.shields.io/cii/level/12939?label=openssf%20best%20practices&style=for-the-badge)](https://www.bestpractices.dev/projects/12939)


[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](https://github.com/OWASP/DockSec/blob/main/LICENSE) [![Last Commit](https://img.shields.io/github/last-commit/OWASP/DockSec/main?color=blue&style=for-the-badge&label=Last%20commit)](https://github.com/OWASP/DockSec/commits/main/) [![Contributors](https://img.shields.io/github/contributors/OWASP/DockSec?style=for-the-badge&label=Contributors&color=blue)](https://github.com/OWASP/DockSec/graphs/contributors)

[![Forks](https://img.shields.io/github/forks/OWASP/DockSec?style=for-the-badge&label=Forks&color=blue)](https://github.com/OWASP/DockSec/network/members) [![Stars](https://img.shields.io/github/stars/OWASP/DockSec?style=for-the-badge&label=Stars&color=blue)](https://github.com/OWASP/DockSec/stargazers) ![PyPI Downloads](https://img.shields.io/pepy/dt/docksec?style=for-the-badge&color=blue)

[![Issues](https://img.shields.io/github/issues/OWASP/DockSec?color=blue&style=for-the-badge&label=Issues)](https://github.com/OWASP/DockSec/issues) [![Pull Requests](https://img.shields.io/github/issues-pr/OWASP/DockSec?color=blue&style=for-the-badge&label=Pull%20Requests)](https://github.com/OWASP/DockSec/pulls)

[![CREATED](https://img.shields.io/badge/created-feb,%202025-blue?style=for-the-badge)](https://github.com/OWASP/DockSec/commit/80664db8935e4b5ab44df5867913e)

<picture>
  <source srcset="https://raw.githubusercontent.com/OWASP/DockSec/main/images/docksec-logo-for-github.png" media="(prefers-color-scheme: dark)">
  <img src="https://raw.githubusercontent.com/OWASP/DockSec/main/images/docksec-logo-for-github.png" alt="DockSec Logo" width="600">
</picture><br>
<img src="https://raw.githubusercontent.com/OWASP/DockSec/main/images/owasp-logo.png" alt="OWASP Logo" width="300">

# [DockSec](https://owasp.org/DockSec/)

**AI-powered Docker security scanner that explains vulnerabilities in plain English**

</div>

---

## What is DockSec?

DockSec is an **OWASP Lab Project** that bridges the gap between complex security scan results and actionable developer fixes. It integrates industry-standard scanners (Trivy, Hadolint, Docker Scout) with advanced AI to provide **context-aware security analysis**. 

Instead of overwhelming you with a list of 200+ CVEs, DockSec:

- **Prioritizes** what actually affects your specific container setup.
- **Explains** vulnerabilities in plain English, not just security jargon.
- **Suggests** specific, line-by-line fixes for your Dockerfile.
- **Generates** professional, interactive security reports for your team.

Think of it as having a security expert sitting right next to you, reviewing your Dockerfiles in real-time.

---

## How It Works

<div align="center">
  <img src="https://raw.githubusercontent.com/OWASP/DockSec/main/images/workflow.png" alt="DockSec Workflow" width="800">
  <p><em>DockSec workflow: From scanning to actionable insights</em></p>
</div>

DockSec follows a robust four-stage pipeline:
1. **Scan**: Runs Trivy, Hadolint, and Docker Scout locally on your environment.
2. **Analyze**: AI correlates findings across all scanners to remove noise and assess real-world impact.
3. **Recommend**: Generates human-readable explanations and specific remediation steps.
4. **Report**: Exports actionable results in JSON, PDF, HTML, or Markdown formats.

---

## Leaders

DockSec is led by a dedicated team committed to making container security accessible.

- [Advait Patel](https://github.com/advaitpatel) - Project Lead
- [Arkadii Yakovets](https://github.com/arkid15r) - Project Co-lead 

For questions or discussions, please join the [#project-docksec](https://owasp.slack.com/archives/C0APXGCUW7M) channel on OWASP Slack.

---

## Quick Start

### GitHub Action

Integrate DockSec into your GitHub Actions workflow:

```yaml
- name: Run DockSec AI Scanner
  uses: OWASP/DockSec@main
  with:
    dockerfile: 'Dockerfile'
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
```

### CLI Usage

```bash
# Install DockSec
pip install docksec

# Scan a Dockerfile (AI-powered)
# Reports will be saved to ~/.docksec/results/
docksec Dockerfile

# Scan Dockerfile + Docker image
docksec Dockerfile -i myapp:latest

# Scan a Docker Compose file and all its services
docksec --compose docker-compose.yml

# Scan only a Docker image
docksec --image-only -i myapp:latest

# Fast scan only (no AI)
docksec Dockerfile --scan-only

# Choose which severity levels the image scan reports (default: CRITICAL,HIGH)
docksec -i myapp:latest --image-only --severity CRITICAL,HIGH,MEDIUM

# Fail the build (exit 1) if any finding is HIGH or above
docksec -i myapp:latest --image-only --fail-on high

# Write only the report formats you want, to a directory of your choice
docksec Dockerfile --scan-only --format json,html --output-dir ./reports

# Print results as JSON to stdout for scripts and CI pipelines
docksec -i myapp:latest --image-only --json

# Write a SARIF report for GitHub Code Scanning
docksec Dockerfile --scan-only --sarif

# Write a CycloneDX SBOM of an image for supply-chain tooling
docksec --image-only -i myapp:latest --sbom

# Fully offline scan: local Trivy DB, no network, no AI
docksec --image-only -i myapp:latest --offline

# Install AI-assistant skill files (Claude Code, Cursor, Copilot, and more)
docksec install-skill

# Save today's findings as a baseline, then only gate on new findings later
docksec -i myapp:latest --image-only --baseline .docksec-baseline.json --update-baseline
docksec -i myapp:latest --image-only --baseline .docksec-baseline.json --fail-on high

# Reduce output to warnings, errors, and the result summary
docksec Dockerfile --scan-only --quiet

# Disable colored output (also honors the NO_COLOR env var)
docksec Dockerfile --no-color

# Enable INFO logging for command output details
docksec --verbose --image-only -i myapp:latest
```

Every scan ends with a result summary: a severity table, the security score with a
rating, a "Quick take" action block, the generated reports, and a suggested next
command. Use `--quiet` for a compact result and `--no-color` for plain output.

### Machine-readable output

`--json` prints a single JSON object to stdout (scan info, vulnerabilities, severity
counts, and any AI findings) instead of the human-readable summary, so it can be piped
straight into other tools:

```bash
docksec -i myapp:latest --image-only --json | jq '.severity_counts'
```

With `--json` alone, no report files are written; combine it with `--format` to write
files and print JSON in the same run. All human-readable messages (info, warnings,
errors) move to stderr in `--json` mode, so stdout only ever contains the JSON payload.

### Report Formats

When using the `--format` flag, you can export your security scan results into four different formats. Each format serves a specific use case:

*   **json**: Full, machine-readable scan data containing core metrics and any AI-generated findings. For stdout piping options, see the [Machine-readable output](#machine-readable-output) section above.
*   **html**: An interactive, visually clean web report summarizing your findings.
*   **pdf**: A portable, presentation-ready document summing up the report.
*   **csv**: A spreadsheet-ready tabular format listing out individual vulnerabilities.

> ⚠️ **Note on CSV Behavior:** If DockSec detects **zero vulnerabilities**, it will still generate a CSV file, but it will be **header-only** (containing only the column names with no data rows). This is intentional behavior to prevent downstream automated tools or CI/CD pipelines from breaking on a completely empty file, and should not be treated as a bug.

For specialized cloud-native workflows, you can also cross-reference the [SARIF output](#sarif-output) section.

### SARIF output for GitHub Code Scanning

`--sarif` writes a SARIF 2.1.0 report alongside the other report formats. Upload it
with the standard `github/codeql-action/upload-sarif` action to see findings annotated
directly on pull requests and in the Security tab:

```yaml
- name: Run DockSec
  uses: OWASP/DockSec@main
  with:
    dockerfile: 'Dockerfile'
    sarif: 'true'

- name: Upload SARIF to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: ~/.docksec/results
```

> `if: always()` is important: without it, the upload step is skipped whenever
> `--fail-on` causes DockSec to exit non-zero, losing the findings exactly when they
> matter most.

`--sarif` is independent of `--format`: it always writes a `.sarif` file regardless of
which report formats you've selected, since it targets CI/Code Scanning rather than
local reading.

### CycloneDX SBOM

`--sbom` writes a CycloneDX software bill of materials (`<image>.cdx.json`) of the
scanned image, listing every package component plus known vulnerabilities. The BOM is
produced by Trivy's native exporter (so it is spec-compliant) and DockSec stamps itself
into the tool metadata. Feed it into Dependency-Track, GitHub's dependency graph, or any
other SBOM consumer:

```bash
docksec --image-only -i myapp:latest --sbom
```

`--sbom` needs a single image (`-i`), so it is skipped for compose runs. Like `--sarif`,
it is independent of `--format`.

### Offline mode

`--offline` runs a scan with no network access. It uses the Trivy vulnerability database
already on disk (no DB update) and skips the AI analysis and the Docker Scout advanced
scan, both of which require network. This is the simplest way to scan in an air-gapped or
locked-down environment:

```bash
docksec --image-only -i myapp:latest --offline
```

Make sure the Trivy DB has been downloaded at least once (any prior online scan does
this) before relying on `--offline`.

### AI-assistant skills (`install-skill`)

`docksec install-skill` writes DockSec usage instructions into the well-known context
files for popular AI coding assistants, so an assistant working in your repo knows how to
invoke DockSec:

```bash
docksec install-skill
```

This creates or updates:

- `.claude/commands/docksec.md` (Claude Code slash command `/docksec`)
- `.cursor/rules/docksec.mdc` (Cursor)
- `AGENTS.md` (Codex CLI), `GEMINI.md` (Gemini CLI)
- `.github/copilot-instructions.md` (GitHub Copilot)

The files are plain text you can review and commit; nothing is executed. Re-running the
command updates the DockSec section in place instead of duplicating it.

### Baseline / ratchet mode

`--baseline FILE` lets you adopt `--fail-on` on an existing project without a wall of
pre-existing findings blocking every build. Run once with `--update-baseline` to snapshot
today's findings, then commit the baseline file; from then on, `--fail-on` only gates on
findings that aren't already in the baseline:

```bash
# Snapshot current findings (does not gate)
docksec -i myapp:latest --image-only --baseline .docksec-baseline.json --update-baseline

# Later runs only fail on NEW findings above the threshold
docksec -i myapp:latest --image-only --baseline .docksec-baseline.json --fail-on high
```

Findings are matched by vulnerability ID, target, and package name, so the baseline stays
valid as unrelated findings come and go. Re-run with `--update-baseline` whenever you want
to accept the current state as the new baseline (e.g. after triaging and deciding to defer
a finding).

### Exit codes

DockSec uses CI-friendly exit codes so builds and shells can react to results:

| Code | Meaning |
|---|---|
| `0` | Success, no findings at or above `--fail-on` |
| `1` | Findings at or above the `--fail-on` threshold |
| `2` | Usage or argument error |
| `3` | Tool or runtime error (scan failed, image not found, missing tools) |

`--fail-on` gates on the structured findings (image vulnerabilities and compose
misconfigurations). When `--fail-on` is below the requested `--severity`, the scan
severity is widened automatically so the gate can observe those findings.

---

## Features

- **Smart Analysis**: AI explains what vulnerabilities mean for *your* specific setup.
- **Multi-LLM Support**: Use OpenAI, Anthropic Claude (4.x), Google Gemini (1.5+), or local models via Ollama.
- **Docker Compose Scanning**: Detect orchestration-level misconfigurations and scan all services in a compose file.
- **Deep Integration**: Combines Trivy (vulnerabilities), Hadolint (linting), and Docker Scout.
- **Security Scoring**: Get a 0-100 score to track your security posture over time.
- **Centralized Reporting**: All reports are neatly organized in `~/.docksec/results/` by default.
- **Rich Formats**: Professional exports in HTML (interactive), PDF, JSON, CSV, SARIF, and CycloneDX SBOM.
- **Supply-Chain Ready**: Generate a CycloneDX SBOM (`--sbom`) of any image for Dependency-Track and other consumers.
- **Offline Mode**: Scan fully air-gapped (`--offline`) using the local Trivy database, no network required.
- **CI/CD Ready**: Designed for easy integration into GitHub Actions and build pipelines.
- **AI-Assistant Skills**: `docksec install-skill` teaches Claude Code, Cursor, Copilot, and others how to run DockSec in your repo.
- **GitHub Action**: Available on the GitHub Marketplace for automated security scans.

---

## How DockSec Compares

Here is a comparison of how DockSec relates to other container security tools.

Legend: ✅ full support &nbsp; ⚠️ partial or caveated &nbsp; ❌ not supported

| Capability | DockSec | Trivy (standalone) | Snyk Container | Aikido |
|---|---|---|---|---|
| License and cost | ✅ Free, open source (MIT) | ✅ Free, open source (Apache 2.0) | ⚠️ Commercial (limited free tier) | ⚠️ Commercial (limited free tier) |
| Governance | ✅ OWASP Lab Project, vendor neutral | ✅ Open source, maintained by Aqua | ⚠️ Single vendor | ⚠️ Single vendor |
| Detects CVEs and Dockerfile misconfigurations | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Explains findings in plain English | ✅ Yes (AI-written context and impact) | ❌ No (raw CVE data) | ⚠️ Partial (severity and fix hints) | ⚠️ Partial (AI summaries in platform) |
| Contextual, line level Dockerfile remediation | ✅ Yes (line specific rewrites with explanation) | ❌ No (detection only) | ✅ Yes (base image upgrade advice, fix PRs) | ✅ Yes (AI AutoFix PRs) |
| Docker Compose (multi service) scanning | ✅ Yes (orchestration checks and per service scan) | ⚠️ Partial (config scan, no per service fan out) | ⚠️ Partial | ⚠️ Partial |
| Baseline / ratchet mode (fail only on new findings) | ✅ Yes | ❌ No | ⚠️ Partial (platform policies) | ⚠️ Partial (platform policies) |
| CI native output (SARIF for GitHub Code Scanning) | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| SBOM export (CycloneDX) | ✅ Yes (`--sbom`) | ✅ Yes | ✅ Yes | ✅ Yes |
| AI-assistant skill install (Claude Code, Cursor, Copilot) | ✅ Yes (`install-skill`) | ❌ No | ❌ No | ❌ No |
| Runs fully offline / air gapped | ✅ Yes (local LLM via Ollama, scan only mode, no API key) | ⚠️ Yes for scanning (no remediation layer) | ❌ No (cloud platform) | ❌ No (hosted platform) |
| Your image data stays on your network | ✅ Yes | ✅ Yes | ❌ No | ❌ No |
| Bring your own LLM / model choice | ✅ Yes (OpenAI, Anthropic, Gemini, or local Ollama) | ⚠️ Not applicable | ❌ No (proprietary AI) | ❌ No (proprietary AI) |
| Self hostable, no platform deployment | ✅ Yes | ✅ Yes | ❌ No | ❌ No |
| Vendor lock in | ✅ None | ✅ None | ❌ Yes | ❌ Yes |
| Security score (0 to 100) and multi format reports (HTML, PDF, JSON, CSV, Markdown) | ✅ Yes | ⚠️ Partial (machine formats, no remediation report) | ⚠️ Partial (dashboard reports) | ⚠️ Partial (dashboard reports) |

DockSec is the only one of these that pairs contextual, line level Dockerfile remediation with a fully open source, OWASP governed, locally runnable design. Snyk and Aikido offer capable AI remediation, but only as commercial cloud platforms that send your data to their service. Trivy is open source and local but stops at detection and does not help you fix anything. DockSec fills the gap for developers and for regulated or air gapped teams who need both the fix guidance and full control of their data, at no cost.

---

## Contributing

DockSec thrives on community contributions. Whether you are a developer, designer, or security enthusiast, there are many ways to get involved:

- **Code Contributions**: Fix bugs or add new features.
- **Documentation**: Improve guides or create tutorials.
- **Issue Reporting**: Identify and report bugs.
- **Feedback**: Share your experience and suggestions.

To get started, check out our [Contributing Guidelines](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md), and [Sponsorship Guide](SPONSORSHIP.md).

---

## Community and Social Media

- **OWASP Project Page**: [owasp.org/DockSec/](https://owasp.org/DockSec/)
- **OWASP Slack**: [#project-docksec](https://owasp.slack.com/archives/C0APXGCUW7M)
- **PyPI**: [pypi.org/project/docksec/](https://pypi.org/project/docksec/)
- **Issues**: [Report a bug](https://github.com/OWASP/DockSec/issues)

---

<div align="center">
  <strong>If DockSec helps you, star the repo to help others discover it.</strong><br>
  Built by <a href="https://github.com/advaitpatel">Advait Patel</a> and the OWASP community.
</div>
