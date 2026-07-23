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

DockSec is an **OWASP Lab Project** that bridges the gap between complex security scan results and actionable developer fixes. It integrates industry-standard scanners (Trivy, Grype, Hadolint, Docker Scout) with AI to provide **context-aware security analysis**.

Instead of overwhelming you with a list of 200+ CVEs, DockSec:

- **Prioritizes** what actually affects your specific container setup.
- **Explains** vulnerabilities in plain English, not just security jargon.
- **Suggests** specific fixes for your Dockerfile.
- **Generates** professional, interactive security reports for your team.

Everything scans locally; the only thing that ever leaves your machine is the (secret-redacted) file content sent to the AI provider you choose - and with a local model or scan-only mode, nothing leaves at all. See [Data flow and privacy](#data-flow-and-privacy).

---

## How It Works

<div align="center">
  <img src="https://raw.githubusercontent.com/OWASP/DockSec/main/images/workflow.png" alt="DockSec Workflow" width="800">
  <p><em>DockSec workflow: from scanning to actionable insights</em></p>
</div>

DockSec follows a four-stage pipeline:

1. **Scan**: Runs Trivy, Grype, Hadolint, and Docker Scout locally on your environment.
2. **Analyze**: AI correlates findings across all scanners to remove noise and assess real-world impact.
3. **Recommend**: Generates human-readable explanations and specific remediation steps.
4. **Report**: Exports actionable results as HTML, PDF, JSON, CSV, SARIF, and CycloneDX SBOM.

---

## Getting Started

### 1. Prerequisites

DockSec orchestrates local scanners, so it needs:

| Requirement | Needed for | Install |
|---|---|---|
| Python 3.12+ | DockSec itself | [python.org](https://www.python.org/downloads/) |
| Trivy | All scans (required) | `brew install trivy` or [Trivy docs](https://trivy.dev/latest/getting-started/installation/) |
| Grype | Vulnerability scanning (optional) | `brew install anchore/grype/grype` or [Grype docs](https://github.com/anchore/grype#installation) |
| Hadolint | Dockerfile linting | `brew install hadolint` or [Hadolint docs](https://github.com/hadolint/hadolint#install) |
| Docker | Image scans (`-i`) | [Docker docs](https://docs.docker.com/get-docker/) |

Or let DockSec install Trivy, Grype, and Hadolint for you:

```bash
python -m docksec.setup_external_tools
```

### 2. Install DockSec

```bash
# Full install with AI analysis support (recommended)
pip install "docksec[ai]"

# Or the slim, scan-only core (no LLM dependencies, no API key needed)
pip install docksec
```

### 3. Run your first scan

No API key needed for local scanning:

```bash
docksec Dockerfile --scan-only
```

Every scan ends with a result summary: a severity table, a 0-100 security score with a
rating, a "Quick take" action block, the generated reports (saved to
`~/.docksec/results/` by default), and a suggested next command.

### 4. Enable AI analysis

AI analysis explains findings and suggests fixes. Pick a provider, set its API key, and run:

```bash
# OpenAI (default provider)
export OPENAI_API_KEY="sk-..."
docksec Dockerfile

# Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-..."
docksec Dockerfile --ai-only --provider anthropic --model claude-sonnet-5

# Google Gemini
export GOOGLE_API_KEY="..."
docksec Dockerfile --ai-only --provider google

# Ollama (fully local, no API key, data never leaves your machine)
docksec Dockerfile --ai-only --provider ollama --model llama3.1
```

Each provider has a sensible default model (OpenAI: `gpt-4o`, Anthropic:
`claude-haiku-4-5`, Google: `gemini-1.5-pro`, Ollama: `llama3.1`), so `--model` is
optional. To avoid repeating flags, set environment variables (or put them in a `.env`
file in the directory you run from - DockSec loads it automatically):

```bash
export LLM_PROVIDER=anthropic
export LLM_MODEL=claude-sonnet-5
docksec Dockerfile
```

Before any content is sent to an AI provider, secret-looking values (passwords, tokens,
API keys, private key blocks) are masked automatically. See
[Data flow and privacy](#data-flow-and-privacy).

### 5. Or use the GitHub Action

```yaml
- name: Run DockSec AI Scanner
  uses: OWASP/DockSec@v2026.7.5
  with:
    dockerfile: 'Dockerfile'
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
```

---

## Common Commands

```bash
# Scan Dockerfile + Docker image (AI + scanners)
docksec Dockerfile -i myapp:latest

# Scan a Docker Compose file and all its services
docksec --compose docker-compose.yml

# Scan only a Docker image
docksec --image-only -i myapp:latest

# Fast local scan, no AI, no API key
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

# Use Grype instead of Trivy for vulnerability scanning
docksec -i myapp:latest --image-only --scanner grype

# Run both Trivy and Grype, deduplicate findings
docksec -i myapp:latest --image-only --scanner all

# Fully offline scan: local Trivy DB, no network, no AI
docksec --image-only -i myapp:latest --offline

# Save today's findings as a baseline, then only gate on new findings later
docksec -i myapp:latest --image-only --baseline .docksec-baseline.json --update-baseline
docksec -i myapp:latest --image-only --baseline .docksec-baseline.json --fail-on high

# Suppress triaged findings with an auditable ignore file
docksec -i myapp:latest --image-only --ignore-file .docksec-ignore.yml

# Force a fresh scan, bypassing the results cache
docksec -i myapp:latest --image-only --no-cache

# Install AI-assistant skill files (Claude Code, Cursor, Copilot, and more)
docksec install-skill

# Output control
docksec Dockerfile --scan-only --quiet                  # warnings, errors, summary only
docksec Dockerfile --scan-only --verbose                # INFO-level diagnostics on stderr
docksec Dockerfile --scan-only --verbose --log-file logs/docksec.log
docksec Dockerfile --no-color                           # also honors NO_COLOR
```

---

## CI/CD Integration

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

### Machine-readable output

`--json` prints a single JSON object to stdout (scan info, vulnerabilities, severity
counts, and any AI findings) instead of the human-readable summary, so it can be piped
straight into other tools:

```bash
docksec -i myapp:latest --image-only --json | jq '.severity_counts'
```

With `--json` alone, no report files are written; combine it with `--format` to write
files and print JSON in the same run. All human-readable messages move to stderr in
`--json` mode, so stdout only ever contains the JSON payload.

### SARIF output for GitHub Code Scanning

`--sarif` writes a SARIF 2.1.0 report alongside the other report formats. Upload it
with the standard `github/codeql-action/upload-sarif` action to see findings annotated
directly on pull requests and in the Security tab:

```yaml
- name: Run DockSec
  uses: OWASP/DockSec@v2026.7.5
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
to accept the current state as the new baseline.

### Ignoring findings (waivers)

`--ignore-file FILE` suppresses individual findings a team has triaged and accepted.
Unlike the baseline (a point-in-time snapshot), the ignore file is an explicit,
reviewable list where every entry carries a reason and an optional expiry date.
If a `.docksec-ignore.yml` file exists in the current directory, it is picked up
automatically.

```yaml
# .docksec-ignore.yml
ignores:
  - id: CVE-2023-45853              # Trivy vulnerability ID or DockSec rule ID
    reason: "zlib CVE; code path not reachable, vendor fix pending"
    expires: 2026-12-31              # optional; entry stops applying after this date
  - id: compose-missing-healthcheck
    reason: "healthchecks are handled by the orchestrator"
```

Suppressed findings are removed before scoring, reports, `--json` output, and the
`--fail-on` gate. Expired entries stop applying automatically (with a warning), and
entries without a reason are flagged so waivers stay auditable. Commit the file to
version control so suppressions are reviewed like any other change.

---

## Reports

### Report formats

By default every scan writes four report files; use `--format` to pick a subset:

- **html**: An interactive, visually clean web report: severity cards, score rating, full vulnerability table with fixed versions, and the complete AI findings.
- **pdf**: A portable, presentation-ready document.
- **json**: Full, machine-readable scan data (same shape as `--json` stdout output).
- **csv**: A spreadsheet-ready table of individual vulnerabilities.

> Note on CSV behavior: with zero vulnerabilities, DockSec still writes a header-only
> CSV (column names, no rows) so downstream automation never breaks on a missing or
> empty file. This is intentional.

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

---

## Data flow and privacy

DockSec is designed so you always know what leaves your machine:

- **Scanning is fully local.** Trivy, Grype, Hadolint, and the security score run on your
  machine. Image contents are never uploaded anywhere by DockSec.
- **AI analysis sends only the scanned file.** When the AI pass runs, the Dockerfile
  or compose file content (plus a short summary of vulnerability counts for scoring)
  is sent to the LLM provider you configured. Nothing else is transmitted.
- **Secrets are redacted before they leave.** Secret-looking values (passwords,
  tokens, API keys, private key blocks) in the file are masked before the content is
  sent to the AI provider. Key names stay visible so exposed credentials are still
  flagged. Use `--no-redact` to opt out.
- **Fully local AI is supported.** Use `--provider ollama` to keep the AI analysis on
  your own hardware, or `--scan-only` / `--offline` to skip AI entirely.
- **No telemetry.** DockSec collects no usage data and phones home to nothing.

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

### Scan results cache

Image scan results are cached (default: 24 hours, override with
`DOCKSEC_CACHE_TTL_HOURS`) and keyed by the image's content digest, so a rebuilt tag
such as a reused `:latest` always gets a fresh scan. Use `--no-cache` (or
`DOCKSEC_USE_CACHE=false`) to bypass the cache for a run.

---

## AI-assistant skills (`install-skill`)

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

---

## Features

- **Smart Analysis**: AI explains what vulnerabilities mean for *your* specific setup.
- **Multi-LLM Support**: OpenAI, Anthropic Claude, Google Gemini, or local models via Ollama.
- **Privacy First**: Secret values are redacted before any content reaches an AI provider, scanning is fully local, and there is no telemetry.
- **Docker Compose Scanning**: Detect orchestration-level misconfigurations and scan all services in a compose file.
- **Multi-Scanner**: Run Trivy, Grype, or both (`--scanner all`) with automatic deduplication by CVE ID.
- **Deep Integration**: Combines Trivy (vulnerabilities), Grype (vulnerabilities), Hadolint (linting), and Docker Scout.
- **Security Scoring**: A 0-100 score with a rating to track your security posture over time.
- **Rich Formats**: HTML (interactive), PDF, JSON, CSV, SARIF, and CycloneDX SBOM.
- **CI/CD Ready**: `--fail-on` exit codes, baseline/ratchet mode, auditable waivers, JSON-to-stdout, and a GitHub Action on the Marketplace.
- **Offline Mode**: Scan fully air-gapped (`--offline`) using the local Trivy database.
- **AI-Assistant Skills**: `docksec install-skill` teaches Claude Code, Cursor, Copilot, and others how to run DockSec in your repo.

---

## How DockSec Compares

| Capability | DockSec | Trivy (standalone) | Snyk Container | Aikido |
|---|---|---|---|---|
| License and cost | Free, open source (MIT) | Free, open source (Apache 2.0) | Commercial (limited free tier) | Commercial (limited free tier) |
| Governance | OWASP Lab Project, vendor neutral | Open source, maintained by Aqua | Single vendor | Single vendor |
| Detects CVEs and Dockerfile misconfigurations | Yes | Yes | Yes | Yes |
| Explains findings in plain English | Yes (AI-written context and impact) | No (raw CVE data) | Partial (severity and fix hints) | Partial (AI summaries in platform) |
| Contextual Dockerfile remediation | Yes (specific rewrites with explanation) | No (detection only) | Yes (base image upgrade advice, fix PRs) | Yes (AI AutoFix PRs) |
| Docker Compose (multi-service) scanning | Yes (orchestration checks and per-service scan) | Partial (config scan, no per-service fan-out) | Partial | Partial |
| Baseline / ratchet mode (fail only on new findings) | Yes | No | Partial (platform policies) | Partial (platform policies) |
| Auditable per-finding waivers with reasons and expiry | Yes | Partial (.trivyignore, no reasons enforced) | Partial (platform policies) | Partial (platform policies) |
| CI-native output (SARIF for GitHub Code Scanning) | Yes | Yes | Yes | Yes |
| SBOM export (CycloneDX) | Yes (`--sbom`) | Yes | Yes | Yes |
| AI-assistant skill install (Claude Code, Cursor, Copilot) | Yes (`install-skill`) | No | No | No |
| Runs fully offline / air-gapped | Yes (local LLM via Ollama, scan-only mode, no API key) | Scanning only (no remediation layer) | No (cloud platform) | No (hosted platform) |
| Your image data stays on your network | Yes | Yes | No | No |
| Bring your own LLM / model choice | Yes (OpenAI, Anthropic, Gemini, or local Ollama) | Not applicable | No (proprietary AI) | No (proprietary AI) |
| Self-hostable, no platform deployment | Yes | Yes | No | No |
| Vendor lock-in | None | None | Yes | Yes |
| Security score (0-100) and multi-format reports | Yes | Partial (machine formats, no remediation report) | Partial (dashboard reports) | Partial (dashboard reports) |

DockSec is the only one of these that pairs contextual Dockerfile remediation with a fully open source, OWASP-governed, locally runnable design. Snyk and Aikido offer capable AI remediation, but only as commercial cloud platforms that send your data to their service. Trivy is open source and local but stops at detection and does not help you fix anything. DockSec fills the gap for developers and for regulated or air-gapped teams who need both the fix guidance and full control of their data, at no cost.

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for where DockSec is heading: registry scanning without a
local Docker daemon, a repo-level policy config file, Jenkins/GitLab/Azure DevOps
templates, an official container image, Kubernetes and Helm scanning, and more. Feedback
and votes on priorities are welcome in
[issues](https://github.com/OWASP/DockSec/issues) and on
[OWASP Slack](https://owasp.slack.com/archives/C0APXGCUW7M).

---

## Contributing

DockSec thrives on community contributions. Whether you are a developer, designer, or security enthusiast, there are many ways to get involved:

- **Code Contributions**: Fix bugs or add new features.
- **Documentation**: Improve guides or create tutorials.
- **Issue Reporting**: Identify and report bugs.
- **Feedback**: Share your experience and suggestions.

To get started, check out our [Contributing Guidelines](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md), and [Sponsorship Guide](SPONSORSHIP.md).

---

## Leaders and Community

DockSec is led by a dedicated team committed to making container security accessible:

- [Advait Patel](https://github.com/advaitpatel) - Project Lead
- [Arkadii Yakovets](https://github.com/arkid15r) - Project Co-lead

Find us here:

- **OWASP Project Page**: [owasp.org/DockSec/](https://owasp.org/DockSec/)
- **OWASP Slack**: [#project-docksec](https://owasp.slack.com/archives/C0APXGCUW7M)
- **PyPI**: [pypi.org/project/docksec/](https://pypi.org/project/docksec/)
- **Issues**: [Report a bug](https://github.com/OWASP/DockSec/issues)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

<div align="center">
  <strong>If DockSec helps you, star the repo to help others discover it.</strong><br>
  Built by <a href="https://github.com/advaitpatel">Advait Patel</a> and the OWASP community.
</div>
