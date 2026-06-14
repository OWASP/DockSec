<div align="center">

[![OWASP](https://img.shields.io/badge/Incubator-blue?&label=level&style=for-the-badge)](https://owasp.org/DockSec/) [![OWASP](https://img.shields.io/badge/Code-blue?label=type&style=for-the-badge)](https://owasp.org/DockSec/) [![project-docksec](https://img.shields.io/badge/%23project--docksec-blue?label=slack&logoColor=white&style=for-the-badge)](https://owasp.slack.com/archives/C0APXGCUW7M) [![Build Status](https://img.shields.io/github/actions/workflow/status/OWASP/DockSec/python-app.yml?branch=main&style=for-the-badge&label=Build&color=blue)](https://github.com/OWASP/DockSec/actions)
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

DockSec is an **OWASP Incubator Project** that bridges the gap between complex security scan results and actionable developer fixes. It integrates industry-standard scanners (Trivy, Grype, Hadolint, Docker Scout) with advanced AI to provide **context-aware security analysis**.

Instead of overwhelming you with a list of 200+ CVEs, DockSec:

- **Prioritizes** what actually affects your specific container setup.
- **Explains** vulnerabilities in plain English, not just security jargon.
- **Suggests** specific, line-by-line fixes for your Dockerfile.
- **Generates** professional, interactive security reports for your team.
- **Cross-validates** findings across multiple scanners so you catch what one scanner misses.

Think of it as having a security expert sitting right next to you, reviewing your Dockerfiles in real-time.

---

## How It Works

<div align="center">
  <img src="https://raw.githubusercontent.com/OWASP/DockSec/main/images/workflow.png" alt="DockSec Workflow" width="800">
  <p><em>DockSec workflow: From scanning to actionable insights</em></p>
</div>

DockSec follows a robust four-stage pipeline:
1. **Scan**: Runs Trivy and/or Grype for CVE detection, Hadolint for Dockerfile linting, and Docker Scout for base-image analysis — all locally on your environment.
2. **Analyze**: AI correlates findings across all scanners to remove noise and assess real-world impact. When running both Trivy and Grype, results are automatically deduplicated and cross-validated.
3. **Recommend**: Generates human-readable explanations and specific remediation steps.
4. **Report**: Exports actionable results in JSON, PDF, HTML, or CSV formats — each report includes a **Scanner Coverage** section showing exactly which scanner(s) flagged each CVE.

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

# Install all required external tools (Trivy, Hadolint, Grype)
docksec-setup

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
```

### Choosing a Vulnerability Scanner

DockSec supports three scanner modes via the `--scanner` flag:

```bash
# Default: use Trivy only (fast, widely adopted)
docksec --image-only -i myapp:latest --scanner trivy

# Use Grype only (Anchore's scanner, often finds additional CVEs)
docksec --image-only -i myapp:latest --scanner grype

# Use both scanners and deduplicate results (maximum coverage)
docksec --image-only -i myapp:latest --scanner all

# Works with full scans too
docksec Dockerfile -i myapp:latest --scanner all

# Works with Docker Compose
docksec --compose docker-compose.yml --scanner all
```

You can also set the default scanner via an environment variable (useful in CI/CD):

```bash
# Set a persistent default — no need to pass --scanner on every command
export DOCKSEC_SCANNER=all
docksec --image-only -i myapp:latest
```

> **Why use `--scanner all`?**
> Trivy and Grype use different vulnerability databases and detection methods. In practice they each find CVEs the other misses. Running both and deduplicating gives you the highest confidence results — CVEs flagged by both scanners are shown with a **"Both"** badge in reports, making them the highest-priority findings to fix.

---

## Features

- **Smart Analysis**: AI explains what vulnerabilities mean for *your* specific setup.
- **Dual Vulnerability Scanner**: Choose Trivy, Grype, or run **both at once** (`--scanner all`) for maximum CVE coverage with automatic deduplication.
- **Scanner Coverage Reports**: Every report includes a breakdown of which scanner(s) found each CVE — CVEs confirmed by both scanners are highlighted as highest priority.
- **Multi-LLM Support**: Use OpenAI, Anthropic Claude (4.x), Google Gemini (1.5+), or local models via Ollama.
- **Docker Compose Scanning**: Detect orchestration-level misconfigurations and scan all services in a compose file.
- **Deep Integration**: Combines Trivy, Grype, Hadolint (linting), and Docker Scout.
- **Security Scoring**: Get a 0-100 score to track your security posture over time.
- **Centralized Reporting**: All reports are neatly organized in `~/.docksec/results/` by default.
- **Rich Formats**: Professional exports in HTML (interactive, with scanner badges), PDF, JSON, and CSV.
- **CI/CD Ready**: Designed for easy integration into GitHub Actions and build pipelines. Set `DOCKSEC_SCANNER=all` in your environment for maximum coverage with no code changes.
- **GitHub Action**: Available on the GitHub Marketplace for automated security scans.

---

## How DockSec Compares

Here is a comparison of how DockSec relates to other container security tools.

| Capability | DockSec | Trivy (standalone) | Snyk Container | Aikido |
|---|---|---|---|---|
| License and cost | Free, open source (MIT) | Free, open source (Apache 2.0) | Commercial (limited free tier) | Commercial (limited free tier) |
| Governance | OWASP Incubator Project, vendor neutral | Open source, maintained by Aqua | Single vendor | Single vendor |
| Detects CVEs and Dockerfile misconfigurations | Yes | Yes | Yes | Yes |
| Dual scanner (Trivy + Grype) with deduplication | Yes (`--scanner all`) | No | No | No |
| Contextual, line level Dockerfile remediation | Yes (line specific rewrites with explanation) | No (detection only) | Yes (base image upgrade advice, fix PRs) | Yes (AI AutoFix PRs) |
| Runs fully offline / air gapped | Yes (local LLM via Ollama, scan only mode, no API key) | Yes for scanning (no remediation layer) | No (cloud platform) | No (hosted platform) |
| Your image data stays on your network | Yes | Yes | No | No |
| Bring your own LLM / model choice | Yes (OpenAI, Anthropic, Gemini, or local Ollama) | Not applicable | No (proprietary AI) | No (proprietary AI) |
| Self hostable, no platform deployment | Yes | Yes | No | No |
| Vendor lock in | None | None | Yes | Yes |
| Security score (0 to 100) and multi format reports (HTML, PDF, JSON, CSV) | Yes | Partial (machine formats, no remediation report) | Partial (dashboard reports) | Partial (dashboard reports) |

DockSec is the only one of these that pairs contextual, line level Dockerfile remediation with a fully open source, OWASP governed, locally runnable design. Snyk and Aikido offer capable AI remediation, but only as commercial cloud platforms that send your data to their service. Trivy is open source and local but stops at detection and does not help you fix anything. DockSec fills the gap for developers and for regulated or air gapped teams who need both the fix guidance and full control of their data, at no cost. With `--scanner all`, DockSec runs both Trivy and Grype and automatically deduplicates the results — giving you broader CVE coverage than either scanner alone, without duplicates or extra noise.

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
  <strong>If DockSec helps you, give it a ⭐ to help others discover it!</strong><br>
  Built with ❤️ by <a href="https://github.com/advaitpatel">Advait Patel</a> and the OWASP community.
</div>
