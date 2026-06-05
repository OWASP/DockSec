<div align="center">

[![OWASP](https://img.shields.io/badge/Incubator-blue?&label=level&style=for-the-badge)](https://owasp.org/DockSec/) [![OWASP](https://img.shields.io/badge/Code-blue?label=type&style=for-the-badge)](https://owasp.org/DockSec/) [![project-docksec](https://img.shields.io/badge/%23project--docksec-blue?label=slack&logoColor=white&style=for-the-badge)](https://owasp.slack.com/archives/C0APXGCUW7M) [![Build Status](https://img.shields.io/github/actions/workflow/status/OWASP/DockSec/python-app.yml?branch=main&style=for-the-badge&label=Build&color=blue)](https://github.com/OWASP/DockSec/actions)
<br>[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12939/badge)](https://www.bestpractices.dev/projects/12939)


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

DockSec is an **OWASP Incubator Project** that bridges the gap between complex security scan results and actionable developer fixes. It integrates industry-standard scanners (Trivy, Hadolint, Docker Scout) with advanced AI to provide **context-aware security analysis**. 

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

# Scan only a Docker image
docksec --image-only -i myapp:latest

# Fast scan only (no AI)
docksec Dockerfile --scan-only
```

---

## Features

- **Smart Analysis**: AI explains what vulnerabilities mean for *your* specific setup.
- **Multi-LLM Support**: Use OpenAI, Anthropic Claude (4.x), Google Gemini (1.5+), or local models via Ollama.
- **Deep Integration**: Combines Trivy (vulnerabilities), Hadolint (linting), and Docker Scout.
- **Security Scoring**: Get a 0-100 score to track your security posture over time.
- **Centralized Reporting**: All reports are neatly organized in `~/.docksec/results/` by default.
- **Rich Formats**: Professional exports in HTML (interactive), PDF, JSON, and CSV.
- **CI/CD Ready**: Designed for easy integration into GitHub Actions and build pipelines.
- **GitHub Action**: Available on the GitHub Marketplace for automated security scans.

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
