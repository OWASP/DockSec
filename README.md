<div align="center">

[![OWASP](https://img.shields.io/badge/OWASP-Incubator%20Project-48A646?logo=owasp&style=for-the-badge)](https://owasp.org/www-project-docksec/)
[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](https://github.com/OWASP/DockSec/blob/main/LICENSE)
[![PyPI version](https://img.shields.io/pypi/v/docksec.svg?style=for-the-badge&color=blue)](https://pypi.org/project/docksec/)
[![Python Version](https://img.shields.io/pypi/pyversions/docksec.svg?style=for-the-badge&color=blue)](https://pypi.org/project/docksec/)

[![Build Status](https://img.shields.io/github/actions/workflow/status/OWASP/DockSec/python-app.yml?branch=main&style=for-the-badge&label=Build)](https://github.com/OWASP/DockSec/actions)
[![Contributors](https://img.shields.io/github/contributors/OWASP/DockSec?style=for-the-badge&label=Contributors&color=blue)](https://github.com/OWASP/DockSec/graphs/contributors)
[![Stars](https://img.shields.io/github/stars/OWASP/DockSec?style=for-the-badge&label=Stars&color=blue)](https://github.com/OWASP/DockSec/stargazers)
[![Issues](https://img.shields.io/github/issues/OWASP/DockSec?style=for-the-badge&label=Issues&color=blue)](https://github.com/OWASP/DockSec/issues)

<picture>
  <source srcset="https://raw.githubusercontent.com/OWASP/DockSec/main/images/docksec-logo-II.png" media="(prefers-color-scheme: dark)">
  <img src="https://raw.githubusercontent.com/OWASP/DockSec/main/images/docksec-logo-II.png" alt="DockSec Logo" width="200">
</picture>

# [DockSec](https://owasp.org/www-project-docksec/)

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

For questions or discussions, please join the [#project-docksec](https://owasp.slack.com/archives/C07M1C4JASK) channel on OWASP Slack.

---

## Quick Start

```bash
# Install DockSec
pip install docksec

# Scan a Dockerfile (AI-powered)
docksec Dockerfile

# Scan Dockerfile + Docker image
docksec Dockerfile -i myapp:latest
```

---

## Features

- **Smart Analysis**: AI explains what vulnerabilities mean for *your* specific setup.
- **Multi-LLM Support**: Use OpenAI, Anthropic Claude, Google Gemini, or local models via Ollama.
- **Deep Integration**: Combines Trivy (vulnerabilities), Hadolint (linting), and Docker Scout.
- **Security Scoring**: Get a 0-100 score to track your security posture over time.
- **Rich Reporting**: Professional exports in HTML (interactive), PDF, JSON, and CSV.
- **CI/CD Ready**: Designed for easy integration into GitHub Actions and build pipelines.

---

## Contributing

DockSec thrives on community contributions. Whether you are a developer, designer, or security enthusiast, there are many ways to get involved:

- **Code Contributions**: Fix bugs or add new features.
- **Documentation**: Improve guides or create tutorials.
- **Issue Reporting**: Identify and report bugs.
- **Feedback**: Share your experience and suggestions.

To get started, check out our [Contributing Guidelines](docs/CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Community and Social Media

- **OWASP Project Page**: [owasp.org/www-project-docksec/](https://owasp.org/www-project-docksec/)
- **OWASP Slack**: [#project-docksec](https://owasp.org/slack/invite)
- **PyPI**: [pypi.org/project/docksec/](https://pypi.org/project/docksec/)
- **Issues**: [Report a bug](https://github.com/OWASP/DockSec/issues)

---

<div align="center">
  <strong>If DockSec helps you, give it a ⭐ to help others discover it!</strong><br>
  Built with ❤️ by <a href="https://github.com/advaitpatel">Advait Patel</a> and the OWASP community.
</div>
