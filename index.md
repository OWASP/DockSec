---
layout: col-sidebar
title: OWASP DockSec
tags: docksec
level: 3
type: documentation
---

<p align="center">
  <a href="https://owasp.org/DockSec/"><img src="https://img.shields.io/badge/Lab-blue?&label=level&style=for-the-badge" alt="OWASP Lab"></a>
  <a href="https://owasp.org/DockSec/"><img src="https://img.shields.io/badge/Code-blue?label=type&style=for-the-badge" alt="OWASP Code"></a>
  <a href="https://owasp.slack.com/archives/C0APXGCUW7M"><img src="https://img.shields.io/badge/%23project--docksec-blue?label=slack&logoColor=white&style=for-the-badge" alt="Slack"></a>
  <a href="https://github.com/OWASP/DockSec/actions"><img src="https://img.shields.io/github/actions/workflow/status/OWASP/DockSec/python-app.yml?branch=main&style=for-the-badge&label=Build&color=blue" alt="Build Status"></a>
</p>

<p align="center">
  <a href="https://github.com/OWASP/DockSec/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="License"></a>
  <a href="https://github.com/OWASP/DockSec/commits/main/"><img src="https://img.shields.io/github/last-commit/OWASP/DockSec/main?color=blue&style=for-the-badge&label=Last%20commit" alt="Last Commit"></a>
  <a href="https://github.com/OWASP/DockSec/graphs/contributors"><img src="https://img.shields.io/github/contributors/OWASP/DockSec?style=for-the-badge&label=Contributors&color=blue" alt="Contributors"></a>
</p>

<p align="center">
  <a href="https://github.com/OWASP/DockSec/network/members"><img src="https://img.shields.io/github/forks/OWASP/DockSec?style=for-the-badge&label=Forks&color=blue" alt="Forks"></a>
  <a href="https://github.com/OWASP/DockSec/stargazers"><img src="https://img.shields.io/github/stars/OWASP/DockSec?style=for-the-badge&label=Stars&color=blue" alt="Stars"></a>
  <img src="https://img.shields.io/pepy/dt/docksec?style=for-the-badge&color=blue" alt="PyPI Downloads">
</p>

<p align="center">
  <a href="https://github.com/OWASP/DockSec/issues"><img src="https://img.shields.io/github/issues/OWASP/DockSec?color=blue&style=for-the-badge&label=Issues" alt="Issues"></a>
  <a href="https://github.com/OWASP/DockSec/pulls"><img src="https://img.shields.io/github/issues-pr/OWASP/DockSec?color=blue&style=for-the-badge&label=Pull%20Requests" alt="Pull Requests"></a>
</p>

<p align="center">
  <a href="https://github.com/OWASP/DockSec/commit/80664db8935e4b5ab44df5867913e"><img src="https://img.shields.io/badge/created-feb,%202025-blue?style=for-the-badge" alt="Created"></a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/OWASP/DockSec/main/images/docksec-logo-for-github.png" alt="DockSec Logo" width="600"><br>
  <img src="https://raw.githubusercontent.com/OWASP/DockSec/main/images/owasp-logo.png" alt="OWASP Logo" width="300">
</p>

<h1 align="center"><a href="https://owasp.org/DockSec/">DockSec</a></h1>

<p align="center"><strong>AI-powered Docker security scanner that explains vulnerabilities in plain English</strong></p>

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

## Features

- **Smart Analysis**: AI explains what vulnerabilities mean for *your* specific setup.
- **Multi-LLM Support**: Use OpenAI, Anthropic Claude, Google Gemini, or local models via Ollama.
- **Deep Integration**: Combines Trivy (vulnerabilities), Hadolint (linting), and Docker Scout.
- **Security Scoring**: Get a 0-100 score to track your security posture over time.
- **Rich Reporting**: Professional exports in HTML (interactive), PDF, JSON, and CSV.
- **CI/CD Ready**: Designed for easy integration into GitHub Actions and build pipelines.
- **GitHub Action**: Available on the GitHub Marketplace for automated security scans.

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
