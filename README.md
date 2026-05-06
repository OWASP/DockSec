[![GitHub Repo stars](https://img.shields.io/github/stars/advaitpatel/DockSec?style=flat)](https://github.com/advaitpatel/DockSec)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI version](https://img.shields.io/pypi/v/docksec.svg)](https://pypi.org/project/docksec/)
[![Python Version](https://img.shields.io/pypi/pyversions/docksec.svg)](https://pypi.org/project/docksec/)
[![OWASP Incubator](https://img.shields.io/badge/OWASP-Incubator%20Project-48A646?logo=owasp)](https://owasp.org/www-project-docksec/)

<div align="center">
  <img src="https://github.com/advaitpatel/DockSec/blob/main/images/docksec-logo-II.png" alt="DockSec" height="120">
  
  <h1>DockSec</h1>
  <p><strong>AI-powered Docker security scanner that explains vulnerabilities in plain English</strong></p>
  
  <p>
    <a href="#quick-start">Quick Start</a> •
    <a href="#features">Features</a> •
    <a href="#installation">Installation</a> •
    <a href="#usage">Usage</a> •
    <a href="docs/CONTRIBUTING.md">Contributing</a> •
    <a href="docs/CHANGELOG.md">Changelog</a>
  </p>
  
  <br>
  
  <p>
    <a href="https://owasp.org/www-project-docksec/">
      <img src="images/owasp-logo.png" alt="OWASP" height="60">
    </a>
  </p>
  <p><strong>🏆 Officially recognized as an OWASP Incubator Project</strong></p>
  <p>Trusted by the global security community • 14,000+ downloads</p>
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

### Why OWASP Recognition Matters

Being recognized as an [OWASP Incubator Project](https://owasp.org/www-project-docksec/) means:
- ✅ **Vetted** by security professionals for quality and impact.
- ✅ **Community-driven** development and open governance.
- ✅ **Trusted** by enterprises and security teams worldwide.
- ✅ **Transparent** security practices and open-source maintenance.

---

## How It Works

<div align="center">
  <img src="images/workflow.png" alt="DockSec Workflow" width="800">
  <p><em>DockSec workflow: From scanning to actionable insights</em></p>
</div>

DockSec follows a robust four-stage pipeline:
1. **Scan**: Runs Trivy, Hadolint, and Docker Scout locally on your environment.
2. **Analyze**: AI correlates findings across all scanners to remove noise and assess real-world impact.
3. **Recommend**: Generates human-readable explanations and specific remediation steps.
4. **Report**: Exports actionable results in JSON, PDF, HTML, or Markdown formats.

---

## Quick Start

```bash
# Install DockSec
pip install docksec

# Scan a Dockerfile (AI-powered)
docksec Dockerfile

# Scan Dockerfile + Docker image
docksec Dockerfile -i myapp:latest

# Scan without AI (offline mode, no API key needed)
docksec Dockerfile --scan-only
```

---

## Features

- **Smart Analysis**: AI explains what vulnerabilities mean for *your* specific setup.
- **Multi-LLM Support**: Use OpenAI, Anthropic Claude, Google Gemini, or local models via Ollama.
- **Deep Integration**: Combines Trivy (vulnerabilities), Hadolint (linting), and Docker Scout.
- **Security Scoring**: Get a 0-100 score to track your security posture over time.
- **Rich Reporting**: Professional exports in HTML (interactive), PDF, JSON, and CSV.
- **Privacy First**: All scanning happens locally. Only scan metadata is sent to AI providers.
- **CI/CD Ready**: Designed for easy integration into GitHub Actions and build pipelines.

---

## Installation

### 1. Install via Pip
Requires **Python 3.12+** and **Docker** (for image scanning).

```bash
pip install docksec
```

### 2. Configure AI Provider (Optional)
Choose your preferred LLM provider by setting the appropriate environment variable:

#### OpenAI (Default)
```bash
export OPENAI_API_KEY="your-key-here"
```

#### Anthropic Claude
```bash
export ANTHROPIC_API_KEY="your-key-here"
export LLM_PROVIDER="anthropic"
export LLM_MODEL="claude-3-5-sonnet-20241022"
```

#### Google Gemini
```bash
export GOOGLE_API_KEY="your-key-here"
export LLM_PROVIDER="google"
export LLM_MODEL="gemini-1.5-pro"
```

#### Ollama (Local Models - No API Key Needed)
```bash
# Install Ollama from https://ollama.ai
export LLM_PROVIDER="ollama"
export LLM_MODEL="llama3.1"
```

### 3. Install External Scanners (Optional)
To enable full vulnerability and linting support:

```bash
# Automatically install Trivy and Hadolint
python -m docksec.setup_external_tools
```

---

## Usage

### Common Commands

```bash
# Basic Dockerfile analysis
docksec Dockerfile

# Full analysis (Dockerfile + Image)
docksec Dockerfile -i nginx:latest

# Image-only scan (no Dockerfile needed)
docksec --image-only -i nginx:latest

# Use a specific AI model
docksec Dockerfile --provider anthropic --model claude-3-5-sonnet-20241022

# Save report to a custom path
docksec Dockerfile -o my_report.html
```

### CLI Options

| Option | Description |
|--------|-------------|
| `dockerfile` | Path to the Dockerfile to analyze |
| `-i, --image` | Docker image name to scan |
| `-o, --output` | Custom output file path |
| `--provider` | LLM provider (openai, anthropic, google, ollama) |
| `--model` | Specific model name to use |
| `--ai-only` | Run AI analysis only (requires Dockerfile) |
| `--scan-only` | Run security scanners only (no AI) |
| `--image-only` | Scan image without Dockerfile analysis |
| `--version` | Show version information |

---

## Configuration

You can customize DockSec via environment variables or a `.env` file:

```bash
# LLM Settings
LLM_PROVIDER=openai           # openai, anthropic, google, ollama
LLM_MODEL=gpt-4o              # Model name
LLM_TEMPERATURE=0.0           # Creativity (0.0 recommended for security)

# Results & Timeouts
DOCKSEC_RESULTS_DIR=./results # Where to save reports
TRIVY_SCAN_TIMEOUT=600        # Timeout for image scans
```

---

## Example Output

```text
🔍 Scanning Dockerfile...
⚠️  Security Score: 45/100

Critical Issues (3):
  • Running as root user (line 12)
  • Hardcoded API key detected (line 23)
  • Using vulnerable base image (ubuntu:20.04)

💡 AI Recommendations:
  1. Add non-root user: RUN useradd -m appuser && USER appuser
  2. Move secrets to environment variables or build secrets.
  3. Update FROM ubuntu:20.04 to ubuntu:22.04 (fixes 12 CVEs).

📊 Full report generated: results/nginx_latest_security_report.html
```

---

## Roadmap

- [x] Multi-LLM support (OpenAI, Anthropic, Google, Ollama)
- [x] Professional HTML/PDF report generation
- [ ] Docker Compose multi-service scanning
- [ ] Kubernetes manifest analysis
- [ ] GitHub Action for automated PR reviews
- [ ] Custom security policy enforcement

---

## Troubleshooting

**"No API Key provided"**  
→ Set your API key (e.g., `OPENAI_API_KEY`) or use `--scan-only` mode.

**"Hadolint/Trivy not found"**  
→ Run `python -m docksec.setup_external_tools` to install them automatically.

**"Python version not supported"**  
→ DockSec requires Python 3.12+. We recommend using `pyenv` or `conda` to manage versions.

**"Connection refused" with Ollama**  
→ Ensure the Ollama daemon is running (`ollama serve`) and you have pulled the model (`ollama pull llama3.1`).

---

## Recognition & Community

<div align="center">
  <a href="https://owasp.org/www-project-docksec/">
    <img src="images/owasp-logo.png" alt="OWASP" height="80">
  </a>
</div>

DockSec is proud to be an **OWASP Incubator Project**. Our mission is to make container security accessible, understandable, and actionable for every developer.

### Links
- **OWASP Project Page**: [owasp.org/www-project-docksec/](https://owasp.org/www-project-docksec/)
- **PyPI**: [pypi.org/project/docksec/](https://pypi.org/project/docksec/)
- **Issues**: [Report a bug](https://github.com/advaitpatel/DockSec/issues)
- **Discussions**: [Join the community](https://github.com/advaitpatel/DockSec/discussions)

---

<div align="center">
  <strong>If DockSec helps you, give it a ⭐ to help others discover it!</strong><br>
  Built with ❤️ by <a href="https://github.com/advaitpatel">Advait Patel</a> and the OWASP community.
</div>
