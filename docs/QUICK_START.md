# Quick Start Guide - Get Started in 2 Minutes

The fastest way to scan your Docker images for security vulnerabilities.

## Option 1: Docker Runner (Recommended - No Setup Required)

### Step 1: Verify Docker is Running
```bash
docker --version
# Should show: Docker version X.X.X
```

If Docker isn't installed, go to https://www.docker.com/products/docker-desktop

### Step 2: Run Your First Scan
```bash
# Scan a Docker image (fastest)
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  owasp/docksec:latest \
  --image-only -i python:3.12
```

**What happens:** DockSec scans the `python:3.12` image and shows you vulnerabilities.

### Step 3: Get Full Analysis with Results Saved
```bash
# Create results folder
mkdir -p results

# Scan with full analysis
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd):/scan \
  -v $(pwd)/results:/scan/results \
  -e OPENAI_API_KEY="sk-your-api-key-here" \
  owasp/docksec:latest \
  /scan/Dockerfile -i myapp:latest
```

**Results saved to:** `./results/security_report.json` (and HTML, PDF versions)

---

## Option 2: pip install (For Python Developers)

### Step 1: Install DockSec
```bash
pip install docksec
```

### Step 2: Run Your First Scan
```bash
docksec --image-only -i python:3.12
```

### Step 3: Full Analysis
```bash
docksec Dockerfile -i myapp:latest
```

---

## Next Steps

| Goal | Guide |
|------|-------|
| **Compare pip vs Docker** | Read [SETUP_GUIDE.md](SETUP_GUIDE.md) |
| **Set up API Keys** | Read [API_KEYS_SETUP.md](API_KEYS_SETUP.md) |
| **Understand Docker Runner** | Read [../docs/DOCKER_USAGE.md](../docs/DOCKER_USAGE.md) |
| **Have Questions?** | Check [FAQ.md](FAQ.md) |
| **Try Examples** | See [examples/](examples/) |

---

## What is DockSec Scanning?

DockSec checks your Docker images for:
- 🔴 **Critical Vulnerabilities** - Security flaws that need immediate attention
- 🟠 **High-Risk Issues** - Exploitable vulnerabilities in dependencies
- 🟡 **Medium Issues** - Potential security problems to address
- 🔵 **Best Practices** - Dockerfile improvements and security hardening

---

## Common Commands

```bash
# Scan image only (fastest)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  owasp/docksec:latest --image-only -i myapp:latest

# Analyze Dockerfile only (no image needed)
docker run --rm -v $(pwd):/scan \
  owasp/docksec:latest --ai-only /scan/Dockerfile

# Full analysis with API key
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd):/scan \
  -v $(pwd)/results:/scan/results \
  -e OPENAI_API_KEY="your-key" \
  owasp/docksec:latest /scan/Dockerfile -i myapp:latest

# Using wrapper script
./docker-runner.sh
```

---

## Troubleshooting Quick Fixes

### "Docker socket not found"
```bash
# Make sure Docker is running:
# macOS: Open Docker Desktop
# Linux: sudo systemctl start docker
# Windows: Start Docker Desktop
```

### "Cannot connect to Docker daemon"
```bash
# Add your user to docker group:
sudo usermod -aG docker $USER
# Log out and log back in
```

### "Image not found"
```bash
# Pull the image first:
docker pull myapp:latest

# Then scan it:
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  owasp/docksec:latest --image-only -i myapp:latest
```

### "Permission denied on results directory"
```bash
# Create results directory with proper permissions:
mkdir -p results
chmod 777 results
```

---

## Getting Help

- **Questions?** Check [FAQ.md](FAQ.md)
- **Setup issues?** See [SETUP_GUIDE.md](SETUP_GUIDE.md)
- **Docker problems?** See [../docs/DOCKER_USAGE.md#troubleshooting](../docs/DOCKER_USAGE.md#troubleshooting)
- **Bug report?** Visit https://github.com/OWASP/DockSec/issues

---

## What's Next?

1. **Scan your first image** (try the Quick Start above)
2. **Set up API keys** if you want AI-powered analysis (see [API_KEYS_SETUP.md](API_KEYS_SETUP.md))
3. **Integrate into CI/CD** (see [../docs/DOCKER_USAGE.md#cicd-integration](../docs/DOCKER_USAGE.md#cicd-integration))
4. **Share results with team** (use generated reports)
