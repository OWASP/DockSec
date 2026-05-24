# Setup Guide - Choose Your Installation Method

This guide helps you choose the best installation method for your needs and walk you through the setup process.

## Decision Tree: Which Method Should I Use?

### Quick Flowchart

```
Do you want to scan Docker images frequently?
├─ YES, and I want zero setup → Docker Runner ✓
├─ YES, on multiple projects → Docker Runner ✓
├─ YES, in CI/CD pipelines → Docker Runner ✓
└─ NO, I'm a Python developer integrating into code → pip install ✓

Do you have Docker already installed?
├─ YES → Docker Runner is perfect
└─ NO → Either method works, Docker is easy to install
```

---

## Detailed Comparison

### Docker Runner (Recommended for Most Users)

**What it is:** Run DockSec in a Docker container. Everything is bundled inside.

**Pros:**
- ✅ Zero setup (just `docker run`)
- ✅ No system pollution
- ✅ Same results everywhere (Windows/Mac/Linux)
- ✅ Perfect for CI/CD
- ✅ Easy to update (just pull new image)
- ✅ No version conflicts with other projects
- ✅ Ideal for quick scans

**Cons:**
- ❌ Requires Docker to be installed
- ❌ Can't import DockSec in Python code
- ❌ Slightly slower first run (image pulls)

**Best for:**
- DevOps engineers
- CI/CD pipelines
- Quick security reviews
- Teams using different operating systems
- One-off scans

---

### pip install (Traditional Python Installation)

**What it is:** Install DockSec as a Python package on your system.

**Pros:**
- ✅ Can import DockSec in Python code
- ✅ Integrated with Python ecosystem
- ✅ Can customize easier
- ✅ No Docker required

**Cons:**
- ❌ Requires 10+ manual setup steps
- ❌ Different setup for each OS
- ❌ Can have version conflicts
- ❌ Trivy/Hadolint versions can mismatch
- ❌ System gets cluttered
- ❌ Slow first run

**Best for:**
- Python developers
- Custom integrations
- Advanced use cases
- Single machine setups

---

## Installation Methods

### Method 1: Docker Runner (Recommended & Fastest Setup)

#### Requirements
- Docker Desktop installed
- That's it!

#### Step 1: Install Docker (if needed)

**macOS & Windows:**
1. Go to https://www.docker.com/products/docker-desktop
2. Download and install
3. Launch Docker Desktop
4. Wait for it to fully start (icon shows in menu bar)

**Linux:**
```bash
sudo apt-get update
sudo apt-get install docker.io
sudo systemctl start docker
```

#### Step 2: Verify Docker Works
```bash
docker run hello-world
# Should show: "Hello from Docker!"
```

#### Step 3: Run DockSec (First Time)
```bash
# Scan an image
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  owasp/docksec:latest \
  --image-only -i python:3.12
```

**That's it!** Docker automatically pulls the image and runs your scan.

#### Step 4 (Optional): Use the Wrapper Script for Easier Commands

```bash
# Download the script
curl -o docker-runner.sh https://raw.githubusercontent.com/OWASP/DockSec/main/docker-runner.sh
chmod +x docker-runner.sh

# Use it
./docker-runner.sh --help
SCAN_DIR=. IMAGE_NAME=myapp:latest ./docker-runner.sh
```

---

### Method 2: pip install (Traditional)

#### Requirements
- Python 3.12 or higher
- Docker (for scanning images)
- Trivy (vulnerability scanner)
- Hadolint (Dockerfile linter)

#### Step 1: Verify Python Version
```bash
python3 --version
# Should show: Python 3.12.x or higher

# If not, install Python 3.12:
# macOS: brew install python@3.12
# Linux: sudo apt-get install python3.12
# Windows: Download from python.org
```

#### Step 2: Install System Dependencies

**macOS:**
```bash
# Install Trivy
brew install trivy

# Install Hadolint
brew install hadolint

# Install Docker (for scanning images)
brew install docker
```

**Linux:**
```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasec/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Hadolint
curl -sL -o /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64
chmod +x /usr/local/bin/hadolint

# Install Docker
sudo apt-get install docker.io
sudo systemctl start docker
```

**Windows:**
1. Download Trivy from: https://github.com/aquasec/trivy/releases
2. Download Hadolint from: https://github.com/hadolint/hadolint/releases
3. Add both to your PATH
4. Install Docker Desktop from: https://www.docker.com/products/docker-desktop

#### Step 3: Install DockSec via pip
```bash
pip install docksec
```

#### Step 4: Verify Installation
```bash
docksec --version
# Should show: DockSec 2026.5.22.3 (or similar)

# Test it
docksec --image-only -i python:3.12
```

---

## Scenario-Based Recommendations

### Scenario 1: "I just want to quickly scan an image"
**Recommendation:** Docker Runner
```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  owasp/docksec:latest --image-only -i myapp:latest
```
Time to first scan: 2 minutes (if Docker already installed)

### Scenario 2: "I'm a DevOps engineer managing CI/CD pipelines"
**Recommendation:** Docker Runner
```yaml
- name: Scan with DockSec
  run: |
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
      -v $(pwd):/scan owasp/docksec:latest /scan/Dockerfile -i myapp:latest
```
Benefit: Same code works in GitHub Actions, GitLab CI, Jenkins, etc.

### Scenario 3: "I'm a Python developer building tools"
**Recommendation:** pip install
```python
import subprocess
result = subprocess.run(['docksec', '--image-only', '-i', 'myapp:latest'])
```
Benefit: Can integrate into Python applications

### Scenario 4: "I manage a development team"
**Recommendation:** Docker Runner for team consistency
Everyone runs: `docker run owasp/docksec:latest ...`

Benefit: 
- No "works on my machine" issues
- All team members get identical results
- Easy onboarding for new developers

### Scenario 5: "I use multiple Docker-based tools"
**Recommendation:** Docker Runner
All your tools are already in containers, DockSec fits naturally

### Scenario 6: "My company only allows pip packages"
**Recommendation:** pip install
```bash
pip install docksec
docksec --image-only -i myapp:latest
```

---

## Post-Installation

### For Docker Runner Users

**1. Create a convenient alias:**
```bash
# Add to ~/.bashrc or ~/.zshrc
alias docksec='docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd):/scan \
  -v $(pwd)/results:/scan/results \
  owasp/docksec:latest'

# Then just use: docksec Dockerfile -i myapp:latest
```

**2. Create results directory:**
```bash
mkdir -p results
chmod 777 results
```

**3. Set up API keys (optional, for AI features):**
```bash
export OPENAI_API_KEY="sk-your-key"
# Now scans will have AI analysis
```

### For pip install Users

**1. Verify all tools are installed:**
```bash
docksec --version
trivy --version
hadolint --version
docker --version
```

**2. Set up API keys (optional):**
```bash
export OPENAI_API_KEY="sk-your-key"
```

**3. Create results directory:**
```bash
mkdir -p ~/.docksec/results
```

---

## Next Steps

1. **Choose your method** (Docker Runner recommended for most)
2. **Follow the installation steps above**
3. **Run your first scan:** See [QUICK_START.md](QUICK_START.md)
4. **Set up API Keys:** See [API_KEYS_SETUP.md](API_KEYS_SETUP.md) (optional)
5. **Learn advanced features:** See [../docs/DOCKER_USAGE.md](../docs/DOCKER_USAGE.md)

---

## Troubleshooting Installation

### "Python 3.12 not found" (pip install)
```bash
# Check your Python version
python3 --version

# If you have 3.11, you need 3.12:
# macOS: brew install python@3.12
# Linux: sudo apt-get install python3.12
# Windows: Download from python.org
```

### "Trivy not found" (pip install)
```bash
# Install Trivy:
# macOS: brew install trivy
# Linux: curl -sfL https://raw.githubusercontent.com/aquasec/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
# Windows: Download from GitHub releases
```

### "Docker daemon not running" (both methods)
```bash
# macOS: Open Docker Desktop from Applications
# Linux: sudo systemctl start docker
# Windows: Start Docker Desktop
```

### "Permission denied on Docker socket" (Docker Runner)
```bash
# Add your user to docker group (Linux):
sudo usermod -aG docker $USER
# Log out and log back in

# Or run with sudo (not recommended):
sudo docker run ...
```

### "pip: command not found"
```bash
# Ensure pip is installed:
python3 -m pip --version

# If not, install:
python3 -m ensurepip
```

---

## Uninstalling

### Docker Runner
```bash
# Remove image (optional)
docker rmi owasp/docksec:latest

# Nothing else to remove!
```

### pip install
```bash
# Remove package
pip uninstall docksec

# Remove system dependencies (optional):
# macOS: brew uninstall trivy hadolint
# Linux: sudo apt-get remove trivy hadolint
```

---

## Getting Help

- **Installation issues?** Check the Troubleshooting section above
- **General questions?** See [FAQ.md](FAQ.md)
- **Need help with Docker?** See [../docs/DOCKER_USAGE.md](../docs/DOCKER_USAGE.md)
- **Found a bug?** Report at https://github.com/OWASP/DockSec/issues
