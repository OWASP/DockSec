# Docker Runner Guide for DockSec

DockSec can be run entirely within a Docker container, eliminating the need to install Trivy, Hadolint, Docker CLI, and other dependencies on your host system.

## Table of Contents

- [Why Docker Runner?](#why-docker-runner)
- [Quick Start](#quick-start)
- [Step-by-Step Tutorial](#step-by-step-tutorial)
- [Installation](#installation)
- [Usage Examples](#usage-examples)
  - [Basic Docker Run](#basic-docker-run)
  - [With Docker Compose](#with-docker-compose)
  - [Using the Wrapper Script](#using-the-wrapper-script)
- [Volume Mounting](#volume-mounting)
- [Environment Variables](#environment-variables)
- [Troubleshooting](#troubleshooting)
- [Performance & Optimization](#performance--optimization)
- [CI/CD Integration](#cicd-integration)

---

## Why Docker Runner?

The Docker Runner is the **recommended way** to use DockSec for several reasons:

1.  **Zero Installation**: No need to manually install Trivy, Hadolint, or manage Python versions. Everything is pre-configured inside the image.
2.  **Consistency**: Ensures the exact same versions of scanners are used across your entire team and CI/CD pipelines.
3.  **Security Isolation**: The scanner runs in its own isolated environment, minimizing impact on your host system.
4.  **Easy Updates**: Simply pull the latest image to get the newest security definitions and features.
5.  **Cross-Platform**: Works identically on Linux, macOS, and Windows.

---

## Quick Start

### Scan a Docker Image

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  owasp/docksec:latest \
  --image-only -i myapp:latest
```

### Scan Dockerfile and Image

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd):/scan \
  -v $(pwd)/results:/scan/results \
  owasp/docksec:latest \
  /scan/Dockerfile -i myapp:latest
```

### Save Results to Host

```bash
mkdir -p results

docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/Dockerfile:/scan/Dockerfile \
  -v $(pwd)/results:/scan/results \
  owasp/docksec:latest \
  /scan/Dockerfile -i myapp:latest \
  -o /scan/results/security_report
```

---

## Step-by-Step Tutorial: Your First Scan

Follow these steps to perform a full security analysis of a local project.

### 1. Prepare Your Environment
Ensure you have a `Dockerfile` in your current directory and a built image you want to scan.

```bash
# Example: Build your image first
docker build -t myapp:latest .
```

### 2. Create a Results Directory
DockSec needs a place to save the generated reports.

```bash
mkdir -p results
# On Linux, ensure it's writable by the container
chmod 777 results
```

### 3. Run the Scan
Run the following command, replacing `myapp:latest` with your image name.

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd):/scan \
  -v $(pwd)/results:/scan/results \
  -e OPENAI_API_KEY="your-api-key-here" \
  owasp/docksec:latest \
  /scan/Dockerfile -i myapp:latest
```

### 4. View Your Results
Once finished, check the `results` folder for your reports:
- `security_report.html`: Open this in your browser for an interactive experience.
- `security_report.json`: Use this for automated processing.
- `security_report.pdf`: Perfect for sharing with stakeholders.

---

## Installation

### Pull from Docker Registry

```bash
docker pull owasp/docksec:latest
```

### Build Locally

```bash
git clone https://github.com/OWASP/DockSec.git
cd DockSec
docker build -t docksec:dev .
```

---

## Usage Examples

### Basic Docker Run

#### Scan Only a Docker Image

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  owasp/docksec:latest \
  --image-only -i myapp:latest
```

**What it does:**
- Scans the `myapp:latest` image using Trivy and Docker Scout
- No Dockerfile analysis
- No AI analysis (use `--ai-only` or provide Dockerfile for AI)

#### Scan Dockerfile Only (AI Analysis)

```bash
docker run --rm \
  -v $(pwd)/Dockerfile:/scan/Dockerfile \
  -v $(pwd)/results:/scan/results \
  -e OPENAI_API_KEY="your-api-key" \
  owasp/docksec:latest \
  --ai-only /scan/Dockerfile
```

**What it does:**
- Analyzes Dockerfile using AI
- No image scanning (faster analysis)
- Provides security recommendations based on Dockerfile content

#### Full Analysis (Dockerfile + Image)

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd):/scan \
  -v $(pwd)/results:/scan/results \
  -e OPENAI_API_KEY="your-api-key" \
  owasp/docksec:latest \
  /scan/Dockerfile -i myapp:latest
```

**What it does:**
- Analyzes Dockerfile with AI
- Scans Docker image with Trivy/Docker Scout
- Correlates findings from both sources
- Generates comprehensive security report

### With Docker Compose

```bash
# Set environment variables
export OPENAI_API_KEY="your-key"
export IMAGE_NAME="myapp:latest"

# Run with compose
docker-compose up docksec

# View results
cat results/security_report.json
```

Edit `docker-compose.yml` to customize:
- Image name to scan
- Dockerfile location
- Results directory
- API keys and LLM provider

### Using the Wrapper Script

The `docker-runner.sh` script simplifies Docker command construction:

```bash
# Make script executable
chmod +x docker-runner.sh

# Scan image
SCAN_DIR=. IMAGE_NAME=myapp:latest ./docker-runner.sh

# Scan with custom results directory
SCAN_DIR=. \
  IMAGE_NAME=myapp:latest \
  RESULTS_DIR=/tmp/reports \
  ./docker-runner.sh

# Verbose output
./docker-runner.sh --verbose
```

The wrapper script:
- Handles Docker socket mounting automatically
- Validates Docker daemon is running
- Creates results directory if needed
- Passes through environment variables (API keys)
- Provides helpful error messages

---

## Volume Mounting

### Docker Socket (Required for Image Scanning)

```bash
-v /var/run/docker.sock:/var/run/docker.sock
```

- **Purpose:** Allows container to access host Docker daemon
- **Mode:** Read-only is recommended (`:ro`) for security
- **Why needed:** To scan existing Docker images

### Dockerfile Input

```bash
# Mount entire directory
-v $(pwd):/scan

# OR mount specific file
-v $(pwd)/Dockerfile:/scan/Dockerfile:ro
```

- **Purpose:** Provide Dockerfile to container
- **Mode:** Read-only (`:ro`) is recommended
- **Path in container:** `/scan/Dockerfile` or `/scan/<path>`

### Results Output

```bash
-v $(pwd)/results:/scan/results
```

- **Purpose:** Save security reports on host machine
- **Files generated:**
  - `security_report.json` - Structured vulnerability data
  - `security_report.html` - Interactive HTML report
  - `security_report.pdf` - Printable PDF report
  - `security_report.md` - Markdown report

### Complete Volume Example

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v $(pwd)/Dockerfile:/scan/Dockerfile:ro \
  -v $(pwd)/results:/scan/results \
  owasp/docksec:latest \
  /scan/Dockerfile -i myapp:latest
```

---

## Environment Variables

### API Keys

```bash
# OpenAI
-e OPENAI_API_KEY="sk-..."

# Anthropic
-e ANTHROPIC_API_KEY="sk-ant-..."

# Google
-e GOOGLE_API_KEY="AIza..."

# Ollama (local)
# Set OLLAMA_BASE_URL if using local Ollama instance
-e OLLAMA_BASE_URL="http://localhost:11434"
```

### LLM Configuration

```bash
# Specify provider
-e LLM_PROVIDER="openai"  # openai, anthropic, google, ollama

# Specify model
-e LLM_MODEL="gpt-4o"     # or claude-3-5-sonnet, gemini-1.5-pro, etc.
```

### DockSec Options

```bash
# Enable/disable cache
-e DOCKSEC_USE_CACHE="true"

# Compact output
-e DOCKSEC_COMPACT_OUTPUT="false"
```

### Complete Environment Example

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v $(pwd):/scan \
  -v $(pwd)/results:/scan/results \
  -e OPENAI_API_KEY="sk-..." \
  -e LLM_PROVIDER="openai" \
  -e LLM_MODEL="gpt-4o" \
  -e DOCKSEC_USE_CACHE="true" \
  owasp/docksec:latest \
  /scan/Dockerfile -i myapp:latest
```

---

## Troubleshooting

### Docker Socket Not Found

**Error:** `Docker socket not found at /var/run/docker.sock`

**Causes & Solutions:**

1. **Docker daemon not running**
   ```bash
   # Linux
   sudo systemctl start docker
   
   # macOS
   open /Applications/Docker.app
   
   # Windows
   # Start Docker Desktop from Applications
   ```

2. **Socket in different location (macOS/Windows)**
   ```bash
   # macOS with Docker Desktop
   ls -la ~/.docker/run/docker.sock
   
   # Mount from correct location
   -v ~/.docker/run/docker.sock:/var/run/docker.sock
   ```

3. **Permission denied**
   ```bash
   # Add user to docker group (Linux)
   sudo usermod -aG docker $USER
   sudo newgrp docker
   
   # OR run with sudo (not recommended)
   sudo docker run ...
   ```

### Cannot Connect to Docker Daemon

**Error:** `Cannot connect to the Docker daemon`

**Solutions:**

```bash
# Check Docker status
docker ps

# Check socket permissions
ls -la /var/run/docker.sock

# Ensure you have access
docker run hello-world

# If all else fails, try with sudo (not recommended for security)
sudo docker-runner.sh
```

### Dockerfile Not Found in Container

**Error:** `No such file or directory: /scan/Dockerfile`

**Solution:**

```bash
# Ensure Dockerfile is mounted correctly
docker run --rm \
  -v $(pwd)/Dockerfile:/scan/Dockerfile \
  owasp/docksec:latest \
  /scan/Dockerfile ...

# Verify mounting
docker run --rm \
  -v $(pwd):/scan \
  owasp/docksec:latest \
  ls -la /scan/
```

### Results Directory Not Writable

**Error:** `Permission denied: /scan/results`

**Solution:**

```bash
# Ensure results directory exists and is writable
mkdir -p results
chmod 777 results

# OR specify with correct permissions
docker run --rm \
  -v $(pwd)/results:/scan/results:rw \
  ...
```

### API Key Not Recognized

**Error:** `Invalid API key` or `Authentication failed`

**Solutions:**

```bash
# Check key is exported correctly
echo $OPENAI_API_KEY  # Should print your key

# Verify it's passed to container
docker run --rm \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -e DEBUG=true \
  owasp/docksec:latest ...

# Use .env file with docker compose
# Create .env file
echo "OPENAI_API_KEY=sk-..." > .env
docker-compose up
```

### Image Not Found in Docker

**Error:** `Docker image 'myapp:latest' not found locally`

**Solution:**

```bash
# Build image first
docker build -t myapp:latest .

# OR pull from registry
docker pull myapp:latest

# Verify image exists
docker images | grep myapp

# Then scan
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  owasp/docksec:latest \
  --image-only -i myapp:latest
```

### Running on macOS with Docker Desktop

Docker Desktop stores the socket in a different location:

```bash
# For Docker Desktop on macOS
docker run --rm \
  -v ~/.docker/run/docker.sock:/var/run/docker.sock:ro \
  owasp/docksec:latest \
  --image-only -i myapp:latest

# Or use docker-runner.sh with custom socket
# Update docker-runner.sh DOCKER_SOCKET variable
```

---

## Performance & Optimization

### Caching Scan Results

DockSec caches results by default to avoid re-scanning the same image:

```bash
# Use cache (default)
-e DOCKSEC_USE_CACHE="true"

# Disable cache (always scan)
-e DOCKSEC_USE_CACHE="false"

# Clear cache
docker run --rm \
  -v $(pwd)/results:/scan/results \
  owasp/docksec:latest \
  docksec --image-only -i myapp:latest --cache-clear
```

### Reducing Output Verbosity

```bash
# Compact output (less verbose)
-e DOCKSEC_COMPACT_OUTPUT="true"

# Or use CLI flag
docker run --rm \
  owasp/docksec:latest \
  /scan/Dockerfile --compact-output
```

### Skip AI Analysis for Faster Scans

```bash
# Security scan only (no AI)
docker run --rm \
  owasp/docksec:latest \
  --scan-only -i myapp:latest

# AI analysis only (no scanning)
docker run --rm \
  owasp/docksec:latest \
  --ai-only /scan/Dockerfile
```

### Memory & CPU Limits

```bash
# Limit resources
docker run --rm \
  --memory=2g \
  --cpus=2 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  owasp/docksec:latest \
  --image-only -i myapp:latest
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Container Security Scan

on: [push, pull_request]

jobs:
  docksec:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Docker Image
        run: docker build -t myapp:test .
      
      - name: Run DockSec Scan
        run: |
          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v $(pwd):/scan \
            -v $(pwd)/results:/scan/results \
            -e OPENAI_API_KEY=${{ secrets.OPENAI_API_KEY }} \
            owasp/docksec:latest \
            /scan/Dockerfile -i myapp:test
      
      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: docksec-results
          path: results/
```

### GitLab CI

```yaml
docksec:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker pull owasp/docksec:latest
    - docker run --rm
        -v /var/run/docker.sock:/var/run/docker.sock
        -v $(pwd):/scan
        -v $(pwd)/results:/scan/results
        -e OPENAI_API_KEY=$OPENAI_API_KEY
        owasp/docksec:latest
        /scan/Dockerfile -i $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  artifacts:
    paths:
      - results/
```

### Jenkins

```groovy
pipeline {
    agent any
    
    stages {
        stage('DockSec Scan') {
            steps {
                sh '''
                    docker run --rm \
                      -v /var/run/docker.sock:/var/run/docker.sock \
                      -v ${WORKSPACE}:/scan \
                      -v ${WORKSPACE}/results:/scan/results \
                      -e OPENAI_API_KEY=${OPENAI_API_KEY} \
                      owasp/docksec:latest \
                      /scan/Dockerfile -i myapp:${BUILD_NUMBER}
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'results/**', allowEmptyArchive: true
        }
    }
}
```

### Docker Compose (Development)

```bash
# Create .env file
cat > .env << EOF
OPENAI_API_KEY=your-key-here
IMAGE_NAME=myapp:latest
EOF

# Run scan
docker-compose up docksec

# View results
ls results/
```

---

## Advanced Usage

### Custom LLM Provider

```bash
# Use local Ollama instance
docker run --rm \
  --network host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e LLM_PROVIDER="ollama" \
  -e OLLAMA_BASE_URL="http://localhost:11434" \
  owasp/docksec:latest \
  --image-only -i myapp:latest
```

### Multiple Images

```bash
# Scan multiple images
for image in myapp:latest nginx:latest python:3.12; do
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v $(pwd)/results/${image}:/scan/results \
    owasp/docksec:latest \
    --image-only -i $image
done
```

### Scan Private Registry Images

```bash
# Ensure image is pulled/authenticated first
docker pull my-registry.com/myapp:latest

# Then scan
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  owasp/docksec:latest \
  --image-only -i my-registry.com/myapp:latest
```

---

## Getting Help

- **GitHub Issues:** https://github.com/OWASP/DockSec/issues
- **OWASP Slack:** #project-docksec
- **Documentation:** https://github.com/OWASP/DockSec/blob/main/README.md
