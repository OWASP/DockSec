# Frequently Asked Questions (FAQ)

Quick answers to common questions about DockSec.

---

## Getting Started

### Q: What does DockSec do?
**A:** DockSec scans your Docker images for security vulnerabilities and provides AI-powered explanations and fixes. It combines three industry-standard scanners (Trivy, Hadolint, Docker Scout) and uses AI to help you understand and fix security issues.

### Q: Do I need to understand Docker to use DockSec?
**A:** No! You just need to have Docker installed. DockSec works with any Docker image. Basic familiarity helps, but not required.

### Q: How long does a scan take?
**A:** 
- First scan: 30-60 seconds (image download + scan)
- Subsequent scans: 5-15 seconds (with caching)
- Faster scans available: `--scan-only` (skip AI analysis)

### Q: Can I use DockSec without Docker?
**A:** With `pip install`, you can scan Dockerfiles without Docker. But to scan actual Docker images, you need Docker. For pure Docker runner, yes, Docker is required.

### Q: Is DockSec free?
**A:** 
- Basic scanning: Free (uses open-source scanners)
- AI analysis: Requires API key from LLM provider (usually $0.02-0.05 per scan)
- Local AI (Ollama): Free and runs on your machine

---

## Installation & Setup

### Q: Which installation method should I use?
**A:** 
- **Docker Runner** (recommended): `docker run owasp/docksec:latest` - Zero setup, best for most users. It bundles all security tools (Trivy, Hadolint) so you don't have to install them manually.
- **pip install**: `pip install docksec` - For Python developers or when Docker isn't available.

See [SETUP_GUIDE.md](SETUP_GUIDE.md) for detailed comparison.

### Q: Is the Docker Runner secure?
**A:** Yes. While it requires access to the Docker socket to scan images, the container itself is isolated. We recommend mounting the socket as read-only (`:ro`) where possible for extra security.

### Q: Why does Docker Runner require Docker?
**A:** Docker Runner IS a Docker container. It bundles everything (Trivy, Hadolint, DockSec) together. You can't run a Docker container without Docker installed.

### Q: Do I need to install Trivy or Hadolint separately?
**A:** 
- With **Docker Runner**: No, they're already inside the image
- With **pip install**: Yes, you need to install them separately

### Q: How do I install Docker?
**A:** Go to https://www.docker.com/products/docker-desktop and download for your OS. See [SETUP_GUIDE.md](SETUP_GUIDE.md#step-1-install-docker-if-needed) for detailed instructions.

### Q: What if I don't want to use AI features?
**A:** Just don't set an API key. DockSec works perfectly without AI - you'll get vulnerability information from Trivy/Hadolint.

```bash
# Works without API key
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  owasp/docksec:latest --image-only -i myapp:latest
```

---

## Usage

### Q: How do I scan my Docker image?
**A:** Assuming your image is built and named `myapp:latest`:

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  owasp/docksec:latest \
  --image-only -i myapp:latest
```

### Q: What's the difference between `--scan-only` and `--ai-only`?
**A:**
- `--scan-only`: Scan image/Dockerfile (Trivy, Hadolint) but no AI analysis
- `--ai-only`: AI analysis only (no scanning required)
- Default (no flags): Both scanning and AI analysis

### Q: Can I scan an image that's not on my machine?
**A:** No, the image must be built or pulled locally first:

```bash
# Pull the image first
docker pull myregistry.com/myapp:latest

# Then scan it
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  owasp/docksec:latest --image-only -i myregistry.com/myapp:latest
```

### Q: How do I save the scan results?
**A:** Mount a results directory:

```bash
mkdir -p results
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd):/scan \
  -v $(pwd)/results:/scan/results \
  owasp/docksec:latest \
  /scan/Dockerfile -i myapp:latest
```

Results are saved to `./results/`

### Q: What formats are available for results?
**A:** DockSec generates:
- `security_report.json` - Structured data
- `security_report.html` - Interactive report
- `security_report.pdf` - Printable report
- `security_report.md` - Markdown format
- `security_report.csv` - Spreadsheet format

### Q: Can I scan multiple images at once?
**A:** Not in one command, but you can loop:

```bash
for image in myapp:latest nginx:latest python:3.12; do
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    owasp/docksec:latest --image-only -i $image
done
```

---

## Docker Runner Specific

### Q: What is Docker Runner?
**A:** A way to run DockSec in a Docker container. Everything (Trivy, Hadolint, Python) is bundled inside. You just run `docker run ...` and it works.

### Q: Why would I use Docker Runner instead of pip?
**A:** 
- Zero setup (no system dependencies)
- Works on any OS identically
- No version conflicts
- Perfect for CI/CD
- Easy to update

See [SETUP_GUIDE.md](SETUP_GUIDE.md#detailed-comparison) for full comparison.

### Q: What's the `/var/run/docker.sock` parameter?
**A:** It's how the container accesses your Docker daemon (the thing that runs Docker). Without it, DockSec can't scan images.

```bash
-v /var/run/docker.sock:/var/run/docker.sock
#   ^Host path             ^Path in container
```

### Q: Why do I need to mount volumes?
**A:** 
- Input (Dockerfile): Container needs to read your Dockerfile
- Output (results): Container saves results here
- Socket (docker.sock): Container accesses Docker daemon

### Q: Can I use Docker Compose instead?
**A:** Yes! There's a `docker-compose.yml` in the repo:

```bash
docker-compose up docksec
```

---

## API Keys & Configuration

### Q: Do I need an API key?
**A:** No, scanning works without it. But AI-powered analysis requires an API key from OpenAI, Anthropic, Google, or Ollama.

### Q: Which API provider should I use?
**A:** 
- **New to AI APIs?** → OpenAI (most popular)
- **Privacy important?** → Ollama (local, free)
- **Budget tight?** → Google Gemini (cheapest)
- **Using Claude already?** → Anthropic

See [API_KEYS_SETUP.md](API_KEYS_SETUP.md#choosing-which-provider) for full comparison.

### Q: How much does it cost?
**A:** $0.02-0.10 per scan typically. Google is cheapest (~$0.001), OpenAI middle ($0.02-0.10). Ollama is free.

See [API_KEYS_SETUP.md](API_KEYS_SETUP.md#cost-estimation) for detailed pricing.

### Q: Where do I get an API key?
**A:** See [API_KEYS_SETUP.md](API_KEYS_SETUP.md) - step-by-step guides for each provider.

### Q: How do I set the API key?
**A:** Export as environment variable:

```bash
export OPENAI_API_KEY="sk-your-key-here"
docker run -e OPENAI_API_KEY="$OPENAI_API_KEY" ...
```

Or in docker-compose:
```yaml
environment:
  - OPENAI_API_KEY=${OPENAI_API_KEY}
```

### Q: Is my API key safe?
**A:** 
- Docker Runner: Key is only used inside container, never stored
- pip install: Key is used locally
- **Never commit keys to git!** Add `.env` to `.gitignore`

---

## Results & Reports

### Q: How do I interpret the vulnerability scores?
**A:** 
- **Critical (9-10)**: Immediately exploitable, fix ASAP
- **High (7-8)**: Serious vulnerability, fix soon
- **Medium (4-6)**: Moderate risk, should fix
- **Low (1-3)**: Minor issues, can address later

### Q: What do the severity levels mean?
**A:**
- **CRITICAL**: Remote code execution possible
- **HIGH**: Authentication bypass, data leak possible
- **MEDIUM**: Denial of service, information disclosure
- **LOW**: Low-impact issues, information leaks

### Q: Why does DockSec show so many vulnerabilities?
**A:** Because base images (Ubuntu, Python, etc.) have many vulnerabilities. Most aren't exploitable in your specific setup. DockSec uses AI to prioritize what actually matters.

### Q: Can I export results to a specific location?
**A:** Yes, mount the results directory:

```bash
docker run --rm \
  -v $(pwd)/my-results:/scan/results \
  owasp/docksec:latest ...
```

Reports go to `my-results/`

---

## Troubleshooting

### Q: "Docker socket not found" error
**A:** Docker isn't running:
- **macOS**: Open Docker Desktop from Applications
- **Linux**: Run `sudo systemctl start docker`
- **Windows**: Start Docker Desktop

### Q: "Cannot connect to Docker daemon" error
**A:** Permission issue (Linux specific):

```bash
# Add yourself to docker group:
sudo usermod -aG docker $USER

# Log out and back in, or:
newgrp docker
```

### Q: "Image not found" error
**A:** Build or pull the image first:

```bash
# Build:
docker build -t myapp:latest .

# Or pull:
docker pull python:3.12
```

### Q: "Permission denied" on results directory
**A:** Create with proper permissions:

```bash
mkdir -p results
chmod 777 results
```

### Q: Scan is very slow
**A:**
- First run: Normal (downloads image)
- Slow on second run? Enable caching:
  ```bash
  -e DOCKSEC_USE_CACHE="true"
  ```

### Q: "API key invalid" error
**A:** Check:
1. Key is correct (copy from provider dashboard again)
2. Provider is correct (OpenAI key won't work with Google)
3. Key hasn't expired

### Q: Dockerfile analysis shows "no vulnerabilities" but image has many
**A:** Different tools check different things:
- Dockerfile analysis: Bad practices, base image issues
- Image scanning (Trivy): Actual vulnerabilities in software

Both are important!

---

## CI/CD Integration

### Q: How do I integrate DockSec into GitHub Actions?
**A:** See [../docs/DOCKER_USAGE.md#github-actions](../docs/DOCKER_USAGE.md#github-actions) for examples.

### Q: Can I fail the build if vulnerabilities are found?
**A:** Yes, you can check the exit code:

```yaml
- name: Scan with DockSec
  run: |
    docker run --rm ... owasp/docksec:latest ...
    if [ $? -ne 0 ]; then
      echo "Security vulnerabilities found!"
      exit 1
    fi
```

### Q: How do I pass secrets to DockSec?
**A:** Use GitHub Secrets:

```yaml
env:
  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

---

## Performance

### Q: How can I make scans faster?
**A:** 
1. Use `--scan-only` (skip AI): `docksec --scan-only -i myapp:latest`
2. Enable caching: `-e DOCKSEC_USE_CACHE="true"`
3. Use compact output: `-e DOCKSEC_COMPACT_OUTPUT="true"`

### Q: Can I cache scan results?
**A:** Yes, enabled by default:

```bash
# Disable cache if needed:
-e DOCKSEC_USE_CACHE="false"
```

### Q: How much disk space does DockSec use?
**A:**
- Docker image: ~1.5 GB
- Cache per image: ~5-50 MB
- Results per scan: ~100 KB - 1 MB

---

## Advanced Topics

### Q: Can I use DockSec in my Python code?
**A:** Yes, with `pip install`:

```python
from docksec.docker_scanner import DockerSecurityScanner

scanner = DockerSecurityScanner("Dockerfile", "myapp:latest")
results = scanner.run_full_scan()
```

### Q: Can I customize the scanning?
**A:** Limited customization available via CLI flags. See `docksec --help` for options.

### Q: Can I use a private Docker registry?
**A:** Yes, authenticate first:

```bash
docker login my-registry.com
docker pull my-registry.com/myapp:latest
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  owasp/docksec:latest --image-only -i my-registry.com/myapp:latest
```

---

## Security & Privacy

### Q: Does DockSec send my Dockerfile to the cloud?
**A:** 
- **With API key**: Dockerfile content may be sent to the AI provider (OpenAI, Anthropic, etc.)
- **Without API key**: No, everything stays local
- **With Ollama**: Completely local, no cloud connection

### Q: Is my image scanned locally or on cloud?
**A:** Locally! The image scanning (Trivy/Hadolint) runs locally. Only Dockerfile is sent to AI provider (if using AI).

### Q: How are vulnerabilities disclosed?
**A:** See [../docs/SECURITY.md](../docs/SECURITY.md) for our security policy.

---

## Updating DockSec

### Q: How do I update DockSec?
**A:**
- **Docker Runner**: `docker pull owasp/docksec:latest`
- **pip**: `pip install --upgrade docksec`

### Q: How often is DockSec updated?
**A:** Regularly, as new vulnerabilities are discovered. We recommend updating monthly.

---

## Getting Help

| Issue | Where to Get Help |
|-------|------------------|
| **General questions** | This FAQ |
| **Setup issues** | [SETUP_GUIDE.md](SETUP_GUIDE.md) |
| **Docker usage** | [../docs/DOCKER_USAGE.md](../docs/DOCKER_USAGE.md) |
| **API key setup** | [API_KEYS_SETUP.md](API_KEYS_SETUP.md) |
| **Bug report** | https://github.com/OWASP/DockSec/issues |
| **Slack community** | https://owasp.slack.com/archives/C0APXGCUW7M |

---

## Still Have Questions?

Don't find your answer here?
1. Check [SETUP_GUIDE.md](SETUP_GUIDE.md) and [../docs/DOCKER_USAGE.md](../docs/DOCKER_USAGE.md)
2. Search [GitHub Issues](https://github.com/OWASP/DockSec/issues)
3. Open a [new issue](https://github.com/OWASP/DockSec/issues/new)
4. Ask in [OWASP Slack #project-docksec](https://owasp.slack.com/archives/C0APXGCUW7M)
