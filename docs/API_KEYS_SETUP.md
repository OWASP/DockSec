# API Keys Setup Guide

Configure AI-powered analysis by setting up API keys. This guide shows you how to get keys from each LLM provider.

## Overview

DockSec can use AI to provide intelligent security analysis. Here are the supported providers:

| Provider | Ease | Speed | Cost | Best For |
|----------|------|-------|------|----------|
| **OpenAI** | ⭐⭐⭐⭐⭐ | Very Fast | $$ | Most popular, recommended |
| **Anthropic** | ⭐⭐⭐⭐ | Fast | $$ | Great alternative to OpenAI |
| **Google Gemini** | ⭐⭐⭐⭐ | Very Fast | $ | Most affordable |
| **Ollama (Local)** | ⭐⭐⭐ | Depends | Free | Privacy-first, no API cost |

**TL;DR:** Start with OpenAI if new, it's the easiest and most reliable.

---

## Option 1: OpenAI (Recommended)

### Step 1: Create OpenAI Account

1. Go to https://platform.openai.com/signup
2. Sign up with email or Google/Microsoft account
3. Verify your email
4. Add payment method (credit card required)

### Step 2: Create API Key

1. Go to https://platform.openai.com/account/api-keys
2. Click "Create new secret key"
3. Choose a name (e.g., "DockSec")
4. Click "Create secret key"
5. **Copy the key immediately** (you won't see it again!)

Example key: `sk-proj-abc123xyz...`

### Step 3: Use the Key with DockSec

**Docker Runner:**
```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd):/scan \
  -e OPENAI_API_KEY="sk-proj-your-key-here" \
  owasp/docksec:latest \
  /scan/Dockerfile -i myapp:latest
```

**pip install:**
```bash
export OPENAI_API_KEY="sk-proj-your-key-here"
docksec Dockerfile -i myapp:latest
```

**Permanently store the key:**
```bash
# Add to ~/.bashrc or ~/.zshrc
export OPENAI_API_KEY="sk-proj-your-key-here"

# Then reload:
source ~/.bashrc  # or source ~/.zshrc
```

### Step 4: Test It Works

```bash
# With Docker
docker run --rm \
  -e OPENAI_API_KEY="sk-proj-your-key-here" \
  owasp/docksec:latest \
  --ai-only /scan/Dockerfile

# Or with pip
docksec --ai-only Dockerfile
```

You should see AI-powered analysis output.

### Pricing & Limits

**Pricing:**
- Typical DockSec scan: $0.02 - $0.10 per scan
- Free trial: $5 credit for 3 months

**Rate Limits:**
- Free: 3 requests/minute
- Paid: Higher limits based on plan

**Monitor Usage:**
- Go to https://platform.openai.com/account/billing/overview
- See your usage and remaining credits

---

## Option 2: Anthropic Claude

### Step 1: Create Anthropic Account

1. Go to https://console.anthropic.com
2. Sign up with email
3. Add payment method
4. Verify email

### Step 2: Create API Key

1. Go to https://console.anthropic.com/account/keys
2. Click "Create Key"
3. Copy the key

Example key: `sk-ant-abc123xyz...`

### Step 3: Use with DockSec

**Docker Runner:**
```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd):/scan \
  -e ANTHROPIC_API_KEY="sk-ant-your-key-here" \
  -e LLM_PROVIDER="anthropic" \
  owasp/docksec:latest \
  /scan/Dockerfile -i myapp:latest
```

**pip install:**
```bash
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
export LLM_PROVIDER="anthropic"
docksec Dockerfile -i myapp:latest
```

### Pricing

- Pay per token
- Typically $0.01 - $0.05 per scan
- No free tier, but inexpensive

---

## Option 3: Google Gemini

### Step 1: Create Google Cloud Account

1. Go to https://console.cloud.google.com
2. Click "Create Project"
3. Name it "DockSec" (or similar)
4. Click "Create"

### Step 2: Enable Gemini API

1. In the Google Cloud Console, go to "APIs & Services"
2. Click "Enable APIs and Services"
3. Search for "Generative Language"
4. Click "Google Generative Language API"
5. Click "Enable"

### Step 3: Create API Key

1. Go to "APIs & Services" → "Credentials"
2. Click "Create Credentials" → "API Key"
3. Copy the key

Example key: `AIza...`

### Step 4: Use with DockSec

**Docker Runner:**
```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd):/scan \
  -e GOOGLE_API_KEY="AIza-your-key-here" \
  -e LLM_PROVIDER="google" \
  owasp/docksec:latest \
  /scan/Dockerfile -i myapp:latest
```

**pip install:**
```bash
export GOOGLE_API_KEY="AIza-your-key-here"
export LLM_PROVIDER="google"
docksec Dockerfile -i myapp:latest
```

### Pricing

- Free tier: 60 requests per minute
- Very affordable ($0.001 - $0.005 per scan)

---

## Option 4: Ollama (Local, Free)

Use Ollama to run language models locally without paying or sending data to the cloud.

### Step 1: Install Ollama

1. Go to https://ollama.ai
2. Download for your OS (macOS, Linux)
3. Install and launch

### Step 2: Download a Model

```bash
# Pull a model (choose one)
ollama pull mistral      # Small, fast
ollama pull neural-chat  # Good balance
ollama pull llama2       # Full-featured

# Model downloads (first time only):
# mistral: ~4GB
# neural-chat: ~5GB
# llama2: ~7GB
```

### Step 3: Start Ollama Server

```bash
# On macOS: Launch Ollama from Applications
# On Linux: ollama serve

# Verify it's running:
curl http://localhost:11434/api/tags
```

### Step 4: Use with DockSec

**Docker Runner:**
```bash
docker run --rm \
  --network host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd):/scan \
  -e LLM_PROVIDER="ollama" \
  -e OLLAMA_BASE_URL="http://localhost:11434" \
  owasp/docksec:latest \
  /scan/Dockerfile -i myapp:latest
```

**pip install:**
```bash
export LLM_PROVIDER="ollama"
export OLLAMA_BASE_URL="http://localhost:11434"
docksec Dockerfile -i myapp:latest
```

### Advantages of Ollama

- ✅ Completely free (no API costs)
- ✅ Data stays on your machine (privacy)
- ✅ Works offline
- ✅ No account needed

### Disadvantages

- ❌ Requires downloading models (~4-7GB each)
- ❌ Slower than cloud services (depends on your hardware)
- ❌ Uses local CPU/GPU (can be slow on older machines)

---

## Choosing Which Provider

### Decision Table

| Use Case | Recommendation | Why |
|----------|---|---|
| **Just trying it out** | Google (free tier) | Free, no setup |
| **Production use** | OpenAI | Most reliable, best results |
| **Budget conscious** | Google Gemini | $0.001 per scan |
| **Privacy critical** | Ollama | Runs locally, free |
| **Team using Claude** | Anthropic | Familiar with Claude |

---

## Using Different Models

Each provider has multiple models. Specify with `LLM_MODEL`:

### OpenAI Models
```bash
-e LLM_MODEL="gpt-4o"          # Best, most expensive
-e LLM_MODEL="gpt-4"           # Very good, expensive
-e LLM_MODEL="gpt-3.5-turbo"   # Fast, cheap (default)
```

### Anthropic Models
```bash
-e LLM_MODEL="claude-3-5-sonnet"   # Best quality
-e LLM_MODEL="claude-3-opus"       # Most powerful
-e LLM_MODEL="claude-3-haiku"      # Fast, cheap
```

### Google Models
```bash
-e LLM_MODEL="gemini-1.5-pro"      # Best
-e LLM_MODEL="gemini-1.5-flash"    # Fast
-e LLM_MODEL="gemini-pro"          # Basic
```

### Ollama Models
```bash
-e LLM_MODEL="mistral"      # Fast
-e LLM_MODEL="neural-chat"  # Balanced
-e LLM_MODEL="llama2"       # Best quality
```

---

## Storing Keys Securely

### Option 1: Environment Variables (For Testing)

```bash
export OPENAI_API_KEY="sk-..."
docksec Dockerfile -i myapp:latest
```

### Option 2: .env File (For Development)

Create `.env` file in your project:
```
OPENAI_API_KEY=sk-...
LLM_PROVIDER=openai
```

Load it:
```bash
export $(cat .env)
docksec Dockerfile -i myapp:latest
```

**Important:** Add `.env` to `.gitignore`!

### Option 3: ~/.bashrc or ~/.zshrc (Permanent)

```bash
# Add to ~/.bashrc or ~/.zshrc
export OPENAI_API_KEY="sk-..."

# Reload:
source ~/.bashrc
```

### Option 4: Docker Compose

```yaml
environment:
  - OPENAI_API_KEY=${OPENAI_API_KEY}
  - LLM_PROVIDER=openai
```

Run with:
```bash
OPENAI_API_KEY="sk-..." docker-compose up
```

### Option 5: GitHub Secrets (For CI/CD)

```yaml
env:
  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

---

## Troubleshooting API Keys

### "Invalid API key" Error

```bash
# 1. Verify key is set correctly:
echo $OPENAI_API_KEY  # Should show your key, not blank

# 2. Copy-paste error? Re-copy from provider dashboard

# 3. Key expired? Create a new one

# 4. Wrong provider? Check you're using right key:
# OpenAI key starts with: sk-proj-
# Anthropic key starts with: sk-ant-
# Google key starts with: AIza-
```

### "Rate limit exceeded"

```bash
# You're making too many requests
# Wait a few minutes and try again
# Or upgrade to paid tier for higher limits
```

### "Quota exceeded"

```bash
# You've exceeded free tier limits
# Option 1: Wait for reset (monthly)
# Option 2: Add payment method and upgrade
# Option 3: Switch to different provider
```

### Scan works without key?

```bash
# DockSec works without AI keys!
# You just won't get AI-powered analysis
docksec --image-only -i myapp:latest  # Works, but basic
docksec -e OPENAI_API_KEY="sk-..." --image-only -i myapp:latest  # With AI
```

---

## Testing Your API Key

### Test 1: Basic Connection Test

**Docker:**
```bash
docker run --rm \
  -e OPENAI_API_KEY="sk-your-key" \
  owasp/docksec:latest \
  --ai-only /scan/Dockerfile
```

**pip:**
```bash
export OPENAI_API_KEY="sk-your-key"
docksec --ai-only Dockerfile
```

Should work without errors.

### Test 2: Full Scan with AI

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e OPENAI_API_KEY="sk-your-key" \
  owasp/docksec:latest \
  --image-only -i python:3.12
```

Should show AI-powered recommendations.

---

## Switching Providers

Want to switch from OpenAI to Google?

```bash
# Just change the environment variables:
export OPENAI_API_KEY=""  # Unset old key
export LLM_PROVIDER="google"
export GOOGLE_API_KEY="AIza-your-key"

# Run scan:
docksec Dockerfile -i myapp:latest
```

---

## Cost Estimation

### Typical DockSec Scan Costs

| Provider | Per Scan | Monthly (daily scans) |
|----------|----------|----------------------|
| OpenAI (GPT-3.5) | $0.02 | $0.60 |
| OpenAI (GPT-4) | $0.20 | $6.00 |
| Anthropic | $0.03 | $0.90 |
| Google Gemini | $0.001 | $0.03 |
| Ollama (Local) | Free | Free |

---

## Next Steps

1. **Choose a provider** (OpenAI recommended if unsure)
2. **Follow the setup steps** for your choice
3. **Set the API key** in your environment
4. **Test it** with a simple scan
5. **Start scanning** your Docker images!

---

## Need Help?

- **API issues?** Check Troubleshooting section above
- **Provider specific?** Visit their documentation
- **DockSec issues?** See [FAQ.md](FAQ.md)
- **Found a bug?** Report at https://github.com/OWASP/DockSec/issues
