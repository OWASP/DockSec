# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.0.19  | :white_check_mark: |
| 0.0.18  | :white_check_mark: |
| < 0.0.18| :x:                |

## Reporting a Vulnerability

We take the security of DockSec seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Where to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of the following methods:

1. **Email**: Send an email to [advaitpa93@gmail.com](mailto:advaitpa93@gmail.com) with the subject line "SECURITY: [Brief Description]"
2. **GitHub Security Advisory**: Use GitHub's private vulnerability reporting feature at https://github.com/OWASP/DockSec/security/advisories/new

### What to Include

Please include the following information in your report:

- **Type of vulnerability** (e.g., code injection, privilege escalation, data exposure)
- **Full paths** of source file(s) related to the vulnerability
- **Location** of the affected source code (tag/branch/commit or direct URL)
- **Step-by-step instructions** to reproduce the issue
- **Proof-of-concept or exploit code** (if possible)
- **Impact** of the vulnerability and how an attacker might exploit it
- **Any possible mitigations** you've identified

### Response Timeline

We will make every effort to respond to your report according to the following timeline:

- **Within 48 hours**: We will acknowledge receipt of your vulnerability report
- **Within 7 days**: We will send an assessment of the vulnerability and an expected timeline for a fix
- **Within 30 days**: We will release a fix or provide a detailed explanation if we disagree that it's a vulnerability

### Disclosure Policy

- We request that you give us reasonable time to investigate and fix the vulnerability before public disclosure
- We will credit you in the security advisory (unless you prefer to remain anonymous)
- We follow a coordinated disclosure process and will work with you on the timing of public disclosure

## Security Best Practices for Users

### API Key Security

DockSec supports multiple LLM providers (including OpenAI, Anthropic, Google, and Ollama). To keep your provider credentials secure:

1. **Never commit API keys** to version control
   ```bash
   # Use environment variables
   export OPENAI_API_KEY="your-openai-key"
   export ANTHROPIC_API_KEY="your-anthropic-key"
   export GOOGLE_API_KEY="your-google-key"
   export OLLAMA_API_KEY="your-ollama-key"
   
   # Or use a .env file (ensure it's in .gitignore)
   cat <<EOF > .env
   OPENAI_API_KEY=your-openai-key
   ANTHROPIC_API_KEY=your-anthropic-key
   GOOGLE_API_KEY=your-google-key
   OLLAMA_API_KEY=your-ollama-key
   EOF
   ```

2. **Restrict API key permissions** in each provider dashboard
3. **Rotate keys regularly**, especially if they may have been exposed
4. **Monitor API usage** for unexpected activity

### Docker Image Scanning

When scanning Docker images:

1. **Scan images from trusted sources** only
2. **Be cautious** when scanning images that may contain sensitive data
3. **Review generated reports** before sharing them (they may contain sensitive information)
4. **Use scan-only mode** in environments where AI/API access is restricted

### CI/CD Integration

When using DockSec in CI/CD pipelines:

1. **Store API keys in CI/CD secrets**, not in code or logs
2. **Limit access** to CI/CD jobs that use DockSec
3. **Review logs** to ensure sensitive information isn't exposed
4. **Use read-only tokens** where possible

### Network Security

DockSec makes network calls to:
- OpenAI API (for AI analysis)
- Docker registries (for image scanning)
- GitHub (for updates)

Ensure your network security policies allow these connections if needed.

## Known Security Considerations

### 1. AI Model Limitations

- DockSec supports multiple LLM providers for AI analysis (including OpenAI when configured)
- AI recommendations should be reviewed by security professionals
- AI models can make mistakes or miss vulnerabilities
- Always combine AI analysis with traditional scanning tools

### 2. External Tool Dependencies

DockSec relies on external tools:
- **Trivy**: Community-maintained vulnerability database
- **Hadolint**: Dockerfile linting rules
- **Docker Scout**: Docker's security scanning

Keep these tools updated to ensure you have the latest security checks.

### 3. Data Privacy

- Dockerfile contents are sent to OpenAI for AI analysis
- Vulnerability scan results are processed locally
- No data is stored or transmitted except to OpenAI (when using AI features)
- Use `--scan-only` mode if you cannot send Dockerfiles to external services

### 4. Report Security

Generated reports may contain:
- Vulnerability details
- Package versions
- Configuration information
- File paths

**Treat reports as sensitive data** and store them securely.

## Security Features in DockSec

### Input Validation

- Path traversal protection
- Image name validation
- Command injection prevention
- Safe file handling

### Rate Limiting

- Built-in rate limiting for API calls
- Automatic retry with exponential backoff
- Prevents accidental API abuse

### Error Handling

- Secure error messages (no sensitive data exposure)
- Graceful degradation
- Safe defaults

## Vulnerability Disclosure History

No security vulnerabilities have been reported or disclosed for DockSec as of January 2026.

This section will be updated as needed.

## Security Testing

We encourage security researchers to test DockSec for vulnerabilities. Our testing recommendations:

### In Scope

- Input validation vulnerabilities
- Code injection attacks
- Path traversal issues
- Privilege escalation
- Information disclosure
- Authentication/authorization bypasses

### Out of Scope

- Social engineering attacks
- Physical attacks
- Denial of Service (DoS) attacks against third-party services
- Issues in dependencies (report these to the respective projects)

## Recognition

We believe in recognizing security researchers who help make DockSec more secure:

- Security researchers will be credited in our security advisories (with permission)
- Significant contributions may be featured in our README and documentation
- We will work with you on the disclosure timeline and content

## Questions?

If you have questions about this security policy or DockSec's security in general, please:

1. Review our documentation
2. Check existing GitHub issues
3. Contact us at advaitpa93@gmail.com

---

**Note**: This security policy may be updated from time to time. Please check back regularly for the latest version.

Last updated: January 9, 2026
