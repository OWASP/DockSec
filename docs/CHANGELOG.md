# Changelog

All notable changes to DockSec will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2026.7.3] - 2026-07-02

### Fixed

- **AI analysis without an image wrote no report, but claimed it did**: running an AI analysis with a Dockerfile but no image (e.g. `docksec Dockerfile --provider anthropic`, or `--ai-only`) set the tool into a mode where the AI pass ran but the scan pass — the only place reports were generated — did not. No report file was written, yet the tool still printed "For detailed AI analysis, check the generated reports at: ...", pointing at a directory that contained only stale files from previous runs. Since the on-screen findings are truncated to the top few per section, the full AI findings were effectively unreachable. AI-only runs now write the complete findings to a report (JSON/CSV/PDF/HTML, plus SARIF with `--sarif`), honoring `--format` and `--output-dir`, and the "reports written" message is only shown when a report was actually generated.

## [2026.7.2] - 2026-07-02

### Fixed

- **Scan cache ignored `--severity`**: `ScanResultsCache` keyed cached results by image name only, so scanning an image at a narrow severity (e.g. `CRITICAL`) and then re-scanning the same image at a wider severity (e.g. `CRITICAL,HIGH,MEDIUM`) silently served the stale, narrower cached result instead of re-scanning, dropping HIGH/MEDIUM findings from the report. The cache key now includes the normalized severity list.
- **AI analysis failures exited 0**: an exception during the AI analysis pass (bad provider/API key, model error) printed `error AI analysis failed: ...` but still exited `0`, contradicting the documented exit-code contract. AI failures now exit `3` (tool/runtime error), matching scan failures.
- **HTML report crashed on a null vulnerability title**: Trivy can return `"Title": null` for some findings; the HTML report writer called `len()` on that field unconditionally and crashed generation for the whole report, silently dropping HTML off the report list whenever a scan hit one of these findings. Vulnerability ID, package name, installed version, and title are now null-safe in the HTML report.
- **`--compose --scan-only` printed an unrelated Dockerfile message**: "No image provided for scan-only mode. Running Dockerfile analysis only." fired for any `--scan-only` run without `--image`, including pure `--compose` runs where no Dockerfile is involved. Now scoped to non-compose runs.
- **Compose vulnerability findings could be invisible to the security score**: when every per-service image scan in a compose file failed (e.g. images not pulled locally), the score calculator treated the vulnerabilities axis as unmeasured and excluded it from the weighted average, even though compose static-misconfiguration findings (privileged mode, host network, etc.) were present. A compose file with multiple CRITICAL findings could score "GOOD". The vulnerabilities axis is now always included whenever findings exist, regardless of whether the image-scan sub-check ran.
- **Security score understated hardcoded credential exposure**: a Dockerfile with hardcoded secrets, no `USER` directive, and other severe misconfigurations could still land in the mid-40s ("POOR" but not alarming) because the blended dockerfile/vulnerabilities/configuration average diluted the credential-exposure penalty. The overall score is now capped at 20/100 whenever a hardcoded credential-looking `ENV` variable (password/secret/API key/token) is detected in the Dockerfile.

### Added
- Docker Compose security scanning support (`--compose` flag).
- Detection for compose-level misconfigurations (e.g., privileged mode, host network, missing resource limits).
- Automatic scanning of all services defined in a docker-compose file.
- Integration of compose findings into the existing LLM remediation and scoring pipeline.
- `DOCKSEC_LOG_LEVEL` environment variable to override log verbosity (e.g. `DOCKSEC_LOG_LEVEL=DEBUG`) for troubleshooting.
- **Redesigned terminal output**: a consolidated result summary with a box-drawing severity table, the security score with a color-coded rating, a "Quick take" action block highlighting the most important findings, the list of generated reports, and a suggested next command.
- `--quiet` flag to reduce output to warnings, errors, and the result summary.
- `--no-color` flag (also honors the `NO_COLOR` environment variable) to disable colored output.
- `--severity` flag to choose which severity levels the image vulnerability scan reports (default `CRITICAL,HIGH`; also settable via `DOCKSEC_DEFAULT_SEVERITY`). Invalid values are rejected with a clear error.
- `--fail-on <severity>` flag: exit with code 1 when any finding is at or above the chosen severity (`CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`). The scan severity is auto-widened when needed so the gate can observe those findings.
- CI-friendly exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage/argument error, `3` tool or runtime error (scan failed, image not found, missing tools).
- `--format` flag to choose which report formats are written (`json`, `csv`, `pdf`, `html`; default: all). Invalid values are rejected with a clear error.
- `--output-dir` flag to write reports to a specific directory for the run (default: `~/.docksec/results` or `DOCKSEC_RESULTS_DIR`).
- `--json` flag: print scan results as a single JSON object to stdout for scripts and CI pipelines. All human-readable output (banner, sections, info/warn/error, the result summary) moves to stderr in `--json` mode, so stdout carries only the JSON payload. `--json` alone does not write report files; combine with `--format` to also write files.
- `--sarif` flag: write a SARIF 2.1.0 report for GitHub Code Scanning and other SARIF-compatible tools. Independent of `--format`; findings map to one SARIF rule per unique vulnerability ID and one result per finding, with severity mapped to SARIF levels (`CRITICAL`/`HIGH` -> `error`, `MEDIUM` -> `warning`, `LOW`/`UNKNOWN` -> `note`).
- GitHub Action inputs for the new CLI flags: `output_dir`, `severity`, `fail_on`, `format`, `sarif`.
- `--baseline <file>` and `--update-baseline` flags for ratchet-mode adoption: `--update-baseline` snapshots the current scan's findings to the baseline file; subsequent runs with `--baseline` and `--fail-on` only gate on findings not already present in the baseline, so `--fail-on` can be adopted on existing projects without pre-existing findings blocking every build. Findings are matched by vulnerability ID, target, and package name.

### Changed
- **Cleaner terminal output**: internal logs now write to `stderr` instead of `stdout` and stay quiet in CLI mode, so raw location-tagged log lines no longer interleave with the tool's user-facing messages. Set `DOCKSEC_LOG_LEVEL` to restore verbose logging.
- `docker_scanner.py`'s Hadolint/Trivy/Docker Scout error and troubleshooting messages now route through `docksec.output` instead of raw `print()`, so they're consistently styled and honor `--quiet`/`--no-color`/`--json` like the rest of the tool's output.
- The security score is now rendered once, in the result summary, instead of mid-scan.
- Report generation runs silently and the CLI renders a single report summary from the result (removes the misleading progress bars).
- **Honest exit codes**: a failed scan (for example, an image that is not found) now exits non-zero instead of ending with "Analysis complete!".

### Fixed (GitHub Action)
- The Action's `output` input was passed to the CLI as `-o`/`--output`, a flag removed earlier in this release; setting it caused every run to fail with an argument-parsing error. It is now remapped to `--output-dir` (kept as a deprecated alias; the new `output_dir` input is preferred).

### Fixed
- **PDF report encoding**: PDF generation no longer fails on non-latin-1 characters (bullets, smart quotes, em dashes, emoji) in vulnerability titles, scanner output, or AI findings; such characters are sanitized consistently across the whole document.
- Suppressed the noisy `PyFPDF & fpdf2` import warning that printed on every run.
- Fixed report progress output that printed each step twice and out of order (caused by mixing `print()` with a live progress display).

### Removed
- Removed the unused `-o/--output` CLI flag, which was declared but never wired up.
- Removed dead duplicate report-writer methods from `DockerSecurityScanner`; report generation is handled solely by `ReportGenerator`.
- Removed the leftover `compose_scanner_cli.py` placeholder module.

## [2026.5.22.2] - 2026-05-22

### Changed
- **CLI Help**: Updated help text and documentation to reflect modern 2026 model names (e.g., `claude-haiku-4-5`).
- **Documentation**: Clarified default model behavior in Getting Started guide.

## [2026.5.22.1] - 2026-05-22

### Fixed
- **Multi-LLM Compatibility**: Fixed `json_mode` errors when using Anthropic, Google, or Ollama providers.
- **Provider Defaults**: Added smart model defaults when switching providers (e.g., automatically selecting Claude 3.5 Sonnet when `LLM_PROVIDER=anthropic`).
- **Linting**: Resolved unused variable warnings in configuration.

## [2026.5.22] - 2026-05-22

### Added
- **Centralized Reporting**: All scan reports are now neatly organized in `~/.docksec/results/` by default, following industry standards for professional CLI tools.
- **Enhanced `--scan-only` Mode**: Improved the scanner to support Dockerfile-only scans without requiring a Docker image name, enabling high-speed static analysis in any environment.

### Changed
- **Modernized PDF Engine**: Refactored the PDF generation to use the latest `fpdf2` APIs, improving performance and future-proofing the reporting engine.
- **Improved Storage Logic**: Added automatic directory creation and a smart fallback to local storage if the home directory is not writable.
- **CLI Feedback**: The tool now explicitly prints the report storage location at the start of every scan for better visibility.

### Fixed
- **PDF Layout**: Resolved the "Not enough horizontal space" error that occurred during PDF generation for complex scan results.
- **Deprecation Warnings**: Eliminated all font and layout-related deprecation warnings from the `fpdf2` library.
- **Test Suite**: Updated and expanded the unit test suite to cover new reporting logic and dynamic tool requirements, achieving 100% pass rate.

---

## [2026.5.21] - 2026-05-21

### Added
- **OWASP Project Website**: Launched the official project site at `https://owasp.org/DockSec/` with a modern, tabbed interface.
- **GitHub Action for Marketplace**: Created a Docker-based GitHub Action (`action.yml`) with pre-installed security tools (**Trivy** and **Hadolint**) for seamless CI/CD integration.
- **Governance & Community**:
  - Added `MENTORS.md` to support new contributors.
  - Added `SPONSORSHIP.md` to facilitate project funding.
  - Enabled GitHub Sponsors via `.github/FUNDING.yml`.
  - Integrated official Slack channel (`#project-docksec`).
- **Developer Tooling**: Added a root-level `Makefile` to standardize environment setup, linting, testing, and security scanning.

### Changed
- **Branding & UI**:
  - Redesigned `README.md` and `index.md` with a centered "pyramid" badge layout and professional `for-the-badge` styling.
  - Updated project logo rendering using modern `<picture>` tags.
- **Project Infrastructure**:
  - Standardized all repository links and documentation to point to the official `OWASP/DockSec` repository.
  - Standardized project URL to `https://owasp.org/DockSec/`.
- **Documentation**:
  - Moved `CONTRIBUTING.md` to the root directory for better visibility.
  - Added a Mermaid workflow diagram to the contribution guide.

### Fixed
- **Website Navigation**: Standardized tab file naming and titles to resolve Jekyll build errors on the OWASP site.
- **Stats Badges**: Fixed the PyPI downloads badge to show **total overall downloads** using a reliable Shields.io provider.

---

## [2026.5.6] - 2026-05-06

### Changed
- **Major Structural Overhaul**: Restructured the project from a flat layout to a proper Python package structure.
  - Core logic moved to `docksec/` directory.
  - CLI entry point moved to `docksec/cli.py`.
  - Templates moved to `docksec/templates/`.
  - Consolidation of redundant files (`main.py` removed).
- **Packaging Improvements**:
  - Updated `setup.py` and `pyproject.toml` for better distribution.
  - Improved `MANIFEST.in` to include all necessary package data.
- **Documentation**:
  - Updated `README.md` and `CONTRIBUTING.md` to reflect the new structure.
  - Improved project structure visualization in documentation.

### Fixed
- Internal import paths updated to use absolute package imports.
- Metadata artifacts (`*:Zone.Identifier`) removed from the repository.

---

## [2026.2.23] - 2026-02-23

### Added
- Multiple LLM Provider Support
  - OpenAI (GPT-4o, GPT-4 Turbo, GPT-3.5 Turbo)
  - Anthropic Claude (Claude 3.5 Sonnet, Claude 3 Opus)
  - Google Gemini (Gemini 1.5 Pro, Gemini 1.5 Flash)
  - Ollama (Llama 3.1, Mistral, Phi-3, and other local models)
  
- New CLI Options
  - `--provider` flag to select LLM provider (openai, anthropic, google, ollama)
  - `--model` flag to specify model name
  - Environment variables: LLM_PROVIDER, LLM_MODEL, ANTHROPIC_API_KEY, GOOGLE_API_KEY, OLLAMA_BASE_URL

- Enhanced Configuration
  - config_manager.py now supports multiple providers with validation
  - Automatic provider detection from environment variables
  - Configurable Ollama base URL for custom deployments

### Changed
- Core Architecture Updates
  - utils.py get_llm() function completely rewritten to support multiple providers
  - Graceful fallback and improved error messages for missing API keys
  - Better provider validation and configuration handling

- Documentation Improvements
  - README updated with multi-provider setup instructions
  - New troubleshooting section for each provider
  - Updated CLI examples showing provider selection

### Fixed
- API key handling improved with provider-specific validation
- Better error messages indicating which provider and API key is needed

### Migration Guide
For existing users:
- **No Breaking Changes**: OpenAI remains the default provider
- Existing OPENAI_API_KEY environment variable still works as before
- To switch providers, simply set LLM_PROVIDER environment variable or use --provider flag

Example migration to Claude:
```bash
export ANTHROPIC_API_KEY="your-key"
export LLM_PROVIDER="anthropic"
export LLM_MODEL="claude-3-5-sonnet-20241022"
docksec Dockerfile
```

Or use local models with Ollama:
```bash
# No API key needed!
ollama pull llama3.1
export LLM_PROVIDER="ollama"
export LLM_MODEL="llama3.1"
docksec Dockerfile
```

### Deprecations
- None. GPT-4 support continues but GPT-4o is recommended for better performance.

---

## [0.0.20] - 2026-01-09

### Added
- 📚 **Comprehensive Documentation Suite**
  - Complete CHANGELOG.md with full version history from v0.0.3 to present
  - SECURITY.md with vulnerability reporting process and security best practices
  - CONTRIBUTING.md with detailed contribution guidelines and development setup
  - PUBLISHING_GUIDE.md for maintainers

- 📁 **Complete Examples Directory**
  - Secure Python Flask application example (Score: 90+) with best practices
  - Vulnerable Node.js application example (Score: 30-) for educational purposes
  - Multi-stage Golang build example (Score: 95+) with distroless base
  - Detailed README for each example explaining security features
  - Examples overview and learning path guide

- 🎫 **GitHub Templates**
  - Bug report issue template with structured format
  - Feature request issue template with use case analysis
  - Question issue template for community support
  - Pull request template with comprehensive checklist

- 📖 **README Enhancements**
  - Quick Start section with 3-step getting started guide
  - Examples & Screenshots section with sample output
  - Documentation section linking to all major docs
  - Roadmap section showing upcoming features
  - Code quality badges (PyPI version, Python version, CI status, Code style)

### Fixed
- 🔗 **Broken Links and References**
  - Fixed GitHub stars badge URL (docksec/docksec → OWASP/DockSec)
  - Removed placeholder Docker Hub link
  - Fixed CONTRIBUTING.md reference (file now exists)
  - Replaced "Coming Soon" demo video section with actual examples

- 🎨 **Badge Updates**
  - Corrected repository URLs in all badges
  - Added PyPI version badge
  - Added Python version support badge
  - Added CI/CD status badge
  - Added code style (black) badge

### Improved
- 📝 **Documentation Quality**
  - Better README structure and navigation
  - More professional appearance for open source promotion
  - Clear learning paths and getting started guides
  - Comprehensive troubleshooting section
  - Security-first documentation approach

- 🏗️ **Repository Structure**
  - Professional GitHub presence with all templates
  - Clear contribution workflow
  - Security policy for vulnerability reports
  - Examples demonstrating best practices

### Developer Experience
- Complete development environment setup guide
- Code style and testing guidelines
- Commit message conventions
- Local testing procedures before PyPI publication

### Community
- Clear paths for bug reports, feature requests, and questions
- Recognition system for contributors
- Transparent roadmap and feature voting

### Notes
This release focuses on documentation, community building, and making DockSec ready for broader open source promotion. No functional changes to the core scanning engine.

---

## [0.0.19] - 2025-06-26

### Added
- Latest stable release with full feature set
- Enhanced error handling and retry mechanisms
- Improved documentation and examples

## [0.0.18] - 2025-06-26

### Added
- Production-ready reliability features
- Automatic retry logic with exponential backoff
- Rate limiting support for OpenAI API
- Configurable timeouts for all scanning tools
- Comprehensive error recovery mechanisms

### Improved
- Enhanced logging with structured output
- Better progress indicators for long-running operations
- More actionable error messages with troubleshooting steps

## [0.0.17] - 2025-06-26

### Added
- Multi-format report generation (JSON, CSV, PDF, HTML)
- Professional HTML reports with interactive styling
- Security score calculation (0-100 rating)

### Fixed
- Report generation issues with special characters
- PDF formatting improvements
- CSV export compatibility

## [0.0.16] - 2025-06-26

### Added
- Image-only scanning mode
- Support for scanning Docker images without Dockerfile
- Enhanced Docker Scout integration

### Improved
- CLI argument validation
- Better error messages for missing dependencies

## [0.0.15] - 2025-06-25

### Added
- AI-only analysis mode
- Scan-only mode (no AI required)
- Configuration via environment variables
- Support for .env files

### Changed
- Refactored CLI interface for better usability
- Improved help documentation

## [0.0.14] - 2025-06-25

### Added
- Rich terminal formatting with progress bars
- Real-time scan progress indicators
- Color-coded severity levels

### Improved
- Terminal output formatting
- Progress tracking for long operations

## [0.0.13] - 2025-06-24

### Added
- Docker Scout integration for vulnerability scanning
- Support for multiple scanning tools (Trivy, Hadolint, Docker Scout)
- Severity-based filtering (CRITICAL, HIGH, MEDIUM, LOW)

## [0.0.12] - 2025-06-24

### Fixed
- Dependency resolution issues
- Package installation errors
- Import path corrections

## [0.0.11] - 2025-06-24

### Added
- LangChain integration for AI-powered analysis
- OpenAI GPT-4 support for intelligent recommendations
- Context-aware security suggestions

## [0.0.10] - 2025-06-24

### Added
- Automated security scoring system
- CVE detection and analysis
- CVSS score reporting

## [0.0.9] - 2025-06-24

### Added
- Trivy integration for comprehensive vulnerability scanning
- Hadolint integration for Dockerfile best practices

## [0.0.8] - 2025-06-24

### Changed
- Major refactoring of core scanning engine
- Improved code organization and modularity

## [0.0.7] - 2025-06-24

### Added
- Basic report generation capabilities
- JSON output format

## [0.0.6] - 2025-06-24

### Fixed
- Critical bug fixes in scanning logic
- Improved error handling

## [0.0.5] - 2025-06-12

### Added
- Initial CLI interface
- Basic Dockerfile analysis

## [0.0.4] - 2025-06-12

### Changed
- Package structure improvements
- Better dependency management

## [0.0.3] - 2025-06-11

### Added
- Initial public release
- Basic Docker security scanning functionality
- AI-powered recommendations using OpenAI
- Support for Dockerfile analysis

### Features
- Command-line interface for easy usage
- Integration with external security tools
- Automated report generation

---

## Version History Notes

### Breaking Changes
- v0.0.15: CLI argument structure changed - see documentation for migration guide
- v0.0.10: Report format updated - old reports may not be compatible

### Deprecations
- v0.0.15: Legacy Python script execution (`python main.py`) still supported but deprecated in favor of CLI (`docksec`)

### Security Updates
- All versions include security-focused scanning and analysis
- Regular updates to vulnerability databases
- No known security issues in any released versions

---

## Upcoming Features (Roadmap)

### Planned for v0.1.0
- [x] Docker Compose support
- [x] Multi-container analysis
- [ ] Kubernetes manifest scanning
- [ ] Custom rule engine
- [ ] Plugin system for extensibility

### Planned for v0.2.0
- [ ] Web dashboard interface
- [ ] Team collaboration features
- [ ] Historical trend analysis
- [ ] Integration with CI/CD platforms (GitHub Actions, GitLab CI, Jenkins)

### Under Consideration
- [ ] Support for additional LLM providers (Claude, Gemini, local models)
- [ ] Offline mode with cached vulnerability databases
- [ ] Container runtime security monitoring
- [ ] Image signing and verification
- [ ] SBOM (Software Bill of Materials) generation

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## Support

For issues, questions, or feature requests, please visit:
- GitHub Issues: https://github.com/OWASP/DockSec/issues
- Documentation: https://github.com/OWASP/DockSec/blob/main/README.md
