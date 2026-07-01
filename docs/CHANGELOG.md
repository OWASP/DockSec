# Changelog

All notable changes to DockSec will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Docker Compose security scanning support (`--compose` flag).
- Detection for compose-level misconfigurations (e.g., privileged mode, host network, missing resource limits).
- Automatic scanning of all services defined in a docker-compose file.
- Integration of compose findings into the existing LLM remediation and scoring pipeline.
- `DOCKSEC_LOG_LEVEL` environment variable to override log verbosity (e.g. `DOCKSEC_LOG_LEVEL=DEBUG`) for troubleshooting.

### Changed
- **Cleaner terminal output**: internal logs now write to `stderr` instead of `stdout` and stay quiet in CLI mode, so raw location-tagged log lines no longer interleave with the tool's user-facing messages. Set `DOCKSEC_LOG_LEVEL` to restore verbose logging.

### Fixed
- **PDF report encoding**: PDF generation no longer fails on non-latin-1 characters (bullets, smart quotes, em dashes, emoji) in vulnerability titles, scanner output, or AI findings; such characters are sanitized consistently across the whole document.
- Suppressed the noisy `PyFPDF & fpdf2` import warning that printed on every run.

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
