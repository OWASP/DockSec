# Changelog

All notable changes to DockSec are documented in this file.

## 2026.7.4

Industry-readiness release: privacy hardening, cache correctness, waivers, and a
slimmer install.

### Added

- Secret redaction before AI analysis: secret-looking values (passwords, tokens,
  API keys, private key blocks) in Dockerfiles and compose files are masked before
  any content is sent to the configured LLM provider. Key names remain visible so
  exposed credentials are still flagged. Opt out with `--no-redact`.
- Ignore file support (`--ignore-file`, or an auto-detected `.docksec-ignore.yml`):
  suppress individual triaged findings by vulnerability or rule ID, with a required
  reason and optional expiry date per entry. Suppressions apply to scoring, reports,
  `--json` output, and the `--fail-on` gate.
- `--no-cache` flag to bypass the scan results cache for a run.
- Cache TTL: cached scan results now expire (default 24 hours; configurable with
  `DOCKSEC_CACHE_TTL_HOURS`).
- "Data flow and privacy" documentation describing exactly what leaves the machine.
- Optional dependency extra: `pip install "docksec[ai]"` installs AI analysis
  support; the base `pip install docksec` is now a slim, scan-only core with no
  LLM dependencies.

- HTML report improvements: a rating badge (Excellent/Good/Fair/Poor) next to the
  security score matching the terminal bands, a "Fixed In" column in the
  vulnerability table, a "fix available" summary line, and a note showing how many
  findings were waived via the ignore file. Waiver information also appears in the
  terminal Quick take and in `--json` output (`scan_info.suppressed_count`,
  `scan_info.ignore_file`).

### Changed

- AI analysis input limits raised from 50 lines / 2,000 characters to 400 lines /
  16,000 characters for Dockerfiles (600 lines / 24,000 characters for compose
  files), and a warning is now printed whenever input is truncated.
- Scan cache is keyed by the image content digest instead of the tag, so a rebuilt
  tag (for example a reused `:latest`) never serves stale results. Full-scan cache
  entries also include the Dockerfile content hash, so results are never reused
  across different Dockerfiles that share an image.
- Compose rule severities tuned to reduce noise: `compose-no-non-root-user` is now
  MEDIUM (was HIGH); `compose-no-resource-limits` and `compose-writable-root-fs`
  are now LOW (was MEDIUM).
- `compose-port-bound-all-interfaces` now flags only sensitive ports (remote admin,
  databases, caches, brokers, Docker API) instead of every published port, and now
  correctly flags bare container-port entries (for example `"6379"`), which bind
  0.0.0.0.
- GitHub Action usage examples now reference the pinned release tag instead of
  `@main`.
- Dependency pins relaxed from exact (`==`) to compatible ranges, and unused
  dependencies (pandas, tqdm, tenacity) removed.

### Fixed

- The Quick take in `--image-only` runs suggested removing `--scan-only` (the wrong
  flag for that mode); it now suggests adding a Dockerfile scan.
- The Trivy progress spinner no longer prints a half-drawn progress bar into
  non-terminal output such as CI logs.
- The Dockerfile scan block in the HTML report used a hardcoded light background
  that was unreadable in dark mode; it now follows the report theme.

- A narrower cached scan could previously be reused in situations where the image
  had been rebuilt under the same tag; digest keying fixes this class of stale
  results.
