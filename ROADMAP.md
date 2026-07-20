# DockSec Roadmap

This is the directional plan for DockSec. Priorities are shaped by user feedback, so
if an item here matters to you (or something is missing), say so in an
[issue](https://github.com/OWASP/DockSec/issues) or in the
[#project-docksec](https://owasp.slack.com/archives/C0APXGCUW7M) channel on OWASP Slack.

Dates are intentionally absent: items ship when they are ready. Recently completed work
moves to the [CHANGELOG](CHANGELOG.md).

Items are grouped by priority and listed in order within each group. "Now" items are
where contributions help most.

## Now (highest priority)

These either unblock everything after them or remove the biggest barriers to adoption.

1. **Persistent scan history.** Store every scan result (score, severity counts,
   findings, target identity) in a local SQLite database under `~/.docksec/`,
   alongside the existing report files. This is the foundation for trends, deltas,
   scan comparison, and the dashboard below - nothing in the "results" track can ship
   without it. Local only, never uploaded, consistent with the no-telemetry stance.
2. **`docksec view`: a local web dashboard.** A single command that opens a local web
   UI over scan history: severity breakdown charts, score trend per image, a
   filterable and sortable findings table, side-by-side comparison of two scans, and
   report downloads. Runs entirely on localhost with no external dependencies. This
   becomes the visual face of the project alongside the CLI and the source of every
   screenshot used to present DockSec.
3. **`docksec init`.** Scaffold a ready-to-scan example project: a deliberately
   imperfect Dockerfile and compose file, a sample `.docksec-ignore.yml`, and a CI
   snippet, so the very first run always produces interesting, teachable findings
   within two minutes of install. First-run success is the single biggest driver of
   whether a new user stays.
4. **Dedicated documentation and project website (Docusaurus).** Move beyond the
   single long README to a proper Docusaurus site published via GitHub Pages: a
   landing page (hero, copy-paste quick start, screenshots), full documentation
   (getting started, CLI reference, configuration, CI integrations with one page per
   CI system, reports and formats, data flow and privacy, compliance mappings,
   architecture, FAQ), and a blog for guides and release announcements - all in one
   build with one design system. The README slims down to value proposition, quick
   start, screenshots, and links.
5. **Demo media in the README.** A short terminal GIF of a real scan (ending on the
   severity table, score, and Quick take) and a screenshot of the HTML report, so
   visitors see the output before installing anything. Cheap, and it improves the
   first impression of every other item on this list.
6. **Official container image.** `docker run ghcr.io/owasp/docksec ...` with Trivy and
   Hadolint baked in, published multi-arch on each release, for zero-install
   evaluation and air-gapped deployment. Also what most platform teams will actually
   deploy in CI.
7. **Repo-level configuration file.** A committed `.docksec.yml` (or `[tool.docksec]`
   in `pyproject.toml`) for severity, fail-on threshold, report formats, output
   directory, disabled rules, ignore entries, and provider settings, so a team's
   policy lives in the repo instead of per-developer flags. Ships with a published
   JSON Schema so editors validate and autocomplete the file.
8. **Dockerfile lint findings as first-class findings.** Parse Hadolint's JSON output
   (`hadolint -f json`) into structured findings with mapped severities so they
   participate in `--fail-on`, `--json`, SARIF, baselines, waivers, and the reports
   the same way image vulnerabilities already do. Today lint results are a raw text
   blob, so CI can pass with a root-user, ADD-from-URL Dockerfile - a credibility gap
   for a Dockerfile security tool.

## Next

High value, but they build on the "Now" items or serve users DockSec has not reached
yet.

1. **Registry / remote image scanning.** Scan images in a registry (Artifactory,
   Harbor, ECR, Docker Hub) without a local Docker daemon, using Trivy's remote
   scanning and the standard registry auth environment variables. Today the scanner
   requires the image locally; this adds a `--remote` mode or automatic fallback that
   skips the daemon check. Unblocks daemonless CI runners, the most common enterprise
   scanning environment.
2. **CI templates beyond GitHub Actions.** Copy-paste, documented examples for Jenkins
   (declarative pipeline stage), GitLab CI (including GitLab's native security report
   format where cheap), Azure Pipelines, CircleCI, and Bitbucket Pipelines, all built
   on the existing exit codes, `--json`, and SARIF output. Each gets its own page on
   the docs site.
3. **Versioned JSON output contract.** A `schema_version` field in the `--json`
   payload and a published JSON Schema in the repo, backed by a golden-file test, so
   automation built on DockSec output cannot break silently between releases. Should
   land before third parties build on the output in earnest.
4. **Trend tracking and deltas.** With scan history in place, report changes between
   scans of the same target ("3 new, 5 fixed since last scan") in the CLI summary,
   and expose score and count trends over time in the dashboard.
5. **`docksec list` / `docksec show`.** CLI access to scan history: list past scans,
   show a previous result without rescanning.
6. **Project landing page.** Rework the public-facing page (the OWASP project page,
   and potentially a dedicated domain) around a clear structure: one-line value
   proposition, a copy-paste install-and-scan command above the fold, three visuals
   (terminal output, HTML report, dashboard), a three-step "Scan, Analyze, Fix"
   explanation, sections addressed to developers, platform teams, and security teams,
   and the privacy/no-telemetry guarantee stated prominently. Depends on the demo
   media and dashboard screenshots existing first.
7. **Guides and articles.** A steady stream of practical content on the docs site:
   hardening guides ("secure a Python Dockerfile step by step", "Docker Compose
   security checklist"), honest comparisons ("DockSec vs standalone Trivy vs
   commercial scanners"), and framework mappings. This kind of content is how
   developers discover security tools, and it compounds over time - the earlier it
   starts, the better.
8. **Homebrew formula.** `brew install docksec` for macOS and Linux users who do not
   want to manage a Python environment. Also document `pipx install docksec` and
   `uv tool install docksec` as the recommended isolated installs.
9. **GitHub Marketplace listing** for the Action, with versioned tags (already
   published as `@v2026.x` releases) so CI can pin safely.
10. **Pull request comment mode** for the GitHub Action: a summary comment on the PR
    with the severity table, score, and Quick take, updated in place on subsequent
    pushes.
11. **Line-anchored AI findings.** Replace the current free-text AI output with a
    structured schema per finding (line number, instruction, severity, issue, fix) so
    AI findings can appear in SARIF regions, PR annotations, and the dashboard, not
    just as prose. Includes prompt-injection hardening for hostile Dockerfile
    comments.
12. **Faster compose scans.** Scan compose services in parallel instead of serially,
    and derive the human-readable summary from the JSON scan instead of running Trivy
    twice per image. On a six-service stack this is the difference between a snappy
    run and a multi-minute wait.
13. **Shareable results.** A way to hand a scan result to a teammate that is better
    than attaching a file: at minimum a self-contained single-file HTML report
    designed for sharing, and a markdown summary suitable for pasting into a PR or
    Slack. A hosted share link is explicitly out of scope for now (it would conflict
    with the local-only privacy stance) unless the community asks for an opt-in
    version.
14. **Automated release pipeline.** Conventional-commit-driven releases: changelog
    generation, PyPI publish, container image build, and Action tag from a single
    release workflow, so releases are frequent and low-effort. Rises in priority as
    the number of published artifacts (image, formula, Action) grows.
15. **Community activation.** GitHub Discussions for questions and ideas (keeping
    issues for bugs and concrete feature work), a curated `good first issue` pipeline
    with pointers into the code, and a contributor wall in the README.
16. **Pre-commit hook support.** A `.pre-commit-hooks.yaml` so teams can run
    `docksec --scan-only` on changed Dockerfiles via the pre-commit framework.
17. **`docksec doctor` and `docksec validate`.** `doctor` checks the environment
    (Python version, Trivy/Hadolint/Docker presence and versions, API key and
    provider configuration, cache and history health) and prints actionable fixes;
    `validate` checks a `.docksec.yml`, ignore file, or baseline file against their
    schemas without running a scan. Both cut support burden and make CI failures
    self-explanatory.
18. **Documented Python API.** A small, stable `import docksec` surface
    (`docksec.scan_dockerfile(...)`, `docksec.scan_image(...)` returning typed
    results) so teams can embed DockSec in their own tooling instead of shelling out
    to the CLI. Documented on the site with examples.
19. **Examples gallery.** Grow `examples/` into a browsable gallery: per-language
    Dockerfiles (Python, Node, Go, Java), insecure-vs-secure pairs, compose stacks,
    CI setups, and waiver/baseline workflows - each with a README explaining what
    DockSec finds and why. Examples double as test fixtures and as documentation.
20. **MCP server mode.** A `docksec mcp` command exposing scans as Model Context
    Protocol tools, so AI agents and assistants can invoke DockSec directly and
    consume structured results. Complements the existing `install-skill` command;
    cheap to build on top of the `--json` contract, but waits for that contract to be
    versioned.

## Later

Important, but dependent on the foundations above or serving more specialized needs.

1. **Kubernetes manifest and Helm chart scanning.** The same static-rule approach as
   compose scanning, applied to Kubernetes manifests and rendered Helm charts
   (privileged pods, missing resource limits, hostPath mounts, missing security
   contexts). The most requested "does it also do..." capability from platform teams,
   but a large surface that deserves its own design pass.
2. **Policy packs.** Named profiles (for example `--profile cis-docker`) that map
   existing findings to compliance frameworks such as the CIS Docker Benchmark, NIST
   SP 800-190, and the OWASP Docker Top 10. Mostly metadata over existing rules, but
   a strong requirement for regulated teams.
3. **Compliance mapping pages.** Standalone documentation pages mapping DockSec checks
   to the CIS Docker Benchmark, NIST SP 800-190, and the OWASP Docker Top 10,
   published ahead of (and then alongside) the policy-pack feature. Can start earlier
   as pure documentation if there is contributor appetite.
4. **Evaluation guide.** A 15-minute walkthrough for security teams assessing DockSec,
   built around a deliberately vulnerable example image, covering scan, triage,
   waivers, baseline, and CI gating.
5. **SPDX SBOM export** alongside the existing CycloneDX support.
6. **Bundled offline vulnerability database** for true air-gap installs (today
   `--offline` relies on a previously downloaded Trivy DB).
7. **Threat model and security documentation.** A published threat model for DockSec
   itself and a SECURITY.md-backed disclosure process (partially in place), moving
   the project toward higher OpenSSF Best Practices tiers.

## Recently shipped

See the [CHANGELOG](CHANGELOG.md). Highlights from 2026.7.4/2026.7.5: secret redaction
before AI analysis, auditable waiver files, digest-keyed scan caching with TTL, a slim
scan-only install, tuned compose rules, and an overhauled HTML report.
