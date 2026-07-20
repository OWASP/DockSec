# Roadmap Implementation Notes

Companion to [ROADMAP.md](../ROADMAP.md) and
[promptfoo-benchmark-review.md](promptfoo-benchmark-review.md). Each roadmap item gets
a "What to build" and "How to build it" section with enough context that work can
start from this document alone. Numbering matches the roadmap tiers.

Conventions that apply to every item:

- Python >= 3.12, argparse CLI (`docksec/cli.py`), Rich terminal output routed through
  `docksec/output.py`, reports via `docksec/report_generator.py`, env-driven config via
  `docksec/config_manager.py`.
- Keep the slim-core promise: new heavy dependencies go behind an extra in `setup.py`
  (like `docksec[ai]`), never into the core install.
- Every feature lands with pytest coverage under `tests/`, a README/docs update, and a
  CHANGELOG entry. New flags must behave sanely with `--json`, `--quiet`, `--no-color`,
  and the exit-code contract (0/1/2/3).
- No telemetry, ever. Anything that stores data stores it locally.

---

## Now

### N1. Persistent scan history

**What:** Every completed scan writes a summary row + full findings into a local
SQLite DB at `~/.docksec/history.db` (respect `DOCKSEC_RESULTS_DIR`'s parent override).
No behavior change otherwise; the DB is the substrate for trends, deltas, `list`,
`show`, and `view`.

**How:**

- New module `docksec/history.py`. Use stdlib `sqlite3` (no ORM; keep core slim).
- Schema v1 (store `schema_version` in a `meta` table for future migrations):
  - `scans(id, timestamp, scan_mode, target, image_digest, dockerfile_hash, score,
    critical, high, medium, low, suppressed_count, docksec_version)`
  - `findings(scan_id, vuln_id, target, pkg_name, installed_version, fixed_version,
    severity, title, source)` where `source` is `trivy | compose | hadolint | ai`.
- Target identity: reuse the cache-key logic in `docker_scanner.ScanResultsCache`
  (image digest via `docker image inspect`, dockerfile content hash) so history rows
  for "the same target" line up with cache semantics.
- Hook the write into `cli.py` right after the results dict is finalized (after
  waivers are applied, before `_render_scan_summary`), for all modes including
  `--json` and ai-only. Failures to write history must warn, never fail the scan.
- Add `--no-history` flag and `DOCKSEC_HISTORY=false` env toggle.
- Concurrency: open with `timeout=5` and WAL mode so parallel CI jobs on one runner
  do not corrupt the DB.
- Tests: golden insert from a fixture results dict; schema-migration test; corrupt-DB
  recovery test (rename and recreate on `sqlite3.DatabaseError`, with a warning).

### N2. `docksec view` local web dashboard

**What:** `docksec view [--port 7777]` serves a localhost dashboard over the history
DB: scan list, severity breakdown, score trend per target, filterable findings table,
scan-vs-scan diff, links to report files. This is the project's screenshot surface -
polish matters (promptfoo's `view` is the model).

**How:**

- New extra `docksec[view]` pulling FastAPI + uvicorn (or keep zero-dep: stdlib
  `http.server` + a single-page static app; decide at build time - FastAPI is the
  recommended path, it stays out of core).
- New package dir `docksec/webui/`: `server.py` (routes: `/api/scans`,
  `/api/scans/{id}`, `/api/trend?target=`, `/api/diff?a=&b=`) and `static/` (one
  `index.html` + vanilla JS or a small prebuilt bundle committed to the repo; avoid a
  Node build step in v1).
- Reuse severity colors/bands from `output._score_band` and the HTML report template
  aesthetics so CLI, HTML report, and dashboard look like one product.
- Charts: a tiny embedded chart lib (e.g. vendored uPlot or hand-rolled SVG bars) -
  no CDN calls, the dashboard must work air-gapped.
- `docksec view` opens the browser (`webbrowser.open`) unless `--no-browser`.
- Diff endpoint: set difference of finding fingerprints (reuse
  `baseline.fingerprint()`) between two scan ids -> added/removed/unchanged.
- Tests: API route tests with a seeded temp DB; no browser tests in v1.

### N3. `docksec init`

**What:** `docksec init [dir]` scaffolds a demo project: `Dockerfile` (deliberately
imperfect: `:latest` base, root user, ADD, a fake-looking ENV secret, no
HEALTHCHECK), `docker-compose.yml` (a couple of tuned-rule triggers),
`.docksec-ignore.yml` with one commented example, `.docksec.yml` once N7 exists, and
a `README.md` telling the user to run `docksec Dockerfile --scan-only`. Ends by
printing the exact next command.

**How:**

- New module `docksec/init_cmd.py`, dispatched in `main()` before argparse exactly
  like `install-skill` is today (follow that pattern; see `install_skill.py`).
- Templates as string constants or `docksec/templates/init/` files included via
  package data (update `MANIFEST.in`).
- Refuse to overwrite existing files (print a warning per skipped file); `--force`
  overwrites. Exit 0 on success, 2 on bad args.
- The demo Dockerfile should be *safe* (never actually exploitable, fake secret
  values obviously fake like `password123-example`) but trip: root user, latest tag,
  ADD, ENV secret, EXPOSE 22 - producing a low score and a rich Quick take.
- Tests: scaffold into tmp_path, run the real scanner logic against the generated
  Dockerfile config-score path (`SecurityScoreCalculator._calculate_config_score`)
  and assert findings fire.

### N4. Documentation and project website (Docusaurus)

**What:** A Docusaurus v3 site in `site/` (promptfoo's exact pattern: marketing
pages, docs, and blog in one build with one design system), published to GitHub
Pages. Three surfaces:

- Landing page (`site/src/pages/index.tsx`): hero with one-line value prop
  ("AI-powered Docker security scanner that explains vulnerabilities in plain
  English"), a copy-paste `pip install docksec && docksec init && docksec Dockerfile
  --scan-only` block above the fold, the N5 GIF and report/dashboard screenshots, a
  three-step Scan/Analyze/Fix section, persona sections (developers, platform teams,
  security teams), the privacy/no-telemetry guarantee, OWASP branding, and links to
  docs and GitHub.
- Docs (`site/docs/`): Getting started, Installation, CLI reference, Configuration,
  CI integrations (one page per system), Reports and formats, Data flow and privacy,
  Compliance mappings, Architecture, FAQ, Contributing.
- Blog (`site/blog/`): guides and release announcements (feeds X7).

**How:**

- `npx create-docusaurus@latest site classic --typescript`; the Node toolchain lives
  only under `site/` and never touches the Python package. Add `site/` to the sdist
  excludes.
- Docusaurus config: `url: https://owasp.github.io`, `baseUrl: /DockSec/` initially
  (switch to a custom domain like `docksec.dev` later via CNAME), dark/light mode,
  navbar (Docs, Blog, GitHub, OWASP Slack), footer with OWASP project links, Prism
  highlighting for `bash`/`yaml`/`dockerfile`.
- Seed docs by splitting the current README: Common Commands -> CLI reference page
  (verify against `docksec --help` output); CI/CD Integration -> per-CI pages;
  Reports, Data flow and privacy move nearly verbatim.
- New workflow `.github/workflows/docs.yml`: on PR touching `site/`, `npm ci &&
  npm run build` (build is the link check); on push to main, deploy to `gh-pages`
  (`actions/deploy-pages` or `peaceiris/actions-gh-pages`). CI workflow changes need
  explicit lead approval per repo rules.
- Style: follow promptfoo's site conventions (their `site/` dir is a good structural
  reference) but with DockSec/OWASP branding - blue palette matching the README
  badges, no vendor content. Keep pages fast and image-light; all assets local.
- Keep README as the front door: value prop, quick start, visuals, links into the
  site (see N5).

### N5. Demo media in the README

**What:** A terminal GIF of `docksec Dockerfile --scan-only` on the `init` demo
project ending on the severity table/score/Quick take, plus a screenshot of the HTML
report (and later the dashboard). Placed right under the tagline like promptfoo's
matrix screenshot.

**How:**

- Record with `vhs` (charmbracelet) so the GIF is reproducible from a committed
  `.tape` script (`docs/media/demo.tape`); output `images/demo.gif`.
- Use a 100-col terminal, the default theme, and trim to <15s / <3MB.
- HTML report screenshot at 1200px wide, light theme, cropped to the summary +
  severity cards.
- Update README: move one visual above the fold (right after the tagline), keep the
  rest in a "See it in action" section.

### N6. Official container image

**What:** `ghcr.io/owasp/docksec` multi-arch (amd64/arm64) with Trivy + Hadolint
baked in, published on each release, `latest` + version tags. Documented
`docker run -v $(pwd):/work ghcr.io/owasp/docksec /work/Dockerfile --scan-only`.

**How:**

- Rework the existing root `Dockerfile`: multi-stage, `python:3.13-slim` base, copy
  Trivy + Hadolint binaries from their official images
  (`aquasec/trivy`, `hadolint/hadolint`), `pip install .` (core, not `[ai]`; document
  `docksec[ai]` variant tag or build-arg), non-root user (dogfood our own advice),
  `ENTRYPOINT ["docksec"]`, `WORKDIR /work`.
- Note: image scanning (`-i`) inside the container needs the Docker socket mounted;
  document it, and point `--remote` users here once X1 lands.
- New workflow `.github/workflows/docker-publish.yml` using
  `docker/build-push-action` with QEMU for arm64, triggered on release tags
  (workflow addition: get explicit approval). Sign with cosign keyless if cheap.
- Smoke test in CI: build, run `--version`, scan a fixture Dockerfile, assert exit 0.

### N7. Repo-level configuration file

**What:** `.docksec.yml` in CWD (or `--config <path>`; also support
`[tool.docksec]` in `pyproject.toml`) providing defaults for: `severity`, `fail_on`,
`format`, `output_dir`, `provider`, `model`, `ignore_file`, `baseline`, plus a
`rules:` block for disabling compose rules. Precedence: CLI flag > env var > config
file > built-in default. Publish a JSON Schema.

**How:**

- New module `docksec/file_config.py`: locate, parse (PyYAML is already a dep via
  compose scanning; verify, else use stdlib tomllib for the pyproject path), validate
  keys, and return a dict.
- Wire into `cli.py` as a resolution layer: after `parse_args`, for each supported
  option, if the CLI value is the argparse default and the env var is unset, take the
  config-file value. Keep the existing severity resolution comment/logic pattern.
- Unknown keys: warn, do not fail (forward compatibility).
- Rule disabling: thread a `disabled_rules: set[str]` into `ComposeScanner` (rule ids
  already exist, e.g. `no-non-root-user`).
- JSON Schema: hand-write `schema/docksec-config.schema.json`, add a test that
  validates the documented example against it, and register intent to submit to
  schemastore.org so editors pick it up automatically.
- Tests: precedence matrix (flag vs env vs file), invalid YAML, unknown key warning,
  disabled rule actually suppressed.

### N8. Hadolint findings as first-class findings

**What:** Run `hadolint -f json`, map results into the same finding shape as
`json_data` (`VulnerabilityID`=rule id e.g. `DL3002`, `Severity` mapped from
hadolint's error/warning/info/style -> HIGH/MEDIUM/LOW/LOW, `Target`=dockerfile,
line number preserved), so they flow through `--fail-on`, `--json`, SARIF (with line
regions), baselines, waivers, reports, and scoring.

**How:**

- In `docker_scanner.py`, change the Hadolint invocation to `-f json` and parse; keep
  the raw text render for the human summary or derive it from JSON.
- Add `source: "hadolint"` to each finding dict; extend `_filter_scan_results`
  consumers to tolerate the new source field (additive, no breaking change).
- SARIF: hadolint findings already have line numbers - emit `region.startLine`
  directly (`_sarif_region` currently parses lines only from compose `Target`
  strings; add a first-class `Line` key instead).
- Severity mapping table lives in one place (`enums.py` or the scanner) with a test.
- `--severity` filter question: keep hadolint findings always-on like compose rules
  (documented), but let waivers/`rules:` config disable individual DLxxxx ids.
- Update `--fail-on` docs + CLAUDE.md note that lint findings now gate.
- Tests: fixture hadolint JSON -> findings; gate trips on DL3002 at `--fail-on high`;
  SARIF region present.

---

## Next

### X1. Registry / remote image scanning

Add `--remote` (and auto-fallback when `docker` is absent): skip the
`docker image inspect` gate in `DockerSecurityScanner`, call Trivy directly with the
image reference (Trivy pulls from the registry itself, honoring
`TRIVY_USERNAME`/`TRIVY_PASSWORD`/`AWS_*`/`GOOGLE_APPLICATION_CREDENTIALS`). Cache
key: use the registry digest from Trivy's JSON output (`Metadata.RepoDigests`)
instead of `docker image inspect`. Docker Scout advanced scan is skipped in remote
mode. Tests: mock subprocess; assert no `docker` invocation happens with `--remote`.

### X2. CI templates beyond GitHub Actions

Pure docs + example files: `examples/ci/Jenkinsfile`, `examples/ci/.gitlab-ci.yml`,
`examples/ci/azure-pipelines.yml`, `examples/ci/circleci-config.yml`,
`examples/ci/bitbucket-pipelines.yml`. Each uses the container image (N6) when
available, otherwise pip install; demonstrates `--fail-on high --json` with the exit
codes, and SARIF upload where the platform supports it (GitLab: convert to its
security-report JSON only if trivially mappable, else skip). One docs-site page per
platform with the file inlined and explained. Verify each in a real pipeline once
before publishing (Jenkins first - Broadcom relevance).

### X3. Versioned JSON output contract

Add `"schema_version": "1.0"` to `_print_json_results` payload and the JSON report
writer. Write `schema/docksec-output.schema.json` (JSON Schema draft 2020-12)
describing `scan_info`, `vulnerabilities[]`, `severity_counts`, `ai_analysis`,
`report_files`. Golden-file test: run a scan on fixtures, validate output against the
schema with `jsonschema` (test-only dep). Rule: additive changes bump minor, breaking
changes bump major + changelog callout.

### X4. Trend tracking and deltas

Reads the history DB (N1). In `_render_scan_summary`, look up the previous scan for
the same target identity; if found, print a delta line under the severity table:
`Since last scan (2026-07-15): 3 new, 5 fixed, score 62 -> 71`. Computation: baseline
`fingerprint()` set difference. Add `--no-delta` to suppress. Expose the same data at
`/api/trend` for the dashboard. Include `delta` object in `--json` output (behind
schema minor bump, see X3).

### X5. `docksec list` / `docksec show`

Subcommands dispatched like `install-skill`. `list`: Rich table of recent scans
(id, date, target, mode, score, C/H/M/L), `--limit`, `--target` filter, `--json`.
`show <id>`: re-render the stored scan through the existing `_render_scan_summary`
path (findings reconstructed from the DB), `--json` prints the stored payload.
This is mostly plumbing over N1; keep rendering code shared with the live-scan path.

### X6. OWASP project page refresh

The Docusaurus landing page (N4) is the primary website. This item reworks the OWASP
project page markdown that also lives in this repo (`index.md`, `info.md`,
`tab_*.md`): one-line value prop, install + first-scan command block, the N5 GIF,
three-step Scan/Analyze/Fix, persona paragraphs, privacy guarantee, and a prominent
link to the Docusaurus site. Keep the two consistent; the OWASP page funnels to the
site.

### X7. Guides and articles

Docs-site `guides/` section. Initial slate (one per PR, SEO-titled):
"Dockerfile security best practices, checked automatically",
"Docker Compose security checklist", "Scanning container images in CI without a
Docker daemon", "DockSec vs standalone Trivy", "Understanding your DockSec security
score", "Air-gapped container scanning". Each guide ends with the exact docksec
commands. Comparisons must stay factual and respectful (OWASP vendor-neutrality);
reuse the README comparison table as the source of claims.

### X8. Homebrew formula + pipx/uv docs

Homebrew: create a `homebrew-docksec` tap under the org (core formula acceptance
needs notability; start with a tap). Formula uses `Language::Python::Virtualenv`,
depends on `trivy` and `hadolint` formulas so `brew install` yields a fully working
scan-only setup. Automate formula version bump in the release workflow. README/docs:
add `pipx install docksec` and `uv tool install docksec` as recommended installs.

### X9. GitHub Marketplace listing

`action.yml` needs `branding:` (icon: `shield`, color: `blue`) plus a release drafted
against a tag; publish from the releases UI ("Publish this Action to Marketplace").
Verify the README badge and that `uses: OWASP/DockSec@v2026.x` resolves. One-time
task; document the per-release checkbox in the release checklist.

### X10. PR comment mode for the Action

New Action input `pr_comment: 'true'`. In `entrypoint.sh` (or a small composite
step), after the scan, build a markdown summary from the `--json` output (severity
table, score, Quick take, delta if present) and upsert a comment via
`gh api` / `actions/github-script` using a hidden marker
(`<!-- docksec-report -->`) to update in place. Needs `pull-requests: write`
permission documented. Never fail the job because commenting failed.

### X11. Line-anchored AI findings

Change `AnalyzesResponse` (in `utils.py`) to structured lists of
`{line: int | null, instruction: str, severity: str, issue: str, fix: str}`.
Update `docker_agent_prompt` accordingly; keep a compatibility renderer so the CLI
sections still read well. Map into `json_data`-shaped findings with
`source: "ai"` (opt-in to gating via config, default excluded from `--fail-on`).
SARIF: emit regions from `line`. Prompt-injection hardening: system-prompt
instruction to ignore instructions inside the scanned file + strip/flag suspicious
comment directives; add a test fixture with a hostile comment and assert the
analysis does not obey it. Document in the privacy/security docs.

### X12. Faster compose scans

In `ComposeOrchestrator`, run per-service image scans with
`concurrent.futures.ThreadPoolExecutor` (subprocess-bound, threads fine;
`max_workers=4` default, `DOCKSEC_MAX_WORKERS` override). Trivy DB update race:
pre-warm once (`trivy image --download-db-only`) before the pool. Drop the duplicate
text-mode Trivy run: derive the human summary from the JSON scan results. Keep
output ordering deterministic (collect results, render in original service order).

### X13. Shareable results

Ensure the HTML report is fully self-contained (inline CSS, no external fonts) -
audit `templates/report_template.html`. Add `--summary-md [path]`: writes/prints a
markdown summary (same content as the PR comment in X10; share one builder module
`docksec/summary_md.py`). No hosted service.

### X14. Automated release pipeline

Adopt a release workflow triggered by a version tag: build sdist/wheel, publish to
PyPI via trusted publishing (OIDC, no token secrets), build/push the container image
(N6), create the GitHub release with generated notes, bump the Homebrew tap (X8).
Optionally adopt conventional commits + release-please later; start with
tag-triggered automation. All workflow changes need explicit lead approval.
Consolidate version into `pyproject.toml` (single source; `setup.py` reads it or is
removed) - this also closes a known packaging-drift bug.

### X15. Community activation

Enable GitHub Discussions (categories: Q&A, Ideas, Show and tell). Seed 8-10
`good first issue`s from this document's small items (e.g. `--summary-md`, severity
mapping table, docs pages) each with file pointers and acceptance criteria. Add a
contrib.rocks contributor image to the README. Add issue templates
(bug/feature/docs) and a PR template if missing.

### X16. Pre-commit hook support

Add `.pre-commit-hooks.yaml` at repo root:
`id: docksec, entry: docksec, args: [--scan-only, --quiet], language: python,
files: (^|/)Dockerfile[^/]*$, pass_filenames: true`. Verify `docksec <file>
--scan-only` behaves with multiple filenames (argparse takes one positional - loop
in a tiny wrapper entry point or set `pass_filenames: false` with a find-based
approach; decide during implementation). Document in the CI docs page.

### X17. MCP server mode

`docksec mcp` subcommand (dispatch like `install-skill`) behind a `docksec[mcp]`
extra using the official `mcp` Python SDK (stdio transport). Tools: `scan_dockerfile
(path, severity?)`, `scan_image(image, severity?)`, `scan_compose(path)`,
`get_history(target?, limit?)` - each returns the versioned JSON payload (X3).
Read-only by design; no tool mutates state beyond normal scan side effects. Document
client config snippets for Claude Code, Cursor, and generic MCP clients; have
`install-skill` mention it.

### X18. `docksec doctor` and `docksec validate`

**What:** `doctor` prints an environment report with pass/warn/fail lines and the
exact fix command for each failure; `validate` checks config artifacts against their
schemas without scanning (promptfoo has both `debug` and `validate`; they cut
support load dramatically).

**How:**

- New module `docksec/doctor.py`, dispatched like `install-skill`. Checks: Python
  version; `trivy`/`hadolint`/`docker` on PATH with versions (reuse
  `DockerSecurityScanner._check_tools` logic); Trivy DB present and its age; AI
  provider config (which provider, key env var set or not - never print key values);
  cache and history DB readable; results dir writable; whether a `.docksec.yml` /
  `.docksec-ignore.yml` was detected. Render with `output.py` primitives; `--json`
  variant for CI. Exit 0 if all pass, 1 if any fail.
- `docksec validate [path...]`: no args validates whatever is auto-detected in CWD
  (`.docksec.yml`, `.docksec-ignore.yml`, baseline file); with args, validates the
  given files by type (extension/keys sniffing). Reuses the JSON Schemas from N7/X3
  and the parsers in `file_config.py`/`ignore.py`/`baseline.py`. Exit 0/2.
- Tests: fixture environments via monkeypatched `shutil.which`/subprocess; schema
  pass/fail fixtures.

### X19. Documented Python API

**What:** A stable, minimal library surface so DockSec is embeddable:
`from docksec import scan_dockerfile, scan_image, scan_compose` returning a typed
`ScanResult` (dataclass mirroring the results-dict contract in CLAUDE.md section 5),
plus `ScanResult.to_json()`.

**How:**

- New `docksec/api.py` wrapping the existing `DockerSecurityScanner` /
  `ComposeOrchestrator` without any Rich output (pass a quiet/null console or add a
  `silent` flag to the scanner paths). Export from `docksec/__init__.py` with
  `__all__`.
- The API is scan-only by default; AI analysis behind an explicit
  `analyze_with_ai=True` that raises the helpful `docksec[ai]` ImportError when the
  extra is missing.
- Semver-style promise documented: the dataclass fields track the JSON schema
  version (X3); breaking changes only with a major schema bump.
- Docs-site page "Using DockSec as a library" with three copy-paste examples
  (gate a pytest suite, scan in a FastAPI endpoint, batch-scan a directory).
- Tests: API smoke tests against fixtures; assert no stdout writes in silent mode.

### X20. Examples gallery

**What:** Grow `examples/` from the two compose files into a browsable gallery, each
subdirectory with a README ("what this shows, what DockSec finds, why it matters"):
per-language Dockerfiles (`python/`, `node/`, `go/`, `java/`) in insecure/secure
pairs, multi-stage build example, compose stacks (current files move here), CI
setups (symlink or reference X2 files), waiver workflow, baseline workflow.

**How:**

- Structure: `examples/<topic>/{README.md, files...}`; top-level `examples/README.md`
  index table. Docs site gets an auto-generated or hand-kept Examples page linking
  into the repo.
- Every insecure example must be safe-by-construction (obviously fake secrets, no
  real exploits) - same rule as N3.
- Wire examples into tests as fixtures (parametrized scan test asserting the
  insecure variant scores below the secure one) so the gallery cannot rot.
- Each example ends with the exact command to run and a snippet of expected output.

---

## Later

### L1. Kubernetes manifest and Helm chart scanning

New `k8s_scanner.py` mirroring `compose_scanner.py`: static rules over parsed YAML
(privileged, hostPath, hostNetwork, missing securityContext/runAsNonRoot, missing
resource limits, :latest images, missing probes), `--k8s <path|dir>` flag, findings
in the standard shape with `file:kind/name:line` targets. Helm: render via
`helm template` when the binary exists, then scan rendered output. Fan out per-image
scans for `image:` references like compose does. Deserves a short design doc first
(rule list + severity defaults) reviewed in an issue before code.

### L2. Policy packs

`docksec/policies/` with YAML pack files mapping existing rule/check ids to framework
controls (`cis-docker.yml`: rule id -> CIS 4.1 etc.). `--profile cis-docker` filters/
annotates findings with control ids; reports and SARIF gain a `compliance` field;
HTML report gets a per-control summary table. Start with CIS Docker Benchmark (the
mapping is mostly the existing config checks), then NIST SP 800-190.

### L3. Compliance mapping pages

Docs-site pages generated from the L2 pack YAML (single source of truth): a table of
control -> DockSec check -> status (covered / partial / planned). Can precede L2 as
hand-written tables if contributors want the docs first.

### L4. Evaluation guide

Docs page + `examples/evaluation/` directory with a deliberately vulnerable image
build. 15-minute script: install, `docksec init`-style scan, read the Quick take,
add a waiver, set a baseline, wire `--fail-on` in CI, view history. Every step is
copy-paste with expected output shown.

### L5. SPDX SBOM export

Trivy supports `--format spdx-json`; mirror the CycloneDX path
(`generate_cyclonedx_report`) with `generate_spdx_report`, flag `--sbom-format
{cyclonedx,spdx}` (default cyclonedx, keep `--sbom` behavior unchanged).

### L6. Bundled offline vulnerability database

Investigate `trivy` DB download/packaging (`trivy image --download-db-only` +
`TRIVY_CACHE_DIR`): ship a `docksec offline-bundle` command that produces a tarball
(DB + optionally the container image) and a documented restore procedure, rather than
literally bundling the DB in the wheel (it is hundreds of MB and updates daily).

### L7. Threat model and security documentation

`docs-site` security section: threat model (attack surface: scanned files are
untrusted input; LLM output is untrusted; subprocess invocation hygiene; report file
permissions), plus the existing SECURITY.md flow. Work through the OpenSSF Best
Practices silver checklist and record evidence.

---

## Suggested build order

Dependencies, not dates:

1. N1 history -> N2 view, X4 deltas, X5 list/show.
2. N3 init + N5 media -> X6 landing page.
3. N4 docs site -> X2 CI templates, X7 guides, L3 compliance pages.
4. N7 config file and X3 JSON contract early - other items (N8, X10, X13, X17)
   build on them.
5. N6 image -> X2 templates use it -> X14 release automation publishes it.
6. N8 hadolint -> X11 AI findings reuse the same "new source" plumbing.
7. N7/X3 schemas -> X18 validate; N1 history + existing scanners -> X18 doctor.
8. X19 Python API waits for the X3 contract; X20 examples feed N3 init, X7 guides,
   and the test suite.
