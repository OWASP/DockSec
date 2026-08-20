# What DockSec should learn from promptfoo

A review of the [promptfoo](https://github.com/promptfoo/promptfoo) repository, read as a
benchmark for what a polished, industry-adopted open source security tool looks like, and
translated into a concrete build list for DockSec.

Reviewed at promptfoo `v0.122.0`. DockSec state as of `2026.8.19`.

This is a prioritized and filtered list, not a catalogue. Items promptfoo has that DockSec
should deliberately *not* copy are called out in the last section, with reasons.

**Progress:** 1 of 12 items shipped. See [Status](#status) for what is done and what is
next.

---

## The one-paragraph summary

promptfoo does not feel professional because of any single feature. It feels professional
because of four things that compound:

1. **A typed config schema is the center of the product.** Everything - CLI, validation,
   docs, editor autocomplete, the JSON output contract - is generated from or checked
   against one schema. Nothing drifts.
2. **The tool teaches you how to use it.** `init` scaffolds a working config from 231
   real examples. `validate` tells you your config is wrong before you waste a run.
   `debug` prints a paste-ready troubleshooting dump.
3. **Results persist and are reviewable.** A local database keeps history, a local web UI
   renders it, and one command produces a shareable link. Scans are not one-shot terminal
   output that disappears.
4. **The docs are a product surface, not a README.** A real docs site with 25 dedicated
   integration pages, so that whatever CI system an evaluator uses, there is a page with
   their name on it.

DockSec has genuinely strong bones - the scanner core, report writers, waivers, baseline
mode, SARIF, and exit-code discipline are all in place and are the hard part. What is
missing is almost entirely the *surface*: config, onboarding, persistence, and docs. That
is good news, because surface work is cheaper and more visible than engine work.

---

## Status

What has been built from this list, and what comes next.

| Item | Status | Shipped in |
| --- | --- | --- |
| 1.1 Config file, schema-first | Done | 2026.8.19 |
| 1.2 `docksec init` | Next | - |
| 1.3 `docksec validate` / `doctor` | Next | - |
| 1.4 CI integration docs | Not started | - |
| 1.5 Publish the container image | Not started | - |
| 2.1 Scan history and trends | Not started | - |
| 2.2 Web UI (Phase A: HTML report) | Not started | - |
| 2.3 Policy packs / compliance mapping | Not started | - |
| 2.4 Examples set + evaluation guide | Not started | - |
| T3 Packaging consolidation | Not started | - |
| T3 Release automation | Not started | - |
| T3 Docs site | Not started | - |

### Recommended next: 1.2 `init` and 1.3 `validate` / `doctor`

Now that 1.1 exists, these three are the cheapest remaining wins and they share a
foundation - all operate on `.docksec.yml` and the `DocksecFileConfig` model, so they can
ship as one piece of work:

- `validate` is close to free: `load_config_file()` already raises `ConfigFileError` with
  the offending key and file path. The command is a thin wrapper that exits 0 or 2.
- `doctor` reuses `find_config_file()` to report the discovered config and its fully
  resolved settings, alongside tool versions and environment.
- `init` writes the annotated `examples/.docksec.yml` template, which already exists.

Two items are latent bugs rather than features and should be picked up regardless of
sequencing: the `Dockerfile` Trivy URL (1.5) and packaging consolidation (Tier 3).

### Fixed along the way

Not on the original list, but found and fixed while building 1.1:

- **Ruff CI breakage.** Both lint workflows ran `pip install ruff` unpinned. Ruff 0.16
  enabled several new rule groups by default, producing 320 errors on untouched code and
  failing every pull request regardless of content. The rule set is now pinned in
  `pyproject.toml` (`[tool.ruff.lint] select`). This is a smaller instance of the same
  lesson as Tier 3's release automation: unpinned tooling in CI breaks builds on someone
  else's release schedule.
- **Flag defaults.** `--offline`, `--no-cache`, `--no-redact`, and `--skip-ai-scoring`
  used argparse's implicit `False`, making "flag absent" indistinguishable from "explicitly
  false". Harmless before a config file existed; a correctness bug the moment one did.

---

## Where DockSec stands today

Worth being precise about, because several of these are already competitive.

| Area | promptfoo | DockSec today |
| --- | --- | --- |
| Machine-readable output | JSON + published JSON Schema | `--json`, SARIF 2.1.0, CycloneDX SBOM |
| CI gating | pass-rate threshold, exit codes | `--fail-on`, exit codes 0/1/2/3, baseline ratchet |
| Suppressions | config-level | `.docksec-ignore.yml` with reason + expiry |
| Config file | `promptfooconfig.yaml` + Zod schema | `.docksec.yml` + published JSON Schema (shipped) |
| Scaffolding | `init` with 231 examples | **none** |
| Config validation | `validate`, `validate-target` | **none** |
| Troubleshooting | `debug` | **none** |
| Result history | SQLite, `list`/`show`/`export` | **none** - reports overwrite |
| Web UI | React 19 + local server, `view` | **none** |
| Docs | Docusaurus site, 25 integration pages | README + 2 files in `docs/` |
| Examples | 231 directories | 2 compose files |
| Distribution | npm, brew, pip, npx, Docker, Helm | PyPI + an unpublished Dockerfile |
| Editor support | `yaml-language-server` schema hint | `yaml-language-server` schema hint (shipped) |

---

## Tier 1 - Do these first

Highest ratio of adoption impact to engineering cost. Each is independently shippable.

### 1.1 A real config file, schema-first - DONE (2026.8.19)

**The single highest-leverage item on this list**, and the reason it was built first:
everything else in Tier 1 operates on the config file, so building them in the other order
would have meant reworking each one.

Shipped as `docksec/project_config.py`:

- `.docksec.yml` (or `.docksec.yaml`), discovered from the working directory upward,
  stopping at the directory containing `.git` - so a monorepo subdirectory inherits the
  root policy, and discovery never escapes the repository.
- Precedence, documented and tested: **CLI flag > env var > config file > default.**
- Covers `severity`, `fail_on`, `formats`, `output_dir`, `provider`, `model`, `offline`,
  `skip_ai_scoring`, `no_redact`, `no_cache`, `ignore_file`, `baseline`, and
  `rules.disabled`.
- Defined as a **Pydantic model** with `extra="forbid"`, so a typo is an error rather than
  a silently ignored setting. Pydantic proved to be DockSec's Zod equivalent exactly as
  expected: one declaration yields parsing, validation, error messages, and JSON Schema
  export. It was already a core dependency, so this cost nothing at install time.
- JSON Schema committed at `docs/docksec-config-schema.json`, emitted by
  `--print-config-schema`, with the `# yaml-language-server:` hint in the example config
  for editor autocomplete.
- A test asserts the committed schema matches the model, so it cannot drift.
- `--config FILE` and `--no-config` for explicit selection and reproducible CI runs.

Per-rule disable (`rules.disabled`) is also the answer to the compose alert-fatigue
problem documented in `CLAUDE.md` section 9b, and it applies before scoring so a disabled
rule cannot influence the security score.

**Decisions worth recording**, since the later Tier 1 items should follow them:

- An invalid config file **exits 2** rather than warning and continuing. This is
  deliberately stricter than the ignore file, where a bad entry is skipped with a warning:
  suppression is advisory, but a broken policy file would mean scanning under rules the
  team never committed. `validate` (1.3) should keep the same contract.
- The schema-drift test is the pattern to reuse for any other generated artifact.
- Discovery stops at the `.git` boundary rather than walking to the filesystem root, so a
  developer's home-directory config can never silently apply to a repository.

### 1.2 `docksec init`

promptfoo's `init` is its best onboarding mechanic: a new user has a working config in
under a minute, without reading docs.

Build `docksec init`:

- Interactive by default: detect Dockerfiles and compose files in the current directory,
  ask which to target, ask for a severity threshold and a CI system.
- Writes a commented `.docksec.yml` plus, optionally, a CI job file for the chosen system.
- `--non-interactive` and `--example <name>` for scripted use and for docs.
- Never overwrite silently: prompt, or require `--force`.

The commented config it emits doubles as documentation. Many users will never read the
docs site but will read the file the tool wrote into their repo.

**Now cheaper than originally scoped:** `examples/.docksec.yml` already is the annotated
template, so `init` mostly needs the prompting and file-writing around it. Dispatch it the
way `install-skill` already is - intercepted as a verb before argparse in `main()` - rather
than adding a subparser, which would break the historical positional-Dockerfile CLI.
Whatever it writes should round-trip through `load_config_file()` in a test, so the
scaffold can never emit a config the tool itself rejects.

### 1.3 `docksec validate` and `docksec doctor`

Two small commands that carry outsized weight in an enterprise evaluation, because they
are what an evaluator hits when something goes wrong.

`docksec validate` - parse `.docksec.yml` against the schema and report errors with the
offending key, the file, and a suggested fix. Exit 0/2. **Now largely free:**
`project_config.load_config_file()` already raises `ConfigFileError` carrying the offending
key and file path, and `_format_validation_error()` already renders it key by key. The
command is a thin wrapper around what 1.1 built. Adding the line number is the only real
work, and needs ruamel's round-trip loader to preserve position data.

`docksec doctor` (promptfoo calls it `debug`) - print an environment report:

- DockSec version, Python version, OS/arch.
- Trivy / Hadolint / Docker presence and versions, and Trivy DB age (a stale DB is a
  silent source of wrong results and a genuine air-gap concern).
- Which config file was discovered and the fully resolved effective settings.
- Which LLM provider is configured, and whether the API key is *present* - never print
  the key or any prefix of it.
- Results directory, cache location, cache entry count.
- Proxy environment variables. Enterprises run behind proxies, and "does it work behind
  our proxy" is a first-week question.
- End with: "Include this output when filing an issue."

Add a `--json` mode to `doctor` so support tooling can consume it.

**Note:** DockSec has no proxy handling today. Trivy and the LLM SDKs mostly honor
`HTTP_PROXY`/`HTTPS_PROXY` on their own, but this should be verified, documented, and
surfaced by `doctor` rather than assumed.

### 1.4 CI integration docs, one page per system

promptfoo ships 25 integration pages: Jenkins, GitLab, Azure Pipelines, CircleCI,
Bitbucket, Travis, SonarQube, and more. The strategic value is search: a platform engineer
searching "promptfoo jenkins" lands on a page written for them.

DockSec has one GitHub Action and nothing else. Write copy-pasteable, tested pages for:

- **Jenkins** (declarative `Jenkinsfile` stage) - the priority, given the Broadcom target.
- **GitLab CI** - and emit GitLab's Code Quality / SAST report format if it is cheap; it
  makes findings render natively in merge requests.
- **Azure Pipelines**.
- **Pre-commit hook** via `.pre-commit-hooks.yaml`. Very low effort, and it puts DockSec
  in developers' inner loop rather than only in CI.

All four are built on `--json`, `--sarif`, and the existing exit codes. This is mostly
writing, not engineering, and it directly unblocks the enterprise pitch.

### 1.5 Publish the container image

`Dockerfile` exists at the repo root but no image is published, so the zero-install
evaluation path - `docker run ghcr.io/owasp/docksec ...` - does not exist. For a security
tool this is the path most platform teams actually want, and it is the natural air-gap
story.

- Publish multi-arch (`amd64` + `arm64`) to GHCR on every release tag.
- Bake in pinned Trivy and Hadolint versions.
- Ship a variant with the Trivy DB pre-seeded for air-gapped use.
- Document `docker run` usage prominently in the README.

**Bug found while reviewing:** the root `Dockerfile` installs Trivy from
`https://raw.githubusercontent.com/aquasec/trivy/...`. The correct organization is
`aquasecurity`. The current URL 404s, so the Trivy install step is silently producing a
broken image. Fix this before publishing anything.

---

## Tier 2 - The differentiators

Bigger builds. These are what move DockSec from "a competent wrapper" to "a tool with a
point of view."

### 2.1 Scan history and trend tracking

promptfoo persists every eval to SQLite and exposes `list`, `show`, and `export`. This is
what makes it feel like a system of record instead of a script. DockSec's reports
currently overwrite, so there is no answer to "are we getting better?"

Build:

- SQLite at `~/.docksec/history.db` - stdlib `sqlite3`, no new dependency.
- Record per scan: timestamp, target, image digest, severity counts, score, finding
  fingerprints (`baseline.py` already has a stable `fingerprint()` - reuse it).
- `docksec history` - table of recent scans with score trend.
- `docksec diff <a> <b>` - findings added and removed between two scans.
- A delta line in the normal scan summary: **"3 new, 5 fixed since last scan."**

That one delta line is the highest-value part and can ship before the rest of the
commands. It reframes DockSec from a point-in-time scanner into a security posture tracker,
which is a materially stronger enterprise story. It also makes the existing baseline
feature more discoverable.

Design constraint: shared CI runners write concurrently to `~/.docksec`. Use WAL mode and
treat write failures as non-fatal - a history write must never fail a scan.

### 2.2 Local web UI (`docksec view`)

The big-ticket item, and honestly a large part of why promptfoo *looks* better than
DockSec. Their React 19 + MUI app has 17 page directories, served locally by `promptfoo view`.

**Scope this carefully - do not build their app.** The realistic version for DockSec:

- **Phase A, cheap and high-return:** the HTML report already exists. Invest in it
  instead. Add sorting and filtering by severity, a search box, collapsible groups by
  package, and a trend chart once 2.1 lands. This is a self-contained HTML file with
  inline JS - no server, no build step, no new dependencies, and it stays emailable and
  attachable to a compliance ticket. **Do this first.**
- **Phase B, only if demand is real:** `docksec view` starts a local server rendering
  history from the 2.1 database. Keep it a single small FastAPI or stdlib server with
  server-rendered templates. Adding a React build toolchain to a Python security tool is
  a large, permanent maintenance burden - it doubles the CI surface and the dependency
  audit scope, which is a genuine cost for a tool whose whole pitch is supply-chain
  security.

Be honest in planning: Phase B is where the visual gap really closes, but Phase A gets
most of the way for a fraction of the cost and risk. Ship A, measure demand, then decide.

**Explicitly out of scope:** promptfoo's hosted sharing (`promptfoo share` uploading to
promptfoo.dev). That requires running and securing a service that receives customers'
security findings. For an OWASP project with no funded infrastructure, the liability and
operational burden are not worth it. If sharing is ever wanted, make it self-hostable and
opt-in, and never make it the default path.

### 2.3 Policy packs and compliance mapping

Not something promptfoo has in this form, but it is the natural analogue of their redteam
plugin system, and it is where DockSec can be genuinely differentiated rather than
imitative.

`docksec --profile cis-docker` maps findings to CIS Docker Benchmark and NIST SP 800-190
control IDs, with the mapping carried through into the reports and into SARIF rule
metadata.

This is mostly metadata over rules that already exist, and "which CIS controls does this
cover" is a question that comes up in every enterprise security review. It is one of the
strongest items on this list relative to its cost.

### 2.4 An examples directory that carries weight

promptfoo has 231 example directories; DockSec has two compose files. Do not chase that
number - most of theirs are provider permutations. But do build a small, deliberate set:

- A vulnerable example image with a documented, expected finding set, so an evaluator can
  confirm DockSec actually works within their first five minutes.
- The corresponding hardened version, showing the delta.
- One example per CI system, matching the Tier 1.4 docs.
- A multi-stage, realistic enterprise-shaped Dockerfile.

Pair this with an **evaluation guide**: a 15-minute scripted walkthrough for a security
team assessing the tool. Enterprises follow exactly this kind of path, and giving them a
prepared one means they see the tool at its best rather than fumbling.

---

## Tier 3 - Repo and process hygiene

Individually minor, collectively responsible for a large share of the "this looks
top-notch" impression. Most are under an hour each.

- **Consolidate packaging.** `setup.py` (63 lines) and `pyproject.toml` (10 lines)
  coexist, with the version defined in `setup.py`. This is a drift bug waiting to happen.
  Move everything to `pyproject.toml` as the single source of truth. Already flagged in
  `CLAUDE.md` section 9b; it should be done before any release automation is added.
- **Automate releases.** promptfoo uses release-please: conventional commits drive
  version bumps, changelog, and tags automatically. DockSec's `CHANGELOG.md` is manual.
  Automating this also fixes the still-open problem that the README pins the Action to a
  tag that has to be remembered by hand.
- **Enforce PR title conventions in CI**, so the changelog generated from them is clean.
- **Add a `Makefile` target set that mirrors CI exactly** (`make lint`, `make test`,
  `make format`). DockSec has a `Makefile`; make sure a contributor can reproduce CI with
  one command.
- **A devcontainer** (`.devcontainer/`) with Trivy and Hadolint pre-installed. For a tool
  with external binary dependencies this meaningfully lowers the contribution barrier.
- **Move SECURITY.md to the repo root.** It currently lives in `docs/`, where GitHub does
  not pick it up for the Security tab. Root placement is also an OpenSSF Scorecard input.
- **Pursue an OpenSSF Best Practices badge.** For an OWASP project this is close to table
  stakes and is a concrete, checklist-driven credibility signal for enterprise reviewers.
- **A real docs site.** README-only is the current ceiling. MkDocs Material is the
  low-effort Python-native option and would host the config reference, the CI integration
  pages, the evaluation guide, and the data-flow/privacy documentation in one searchable
  place. This is a prerequisite for Tier 1.4 having anywhere good to live.

---

## Deliberately not copying

Being selective here matters as much as the list above.

- **Hosted result sharing.** Discussed in 2.2. Operating a service that ingests other
  companies' security findings is a liability an unfunded OWASP project should not take on.
- **Telemetry.** promptfoo ships PostHog analytics, opt-out via
  `PROMPTFOO_DISABLE_TELEMETRY`. DockSec should not. Its core pitch to enterprises is
  "your Dockerfiles do not leave your network," and DockSec's privacy documentation
  currently makes an explicit no-telemetry statement. Adding phone-home analytics would
  directly contradict the strongest part of the existing positioning. If usage data is
  ever genuinely needed, make it strictly opt-**in**.
- **A cloud/enterprise tier.** promptfoo has `src/app/`, auth, and cloud sync because
  there is a company behind it. Not applicable.
- **231 examples.** Volume for its own sake. A dozen well-chosen ones beat 231
  permutations.
- **A React build toolchain**, unless Phase B in 2.2 is explicitly chosen with the
  maintenance cost accepted.

---

## Suggested order

Sequenced so each step unblocks the next rather than by raw priority.

- [x] **Config file and published JSON Schema (1.1).** Done in 2026.8.19. Unblocks 1.2
      and 1.3.
- [ ] **Fix the `Dockerfile` Trivy URL bug (1.5).** Blocks any image publishing.
- [ ] **Consolidate packaging into `pyproject.toml` (Tier 3).** Blocks release automation.
- [ ] **`init` (1.2), then `validate` and `doctor` (1.3).** Build together; they share the
      config file and model.
- [ ] **CI integration docs and the pre-commit hook (1.4)**, plus the examples set (2.4).
- [ ] **Publish the container image (1.5).**
- [ ] **Scan history**, starting with the "3 new, 5 fixed" delta line (2.1).
- [ ] **HTML report upgrade** - Phase A of 2.2.
- [ ] **Docs site (Tier 3)**, which by this point has real content to host.
- [ ] **Policy packs (2.3).**

The Trivy URL bug and the packaging consolidation are small and should be picked up
regardless of where they fall in this order; they are latent bugs rather than features.
The packaging one is now more pressing than when this was written: cutting 2026.8.19
required hand-editing the version in `setup.py` and hand-updating two `@v...` Action pins
in the README, which is exactly the drift that item predicts.

---

## One caveat on the comparison

promptfoo is a venture-backed project, now part of OpenAI, with a full-time team, a
paid cloud product, and 56 npm scripts' worth of build infrastructure. DockSec is an OWASP
Lab project with a lead and a co-lead.

The correct lesson is not "match their surface area." It is that their polish comes from a
small number of structural choices - schema-first config, scaffold-and-validate
onboarding, persistent reviewable results, docs written per-audience - each of which is
independently affordable at DockSec's scale. Tier 1 in this document is roughly a few
focused weeks of work and would close most of the perceived gap. Tier 2.2 Phase B is the
only item here that genuinely requires their scale, which is exactly why it is scoped down.
