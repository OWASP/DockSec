#!/usr/bin/env python3

import sys
import os
import argparse


def get_version() -> str:
    """Return the installed package version.

    Resolution order:
    1. importlib.metadata   — works when installed via pip
    2. pyproject.toml       — works when running from a source checkout
    3. 'unknown'            — last resort fallback
    """
    try:
        from importlib.metadata import version
        return version("docksec")
    except Exception:  # package not installed; fall through to source fallback
        pass

    try:
        import re
        pyproject = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 'pyproject.toml'
        )
        with open(pyproject, 'r', encoding='utf-8') as f:
            # Match the version in [project] only, not a version constraint in
            # a dependency specifier further down the file.
            match = re.search(
                r'^\s*version\s*=\s*["\']([^"\']+)["\']', f.read(), re.MULTILINE
            )
            if match:
                return match.group(1)
    except Exception:  # pyproject missing or unreadable; fall through to unknown
        pass

    return "unknown"

def _load_project_config(args, output):
    """Discover, load, and apply the repo-level config file.

    Returns (file_config, config_path). The path is None when no file was used.

    Precedence is enforced by only filling in settings the user left unset: an
    explicit CLI flag is never overwritten, and env-var-backed settings are
    applied by writing the environment variable only when it is not already set,
    so `LLM_PROVIDER=x docksec ...` still beats a committed provider.

    A config file that exists but is invalid exits 2. Unlike the ignore file,
    where a bad entry is skipped with a warning, a broken policy file must stop
    the run rather than silently scan under rules the team did not commit.
    """
    from docksec.project_config import (
        ConfigFileError,
        DocksecFileConfig,
        find_config_file,
        load_config_file,
    )

    # get_config() calls load_dotenv() lazily, which would otherwise populate
    # the environment *after* the checks below and let the config file win over
    # a .env entry. Load it up front so env-over-file precedence holds.
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:  # python-dotenv is a core dep; tolerate its absence
        pass

    if args.no_config:
        return DocksecFileConfig(), None

    if args.config_file:
        # An explicitly named file that is missing is a usage error; a merely
        # absent auto-discovered file is not.
        if not os.path.isfile(args.config_file):
            output.error(f"Config file not found: {args.config_file}")
            sys.exit(2)
        config_path = args.config_file
    else:
        config_path = find_config_file()
        if not config_path:
            return DocksecFileConfig(), None

    try:
        file_config, warnings = load_config_file(config_path)
    except ConfigFileError as exc:
        output.error(str(exc))
        sys.exit(2)

    for warning in warnings:
        output.warn(warning)

    # Settings that reach the rest of the CLI as attributes on `args`.
    # Severity resolves through get_config().default_severity, which cannot
    # distinguish "DOCKSEC_DEFAULT_SEVERITY was set" from "built-in default".
    # Setting the env var here (only when absent) keeps env-over-file ordering
    # without changing how the rest of the CLI reads the value.
    if file_config.severity and not os.getenv("DOCKSEC_DEFAULT_SEVERITY"):
        os.environ["DOCKSEC_DEFAULT_SEVERITY"] = file_config.severity

    for attr, value in (
        ("fail_on", file_config.fail_on),
        ("output_dir", file_config.output_dir),
        ("ignore_file", file_config.ignore_file),
        ("baseline", file_config.baseline),
        ("offline", file_config.offline),
        ("skip_ai_scoring", file_config.skip_ai_scoring),
        ("no_redact", file_config.no_redact),
        ("no_cache", file_config.no_cache),
    ):
        if value is not None and getattr(args, attr, None) is None:
            setattr(args, attr, value)

    # --format is parsed from a comma-separated string; the file supplies a list.
    if file_config.formats is not None and args.format is None:
        args.format = ",".join(file_config.formats)

    # Provider and model travel via environment variables. Only set them when
    # the env var is absent, so an explicitly exported value still wins.
    if file_config.provider and not os.getenv("LLM_PROVIDER"):
        os.environ["LLM_PROVIDER"] = file_config.provider
    if file_config.model and not os.getenv("LLM_MODEL"):
        os.environ["LLM_MODEL"] = file_config.model

    return file_config, config_path


def _apply_disabled_rules(results, disabled_rules, output):
    """Drop findings whose rule ID is disabled in the config file.

    Applied alongside the ignore-file waivers, before scoring, reports, JSON
    output, and the --fail-on gate, so a disabled rule is invisible everywhere.
    Matching is case-insensitive on VulnerabilityID, consistent with waivers.
    """
    if not disabled_rules or not results.get("json_data"):
        return 0

    disabled = {rule.lower() for rule in disabled_rules}
    kept = []
    removed = 0
    for finding in results["json_data"]:
        rule_id = str(finding.get("VulnerabilityID", "")).lower()
        if rule_id in disabled:
            removed += 1
        else:
            kept.append(finding)

    if removed:
        results["json_data"] = kept
        results["disabled_rule_count"] = removed
        output.info(
            f"Suppressed {removed} finding(s) from {len(disabled)} disabled rule(s) "
            f"in the config file"
        )
    return removed


def main() -> None:
    """
    Main entry point for the DockSec CLI tool.
    Parses arguments and coordinates AI analysis and security scanning.
    """
    # Set CLI mode to suppress INFO logs for user-facing output
    os.environ["DOCKSEC_CLI_MODE"] = "true"

    # Subcommand dispatch (backward compatible): the historical CLI takes a
    # positional Dockerfile, so we intercept known verbs as the first argument
    # before argparse runs. Anything else falls through to the existing
    # flag-based scan CLI unchanged.
    if len(sys.argv) > 1 and sys.argv[1] == "install-skill":
        from docksec import output
        output.configure()
        from docksec.install_skill import install_skill
        install_skill()
        return

    from docksec.enums import LLMProvider
    parser = argparse.ArgumentParser(description='Docker Security Analysis Tool')
    parser.add_argument('dockerfile', nargs='?', help='Path to the Dockerfile to analyze (optional when using --image-only or --compose)')
    parser.add_argument('-i', '--image', help='Docker image name to scan')
    parser.add_argument('-c', '--compose', nargs='?', const='auto', help='Path to docker-compose file to scan. If no path is provided, auto-detects in current directory.')
    parser.add_argument('--ai-only', action='store_true', help='Run only AI-based recommendations (requires Dockerfile)')
    parser.add_argument('--scan-only', action='store_true', help='Run only Dockerfile/image scanning (requires --image)')
    parser.add_argument('--image-only', action='store_true', help='Scan only the Docker image without Dockerfile analysis')
    parser.add_argument('--provider', choices=LLMProvider.values(),
                       help='LLM provider to use (default: openai, can also set LLM_PROVIDER env var)')
    parser.add_argument('--model', help='Model name to use (e.g., gpt-4o, claude-haiku-4-5, gemini-1.5-pro, llama3.1)')
    parser.add_argument('--compact-output', action='store_true', help='Use compact output format (less verbose)')
    parser.add_argument('--skip-ai-scoring', action='store_true', default=None, help='Deprecated and ignored: scoring is always deterministic. Removed in a future release.')
    parser.add_argument('--severity', help='Comma-separated severity levels to scan for (default: CRITICAL,HIGH; or set DOCKSEC_DEFAULT_SEVERITY)')
    parser.add_argument('--fail-on', dest='fail_on', metavar='SEVERITY', help='Exit with code 1 if any finding is at or above this severity (CRITICAL, HIGH, MEDIUM, or LOW)')
    parser.add_argument('--format', dest='format', help='Comma-separated report formats to write: json, csv, pdf, html, markdown (default: all)')
    parser.add_argument('--output-dir', dest='output_dir', metavar='DIR', help='Directory to write reports to (default: ~/.docksec/results or DOCKSEC_RESULTS_DIR)')
    parser.add_argument('--json', dest='json_stdout', action='store_true', help='Print scan results as JSON to stdout (no report files unless --format is also given)')
    parser.add_argument('--sarif', dest='sarif', action='store_true', help='Write a SARIF 2.1.0 report for GitHub Code Scanning and other SARIF-compatible tools')
    parser.add_argument('--sbom', dest='sbom', action='store_true', help='Write a CycloneDX SBOM (.cdx.json) of the scanned image for supply-chain tooling (requires an image)')
    parser.add_argument('--offline', dest='offline', action='store_true', default=None, help='Run without network access: use the local Trivy DB (no DB update) and skip AI analysis')
    parser.add_argument('--fix', dest='fix', action='store_true', help='Apply the safe subset of the suggested Dockerfile changes, keep a .bak, and re-scan to show the delta. Refuses to run on a dirty git working tree unless --force is given.')
    parser.add_argument('--dry-run', dest='dry_run', action='store_true', help='With --fix, print the diff without writing anything')
    parser.add_argument('--force', dest='force', action='store_true', help='With --fix, apply changes even when the git working tree has uncommitted changes to the target file')
    parser.add_argument('--no-epss', dest='no_epss', action='store_true', default=None, help='Skip the EPSS exploitation-likelihood lookup and rank findings by severity alone (only CVE IDs are ever sent; implied by --offline)')
    parser.add_argument('--incomplete-policy', dest='incomplete_policy', choices=['warn', 'fail'], default='warn', help="What to do when a scanner could not run: 'warn' reports the gap and continues (default), 'fail' exits 3 so CI cannot pass on an incomplete scan")
    parser.add_argument('--no-redact', dest='no_redact', action='store_true', default=None, help='Do not mask secret-looking values before sending file content to the AI provider')
    parser.add_argument('--no-cache', dest='no_cache', action='store_true', default=None, help='Bypass the scan results cache and force a fresh scan')
    parser.add_argument('--ignore-file', dest='ignore_file', metavar='FILE', help='Path to an ignore file listing findings to suppress (default: .docksec-ignore.yml in the current directory, if present)')
    parser.add_argument('--baseline', dest='baseline', metavar='FILE', help='Path to a baseline file; with --fail-on, only findings not present in the baseline trigger the gate')
    parser.add_argument('--update-baseline', dest='update_baseline', action='store_true', help='Write the current scan findings to --baseline instead of gating against it')
    parser.add_argument('--config', dest='config_file', metavar='FILE', help='Path to a DockSec config file (default: nearest .docksec.yml, searching up to the repository root)')
    parser.add_argument('--no-config', dest='no_config', action='store_true', help='Ignore any .docksec.yml and use only flags, environment variables, and defaults')
    parser.add_argument('--print-config-schema', dest='print_config_schema', action='store_true', help='Print the JSON Schema for .docksec.yml to stdout and exit')
    parser.add_argument('--quiet', action='store_true', help='Reduce output to warnings, errors, and the result summary')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show INFO-level log lines on stderr')
    parser.add_argument('--log-file', dest='log_file', metavar='FILE', help='Also append log lines to FILE, creating missing parent directories; combine with --verbose to capture INFO-level logs')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output (also honors the NO_COLOR env var)')
    parser.add_argument('--version', action='version', version=f'DockSec {get_version()}')

    args = parser.parse_args()

    # Configure the terminal output layer before anything is printed.
    from docksec import output
    no_color = args.no_color or bool(os.getenv("NO_COLOR"))
    if no_color:
        # Every Rich console (including the AI-findings console in utils) honors
        # NO_COLOR, so set it before those modules are imported.
        os.environ["NO_COLOR"] = "1"
    output.configure(quiet=args.quiet, no_color=no_color, json_mode=args.json_stdout)

    # --print-config-schema is a utility action: emit the schema and exit before
    # any input validation, so it works from any directory with no arguments.
    if args.print_config_schema:
        import json as _json
        from docksec.project_config import config_json_schema
        print(_json.dumps(config_json_schema(), indent=2))
        return

    # Repo-level config file (.docksec.yml). Values here sit below CLI flags and
    # environment variables: a flag always wins, an env var wins over the file,
    # and the file wins over the built-in default. Applied before anything reads
    # the resolved settings below.
    file_config, config_path = _load_project_config(args, output)
    disabled_rules = [rule.strip() for rule in file_config.rules.disabled if rule.strip()]

    # Set provider and model from CLI args if provided (overrides env vars)
    if args.provider:
        os.environ["LLM_PROVIDER"] = args.provider
    if args.model:
        os.environ["LLM_MODEL"] = args.model

    # Set compact output mode if requested
    if args.compact_output:
        os.environ["DOCKSEC_COMPACT_OUTPUT"] = "true"

    # Deprecated flag. Scoring is deterministic now, so this is a no-op, but
    # silently ignoring a flag someone has in a CI config is worse than either
    # honouring it or erroring: warn for one release, then remove.
    if args.skip_ai_scoring:
        output.warn(
            "--skip-ai-scoring is deprecated and has no effect: scoring is "
            "always deterministic. The flag will be removed in a future release."
        )

    # --no-cache: the scanner (and every per-service scanner in compose runs)
    # reads DOCKSEC_USE_CACHE at construction time.
    if args.no_cache:
        os.environ["DOCKSEC_USE_CACHE"] = "false"

    if args.verbose and not os.getenv("DOCKSEC_LOG_LEVEL"):
        os.environ["DOCKSEC_LOG_LEVEL"] = "INFO"

    # Resolve --log-file before any logger is built, so get_custom_logger can
    # attach its file handler. Opening the path here surfaces an unwritable
    # destination as a clean CLI error instead of a traceback mid-scan.
    if args.log_file:
        try:
            parent = os.path.dirname(os.path.abspath(args.log_file))
            os.makedirs(parent, exist_ok=True)
            with open(args.log_file, 'a', encoding='utf-8'):
                pass
        except OSError as exc:
            output.error(f"Cannot write to --log-file '{args.log_file}': {exc}")
            sys.exit(2)
        os.environ["DOCKSEC_LOG_FILE"] = args.log_file

    # Resolve the severity filter: CLI flag > DOCKSEC_DEFAULT_SEVERITY env > default.
    from docksec.config_manager import get_config
    from docksec.enums import Severity
    severity = args.severity or get_config().default_severity
    severity_list = [s.strip().upper() for s in severity.split(',') if s.strip()]
    invalid_severities = [s for s in severity_list if s not in Severity.values()]
    if not severity_list or invalid_severities:
        output.error(
            f"Invalid --severity value '{severity}'. "
            f"Valid levels: {', '.join(Severity.values())}"
        )
        sys.exit(2)
    severity = ','.join(severity_list)

    # Validate --fail-on and widen the scan severity so the gate can see the
    # levels it needs (e.g. --fail-on medium with the default CRITICAL,HIGH scan
    # would otherwise never observe MEDIUM findings). Compose static findings are
    # always emitted at all severities, so widening only affects the image scan.
    if args.fail_on:
        args.fail_on = args.fail_on.strip().upper()
        if args.fail_on not in Severity.gate_levels():
            output.error(
                f"Invalid --fail-on value '{args.fail_on}'. "
                f"Choose one of: {', '.join(Severity.gate_levels())}"
            )
            sys.exit(2)
        needed = {lvl for lvl in Severity.gate_levels()
                  if Severity.rank(lvl) >= Severity.rank(args.fail_on)}
        widened = set(severity_list) | needed
        if widened != set(severity_list):
            severity_list = [lvl for lvl in Severity.values() if lvl in widened]
            severity = ','.join(severity_list)
            output.info(f"Widened scan severity to {severity} to satisfy --fail-on {args.fail_on}")

    # Resolve report formats and output directory.
    from docksec.config import RESULTS_DIR
    valid_formats = ["json", "csv", "pdf", "html", "markdown"]
    report_formats = None  # None = write all formats (default)
    if args.format:
        requested = [f.strip().lower() for f in args.format.split(',') if f.strip()]
        invalid_formats = [f for f in requested if f not in valid_formats]
        if not requested or invalid_formats:
            output.error(
                f"Invalid --format value '{args.format}'. "
                f"Valid formats: {', '.join(valid_formats)}"
            )
            sys.exit(2)
        # Preserve a stable order and drop duplicates.
        report_formats = [f for f in valid_formats if f in requested]
    elif args.json_stdout:
        # --json alone means "just print JSON to stdout" - it does not also
        # write the report file bundle unless the user explicitly asks via
        # --format. Passing an empty list writes nothing.
        report_formats = []
    output_dir = args.output_dir or RESULTS_DIR

    # Validate argument combinations
    if args.update_baseline and not args.baseline:
        output.error("--update-baseline requires --baseline FILE")
        sys.exit(2)

    # --fix edits a Dockerfile in place, so it needs one. Compose changes alter
    # runtime topology and are deliberately never applied automatically.
    if args.fix:
        if args.compose:
            output.error(
                "--fix applies Dockerfile changes; compose changes alter runtime "
                "topology and are reported for you to apply yourself."
            )
            sys.exit(2)
        if not args.dockerfile:
            output.error("--fix requires a Dockerfile path")
            sys.exit(2)
    elif args.dry_run:
        output.error("--dry-run applies to --fix; it has no effect on its own")
        sys.exit(2)

    if args.image_only and args.ai_only:
        output.error("--image-only and --ai-only cannot be used together (AI analysis requires a Dockerfile)")
        sys.exit(2)
    
    if args.image_only and args.scan_only:
        output.error("--image-only and --scan-only cannot be used together (use --image-only for image-only scanning)")
        sys.exit(2)
    
    # Validate Dockerfile requirement
    if not args.image_only and not args.compose and not args.dockerfile:
        output.error("Dockerfile path is required unless using --image-only or --compose")
        print("Usage examples:")
        print("  docksec Dockerfile -i myapp:latest          # Analyze both Dockerfile and image")
        print("  docksec --image-only -i myapp:latest        # Scan only the image")
        print("  docksec --compose docker-compose.yml        # Scan compose file and its services")
        print("  docksec --ai-only Dockerfile                # AI analysis only")
        print("  docksec install-skill                       # Install AI-assistant skill files")
        sys.exit(2)
    
    # Validate that the Dockerfile exists (if provided)
    if args.dockerfile and not os.path.isfile(args.dockerfile):
        output.error(f"Dockerfile not found at {args.dockerfile}")
        sys.exit(2)
    
    # Validate image requirement for image-based operations
    if args.image_only and not args.image:
        output.error("Image name is required for image-only scanning. Use -i/--image to specify the Docker image.")
        print("Example: docksec --image-only -i myapp:latest")
        sys.exit(2)
    
    # In scan-only mode, if no image is provided, we'll only run Dockerfile analysis
    if args.scan_only and not args.image and not args.compose:
        output.info("No image provided for scan-only mode. Running Dockerfile analysis only.")
    
    # Determine which tools to run
    if args.compose:
        run_ai = not args.scan_only
        run_scan = True
        run_compose_analysis = True
        mode_desc = "Compose Analysis"
        
        # Auto-detect compose file if needed
        compose_path = args.compose
        if compose_path == 'auto':
            for name in ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml']:
                if os.path.isfile(name):
                    compose_path = name
                    break
            if compose_path == 'auto':
                output.error("Could not auto-detect a docker-compose file in the current directory.")
                sys.exit(2)
        
        if not os.path.isfile(compose_path):
            output.error(f"Compose file not found at {compose_path}")
            sys.exit(2)
            
        args.compose = compose_path
    elif args.image_only:
        run_ai = False
        run_scan = True
        run_compose_analysis = False
        mode_desc = "Image-only Scan"
    elif args.ai_only:
        # AI analysis correlates over scanner output, so the local Dockerfile
        # scan still runs - it is fast, needs no image, and without it the model
        # has nothing to correlate. What --ai-only now means is "do not scan an
        # image": no registry pull, no Trivy image scan, no Docker Scout.
        run_ai = True
        run_scan = True
        run_compose_analysis = False
        args.image = None
        mode_desc = "AI Analysis (Dockerfile only)"
    elif args.scan_only:
        run_ai = False
        run_scan = True
        run_compose_analysis = False
        mode_desc = "Security Scan Only"
    else:
        # Default mode. The scan pass runs whenever there is anything to scan -
        # a Dockerfile alone now yields structured findings from Hadolint and
        # Trivy's config scanner, so it no longer requires an image. This also
        # matters for the AI pass, which correlates over scanner output and so
        # runs inside the scan block.
        run_ai = bool(args.dockerfile)
        run_scan = bool(args.image) or bool(args.dockerfile)
        run_compose_analysis = False
        mode_desc = "Full Analysis (AI + Scanner)"
    
    # Offline mode: no network calls. AI providers all require network (except
    # a local Ollama, but we keep this simple and predictable), so --offline
    # forces local scanning + local scoring only. The scan still runs against
    # the already-downloaded Trivy DB.
    if args.offline:
        run_ai = False
        mode_desc = f"{mode_desc} (offline)"

    from docksec.config_manager import get_config
    from docksec.enums import LLMProvider

    output.banner(get_version(), mode_desc)
    if config_path:
        # Surface which committed policy is in force; a silently-applied config
        # file is a support burden when a scan behaves unexpectedly.
        output.kv("Config", os.path.relpath(config_path))
    output.kv("Reports", output_dir)
    if run_scan:
        output.kv("Severity", severity)
    if run_ai:
        config = get_config()
        output.kv("AI Provider", str(config.llm_provider))
    
    # Initialize AI findings storage
    ai_findings = None
    
    # Prepare the file content for the AI pass, but do not call the model yet.
    # The analysis runs after the scan so it can correlate against real scanner
    # output; loading and redacting here keeps the failure modes (missing file,
    # unreadable content) next to the other input validation.
    ai_ok = None  # None = AI not run, True = success, False = failed
    ai_file_content = None
    ai_file_type = None
    if run_ai:
        from pathlib import Path

        from docksec.config import truncate_dockerfile
        from docksec.utils import load_docker_file

        if run_compose_analysis:
            ai_file_type = "docker-compose file"
            ai_file_content = load_docker_file(docker_file_path=Path(args.compose))
        else:
            ai_file_type = "Dockerfile"
            ai_file_content = load_docker_file(docker_file_path=Path(args.dockerfile))

        if not ai_file_content:
            output.error(f"No {ai_file_type} content found.")
            sys.exit(2)

        # Redact secret-looking values before the content leaves the machine.
        # Keys stay visible so the model can still flag exposed credentials;
        # the secret material itself is masked.
        if not args.no_redact:
            from docksec.redact import redact_content
            ai_file_content, redacted_count = redact_content(ai_file_content)
            if redacted_count:
                output.info(
                    f"Masked {redacted_count} secret-looking value(s) before AI analysis "
                    f"(--no-redact to disable)"
                )

        # Cap very large inputs to bound token usage; warn when anything is
        # dropped so a partial analysis is never mistaken for a full one.
        if run_compose_analysis:
            capped = truncate_dockerfile(ai_file_content, max_lines=600, max_chars=24000)
        else:
            capped = truncate_dockerfile(ai_file_content, max_lines=400, max_chars=16000)
        if capped != ai_file_content:
            output.warn(
                f"{ai_file_type} is very large; AI analysis covers only the first part "
                f"of the file. Scanner results are unaffected."
            )
        ai_file_content = capped

    # Run the scanner tool
    scan_ok = None  # None = scan not run, True = success, False = failed
    gate_triggered = False  # True when findings meet the --fail-on threshold
    if run_scan:
        scan_title = "Compose" if run_compose_analysis else ("Image" if args.image_only else "Full")
        output.section(f"{scan_title} security scan")
        try:
            from docksec.docker_scanner import DockerSecurityScanner

            if run_compose_analysis:
                from docksec.compose_scanner import ComposeOrchestrator
                orchestrator = ComposeOrchestrator(
                    args.compose,
                    scan_only=not run_ai,
                    skip_ai_scoring=args.skip_ai_scoring
                )
                output.info(f"Scanning Compose file: {args.compose}")
                results = orchestrator.run_full_scan(severity)

                # We need a scanner instance just for scoring and reporting
                scanner = DockerSecurityScanner(None, None, results_dir=output_dir, scan_only=not run_ai, skip_ai_scoring=args.skip_ai_scoring, offline=args.offline)
                scanner.image_name = "Multiple Services"
                scanner.dockerfile_path = args.compose
            else:
                # Initialize the scanner
                dockerfile_path = None if args.image_only else args.dockerfile
                scanner = DockerSecurityScanner(
                    dockerfile_path,
                    args.image,
                    results_dir=output_dir,
                    scan_only=not run_ai,
                    skip_ai_scoring=args.skip_ai_scoring,
                    offline=args.offline
                )

                # Run appropriate scan based on mode
                if args.image_only:
                    # Image-only scan - skip Dockerfile analysis
                    output.info(f"Scanning Docker image: {args.image}")
                    results = scanner.run_image_only_scan(severity)
                else:
                    # Full scan including Dockerfile
                    results = scanner.run_full_scan(severity)

            # Apply ignore-file suppressions before scoring, reports, JSON
            # output, and the --fail-on gate see the findings.
            ignore_path = args.ignore_file
            if not ignore_path:
                from docksec.ignore import find_default_ignore_file
                ignore_path = find_default_ignore_file()
            if ignore_path:
                from docksec.ignore import load_ignore_file, apply_ignores
                ignore_entries, ignore_warnings = load_ignore_file(ignore_path)
                for warning in ignore_warnings:
                    output.warn(warning)
                kept_findings, suppressed_count = apply_ignores(
                    results.get("json_data", []), ignore_entries)
                if suppressed_count:
                    results["json_data"] = kept_findings
                    # Recorded so the reports and JSON payload can state that
                    # findings were waived rather than silently absent.
                    results["suppressed_count"] = suppressed_count
                    results["ignore_file"] = ignore_path
                    output.info(
                        f"{suppressed_count} finding(s) suppressed by ignore file {ignore_path}"
                    )

            # Rules disabled in the config file are dropped before scoring, so a
            # rule a team has switched off cannot influence the score, reports,
            # --json, or the --fail-on gate.
            _apply_disabled_rules(results, disabled_rules, output)

            # EPSS exploitation likelihood, after suppressions so no request is
            # made for a finding the team has already waived. Only CVE IDs are
            # sent; any failure degrades to severity-only ranking and is
            # recorded as a remediation gap rather than failing the scan.
            epss_enabled = not args.no_epss and not args.offline
            epss_candidates = sum(
                1 for v in results.get("json_data", [])
                if str(v.get("VulnerabilityID", "")).upper().startswith("CVE-")
            )
            epss_annotated = 0
            if epss_enabled and epss_candidates:
                from docksec import epss as epss_mod
                epss_annotated = epss_mod.annotate(
                    results["json_data"], cache_dir=scanner.RESULTS_DIR, enabled=True
                )
            results["epss_enabled"] = epss_enabled

            # Record what this scan could not determine, before anything
            # renders it.
            from docksec import completeness as completeness_mod
            scan_completeness = completeness_mod.build(
                results,
                dockerfile_errors=results.get("dockerfile_scan_errors"),
                epss_enabled=epss_enabled,
                epss_annotated=epss_annotated,
                epss_candidates=epss_candidates,
            )
            results["completeness"] = scan_completeness.to_dict()

            # Calculate security score
            scanner.analysis_score = scanner.get_security_score(results)

            # Cross-service exploit chains. Detected by rules over the compose
            # topology, so the flagship output works with --scan-only, offline,
            # and without an API key. The AI pass ranks and explains them; it is
            # not load bearing for finding them.
            compose_data = None
            if run_compose_analysis:
                from docksec import chains as chains_mod
                compose_data = _load_compose_topology(args.compose)
                detected = chains_mod.detect(compose_data, results.get("json_data"))
                if detected:
                    results["exploit_chains"] = chains_mod.to_ai_shape(detected)

            # AI correlation pass. Runs here, after suppressions, disabled
            # rules, EPSS tiering and scoring, so the model reasons over exactly
            # the finding set the user will see - not a raw dump, and not
            # findings the team has already waived.
            if run_ai and ai_file_content:
                output.section("AI correlation and triage")
                ai_findings, ai_ok = _run_ai_correlation(
                    output, ai_file_content, ai_file_type, results, compose_data
                )
                if ai_findings:
                    results["ai_findings"] = ai_findings

            # Generate reports (all formats by default, or the requested subset)
            report_paths = scanner.generate_all_reports(results, formats=report_formats)

            # SARIF is opt-in via --sarif (not part of --format's default bundle)
            # since it targets GitHub Code Scanning / CI rather than local reading.
            if args.sarif:
                report_paths["sarif"] = _generate_sarif_report(scanner, results)

            # SBOM is opt-in via --sbom. It needs a real image to inventory, so
            # it is skipped (with a note) for compose runs and when no image was
            # scanned.
            if args.sbom:
                if run_compose_analysis or not args.image:
                    output.warn("--sbom needs a single image (-i); skipping SBOM for this run.")
                else:
                    sbom_path = _generate_sbom_report(scanner)
                    if sbom_path:
                        report_paths["sbom"] = sbom_path

            # Run advanced scan if available and image is provided (skip for compose
            # and for --json, since Docker Scout output is not part of the payload
            # and would otherwise print to stdout alongside it; skip in --offline
            # since Docker Scout reaches out to Docker's servers)
            if hasattr(scanner, 'advanced_scan') and args.image and not run_compose_analysis \
                    and not args.json_stdout and not args.offline:
                output.section("Advanced scan (Docker Scout)")
                scanner.advanced_scan()

            # A compose run whose services could not be scanned must not report
            # success: the summary and score describe only the static rules, and
            # exiting 0 would let CI pass on a scan that never inspected the
            # images. Exit 3 (tool/runtime error) rather than 1, since this is a
            # scan that did not complete, not a policy violation.
            failed_services = _failed_service_names(results.get("failed_services"))
            scan_ok = not failed_services

            # --incomplete-policy fail: a detection gap means findings may be
            # missing, so CI can choose to treat that as a failed scan rather
            # than a clean one.
            if args.incomplete_policy == "fail" and (results.get("completeness") or {}).get("has_detection_gap"):
                scan_ok = False

            if args.json_stdout:
                _print_json_results(results, scanner, report_paths)
            else:
                _render_scan_summary(output, args, scanner, results, report_paths,
                                     run_ai, run_compose_analysis)

            # --fix runs last, after the user has seen what was found: the
            # changes only make sense in the context of the findings above.
            if args.fix:
                fix_applied = _apply_autofix(output, args, results)
                if fix_applied is False:
                    scan_ok = False

            if failed_services:
                total = results.get("total_services")
                scope = (f"{len(failed_services)} of {total}"
                         if isinstance(total, int) and total > 0
                         else f"{len(failed_services)}")
                output.error(
                    f"{scope} service(s) could not be scanned: "
                    f"{', '.join(failed_services)}. Results cover the compose "
                    f"file's static rules only."
                )

            # --update-baseline: snapshot current findings and skip gating.
            if args.update_baseline:
                from docksec import baseline as baseline_mod
                baseline_mod.save_baseline(args.baseline, results)
                output.info(f"Baseline written to {args.baseline}")

            # --fail-on gate: flag findings at or above the chosen threshold.
            # With --baseline (and not --update-baseline), only findings not
            # already present in the baseline count toward the gate.
            if args.fail_on and not args.update_baseline:
                triggering = _findings_at_or_above(results, args.fail_on)
                if args.baseline:
                    from docksec import baseline as baseline_mod
                    baseline_fingerprints = baseline_mod.load_baseline(args.baseline)
                    new_ids = {baseline_mod.fingerprint(v) for v in baseline_mod.new_findings(results, baseline_fingerprints)}
                    triggering = [v for v in triggering if baseline_mod.fingerprint(v) in new_ids]
                if triggering:
                    gate_triggered = True
                    suffix = " (new since baseline)" if args.baseline else ""
                    output.warn(
                        f"{len(triggering)} finding(s) at or above {args.fail_on}"
                        f"{suffix} (--fail-on {args.fail_on}) -> exit 1"
                    )

        except ValueError as e:
            # Expected, actionable failures (missing image, missing tools, bad input).
            output.error(str(e))
            scan_ok = False
        except ImportError as e:
            output.error(f"Scanner modules not found - {e}")
            sys.exit(3)
        except Exception as e:
            output.error(f"Scanner failed: {e}")
            scan_ok = False

    # The separate AI-only report path that used to live here is gone. It
    # existed because the AI pass ran without a scan and so produced no report;
    # the correlation pass now runs inside the scan block, which already writes
    # reports containing the AI findings.

    # Exit codes (CI-friendly): 0 clean, 1 findings at/above --fail-on,
    # 2 usage error, 3 tool/runtime error.
    if not run_ai and not run_scan:
        output.warn("No analysis performed. Use --help for usage information.")
        sys.exit(2)

    if scan_ok is False or ai_ok is False:
        sys.exit(3)

    if gate_triggered:
        sys.exit(1)


def _apply_autofix(output, args, results):
    """Apply the safe subset of the fix plan to the Dockerfile.

    Returns True on success, False when the run should be treated as failed, and
    None when there was nothing to do. Refuses to edit a file with uncommitted
    changes unless --force: git is the real undo, so the tool makes sure git is
    in a position to help.
    """
    from docksec import autofix, remediation

    dockerfile = args.dockerfile
    findings = results.get("json_data") or []
    plan = remediation.build_plan(findings, dockerfile)

    applicable, needs_review = autofix.plan_edits(plan)
    if not applicable:
        output.section("Automatic fixes")
        output.info("No automatically applicable changes for this Dockerfile.")
        for edit in needs_review[:5]:
            output.detail(f"  - {edit.get('instruction')} ({edit.get('reason')})")
        return None

    if not args.dry_run and not args.force:
        dirty = autofix.working_tree_is_dirty(dockerfile)
        if dirty:
            output.error(
                f"{dockerfile} has uncommitted changes. Commit or stash them "
                f"first so the edits can be reviewed and reverted, or pass "
                f"--force to edit anyway."
            )
            output.detail("  Preview the changes without writing: --fix --dry-run")
            return False

    output.section("Automatic fixes")
    before = len(results.get("dockerfile_findings") or [])

    try:
        result = autofix.apply_to_dockerfile(
            dockerfile, plan, dry_run=args.dry_run, backup=True
        )
    except OSError as exc:
        output.error(f"Could not apply fixes to {dockerfile}: {exc}")
        return False

    if not result.applied:
        output.info("Nothing to change: the applicable fixes are already in place.")
        return None

    if args.dry_run:
        output.fix_diff(result.diff(os.path.basename(dockerfile)), result.applied,
                        result.skipped, dry_run=True)
        return True

    result.findings_before = before
    result.findings_after = autofix.rescan(dockerfile, offline=bool(args.offline))
    output.fix_diff(result.diff(os.path.basename(dockerfile)), result.applied,
                    result.skipped, dry_run=False,
                    backup_path=result.backup_path,
                    before=result.findings_before, after=result.findings_after)
    return True


def _load_compose_topology(compose_path):
    """Parse the compose file for its service topology.

    The topology - what each service publishes, mounts, and connects to - is
    what makes cross-service correlation possible. A parse failure is not fatal:
    the analysis degrades to per-service reasoning.
    """
    try:
        from ruamel.yaml import YAML

        with open(compose_path, "r", encoding="utf-8") as handle:
            return YAML(typ="safe").load(handle)
    except Exception as exc:  # noqa: BLE001 - topology is optional context
        from docksec.utils import get_custom_logger
        get_custom_logger(__name__).debug(f"Could not parse compose topology: {exc}")
        return None


def _run_ai_correlation(output, file_content, file_type, results, compose_data=None):
    """Run the AI correlation pass over the scan output.

    Returns ``(ai_findings, ok)``. A model failure is reported and returns
    ``ok=False``; it never raises, because a scan that produced real findings
    should still deliver them when the optional analysis layer is unavailable.
    """
    from docksec import ai_analysis
    from docksec.config_manager import get_config
    from docksec.enums import LLMProvider
    from docksec.utils import CorrelatedAnalysis, get_llm

    try:
        llm = get_llm()
        provider = get_config().llm_provider

        # OpenAI needs json_mode for reliable structured output; the others do
        # better with LangChain's default tool-calling path.
        if provider == LLMProvider.OPENAI:
            structured = llm.with_structured_output(CorrelatedAnalysis, method="json_mode")
        else:
            structured = llm.with_structured_output(CorrelatedAnalysis)

        context = ai_analysis.build_context(
            file_content, file_type, results=results, compose_data=compose_data
        )
        messages = ai_analysis.build_messages(context)

        finding_count = len(results.get("json_data") or [])
        output.info(
            f"Correlating {finding_count} scanner finding(s) "
            f"(prompt v{ai_analysis.PROMPT_VERSION})"
        )

        response = structured.invoke(messages)
        analysis = ai_analysis.normalize_response(response)
        output.ai_analysis(analysis)
        return ai_analysis.to_legacy_shape(analysis), True

    except ImportError as exc:
        output.error(f"AI analysis needs the [ai] extra: {exc}")
        output.detail('  Install it with: pip install "docksec[ai]"')
        return None, False
    except Exception as exc:  # noqa: BLE001 - the scan result still stands
        output.error(f"AI analysis failed: {exc}")
        output.detail("  Scanner findings above are unaffected.")
        return None, False


def _generate_sarif_report(scanner, results):
    """Write a SARIF 2.1.0 report for the scan and return its path.

    Uses ReportGenerator directly (rather than DockerSecurityScanner's
    generate_all_reports) because SARIF needs the DockSec version embedded in
    the report and is opt-in via --sarif rather than part of --format's
    default bundle.
    """
    from docksec.report_generator import ReportGenerator

    generator = ReportGenerator(scanner.image_name or "docksec_report", scanner.RESULTS_DIR)
    generator.set_analysis_score(getattr(scanner, "analysis_score", None))
    return generator.generate_sarif_report(results, tool_version=get_version())


def _generate_sbom_report(scanner):
    """Generate a CycloneDX SBOM for the scanned image and return its path.

    The BOM is produced by Trivy via the scanner (full package inventory) and
    written by ReportGenerator with DockSec stamped into the tool metadata.
    Returns an empty string if the image could not be inventoried.
    """
    from docksec.report_generator import ReportGenerator

    sbom_json = scanner.generate_sbom()
    if not sbom_json:
        return ""
    generator = ReportGenerator(scanner.image_name or "docksec_report", scanner.RESULTS_DIR)
    return generator.generate_cyclonedx_report(sbom_json, tool_version=get_version())


def _print_json_results(results, scanner, report_paths):
    """Print scan results as a single JSON object to stdout.

    Mirrors the shape ReportGenerator.generate_json_report writes to disk, so
    --json and the JSON report file stay consistent. stdout carries only this
    payload; all human-readable output goes to stderr in --json mode (see
    docksec.output.configure).
    """
    import json as json_module

    from docksec import output
    from docksec.score_calculator import SCORE_VERSION

    vulnerabilities = results.get("json_data", [])
    payload = {
        "scan_info": {
            "image": scanner.image_name,
            "dockerfile": results.get("dockerfile_path", "N/A"),
            "scan_time": results.get("timestamp", ""),
            "analysis_score": getattr(scanner, "analysis_score", None),
            # Identifies the scoring model, so automation can distinguish a
            # model change from a real change in posture.
            "score_version": SCORE_VERSION,
            "scan_mode": results.get("scan_mode", "full"),
        },
        "vulnerabilities": vulnerabilities,
        "severity_counts": output.count_by_severity(vulnerabilities),
    }
    from docksec import epss as epss_mod

    if results.get("completeness"):
        payload["scan_info"]["completeness"] = results["completeness"]
    payload["priority_counts"] = epss_mod.counts_by_priority(vulnerabilities)
    if results.get("exploit_chains"):
        payload["exploit_chains"] = results["exploit_chains"]
    if results.get("suppressed_count"):
        payload["scan_info"]["suppressed_count"] = results["suppressed_count"]
        payload["scan_info"]["ignore_file"] = results.get("ignore_file")
    if results.get("failed_services"):
        payload["scan_info"]["failed_services"] = results["failed_services"]
        payload["scan_info"]["total_services"] = results.get("total_services")
    if "ai_findings" in results:
        payload["ai_analysis"] = results["ai_findings"]
    if report_paths:
        payload["report_files"] = {fmt: path for fmt, path in report_paths.items() if path}

    print(json_module.dumps(payload, indent=2))


def _render_scan_summary(output, args, scanner, results, report_paths,
                         run_ai, run_compose_analysis):
    """Render the consolidated result summary.

    Ordered so a reader gets the answer before the detail: what is here
    (severity table, score), what to do first (priority tiers), what to run
    (fix plan), and what was not checked (coverage).
    """
    from docksec import completeness as completeness_mod
    from docksec import epss as epss_mod
    from docksec import remediation as remediation_mod

    vulnerabilities = results.get("json_data", [])
    counts = output.count_by_severity(vulnerabilities)

    output.section("Results")
    output.severity_table(counts)
    output.score(getattr(scanner, "analysis_score", None))
    output.priority_summary(epss_mod.counts_by_priority(vulnerabilities))

    # Rule-detected chains render here so they appear with or without AI. When
    # the AI pass ran it has already shown its own (richer) chain analysis, so
    # these are not repeated.
    if results.get("exploit_chains") and not results.get("ai_findings"):
        output.ai_analysis({"chains": results["exploit_chains"]})

    output.quick_take(_quick_take_lines(results, counts, run_ai))

    dockerfile_path = results.get("dockerfile_path")
    if dockerfile_path and str(dockerfile_path).startswith("N/A"):
        dockerfile_path = None
    output.fix_plan(remediation_mod.build_plan(vulnerabilities, dockerfile_path))

    gap_messages = [
        gap["message"] for gap in (results.get("completeness") or {}).get("gaps", [])
    ]
    output.coverage(
        completeness_mod.coverage_notes(results, ai_ran=bool(results.get("ai_findings"))),
        gaps=gap_messages,
    )

    if report_paths:
        output.report_results(report_paths, scanner.RESULTS_DIR)
    output.next_command(_suggest_next_command(args, results, run_ai, run_compose_analysis))


def _failed_service_names(failed_services):
    """Return the distinct service names in ``failed_services``, in order.

    A service that fails both its Dockerfile and its image scan is recorded
    once per scan, so de-duplicate before counting.
    """
    names = []
    for entry in failed_services or []:
        name = entry.get("service") if isinstance(entry, dict) else entry
        if not name:
            continue
        name = str(name)
        if name not in names:
            names.append(name)
    return names


def _quick_take_lines(results, counts, run_ai):
    """Build a few high-signal lines summarizing what matters most."""
    from docksec.enums import Severity

    lines = []

    vulnerabilities = results.get("json_data", [])
    total_vulns = sum(counts.get(sev, 0) for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
    if total_vulns:
        crit, high = counts.get("CRITICAL", 0), counts.get("HIGH", 0)
        lines.append(f"{total_vulns} security findings ({crit} critical, {high} high)")

        # How many findings have a known fixed version available upstream — a
        # high-signal, actionable number (mirrors cve-lite's fixable count).
        fixable = sum(1 for v in vulnerabilities if v.get("FixedVersion"))
        if fixable:
            lines.append(f"{fixable} of {total_vulns} have a fixed version available upstream")

    # Dockerfile findings are structured and already counted in the severity
    # table above; surface how many came from the Dockerfile specifically, since
    # those are the ones the user can fix by editing a file they own.
    dockerfile_findings = results.get("dockerfile_findings") or []
    if dockerfile_findings:
        worst = max(dockerfile_findings, key=lambda f: Severity.rank(f.get("Severity")))
        location = f" (line {worst['Line']})" if worst.get("Line") else ""
        lines.append(
            f"{len(dockerfile_findings)} Dockerfile issue(s); most severe: "
            f"{worst['VulnerabilityID']} [{worst['Severity']}] "
            f"{worst['Title']}{location}"
        )

    ai_findings = results.get("ai_findings") or {}
    exposed = ai_findings.get("exposed_credentials") or []
    if exposed:
        lines.append(f"{len(exposed)} likely exposed credential(s) flagged by AI analysis")

    suppressed = results.get("suppressed_count")
    if suppressed:
        lines.append(f"{suppressed} triaged finding(s) suppressed via ignore file")

    # A compose service whose scan failed still leaves the run with a score, so
    # say so here: otherwise the summary reads as if every service was covered.
    failed_names = _failed_service_names(results.get("failed_services"))
    if failed_names:
        names = ", ".join(failed_names)
        total = results.get("total_services")
        if isinstance(total, int) and total > 0:
            lines.append(f"{len(failed_names)} of {total} services could not be scanned: {names}")
        else:
            lines.append(f"{len(failed_names)} service(s) could not be scanned: {names}")

    if not run_ai and not results.get("ai_findings"):
        if results.get("scan_mode") == "image_only":
            lines.append("Add a Dockerfile scan for AI-powered explanations and fixes: docksec <Dockerfile> -i <image>")
        else:
            lines.append("Run without --scan-only to add AI-powered explanations and fixes")

    return lines


def _findings_at_or_above(results, threshold):
    """Return the scan findings whose severity is at or above the threshold.

    Operates on the structured findings in ``json_data`` (image vulnerabilities
    and compose misconfigurations). Hadolint lint warnings are not severity-ranked
    and do not participate in the --fail-on gate.
    """
    from docksec.enums import Severity

    threshold_rank = Severity.rank(threshold)
    return [
        v for v in results.get("json_data", [])
        if Severity.rank(v.get("Severity")) >= threshold_rank
    ]


def _format_hadolint_line(line):
    """Turn a raw Hadolint line into a compact, path-free summary.

    Input:  '/abs/path/Dockerfile:2 DL3020 error: Use COPY instead of ADD'
    Output: 'DL3020 error: Use COPY instead of ADD (line 2)'
    """
    head, _, rest = line.partition(" ")
    rest = rest.strip()
    if not rest:
        return line
    line_no = head.rsplit(":", 1)[-1]
    if line_no.isdigit():
        return f"{rest} (line {line_no})"
    return rest


def _suggest_fix_commands(results, limit=5):
    """Build copy-pasteable upgrade hints from findings that have a fixed version.

    Trivy reports the first fixed version per vulnerable package; we surface the
    most severe fixable packages as concrete 'upgrade PKG to VERSION' lines so a
    user has an immediate next action, not just a CVE list. Deduplicated by
    package name (a package can carry several CVEs), most severe first.
    """
    from docksec.enums import Severity

    fixable = [v for v in results.get("json_data", []) if v.get("FixedVersion") and v.get("PkgName")]
    fixable.sort(key=lambda v: Severity.rank(v.get("Severity")), reverse=True)

    seen = set()
    commands = []
    for v in fixable:
        pkg = v.get("PkgName")
        if pkg in seen:
            continue
        seen.add(pkg)
        installed = v.get("InstalledVersion") or "current"
        fixed = v.get("FixedVersion")
        commands.append(f"upgrade {pkg} {installed} -> {fixed}")
        if len(commands) >= limit:
            break
    return commands


def _suggest_next_command(args, results, run_ai, run_compose_analysis):
    """Suggest the most useful follow-up command for the current run."""
    if run_compose_analysis:
        return ""
    dockerfile = getattr(args, "dockerfile", None)
    # No image was scanned but a Dockerfile is present: suggest adding one.
    image_skipped = results.get("image_scan", {}).get("skipped")
    if dockerfile and image_skipped and not args.image:
        return f"docksec {dockerfile} -i <your-image>:<tag>"
    return ""

if __name__ == "__main__":
    main()
