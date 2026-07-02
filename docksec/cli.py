#!/usr/bin/env python3

import sys
import os
import argparse


def get_version() -> str:
    """Return the installed package version.

    Resolution order:
    1. importlib.metadata  — works when installed via pip
    2. setup.py on disk    — works when running from source
    3. 'unknown'           — last resort fallback
    """
    try:
        from importlib.metadata import version
        return version("docksec")
    except Exception:  # package not installed; fall through to source fallback
        pass

    try:
        import re
        setup_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'setup.py')
        with open(setup_path, 'r') as f:
            match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', f.read())
            if match:
                return match.group(1)
    except Exception:  # setup.py missing or unreadable; fall through to unknown
        pass

    return "unknown"

def main() -> None:
    """
    Main entry point for the DockSec CLI tool.
    Parses arguments and coordinates AI analysis and security scanning.
    """
    # Set CLI mode to suppress INFO logs for user-facing output
    os.environ["DOCKSEC_CLI_MODE"] = "true"
    
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
    parser.add_argument('--skip-ai-scoring', action='store_true', help='Skip AI-based security scoring (use local scoring only)')
    parser.add_argument('--severity', help='Comma-separated severity levels to scan for (default: CRITICAL,HIGH; or set DOCKSEC_DEFAULT_SEVERITY)')
    parser.add_argument('--fail-on', dest='fail_on', metavar='SEVERITY', help='Exit with code 1 if any finding is at or above this severity (CRITICAL, HIGH, MEDIUM, or LOW)')
    parser.add_argument('--format', dest='format', help='Comma-separated report formats to write: json, csv, pdf, html (default: all)')
    parser.add_argument('--output-dir', dest='output_dir', metavar='DIR', help='Directory to write reports to (default: ~/.docksec/results or DOCKSEC_RESULTS_DIR)')
    parser.add_argument('--json', dest='json_stdout', action='store_true', help='Print scan results as JSON to stdout (no report files unless --format is also given)')
    parser.add_argument('--sarif', dest='sarif', action='store_true', help='Write a SARIF 2.1.0 report for GitHub Code Scanning and other SARIF-compatible tools')
    parser.add_argument('--baseline', dest='baseline', metavar='FILE', help='Path to a baseline file; with --fail-on, only findings not present in the baseline trigger the gate')
    parser.add_argument('--update-baseline', dest='update_baseline', action='store_true', help='Write the current scan findings to --baseline instead of gating against it')
    parser.add_argument('--quiet', action='store_true', help='Reduce output to warnings, errors, and the result summary')
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

    # Set provider and model from CLI args if provided (overrides env vars)
    if args.provider:
        os.environ["LLM_PROVIDER"] = args.provider
    if args.model:
        os.environ["LLM_MODEL"] = args.model

    # Set compact output mode if requested
    if args.compact_output:
        os.environ["DOCKSEC_COMPACT_OUTPUT"] = "true"

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
    valid_formats = ["json", "csv", "pdf", "html"]
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
        run_ai = True
        run_scan = False
        run_compose_analysis = False
        mode_desc = "AI Analysis Only"
    elif args.scan_only:
        run_ai = False
        run_scan = True
        run_compose_analysis = False
        mode_desc = "Security Scan Only"
    else:
        # Default: run both AI and scan if both Dockerfile and image are provided
        run_ai = bool(args.dockerfile)
        run_scan = bool(args.image)
        run_compose_analysis = False
        mode_desc = "Full Analysis (AI + Scanner)"
    
    from docksec.config_manager import get_config
    from docksec.enums import LLMProvider

    output.banner(get_version(), mode_desc)
    output.kv("Reports", output_dir)
    if run_scan:
        output.kv("Severity", severity)
    if run_ai:
        config = get_config()
        output.kv("AI Provider", str(config.llm_provider))
    
    # Initialize AI findings storage
    ai_findings = None
    
    # Run the AI-based recommendation tool
    ai_ok = None  # None = AI not run, True = success, False = failed
    if run_ai:
        output.section("AI-based Dockerfile analysis")
        try:
            # Import required modules from main.py
            from docksec.utils import (
                load_docker_file,
                get_llm,
                analyze_security,
                AnalyzesResponse
            )
            from docksec.config import docker_agent_prompt, truncate_dockerfile
            from pathlib import Path
            
            # Set up the same components as main.py
            llm = get_llm()
            
            # Use appropriate structured output method based on provider
            config = get_config()
            provider = config.llm_provider
            
            if provider == LLMProvider.OPENAI:
                Report_llm = llm.with_structured_output(AnalyzesResponse, method="json_mode")
            else:
                # For Anthropic, Google, and Ollama, let LangChain choose the best method (usually tool calling)
                Report_llm = llm.with_structured_output(AnalyzesResponse)
                
            analyser_chain = docker_agent_prompt | Report_llm
            
            # Load and analyze the file
            if run_compose_analysis:
                filecontent = load_docker_file(docker_file_path=Path(args.compose))
                file_type = "docker-compose file"
            else:
                filecontent = load_docker_file(docker_file_path=Path(args.dockerfile))
                file_type = "Dockerfile"
            
            if not filecontent:
                output.error(f"No {file_type} content found.")
                return

            # Truncate content to reduce token usage
            truncated_content = truncate_dockerfile(filecontent, max_lines=150, max_chars=4000) if run_compose_analysis else truncate_dockerfile(filecontent, max_lines=50, max_chars=2000)

            response = analyser_chain.invoke({"filecontent": truncated_content})
            ai_findings = analyze_security(response, compact=True, report_path=output_dir)
            ai_ok = True

        except ImportError as e:
            output.error(f"Required modules not found - {e}")
            sys.exit(3)
        except Exception as e:
            output.error(f"AI analysis failed: {e}")
            ai_ok = False
    
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
                scanner = DockerSecurityScanner(None, None, results_dir=output_dir, scan_only=not run_ai, skip_ai_scoring=args.skip_ai_scoring)
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
                    skip_ai_scoring=args.skip_ai_scoring
                )

                # Run appropriate scan based on mode
                if args.image_only:
                    # Image-only scan - skip Dockerfile analysis
                    output.info(f"Scanning Docker image: {args.image}")
                    results = scanner.run_image_only_scan(severity)
                else:
                    # Full scan including Dockerfile
                    results = scanner.run_full_scan(severity)

            # Calculate security score
            scanner.analysis_score = scanner.get_security_score(results)

            # Add AI findings to results if available
            if ai_findings:
                results["ai_findings"] = ai_findings

            # Generate reports (all formats by default, or the requested subset)
            report_paths = scanner.generate_all_reports(results, formats=report_formats)

            # SARIF is opt-in via --sarif (not part of --format's default bundle)
            # since it targets GitHub Code Scanning / CI rather than local reading.
            if args.sarif:
                report_paths["sarif"] = _generate_sarif_report(scanner, results)

            # Run advanced scan if available and image is provided (skip for compose
            # and for --json, since Docker Scout output is not part of the payload
            # and would otherwise print to stdout alongside it)
            if hasattr(scanner, 'advanced_scan') and args.image and not run_compose_analysis \
                    and not args.json_stdout:
                output.section("Advanced scan (Docker Scout)")
                scanner.advanced_scan()

            scan_ok = True
            if args.json_stdout:
                _print_json_results(results, scanner, report_paths)
            else:
                _render_scan_summary(output, args, scanner, results, report_paths,
                                     run_ai, run_compose_analysis)

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

    # Exit codes (CI-friendly): 0 clean, 1 findings at/above --fail-on,
    # 2 usage error, 3 tool/runtime error.
    if not run_ai and not run_scan:
        output.warn("No analysis performed. Use --help for usage information.")
        sys.exit(2)

    if scan_ok is False or ai_ok is False:
        sys.exit(3)

    if gate_triggered:
        sys.exit(1)


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


def _print_json_results(results, scanner, report_paths):
    """Print scan results as a single JSON object to stdout.

    Mirrors the shape ReportGenerator.generate_json_report writes to disk, so
    --json and the JSON report file stay consistent. stdout carries only this
    payload; all human-readable output goes to stderr in --json mode (see
    docksec.output.configure).
    """
    import json as json_module

    from docksec import output

    vulnerabilities = results.get("json_data", [])
    payload = {
        "scan_info": {
            "image": scanner.image_name,
            "dockerfile": results.get("dockerfile_path", "N/A"),
            "scan_time": results.get("timestamp", ""),
            "analysis_score": getattr(scanner, "analysis_score", None),
            "scan_mode": results.get("scan_mode", "full"),
        },
        "vulnerabilities": vulnerabilities,
        "severity_counts": output.count_by_severity(vulnerabilities),
    }
    if "ai_findings" in results:
        payload["ai_analysis"] = results["ai_findings"]
    if report_paths:
        payload["report_files"] = {fmt: path for fmt, path in report_paths.items() if path}

    print(json_module.dumps(payload, indent=2))


def _render_scan_summary(output, args, scanner, results, report_paths,
                         run_ai, run_compose_analysis):
    """Render the consolidated result summary: severity table, score, a Quick
    take action block, the generated reports, and a suggested next command."""
    vulnerabilities = results.get("json_data", [])
    counts = output.count_by_severity(vulnerabilities)

    output.section("Results")
    output.severity_table(counts)
    output.score(getattr(scanner, "analysis_score", None))

    failed_services = results.get("failed_services") or []
    if failed_services:
        names = ", ".join(f["service"] for f in failed_services)
        total = results.get("scanned_services") or len(failed_services)
        output.warn(
            f"{len(failed_services)} of {total} service(s) could not be scanned: {names}"
        )
        for f in failed_services:
            output.detail(f"  {f['service']}: {f['reason']}")
        output.detail("Vulnerability data for these services is missing; only static compose checks were applied.")

    output.quick_take(_quick_take_lines(results, counts, run_ai))
    if report_paths:
        output.report_results(report_paths, scanner.RESULTS_DIR)
    output.next_command(_suggest_next_command(args, results, run_ai, run_compose_analysis))


def _quick_take_lines(results, counts, run_ai):
    """Build a few high-signal lines summarizing what matters most."""
    lines = []

    total_vulns = sum(counts.get(sev, 0) for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
    if total_vulns:
        crit, high = counts.get("CRITICAL", 0), counts.get("HIGH", 0)
        lines.append(f"{total_vulns} security findings ({crit} critical, {high} high)")

    failed_services = results.get("failed_services") or []
    if failed_services:
        names = ", ".join(f["service"] for f in failed_services)
        total = results.get("scanned_services") or len(failed_services)
        lines.append(
            f"{len(failed_services)} of {total} service(s) could not be scanned: {names}"
            " -- score does not reflect their image vulnerabilities"
        )

    dockerfile_scan = results.get("dockerfile_scan", {})
    if not dockerfile_scan.get("skipped") and not dockerfile_scan.get("success"):
        output_text = dockerfile_scan.get("output") or ""
        issue_lines = [ln for ln in output_text.splitlines() if ln.strip()]
        if issue_lines:
            top = _format_hadolint_line(issue_lines[0].strip())
            lines.append(f"{len(issue_lines)} Dockerfile lint issues; top: {top}")

    ai_findings = results.get("ai_findings") or {}
    exposed = ai_findings.get("exposed_credentials") or []
    if exposed:
        lines.append(f"{len(exposed)} likely exposed credential(s) flagged by AI analysis")

    if not run_ai and not results.get("ai_findings"):
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