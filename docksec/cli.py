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
    parser.add_argument('-o', '--output', help='Output file for the report (default: security_report.txt)')
    parser.add_argument('--ai-only', action='store_true', help='Run only AI-based recommendations (requires Dockerfile)')
    parser.add_argument('--scan-only', action='store_true', help='Run only Dockerfile/image scanning (requires --image)')
    parser.add_argument('--image-only', action='store_true', help='Scan only the Docker image without Dockerfile analysis')
    parser.add_argument('--provider', choices=LLMProvider.values(),
                       help='LLM provider to use (default: openai, can also set LLM_PROVIDER env var)')
    parser.add_argument('--model', help='Model name to use (e.g., gpt-4o, claude-haiku-4-5, gemini-1.5-pro, llama3.1)')
    parser.add_argument('--compact-output', action='store_true', help='Use compact output format (less verbose)')
    parser.add_argument('--skip-ai-scoring', action='store_true', help='Skip AI-based security scoring (use local scoring only)')
    parser.add_argument('--version', action='version', version=f'DockSec {get_version()}')
    
    args = parser.parse_args()
    
    # Set provider and model from CLI args if provided (overrides env vars)
    if args.provider:
        os.environ["LLM_PROVIDER"] = args.provider
    if args.model:
        os.environ["LLM_MODEL"] = args.model
    
    # Set compact output mode if requested
    if args.compact_output:
        os.environ["DOCKSEC_COMPACT_OUTPUT"] = "true"
    
    # Validate argument combinations
    if args.image_only and args.ai_only:
        print("Error: --image-only and --ai-only cannot be used together (AI analysis requires Dockerfile)")
        sys.exit(1)
    
    if args.image_only and args.scan_only:
        print("Error: --image-only and --scan-only cannot be used together (use --image-only for image-only scanning)")
        sys.exit(1)
    
    # Validate Dockerfile requirement
    if not args.image_only and not args.compose and not args.dockerfile:
        print("Error: Dockerfile path is required unless using --image-only or --compose")
        print("Usage examples:")
        print("  docksec Dockerfile -i myapp:latest          # Analyze both Dockerfile and image")
        print("  docksec --image-only -i myapp:latest        # Scan only the image")
        print("  docksec --compose docker-compose.yml        # Scan compose file and its services")
        print("  docksec --ai-only Dockerfile                # AI analysis only")
        sys.exit(1)
    
    # Validate that the Dockerfile exists (if provided)
    if args.dockerfile and not os.path.isfile(args.dockerfile):
        print(f"Error: Dockerfile not found at {args.dockerfile}")
        sys.exit(1)
    
    # Validate image requirement for image-based operations
    if args.image_only and not args.image:
        print("Error: Image name is required for image-only scanning. Use -i/--image to specify the Docker image.")
        print("Example: docksec --image-only -i myapp:latest")
        sys.exit(1)
    
    # In scan-only mode, if no image is provided, we'll only run Dockerfile analysis
    if args.scan_only and not args.image:
        print("[INFO] No image provided for scan-only mode. Running Dockerfile analysis only.")
    
    # Determine which tools to run
    if args.compose:
        run_ai = not args.scan_only
        run_scan = True
        run_dockerfile_analysis = False
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
                print("Error: Could not auto-detect a docker-compose file in the current directory.")
                sys.exit(1)
        
        if not os.path.isfile(compose_path):
            print(f"Error: Compose file not found at {compose_path}")
            sys.exit(1)
            
        args.compose = compose_path
    elif args.image_only:
        run_ai = False
        run_scan = True
        run_dockerfile_analysis = False
        run_compose_analysis = False
        mode_desc = "Image-only Scan"
    elif args.ai_only:
        run_ai = True
        run_scan = False
        run_dockerfile_analysis = True
        run_compose_analysis = False
        mode_desc = "AI Analysis Only"
    elif args.scan_only:
        run_ai = False
        run_scan = True
        run_dockerfile_analysis = True
        run_compose_analysis = False
        mode_desc = "Security Scan Only"
    else:
        # Default: run both AI and scan if both Dockerfile and image are provided
        run_ai = bool(args.dockerfile)
        run_scan = bool(args.image)
        run_dockerfile_analysis = bool(args.dockerfile)
        run_compose_analysis = False
        mode_desc = "Full Analysis (AI + Scanner)"
    
    print(f"\n[INFO] Mode: {mode_desc}")
    from docksec.config import RESULTS_DIR
    from docksec.config_manager import get_config
    from docksec.enums import LLMProvider
    print(f"[INFO] Reports will be saved to: {RESULTS_DIR}")
    if run_ai:
        config = get_config()
        print(f"[INFO] AI Provider: {config.llm_provider}")
    
    # Initialize AI findings storage
    ai_findings = None
    
    # Run the AI-based recommendation tool
    if run_ai:
        print("\n=== Running AI-based Dockerfile analysis ===")
        try:
            # Import required modules from main.py
            from docksec.utils import (
                load_docker_file,
                get_llm,
                analyze_security,
                AnalyzesResponse
            )
            from docksec.config import docker_agent_prompt, truncate_dockerfile, RESULTS_DIR
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
                print(f"Error: No {file_type} content found.")
                return
            
            # Truncate content to reduce token usage
            truncated_content = truncate_dockerfile(filecontent, max_lines=150, max_chars=4000) if run_compose_analysis else truncate_dockerfile(filecontent, max_lines=50, max_chars=2000)
            
            response = analyser_chain.invoke({"filecontent": truncated_content})
            ai_findings = analyze_security(response, compact=True, report_path=RESULTS_DIR)
            
        except ImportError as e:
            print(f"Error: Required modules not found - {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Error running AI analysis: {e}")
    
    # Run the scanner tool
    if run_scan:
        scan_type = "compose" if run_compose_analysis else ("image-only" if args.image_only else "full")
        print(f"\n=== Running {scan_type} security scanner ===")
        try:
            from docksec.docker_scanner import DockerSecurityScanner
            
            if run_compose_analysis:
                from docksec.compose_scanner import ComposeOrchestrator
                orchestrator = ComposeOrchestrator(
                    args.compose,
                    scan_only=not run_ai,
                    skip_ai_scoring=args.skip_ai_scoring
                )
                print(f"Scanning Compose file: {args.compose}")
                results = orchestrator.run_full_scan("CRITICAL,HIGH")
                
                # We need a scanner instance just for scoring and reporting
                scanner = DockerSecurityScanner(None, None, scan_only=not run_ai, skip_ai_scoring=args.skip_ai_scoring)
                scanner.image_name = "Multiple Services"
                scanner.dockerfile_path = args.compose
            else:
                # Initialize the scanner
                dockerfile_path = args.dockerfile if run_dockerfile_analysis else None
                scanner = DockerSecurityScanner(
                    dockerfile_path, 
                    args.image, 
                    scan_only=not run_ai,
                    skip_ai_scoring=args.skip_ai_scoring
                )
                
                # Run appropriate scan based on mode
                if args.image_only:
                    # Image-only scan - skip Dockerfile analysis
                    print(f"Scanning Docker image: {args.image}")
                    results = scanner.run_image_only_scan("CRITICAL,HIGH")
                else:
                    # Full scan including Dockerfile
                    results = scanner.run_full_scan("CRITICAL,HIGH")
            
            # Calculate security score
            scanner.analysis_score = scanner.get_security_score(results)
            
            # Add AI findings to results if available
            if ai_findings:
                results["ai_findings"] = ai_findings
            
            # Generate all reports
            scanner.generate_all_reports(results)
            
            # Run advanced scan if available and image is provided (skip for compose)
            if hasattr(scanner, 'advanced_scan') and args.image and not run_compose_analysis:
                print("\n=== Running Advanced Scan ===")
                scanner.advanced_scan()
            
            print("\n=== Scanning Complete ===")
            
        except ValueError as e:
            print(f"Scanner error: {e}")
        except ImportError as e:
            print(f"Error: Scanner modules not found - {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Error running scanner: {e}")
    
    if not run_ai and not run_scan:
        print("No analysis performed. Use --help for usage information.")
    else:
        print("\nAnalysis complete!")

if __name__ == "__main__":
    main()