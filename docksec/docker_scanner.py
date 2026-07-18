import os
import json
import subprocess
import hashlib
from typing import List, Tuple, Dict, Optional
from datetime import datetime
import sys
import re
from pathlib import Path
from docksec import output as ui  # aliased; a local var named `output` is used below
from docksec.config import RESULTS_DIR
from docksec.enums import Severity
from docksec.utils import ScoreResponse, get_llm, print_section, get_custom_logger
from collections import defaultdict

# Initialize logger
logger = get_custom_logger(__name__)

class ScanResultsCache:
    """Simple cache for scan results to avoid re-scanning same images."""
    
    def _load_cache(self) -> Dict:
        """Load cache from disk."""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}
    
    def _save_cache(self) -> None:
        """Save cache to disk."""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except IOError as e:
            logger.warning(f"Failed to save cache: {e}")
    
    # Default time-to-live for cache entries, in hours. Vulnerability databases
    # move daily, so even a digest-accurate scan goes stale; override with
    # DOCKSEC_CACHE_TTL_HOURS.
    DEFAULT_TTL_HOURS = 24

    def __init__(self, cache_dir: str = RESULTS_DIR):
        self.cache_file = os.path.join(cache_dir, ".docksec_cache.json")
        self.cache = self._load_cache()
        try:
            self.ttl_hours = float(os.getenv("DOCKSEC_CACHE_TTL_HOURS", self.DEFAULT_TTL_HOURS))
        except ValueError:
            self.ttl_hours = self.DEFAULT_TTL_HOURS

    def get_key(self, image_id: str, severity: str = "CRITICAL,HIGH", extra: str = "") -> str:
        """Generate cache key from image identity, severity filter, and any
        extra scan-input identity (e.g. the Dockerfile content hash).

        image_id should be the image digest/ID when available so a rebuilt
        tag (e.g. a reused :latest) never serves stale results.
        """
        normalized_severity = ",".join(sorted(s.strip().upper() for s in severity.split(",")))
        return hashlib.md5(f"{image_id}|{normalized_severity}|{extra}".encode()).hexdigest()

    def _is_expired(self, entry: Dict) -> bool:
        try:
            entry_time = datetime.fromisoformat(entry.get("timestamp", ""))
        except (ValueError, TypeError):
            return True
        from datetime import timedelta
        return datetime.now() - entry_time > timedelta(hours=self.ttl_hours)

    def get(self, image_id: str, severity: str = "CRITICAL,HIGH", extra: str = "") -> Optional[Dict]:
        """Get cached results for an image scanned at a given severity.

        Entries older than the TTL are dropped and treated as a miss.
        """
        key = self.get_key(image_id, severity, extra)
        entry = self.cache.get(key)
        if entry is None:
            return None
        if self._is_expired(entry):
            del self.cache[key]
            self._save_cache()
            return None
        return entry

    def set(self, image_id: str, results: Dict, severity: str = "CRITICAL,HIGH", extra: str = "") -> None:
        """Cache scan results for an image scanned at a given severity."""
        key = self.get_key(image_id, severity, extra)
        self.cache[key] = {
            "image": image_id,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
            "results": results
        }
        self._save_cache()
    
    def clear_old(self, days: int = 7) -> None:
        """Clear cache entries older than specified days."""
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(days=days)
        keys_to_delete = []
        
        for key, entry in self.cache.items():
            try:
                entry_time = datetime.fromisoformat(entry.get("timestamp", ""))
                if entry_time < cutoff:
                    keys_to_delete.append(key)
            except (ValueError, TypeError):
                keys_to_delete.append(key)
        
        for key in keys_to_delete:
            del self.cache[key]
        
        if keys_to_delete:
            self._save_cache()
            logger.info(f"Cleared {len(keys_to_delete)} old cache entries")

class DockerSecurityScanner:
    @staticmethod
    def _validate_file_path(file_path: str) -> Path:
        """
        Validate and sanitize file path to prevent path traversal attacks.
        
        Args:
            file_path: Path to validate
            
        Returns:
            Path object if valid
            
        Raises:
            ValueError: If path is invalid or contains path traversal attempts
        """
        if not file_path:
            raise ValueError("File path cannot be empty")

        # Check the raw string before resolution — Path.resolve() removes '..'
        # so checking the resolved path would silently allow traversal attempts.
        if '..' in file_path:
            raise ValueError(f"Invalid path: path traversal detected in '{file_path}'")

        try:
            path = Path(file_path).resolve()
            return path
        except (OSError, ValueError) as e:
            raise ValueError(f"Invalid file path '{file_path}': {str(e)}")
    
    @staticmethod
    def _validate_image_name(image_name: str) -> str:
        """
        Validate Docker image name format.
        
        Args:
            image_name: Docker image name to validate
            
        Returns:
            Sanitized image name
            
        Raises:
            ValueError: If image name is invalid
        """
        if not image_name:
            raise ValueError("Image name cannot be empty")
        
        # Basic validation - image names should be alphanumeric with :, /, -, _, .
        # More lenient than strict Docker validation, but prevents obvious injection
        if len(image_name) > 512:  # Docker image name max length
            raise ValueError(f"Image name too long (max 512 characters): {len(image_name)}")
        
        # Check for path traversal attempts
        if '..' in image_name or image_name.startswith('/'):
            raise ValueError(f"Image name contains path traversal or absolute path: '{image_name}'")
        
        # Whitelist: Docker image names allow alphanumeric, '/', ':', '-', '_', '.', '@'
        # Anything outside this set (spaces, shell metacharacters, etc.) is rejected.
        if not re.match(r'^[a-zA-Z0-9/:._\-@]+$', image_name):
            raise ValueError(f"Image name contains invalid characters: '{image_name}'")
        
        return image_name.strip()
    
    @staticmethod
    def _validate_severity(severity: str) -> str:
        """
        Validate severity string for Trivy.
        
        Args:
            severity: Comma-separated severity levels
            
        Returns:
            Validated severity string
            
        Raises:
            ValueError: If severity contains invalid values
        """
        if not severity:
            raise ValueError("Severity cannot be empty")
        
        valid_severities = Severity.values()
        severity_list = [s.strip().upper() for s in severity.split(',')]

        for sev in severity_list:
            if sev not in valid_severities:
                raise ValueError(f"Invalid severity level: {sev}. Valid values: {', '.join(valid_severities)}")
        
        return ','.join(severity_list)
    
    def _print_compact_vulnerability_summary(self, vulnerabilities: List[Dict]) -> None:
        """
        Print a compact summary of vulnerabilities without full details.
        Shows count by severity in a single-line format.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
        """
        if not vulnerabilities:
            ui.success("No vulnerabilities found.")
            return
        
        severity_counts = defaultdict(int)
        for vuln in vulnerabilities:
            severity = vuln.get('Severity', Severity.UNKNOWN)
            severity_counts[severity] += 1
        
        # Print compact single-line summary
        total = sum(severity_counts.values())
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        summary_parts = []
        
        for severity in severity_order:
            count = severity_counts.get(severity, 0)
            if count > 0:
                summary_parts.append(f"{severity}: {count}")
        
        ui.detail(f"  Vulnerabilities: {' | '.join(summary_parts)} | Total: {total}")
        
        # Show top 3 critical/high only
        critical_high = [v for v in vulnerabilities if v.get('Severity') in [Severity.CRITICAL, Severity.HIGH]]
        if critical_high:
            ui.detail("  Top issues:")
            for i, vuln in enumerate(critical_high[:3], 1):
                title = vuln.get('Title', 'N/A')
                if title and len(title) > 60:
                    title = title[:57] + "..."
                ui.detail(f"    - [{vuln.get('Severity')}] {vuln.get('VulnerabilityID', 'N/A')}: {title}")
    
    def __init__(self, dockerfile_path: Optional[str], image_name: Optional[str], results_dir: str = RESULTS_DIR, scan_only: bool = False, skip_ai_scoring: bool = False, offline: bool = False):
        """
        Initialize the Docker Security Scanner with a Dockerfile path and/or image name.
        Verifies that required tools are installed and the specified files exist.

        Args:
            dockerfile_path: Path to the Dockerfile to scan
            image_name: Name of the Docker image to scan
            results_dir: Directory to store scan results
            scan_only: When True, skip LLM initialization and use local scoring only
            skip_ai_scoring: When True, skip AI-based scoring

        Raises:
            ValueError: If required tools are missing or specified files don't exist
        """
        # Validate and sanitize inputs
        self.image_name = self._validate_image_name(image_name) if image_name else None
        if dockerfile_path:
            validated_path = self._validate_file_path(dockerfile_path)
            self.dockerfile_path = str(validated_path)
        else:
            self.dockerfile_path = None
        
        self.required_tools = ['trivy']
        if self.image_name:
            self.required_tools.append('docker')
        if self.dockerfile_path:
            self.required_tools.append('hadolint')

        self.RESULTS_DIR = results_dir
        self.scan_only = scan_only
        self.skip_ai_scoring = skip_ai_scoring
        # Offline mode: pass Trivy --offline-scan --skip-db-update so no network
        # is used (uses the already-downloaded Trivy vuln DB). Threaded into the
        # image scan calls and SBOM generation below.
        self.offline = offline
        self.analysis_score = None  # Initialize to avoid AttributeError when accessed before calculation
        
        # Initialize score chain: skip if scan_only or skip_ai_scoring flags are set
        if scan_only or skip_ai_scoring:
            self.score_chain = None
        else:
            try:
                from docksec.enums import LLMProvider
                from docksec.config_manager import get_config
                from docksec.config import docker_score_prompt
                config = get_config()
                provider = config.llm_provider
                llm = get_llm()
                
                if provider == LLMProvider.OPENAI:
                    self.score_chain = docker_score_prompt | llm.with_structured_output(ScoreResponse, method="json_mode")
                else:
                    self.score_chain = docker_score_prompt | llm.with_structured_output(ScoreResponse)
            except Exception as e:
                logger.warning(f"Failed to initialize AI scoring: {e}")
                self.score_chain = None
        
        # Ensure results directory exists
        try:
            os.makedirs(self.RESULTS_DIR, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create results directory {self.RESULTS_DIR}: {e}")
            # Fallback is handled in config.py, but this is a safety check
        
        # Initialize output mode for console display
        self.compact_output = os.getenv("DOCKSEC_COMPACT_OUTPUT", "false").lower() == "true"
        
        # Initialize cache
        self.cache = ScanResultsCache(self.RESULTS_DIR)
        self.use_cache = os.getenv("DOCKSEC_USE_CACHE", "true").lower() == "true"

        # Verify required tools
        missing_tools = self._check_tools()
        if missing_tools:
            error_msg = f"Missing required tools: {', '.join(missing_tools)}\n\n"
            error_msg += "Installation instructions:\n"
            for tool in missing_tools:
                error_msg += f"\n{tool.upper()}:\n{self._get_tool_installation_instructions(tool)}\n"
            raise ValueError(error_msg)
        
        # Verify Dockerfile exists (after validation)
        if self.dockerfile_path and not os.path.exists(self.dockerfile_path):
            raise ValueError(f"Dockerfile not found at {self.dockerfile_path}")
        
        # Verify Docker image exists (using validated image_name) if provided
        if self.image_name:
            try:
                subprocess.run(
                    ['docker', 'image', 'inspect', self.image_name],
                    capture_output=True,
                    check=True,
                    text=True,
                    timeout=30,
                    shell=False  # Explicitly disable shell for security
                )
            except subprocess.CalledProcessError as e:
                # Check if the error is due to permission issues
                error_output = e.stderr.lower() if e.stderr else ""
                if "permission denied" in error_output or "cannot connect to the docker daemon" in error_output:
                    raise ValueError(
                        f"Unable to access Docker. This may require elevated permissions.\n"
                        f"Possible solutions:\n"
                        f"  1. Add your user to the docker group: sudo usermod -aG docker $USER (then log out and back in)\n"
                        f"  2. Ensure Docker daemon is running: sudo systemctl start docker (Linux) or start Docker Desktop\n"
                        f"  3. If you must use sudo, run DockSec with sudo (not recommended for security reasons)\n"
                        f"Original error: {e.stderr.strip() if e.stderr else str(e)}"
                    )
                # If it's not a permission error, assume the image doesn't exist
                raise ValueError(f"Docker image '{self.image_name}' not found locally")
            except FileNotFoundError:
                raise ValueError(
                    "Docker command not found. Please ensure Docker is installed and accessible in your PATH."
                )
    def _cache_image_id(self) -> str:
        """Resolve the image's content digest/ID for cache keying.

        Using the image ID (not the tag) means a rebuilt tag such as a reused
        :latest is a cache miss instead of silently serving stale findings.
        Falls back to the image name if the ID cannot be resolved.
        """
        if not self.image_name:
            return "no-image"
        try:
            result = subprocess.run(
                ['docker', 'image', 'inspect', '-f', '{{.Id}}', self.image_name],
                capture_output=True, text=True, timeout=30, shell=False
            )
            image_id = (result.stdout or "").strip()
            if result.returncode == 0 and image_id:
                return image_id
            logger.debug(
                f"docker image inspect returned no ID for {self.image_name} "
                f"(rc={result.returncode}); caching by image name instead"
            )
        except (subprocess.SubprocessError, OSError) as e:
            logger.debug(
                f"Could not resolve image ID for {self.image_name} ({e}); "
                f"caching by image name instead"
            )
        return self.image_name

    def _dockerfile_fingerprint(self) -> str:
        """Content hash of the Dockerfile so cached full-scan results are never
        reused across different Dockerfiles that share an image."""
        if not self.dockerfile_path:
            return "no-dockerfile"
        try:
            with open(self.dockerfile_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except OSError:
            return f"unreadable:{self.dockerfile_path}"

    def run_image_only_scan(self, severity: str = "CRITICAL,HIGH") -> Dict:
        """
        Run image-only security scan without Dockerfile analysis.
        
        Args:
            severity: Comma-separated list of severity levels to scan for
            
        Returns:
            Dictionary containing scan results
        """
        # Validate severity input
        severity = self._validate_severity(severity)

        # Check cache first (keyed by image digest so rebuilt tags miss)
        cache_id = self._cache_image_id() if self.use_cache else None
        if self.use_cache:
            cached = self.cache.get(cache_id, severity)
            if cached:
                ui.info(f"Using cached scan results for {self.image_name} (scanned at {cached.get('timestamp', 'N/A')})")
                ui.detail("Tip: use --no-cache (or DOCKSEC_USE_CACHE=false) to bypass the cache")
                return cached.get('results', {})

        logger.info(f"Starting image-only scan for {self.image_name}")
        
        results = {
            'dockerfile_scan': {
                'success': True,  # Skip Dockerfile scan
                'output': "Skipped - Image-only scan mode",
                'skipped': True
            },
            'image_scan': {
                'success': False,
                'output': None
            },
            'json_data': [],
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'image_name': self.image_name,
            'dockerfile_path': self.dockerfile_path or "N/A - Image-only scan",
            'scan_mode': 'image_only'
        }

        # Run image vulnerability scan
        image_success, image_output = self.scan_image(severity)
        results['image_scan']['success'] = image_success
        results['image_scan']['output'] = image_output

        # Get JSON data for vulnerabilities
        json_success, json_data = self.scan_image_json(severity)
        if json_success:
            results['json_data'] = json_data

        # Cache results
        if self.use_cache:
            self.cache.set(cache_id, results, severity)

        # Print final summary
        if not json_data:
            ui.success(f"Image scan completed for {self.image_name} (no vulnerabilities found).")
        else:
            severity_counts = defaultdict(int)
            for v in json_data:
                severity_counts[v.get('Severity', Severity.UNKNOWN)] += 1
            ui.info(f"Image scan completed for {self.image_name}. Found {len(json_data)} vulnerabilities.")
            # self._print_compact_vulnerability_summary(json_data) is already called in scan_image_json

        return results 
          
    def _check_tools(self) -> List[str]:
        """Check if all required tools are installed and return list of missing tools."""
        missing_tools = []
        
        for tool in self.required_tools:
            try:
                subprocess.run(
                    [tool, '--version'],
                    capture_output=True,
                    check=True,
                    timeout=10,
                    shell=False
                )
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                missing_tools.append(tool)
        
        return missing_tools
    
    def _get_tool_installation_instructions(self, tool: str) -> str:
        """Get installation instructions for a missing tool."""
        instructions = {
            'docker': (
                "Docker is required for image scanning. Please install Docker:\n"
                "  - Linux: https://docs.docker.com/engine/install/\n"
                "  - macOS: https://docs.docker.com/desktop/install/mac-install/\n"
                "  - Windows: https://docs.docker.com/desktop/install/windows-install/"
            ),
            'trivy': (
                "Trivy is required for vulnerability scanning. Install it:\n"
                "  - Linux/Mac: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin\n"
                "  - Windows: See https://aquasecurity.github.io/trivy/latest/getting-started/installation/\n"
                "  - Or run: python setup_external_tools.py"
            ),
            'hadolint': (
                "Hadolint is required for Dockerfile linting. Install it:\n"
                "  - Linux: curl -L -o hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 && chmod +x hadolint && sudo mv hadolint /usr/local/bin/\n"
                "  - macOS: brew install hadolint\n"
                "  - Windows: See https://github.com/hadolint/hadolint#install\n"
                "  - Or run: python setup_external_tools.py"
            )
        }
        return instructions.get(tool, f"Please install {tool} from its official documentation.")

    def scan_dockerfile(self) -> Tuple[bool, Optional[str]]:
        """
        Scan Dockerfile using Hadolint.
        
        Returns:
            Tuple containing:
                - bool: True if no issues found, False otherwise
                - Optional[str]: Output from the scan or None if successful
        """
        logger.info(f"Starting Dockerfile scan with Hadolint: {self.dockerfile_path}")
        try:
            result = subprocess.run(
                ['hadolint', self.dockerfile_path],
                capture_output=True,
                text=True,
                timeout=300,
                shell=False
            )
            
            if result.returncode != 0:
                output = result.stdout if result.stdout else result.stderr
                logger.warning(f"Hadolint found issues in {self.dockerfile_path}")
                ui.warn("Dockerfile linting issues found:")
                ui.detail(output)
                ui.detail("Tip: ignore a rule with 'hadolint --ignore DL3000 <Dockerfile>'")
                return False, output
            else:
                logger.info("No Dockerfile linting issues found.")
                ui.success("No Dockerfile linting issues found.")
                return True, None
                
        except subprocess.CalledProcessError as e:
            error_msg = f"Hadolint execution failed: {e}"
            logger.error(error_msg, exc_info=True)
            ui.error(error_msg)
            ui.detail("Troubleshooting steps:")
            ui.detail("  1. Verify Hadolint is installed: hadolint --version")
            ui.detail("  2. Check file permissions on the Dockerfile")
            ui.detail("  3. Ensure Dockerfile syntax is valid")
            return False, str(e)
        except subprocess.TimeoutExpired:
            error_msg = "Hadolint scan timed out after 300 seconds"
            logger.error(f"{error_msg} for {self.dockerfile_path}")
            ui.error(error_msg)
            ui.detail("Troubleshooting steps:")
            ui.detail("  1. The Dockerfile may be extremely large")
            ui.detail("  2. Try splitting into smaller Dockerfiles")
            ui.detail("  3. Check for infinite loops or circular dependencies")
            return False, "Scan timeout"
        except FileNotFoundError:
            error_msg = "Hadolint not found in PATH"
            logger.error(error_msg)
            ui.error(error_msg)
            ui.detail("Installation instructions:")
            ui.detail(self._get_tool_installation_instructions('hadolint'))
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error during Hadolint scan: {e}"
            logger.error(error_msg, exc_info=True)
            ui.error(error_msg)
            return False, str(e)
    
    def _filter_scan_results(self, scan_results: Dict) -> List[Dict]:
        """
        Filter Trivy scan results to extract specific vulnerability data.
        
        Args:
            scan_results: The raw Trivy scan results
            
        Returns:
            List of filtered vulnerability data with key information
        """
        filtered_vulnerabilities = []
        
        for result in scan_results.get("Results", []):
            target = result.get("Target", "")
            
            for vulnerability in result.get('Vulnerabilities', []):
                description = vulnerability.get("Description", "")
                if description and len(description) > 150:
                    description = description[:150] + "..."
                
                filtered_vulnerability = {
                    "VulnerabilityID": vulnerability.get("VulnerabilityID"),
                    "Target": target,
                    "PkgName": vulnerability.get("PkgName"),
                    "InstalledVersion": vulnerability.get("InstalledVersion"),
                    "FixedVersion": vulnerability.get("FixedVersion"),
                    "Severity": vulnerability.get("Severity"),
                    "Title": vulnerability.get("Title"),
                    "Description": description,
                    "Status": vulnerability.get("Status"),
                    "CVSS": vulnerability.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                    "PrimaryURL": vulnerability.get("PrimaryURL")
                }
                
                filtered_vulnerabilities.append(filtered_vulnerability)
        
        return filtered_vulnerabilities
    
    def scan_image_json(self, severity: str = "CRITICAL,HIGH") -> Tuple[bool, Optional[List[Dict]]]:
        """
        Scan Docker image using Trivy and return the results as structured data (compact).
        
        Args:
            severity: Comma-separated list of severity levels to scan for
            
        Returns:
            Tuple containing:
                - bool: True if scan completed successfully, False otherwise
                - Optional[List[Dict]]: Filtered vulnerability data or None if scan failed
        """
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
        
        # Validate severity input
        severity = self._validate_severity(severity)
        logger.info(f"Starting Trivy JSON scan for image: {self.image_name}")
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                # Route the spinner through the shared output console so it
                # honors --json (which redirects human output to stderr) and
                # never pollutes the machine-readable stdout payload.
                console=ui.get_console(),
                # No live spinner when quiet or when output is not a terminal
                # (CI logs would otherwise capture a half-drawn progress bar).
                disable=ui.is_quiet() or not ui.get_console().is_terminal,
            ) as progress:
                scan_task = progress.add_task(
                    f"[cyan]Scanning {self.image_name}...",
                    total=None
                )
                
                trivy_cmd = [
                    'trivy',
                    'image',
                    '-f', 'json',
                    '--severity', severity,
                    '--no-progress',
                    '--skip-version-check',
                ]
                if getattr(self, 'offline', False):
                    trivy_cmd += ['--offline-scan', '--skip-db-update']
                trivy_cmd.append(self.image_name)

                result = subprocess.run(
                    trivy_cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    timeout=600,
                    shell=False
                )
                
                progress.update(scan_task, completed=True)
            
            if result.stderr and 'error' in result.stderr.lower() and not result.stdout:
                ui.error(f"Trivy scan failed: {result.stderr[:200]}")
                return False, None
            
            if not result.stdout:
                return True, []

            response = json.loads(result.stdout)
            filtered_results = self._filter_scan_results(response)
            
            # Print compact summary
            self._print_compact_vulnerability_summary(filtered_results)
                
            return True, filtered_results
            
        except subprocess.TimeoutExpired:
            error_msg = "Trivy scan timed out after 600 seconds"
            logger.error(error_msg)
            ui.error(error_msg)
            return False, None
        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse Trivy output: {e}"
            logger.error(error_msg)
            ui.error(error_msg)
            return False, None
        except (subprocess.CalledProcessError, Exception) as e:
            error_msg = f"Trivy scan failed: {e}"
            logger.error(error_msg, exc_info=True)
            ui.error(error_msg)
            return False, None

    def scan_image(self, severity: str = "CRITICAL,HIGH") -> Tuple[bool, Optional[str]]:
        """
        Scan Docker image using Trivy and return text output (compressed).
        
        Args:
            severity: Comma-separated list of severity levels to scan for
            
        Returns:
            Tuple containing:
                - bool: True if no vulnerabilities found, False otherwise
                - Optional[str]: Output from the scan or None if failed
        """
        # Validate severity input
        severity = self._validate_severity(severity)
        logger.info(f"Starting Trivy scan for image: {self.image_name} with severity: {severity}")
        
        try:
            trivy_cmd = [
                'trivy',
                'image',
                '--severity', severity,
                '--no-progress',
                '--skip-version-check',
                '--quiet',
            ]
            if getattr(self, 'offline', False):
                trivy_cmd += ['--offline-scan', '--skip-db-update']
            trivy_cmd.append(self.image_name)

            result = subprocess.run(
                trivy_cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=600,
                shell=False
            )
            
            # In compact mode, we mostly rely on scan_image_json for output
            # This method is kept for backward compatibility and full text results
            return result.returncode == 0, result.stdout
            
        except subprocess.TimeoutExpired:
            ui.error("Trivy scan timed out after 600 seconds")
            return False, "Scan timed out"
        except subprocess.CalledProcessError as e:
            ui.error(f"Error running Trivy scan: {e}")
            return False, str(e)

    def advanced_scan(self) -> Dict:
        """
        Run advanced Docker Scout scan and show a concise summary.
        
        Returns:
            Dict containing scan results, or empty dict if scan failed
        """
        result_dict = {
            'success': False,
            'output': None,
            'error': None
        }
        
        try:
            # Running Docker Scout quick scan
            result = subprocess.run(
                ["docker", "scout", "quickview", self.image_name], 
                capture_output=True, text=True, check=True, timeout=300, shell=False
            )
            
            # Parse and show concise summary
            output = result.stdout
            summary_lines = []
            for line in output.split('\n'):
                # Extract lines containing counts or recommendations
                if any(x in line for x in ['Target', 'Base image', 'Updated base image', 'vulnerabilities']):
                    summary_lines.append(line.strip())
            
            ui.info(f"Docker Scout Summary for {self.image_name}:")
            if summary_lines:
                for line in summary_lines[:5]: # Show top 5 summary lines
                    ui.detail(f"  {line}")
            else:
                # Fallback to a very short version of output if parsing fails
                ui.detail(f"  {output.splitlines()[0] if output.splitlines() else 'Scan completed.'}")
            
            result_dict['success'] = True
            result_dict['output'] = result.stdout
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr if e.stderr else str(e)
            logger.warning(f"Docker Scout failed: {error_msg}")
            result_dict['error'] = error_msg
        except subprocess.TimeoutExpired:
            error_msg = "Docker Scout scan timed out"
            logger.warning(error_msg)
            result_dict['error'] = error_msg
        except FileNotFoundError:
            # Silently fail if tool not found, as it's optional
            result_dict['error'] = "Docker Scout not found"

        return result_dict

    def generate_sbom(self) -> Optional[str]:
        """
        Generate a CycloneDX SBOM for the image using Trivy's native exporter.

        Trivy produces a spec-compliant CycloneDX 1.x document that lists every
        package component in the image plus any known vulnerabilities, which is
        exactly what supply-chain consumers (Dependency-Track, GitHub, etc.)
        expect. Writing it here (rather than re-deriving a BOM from the filtered
        findings) keeps DockSec's SBOM faithful to the full package inventory,
        not just the severity-filtered vulnerability subset.

        Returns:
            The raw CycloneDX JSON string, or None if generation failed. The
            caller (ReportGenerator) owns writing it to a file.
        """
        if not self.image_name:
            return None

        cmd = ['trivy', 'image', '--format', 'cyclonedx', '--no-progress',
               '--skip-version-check', '--quiet']
        if getattr(self, 'offline', False):
            cmd += ['--offline-scan', '--skip-db-update']
        cmd.append(self.image_name)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=600,
                shell=False
            )
            if result.returncode != 0 or not result.stdout:
                logger.warning(
                    f"Trivy SBOM generation failed for {self.image_name}: "
                    f"{(result.stderr or '')[:200]}"
                )
                ui.warn("SBOM generation failed; see logs for details.")
                return None
            return result.stdout
        except subprocess.TimeoutExpired:
            ui.error("SBOM generation timed out after 600 seconds")
            return None
        except FileNotFoundError:
            ui.error("Trivy not found in PATH; cannot generate SBOM.")
            return None
        except Exception as e:
            logger.error(f"SBOM generation failed: {e}", exc_info=True)
            ui.error(f"SBOM generation failed: {e}")
            return None

    def run_full_scan(self, severity: str = "CRITICAL,HIGH") -> Dict:
        """
        Run all security scans and return results.
        
        Args:
            severity: Comma-separated list of severity levels to scan for
            
        Returns:
            Dictionary containing scan results
        """
        # Validate severity input
        severity = self._validate_severity(severity)

        # Check cache first (only if image name is provided). The key includes
        # the image digest and the Dockerfile content hash so cached results
        # are never reused for a rebuilt tag or a different Dockerfile.
        cache_id = None
        dockerfile_fp = None
        if self.image_name and self.use_cache:
            cache_id = self._cache_image_id()
            dockerfile_fp = self._dockerfile_fingerprint()
            cached = self.cache.get(cache_id, severity, extra=dockerfile_fp)
            if cached:
                ui.info(f"Using cached scan results for {self.image_name} (scanned at {cached.get('timestamp', 'N/A')})")
                ui.detail("Tip: use --no-cache (or DOCKSEC_USE_CACHE=false) to bypass the cache")
                return cached.get('results', {})

        scan_status = True
        results = {
            'dockerfile_scan': {
                'success': False,
                'output': None
            },
            'image_scan': {
                'success': True,  # Default to True if skipped
                'output': "Skipped - No image provided",
                'skipped': True
            },
            'json_data': [],
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'image_name': self.image_name or "N/A",
            'dockerfile_path': self.dockerfile_path
        }

        # Run Dockerfile scan
        if self.dockerfile_path:
            dockerfile_success, dockerfile_output = self.scan_dockerfile()
            results['dockerfile_scan']['success'] = dockerfile_success
            results['dockerfile_scan']['output'] = dockerfile_output
            if not dockerfile_success:
                scan_status = False
        else:
            results['dockerfile_scan']['success'] = True
            results['dockerfile_scan']['output'] = "Skipped - No Dockerfile provided"
            results['dockerfile_scan']['skipped'] = True

        # Run image vulnerability scan (only if image name is provided)
        if self.image_name:
            image_success, image_output = self.scan_image(severity)
            results['image_scan']['success'] = image_success
            results['image_scan']['output'] = image_output
            results['image_scan']['skipped'] = False
            if not image_success:
                scan_status = False

            # Get JSON data
            json_success, json_data = self.scan_image_json(severity)
            if json_success:
                results['json_data'] = json_data

            # Cache results
            if self.use_cache:
                self.cache.set(cache_id, results, severity, extra=dockerfile_fp)

        # Print final summary
        target_name = self.image_name if self.image_name else self.dockerfile_path
        if scan_status:
            ui.success(f"All security scans completed for {target_name}.")
        else:
            ui.warn(f"Security scans completed for {target_name} with some issues.")

        return results

    def generate_all_reports(self, results: Dict, formats=None) -> Dict:
        """
        Generate report formats (JSON, CSV, PDF, HTML) from scan results.

        Args:
            results: The scan results to save
            formats: Optional iterable of formats to write ('json', 'csv', 'pdf',
                     'html'). When None, all four formats are written.

        Returns:
            Dictionary with paths to the generated reports
        """
        from docksec.report_generator import ReportGenerator

        # Calculate security score if not already set
        if self.analysis_score is None:
            self.analysis_score = self.get_security_score(results)

        # Initialize report generator
        generator = ReportGenerator(self.image_name or "docksec_report", self.RESULTS_DIR)
        generator.set_analysis_score(self.analysis_score)

        # Generate the requested reports using the dedicated generator
        report_paths = generator.generate_all_reports(results, formats=formats)

        return report_paths
    
    def _calculate_local_score(self, results: Dict) -> float:
        """
        Calculate a security score locally without any LLM call.
        Used when scan_only=True. Mirrors the weighted logic in SecurityScoreCalculator.

        Weights: vulnerabilities 50%, dockerfile quality 30%, configuration 20%.
        """
        from docksec.score_calculator import SecurityScoreCalculator
        calculator = SecurityScoreCalculator(skip_llm=True)
        breakdown = calculator.get_score_breakdown(results)
        # The score and its rating are rendered once by the CLI summary
        # (docksec.output.score); this method only computes the value.
        return breakdown['overall']

    def get_security_score(self, results: Dict) -> float:
        """
        Calculate the security score based on scan results.

        Uses LLM-based scoring when available. Falls back to local static
        scoring when scan_only=True or if the LLM call fails (e.g., quota exceeded).
        
        Optimizes token usage by sending summarized vulnerability data to LLM.

        Args:
            results: The scan results to calculate the score from

        Returns:
            The calculated security score
        """
        if self.score_chain is None:
            return self._calculate_local_score(results)

        try:
            from docksec.config import summarize_vulnerabilities
            
            # Create summarized vulnerability data instead of sending full results
            vulnerabilities = results.get('json_data', [])
            vuln_summary = summarize_vulnerabilities(vulnerabilities, max_count=20)
            
            # Send only summary, not full results dict
            score = self.score_chain.invoke({"results": vuln_summary})
            return score.score
        except Exception as e:
            logger.warning(f"AI scoring failed: {e}. Falling back to local scoring.")
            return self._calculate_local_score(results)
    
def main():
    """Main function to run the security scanner."""
    if len(sys.argv) < 3:
        print("Usage: python docker_scanner.py <dockerfile_path> <image_name> [severity] [output_file]")
        print("Example: python docker_scanner.py ./Dockerfile myapp:latest CRITICAL,HIGH results.json")
        sys.exit(1)

    dockerfile_path = sys.argv[1]
    image_name = sys.argv[2]
    severity = sys.argv[3] if len(sys.argv) > 3 else "CRITICAL,HIGH"
    # output_file = sys.argv[4] if len(sys.argv) > 4 else "results/scan_results.json"
    
    try:
        # Initialize scanner with verification
        scanner = DockerSecurityScanner(dockerfile_path, image_name)
        
        # Run full scan
        results = scanner.run_full_scan(severity)
        
        # Calculate security score
        score = scanner.get_security_score(results)
        print_section("Security Score", [f"Score: {score}"], "yellow")

        # Save results to file
        scanner.generate_all_reports(results)

        print("\n=== Doing Advanced Scan ===")
        
        # Run advanced scan
        scanner.advanced_scan()

        print("\n=== Finished Scanning ===")
        # Exit with appropriate code
        if results['dockerfile_scan']['success'] and results['image_scan']['success']:
            sys.exit(0)
        else:
            sys.exit(1)
            
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()