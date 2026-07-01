import os
import json
import subprocess
import hashlib
from typing import List, Tuple, Dict, Optional
from datetime import datetime
import sys
import re
from pathlib import Path
from docksec.config import RESULTS_DIR, docker_score_prompt
from docksec.enums import Severity
from docksec.utils import ScoreResponse, get_llm, print_section, get_custom_logger
from collections import defaultdict

# Initialize logger
logger = get_custom_logger(__name__)

class ScanResultsCache:
    """Simple cache for scan results to avoid re-scanning same images."""
    
    def __init__(self, cache_dir: str = RESULTS_DIR):
        self.cache_file = os.path.join(cache_dir, ".docksec_cache.json")
        self.cache = self._load_cache()
    
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
    
    def get_key(self, image_name: str) -> str:
        """Generate cache key from image name."""
        return hashlib.md5(image_name.encode()).hexdigest()
    
    def get(self, image_name: str) -> Optional[Dict]:
        """Get cached results for an image."""
        key = self.get_key(image_name)
        return self.cache.get(key)
    
    def set(self, image_name: str, results: Dict) -> None:
        """Cache scan results for an image."""
        key = self.get_key(image_name)
        self.cache[key] = {
            "image": image_name,
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
            print("[SUCCESS] No vulnerabilities found.")
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
        
        print(f"  [VULNERABILITIES] {' | '.join(summary_parts)} | Total: {total}")
        
        # Show top 3 critical/high only
        critical_high = [v for v in vulnerabilities if v.get('Severity') in [Severity.CRITICAL, Severity.HIGH]]
        if critical_high:
            print("  Top Issues:")
            for i, vuln in enumerate(critical_high[:3], 1):
                title = vuln.get('Title', 'N/A')
                if title and len(title) > 60:
                    title = title[:57] + "..."
                print(f"    • [{vuln.get('Severity')}] {vuln.get('VulnerabilityID', 'N/A')}: {title}")
    
    def __init__(self, dockerfile_path: Optional[str], image_name: Optional[str], results_dir: str = RESULTS_DIR, scan_only: bool = False, skip_ai_scoring: bool = False):
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
        self.analysis_score = None  # Initialize to avoid AttributeError when accessed before calculation
        
        # Initialize score chain: skip if scan_only or skip_ai_scoring flags are set
        if scan_only or skip_ai_scoring:
            self.score_chain = None
        else:
            try:
                from docksec.enums import LLMProvider
                from docksec.config_manager import get_config
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
    def run_image_only_scan(self, severity: str = "CRITICAL,HIGH") -> Dict:
        """
        Run image-only security scan without Dockerfile analysis.
        
        Args:
            severity: Comma-separated list of severity levels to scan for
            
        Returns:
            Dictionary containing scan results
        """
        # Check cache first
        if self.use_cache:
            cached = self.cache.get(self.image_name)
            if cached:
                print(f"[INFO] Using cached scan results for {self.image_name} (scanned at {cached.get('timestamp', 'N/A')})")
                print("[TIP] To bypass cache, set environment variable DOCKSEC_USE_CACHE=false")
                return cached.get('results', {})
        
        # Validate severity input
        severity = self._validate_severity(severity)
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
            self.cache.set(self.image_name, results)

        # Print final summary
        if not json_data:
            print(f"[SUCCESS] Image scan completed for {self.image_name} (no vulnerabilities found).")
        else:
            severity_counts = defaultdict(int)
            for v in json_data:
                severity_counts[v.get('Severity', Severity.UNKNOWN)] += 1
            print(f"[INFO] Image scan completed for {self.image_name}. Found {len(json_data)} vulnerabilities.")
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
        print("\n=== Starting Dockerfile scan with Hadolint ===")
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
                print("[WARNING] Dockerfile linting issues found:")
                print(output)
                print("\n[TIP] Run 'hadolint --help' to learn about specific rules")
                print("   You can ignore specific rules with: hadolint --ignore DL3000 Dockerfile")
                return False, output
            else:
                logger.info("No Dockerfile linting issues found.")
                print("[SUCCESS] No Dockerfile linting issues found.")
                return True, None
                
        except subprocess.CalledProcessError as e:
            error_msg = f"Hadolint execution failed: {e}"
            logger.error(error_msg, exc_info=True)
            print(f"\n[ERROR] Error: {error_msg}")
            print("\nTroubleshooting steps:")
            print("  1. Verify Hadolint is installed: hadolint --version")
            print("  2. Check file permissions on the Dockerfile")
            print("  3. Ensure Dockerfile syntax is valid")
            return False, str(e)
        except subprocess.TimeoutExpired:
            error_msg = "Hadolint scan timed out after 300 seconds"
            logger.error(f"{error_msg} for {self.dockerfile_path}")
            print(f"\n[ERROR] Error: {error_msg}")
            print("\nTroubleshooting steps:")
            print("  1. The Dockerfile may be extremely large")
            print("  2. Try splitting into smaller Dockerfiles")
            print("  3. Check for infinite loops or circular dependencies")
            return False, "Scan timeout"
        except FileNotFoundError:
            error_msg = "Hadolint not found in PATH"
            logger.error(error_msg)
            print(f"\n[ERROR] Error: {error_msg}")
            print("\nInstallation instructions:")
            print(self._get_tool_installation_instructions('hadolint'))
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error during Hadolint scan: {e}"
            logger.error(error_msg, exc_info=True)
            print(f"\n[ERROR] Error: {error_msg}")
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
                console=None
            ) as progress:
                scan_task = progress.add_task(
                    f"[cyan]Scanning {self.image_name}...",
                    total=None
                )
                
                result = subprocess.run(
                    [
                        'trivy',
                        'image',
                        '-f', 'json',
                        '--severity', severity,
                        '--no-progress',
                        '--skip-version-check',
                        self.image_name
                    ],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    timeout=600,
                    shell=False
                )
                
                progress.update(scan_task, completed=True)
            
            if result.stderr and 'error' in result.stderr.lower() and not result.stdout:
                print(f"[ERROR] Trivy scan failed: {result.stderr[:200]}")
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
            print(f"[ERROR] {error_msg}")
            return False, None
        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse Trivy output: {e}"
            logger.error(error_msg)
            print(f"[ERROR] {error_msg}")
            return False, None
        except (subprocess.CalledProcessError, Exception) as e:
            error_msg = f"Trivy scan failed: {e}"
            logger.error(error_msg, exc_info=True)
            print(f"[ERROR] {error_msg}")
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
            result = subprocess.run(
                [
                    'trivy',
                    'image',
                    '--severity', severity,
                    '--no-progress',
                    '--skip-version-check',
                    '--quiet',
                    self.image_name
                ],
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
            print("[ERROR] Trivy scan timed out after 600 seconds")
            return False, "Scan timed out"
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Error running Trivy scan: {e}")
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
            
            print(f"  [ADVANCED] Docker Scout Summary for {self.image_name}:")
            if summary_lines:
                for line in summary_lines[:5]: # Show top 5 summary lines
                    print(f"    {line}")
            else:
                # Fallback to a very short version of output if parsing fails
                print(f"    {output.splitlines()[0] if output.splitlines() else 'Scan completed.'}")
            
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
    def run_full_scan(self, severity: str = "CRITICAL,HIGH") -> Dict:
        """
        Run all security scans and return results.
        
        Args:
            severity: Comma-separated list of severity levels to scan for
            
        Returns:
            Dictionary containing scan results
        """
        # Check cache first (only if image name is provided)
        if self.image_name and self.use_cache:
            cached = self.cache.get(self.image_name)
            if cached:
                print(f"[INFO] Using cached scan results for {self.image_name} (scanned at {cached.get('timestamp', 'N/A')})")
                print("[TIP] To bypass cache, set environment variable DOCKSEC_USE_CACHE=false")
                return cached.get('results', {})
        
        # Validate severity input
        severity = self._validate_severity(severity)
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
                self.cache.set(self.image_name, results)

        # Print final summary
        target_name = self.image_name if self.image_name else self.dockerfile_path
        if scan_status:
            print(f"[SUCCESS] All security scans completed for {target_name}.")
        else:
            print(f"[WARNING] Security scans completed for {target_name} with some issues.")

        return results

    def generate_all_reports(self, results: Dict) -> Dict:
        """
        Generate all report formats (JSON, CSV, PDF, HTML) from scan results.
        
        Args:
            results: The scan results to save
            
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
        
        # Generate all reports using the dedicated generator
        report_paths = generator.generate_all_reports(results)
        
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
        score = breakdown['overall']

        print(f"Security Score: {score}/100")
        if score >= 90:
            print("[EXCELLENT] Excellent security posture!")
        elif score >= 70:
            print("[GOOD] Good security, but some improvements recommended")
        elif score >= 50:
            print("[FAIR] Fair security - multiple issues need attention")
        else:
            print("[POOR] Poor security - immediate action required")

        return score

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
            print(f"Security Score: {score.score}")
            return score.score
        except Exception as e:
            logger.warning(f"AI scoring failed: {e}. Falling back to local scoring.")
            print(f"AI scoring unavailable: {e}. Falling back to local scoring.")
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