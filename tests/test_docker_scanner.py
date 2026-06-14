"""Unit tests for DockerSecurityScanner class."""
import unittest
import os
import tempfile
import json
from unittest.mock import Mock, patch
from pathlib import Path

# Import after mocking external dependencies
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestDockerSecurityScanner(unittest.TestCase):
    """Test cases for DockerSecurityScanner."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dockerfile = None
        self.test_dir = None
    
    def tearDown(self):
        """Clean up test fixtures."""
        if self.test_dir and os.path.exists(self.test_dir):
            import shutil
            shutil.rmtree(self.test_dir)
    
    def create_test_dockerfile(self, content="FROM ubuntu:latest"):
        """Create a temporary Dockerfile for testing."""
        self.test_dir = tempfile.mkdtemp()
        self.test_dockerfile = os.path.join(self.test_dir, "Dockerfile")
        with open(self.test_dockerfile, 'w') as f:
            f.write(content)
        return self.test_dockerfile
    
    @patch('docksec.docker_scanner.subprocess.run')
    @patch('docksec.docker_scanner.get_llm')
    def test_init_with_valid_inputs(self, mock_llm, mock_subprocess):
        """Test initialization with valid inputs."""
        # Mock subprocess calls for tool checking and docker image inspect
        mock_subprocess.return_value = Mock(returncode=0, stdout="", stderr="")
        
        # Mock LLM
        mock_llm.return_value = Mock()
        
        dockerfile = self.create_test_dockerfile()
        
        from docksec.docker_scanner import DockerSecurityScanner
        
        scanner = DockerSecurityScanner(dockerfile, "test:latest")
        # Compare resolved paths — on macOS tempfile returns /var/... but
        # _validate_file_path resolves it to /private/var/... via symlink.
        self.assertEqual(scanner.dockerfile_path, str(Path(dockerfile).resolve()))
        self.assertEqual(scanner.image_name, "test:latest")
        self.assertIsNone(scanner.analysis_score)
        # Should require docker, trivy, and hadolint
        self.assertIn('docker', scanner.required_tools)
        self.assertIn('trivy', scanner.required_tools)
        self.assertIn('hadolint', scanner.required_tools)

    @patch('docksec.docker_scanner.subprocess.run')
    def test_init_dockerfile_only(self, mock_subprocess):
        """Test initialization with only a Dockerfile (no image)."""
        mock_subprocess.return_value = Mock(returncode=0, stdout="", stderr="")
        
        dockerfile = self.create_test_dockerfile()
        from docksec.docker_scanner import DockerSecurityScanner
        
        scanner = DockerSecurityScanner(dockerfile, None, scan_only=True)
        self.assertEqual(scanner.image_name, None)
        self.assertIn('hadolint', scanner.required_tools)
        self.assertIn('trivy', scanner.required_tools)
        self.assertNotIn('docker', scanner.required_tools)
    
    def test_validate_image_name(self):
        """Test image name validation."""
        from docksec.docker_scanner import DockerSecurityScanner
        
        # Valid image names
        valid_names = ["nginx:latest", "myimage:v1.0", "registry/image:tag"]
        for name in valid_names:
            result = DockerSecurityScanner._validate_image_name(name)
            self.assertEqual(result, name)
        
        # Invalid image names
        invalid_names = ["", "../../etc/passwd", "image with spaces", "image\nnewline"]
        for name in invalid_names:
            with self.assertRaises(ValueError):
                DockerSecurityScanner._validate_image_name(name)
    
    def test_validate_file_path(self):
        """Test file path validation."""
        from docksec.docker_scanner import DockerSecurityScanner
        
        # Path traversal attempts should be rejected
        with self.assertRaises(ValueError):
            DockerSecurityScanner._validate_file_path("../../../etc/passwd")
        
        # Valid path should work
        dockerfile = self.create_test_dockerfile()
        result = DockerSecurityScanner._validate_file_path(dockerfile)
        self.assertTrue(result.exists())
    
    def test_validate_severity(self):
        """Test severity validation."""
        from docksec.docker_scanner import DockerSecurityScanner
        from docksec.enums import Severity

        # Valid severities
        for sev in Severity.values():
            result = DockerSecurityScanner._validate_severity(sev)
            self.assertIn(sev.upper(), result)
        
        # Invalid severity
        with self.assertRaises(ValueError):
            DockerSecurityScanner._validate_severity("INVALID")
        
        # Multiple valid severities
        result = DockerSecurityScanner._validate_severity("CRITICAL,HIGH")
        self.assertIn("CRITICAL", result)
        self.assertIn("HIGH", result)
    
    @patch('docksec.docker_scanner.subprocess.run')
    def test_check_tools_missing(self, mock_subprocess):
        """Test tool checking with missing tools."""
        from docksec.docker_scanner import DockerSecurityScanner
        
        # Mock FileNotFoundError for missing tool
        mock_subprocess.side_effect = FileNotFoundError()
        
        self.create_test_dockerfile()
        
        with patch('docksec.docker_scanner.get_llm'):
            scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
            scanner.required_tools = ['docker', 'trivy']
            missing = scanner._check_tools()
            self.assertEqual(missing, ['docker', 'trivy'])
    
    @patch('docksec.docker_scanner.subprocess.run')
    def test_check_tools_present(self, mock_subprocess):
        """Test tool checking with all tools present."""
        from docksec.docker_scanner import DockerSecurityScanner
        
        # Mock successful tool check
        mock_subprocess.return_value = Mock(returncode=0, stdout="", stderr="")
        
        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        scanner.required_tools = ['docker', 'trivy']
        missing = scanner._check_tools()
        self.assertEqual(missing, [])
    
    def test_get_tool_installation_instructions(self):
        """Test installation instructions for tools."""
        from docksec.docker_scanner import DockerSecurityScanner
        
        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        
        # Test known tools
        docker_instructions = scanner._get_tool_installation_instructions('docker')
        self.assertIn('Docker', docker_instructions)
        
        trivy_instructions = scanner._get_tool_installation_instructions('trivy')
        self.assertIn('Trivy', trivy_instructions)
        
        hadolint_instructions = scanner._get_tool_installation_instructions('hadolint')
        self.assertIn('Hadolint', hadolint_instructions)
        
        # Test unknown tool
        unknown_instructions = scanner._get_tool_installation_instructions('unknown')
        self.assertIn('unknown', unknown_instructions)
    
    @patch('docksec.docker_scanner.defaultdict')
    @patch('builtins.print')
    def test_print_compact_vulnerability_summary_no_vulns(self, mock_print, mock_defaultdict):
        """Test compact summary printing with no vulnerabilities."""
        from docksec.docker_scanner import DockerSecurityScanner
        
        # Mock defaultdict to return a plain dict
        mock_defaultdict.side_effect = lambda: {}
        
        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        scanner._print_compact_vulnerability_summary([])
        
        # Should print success message
        mock_print.assert_called()
    
    @patch('builtins.print')
    def test_print_compact_vulnerability_summary_with_vulns(self, mock_print):
        """Test compact summary printing with vulnerabilities."""
        from docksec.docker_scanner import DockerSecurityScanner
        
        vulnerabilities = [
            {'Severity': 'CRITICAL'},
            {'Severity': 'CRITICAL'},
            {'Severity': 'HIGH'},
            {'Severity': 'MEDIUM'},
        ]
        
        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        scanner._print_compact_vulnerability_summary(vulnerabilities)
        
        # Should print summary
        mock_print.assert_called()
        # Check that all calls contain expected info
        print_calls = [str(call) for call in mock_print.call_args_list]
        combined_output = ' '.join(print_calls)
        self.assertIn('CRITICAL', combined_output)
    
    def test_scan_results_cache_initialization(self):
        """Test ScanResultsCache initialization."""
        from docksec.docker_scanner import ScanResultsCache
        import tempfile
        import shutil
        
        temp_dir = tempfile.mkdtemp()
        try:
            cache = ScanResultsCache(temp_dir)
            self.assertIsNotNone(cache)
            self.assertEqual(cache.cache, {})
        finally:
            shutil.rmtree(temp_dir)
    
    def test_scan_results_cache_set_and_get(self):
        """Test ScanResultsCache set and get operations."""
        from docksec.docker_scanner import ScanResultsCache
        import tempfile
        import shutil
        
        temp_dir = tempfile.mkdtemp()
        try:
            cache = ScanResultsCache(temp_dir)
            
            # Set a value
            image_name = "test:latest"
            results = {"image": "test:latest", "vulnerabilities": []}
            cache.set(image_name, results)
            
            # Get the value
            retrieved = cache.get(image_name)
            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved["image"], image_name)
        finally:
            shutil.rmtree(temp_dir)
    
    def test_scan_results_cache_get_key(self):
        """Test cache key generation."""
        from docksec.docker_scanner import ScanResultsCache
        import tempfile
        import shutil
        
        temp_dir = tempfile.mkdtemp()
        try:
            cache = ScanResultsCache(temp_dir)
            
            # Same image should produce same key
            key1 = cache.get_key("test:latest")
            key2 = cache.get_key("test:latest")
            self.assertEqual(key1, key2)
            
            # Different images should produce different keys
            key3 = cache.get_key("other:v1.0")
            self.assertNotEqual(key1, key3)
        finally:
            shutil.rmtree(temp_dir)
    
    def test_scan_results_cache_persistence(self):
        """Test ScanResultsCache persistence to disk."""
        from docksec.docker_scanner import ScanResultsCache
        import tempfile
        import shutil
        
        temp_dir = tempfile.mkdtemp()
        try:
            # Create cache and set value
            cache1 = ScanResultsCache(temp_dir)
            results = {"image": "test:latest", "score": 85}
            cache1.set("test:latest", results)
            
            # Create new cache instance from same directory
            cache2 = ScanResultsCache(temp_dir)
            retrieved = cache2.get("test:latest")
            
            # Should have persisted data
            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved["image"], "test:latest")
        finally:
            shutil.rmtree(temp_dir)
    
    def test_scan_results_cache_invalid_json(self):
        """Test ScanResultsCache handles invalid JSON gracefully."""
        from docksec.docker_scanner import ScanResultsCache
        import tempfile
        import shutil
        import os
        
        temp_dir = tempfile.mkdtemp()
        try:
            cache_file = os.path.join(temp_dir, ".docksec_cache.json")
            
            # Write invalid JSON
            with open(cache_file, 'w') as f:
                f.write("{ invalid json }")
            
            # Should handle gracefully
            cache = ScanResultsCache(temp_dir)
            self.assertEqual(cache.cache, {})
        finally:
            shutil.rmtree(temp_dir)
    
    def test_scan_results_cache_clear_old(self):
        """Test clearing old cache entries."""
        from docksec.docker_scanner import ScanResultsCache
        from datetime import datetime, timedelta
        import tempfile
        import shutil
        
        temp_dir = tempfile.mkdtemp()
        try:
            cache = ScanResultsCache(temp_dir)
            
            # Add entry with old timestamp
            old_date = (datetime.now() - timedelta(days=10)).isoformat()
            cache.cache["old_key"] = {"timestamp": old_date, "image": "old"}
            
            # Add recent entry
            recent_date = datetime.now().isoformat()
            cache.cache["new_key"] = {"timestamp": recent_date, "image": "new"}
            
            # Clear old entries (default 7 days)
            cache.clear_old(days=7)
            
            # Old entry should be removed, new should remain
            self.assertNotIn("old_key", cache.cache)
            self.assertIn("new_key", cache.cache)
        finally:
            shutil.rmtree(temp_dir)
    
    @patch('docksec.docker_scanner.subprocess.run')
    @patch('docksec.docker_scanner.get_llm')
    def test_init_with_skip_ai_scoring_flag(self, mock_llm, mock_subprocess):
        """Test initialization with skip_ai_scoring flag."""
        mock_subprocess.return_value = Mock(returncode=0, stdout="", stderr="")
        
        dockerfile = self.create_test_dockerfile()
        
        from docksec.docker_scanner import DockerSecurityScanner
        
        # With skip_ai_scoring=True, score_chain should be None
        scanner = DockerSecurityScanner(dockerfile, "test:latest", skip_ai_scoring=True)
        self.assertIsNone(scanner.score_chain)
        
        # With skip_ai_scoring=False, score_chain should be initialized
        mock_llm.return_value = Mock()
        scanner2 = DockerSecurityScanner(dockerfile, "test:latest", skip_ai_scoring=False)
        # Score chain is initialized if get_llm doesn't raise
        if mock_llm.call_count > 1:  # Called again for this scanner
            self.assertIsNotNone(scanner2.score_chain)

    @patch('docksec.docker_scanner.subprocess.run')
    def test_scan_image_json_success(self, mock_run):
        """Test successful JSON image scan."""
        from docksec.docker_scanner import DockerSecurityScanner
        
        mock_run.return_value = Mock(
            returncode=0, 
            stdout=json.dumps({"Results": [{"Target": "test", "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "Severity": "HIGH"}]}]}),
            stderr=""
        )
        
        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        scanner.image_name = "test:latest"
        
        success, results = scanner.scan_image_json()
        self.assertTrue(success)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['VulnerabilityID'], "CVE-1")

    @patch('docksec.docker_scanner.subprocess.run')
    def test_run_image_only_scan(self, mock_run):
        """Test image-only scan workflow."""
        from docksec.docker_scanner import DockerSecurityScanner
        
        mock_run.side_effect = [
            Mock(returncode=0, stdout="Trivy output", stderr=""), # scan_image
            Mock(returncode=0, stdout=json.dumps({"Results": []}), stderr="") # scan_image_json
        ]
        
        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        scanner.image_name = "test:latest"
        scanner.dockerfile_path = None
        scanner.use_cache = False
        
        results = scanner.run_image_only_scan()
        self.assertEqual(results['image_name'], "test:latest")
        self.assertTrue(results['image_scan']['success'])

    @patch('docksec.docker_scanner.DockerSecurityScanner.scan_dockerfile')
    @patch('docksec.docker_scanner.DockerSecurityScanner.scan_image')
    @patch('docksec.docker_scanner.DockerSecurityScanner.scan_image_json')
    def test_run_full_scan(self, mock_json, mock_image, mock_dockerfile):
        """Test full scan workflow."""
        from docksec.docker_scanner import DockerSecurityScanner
        
        mock_dockerfile.return_value = (True, None)
        mock_image.return_value = (True, "output")
        mock_json.return_value = (True, [])
        
        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        scanner.image_name = "test:latest"
        scanner.dockerfile_path = "Dockerfile"
        scanner.use_cache = False
        
        results = scanner.run_full_scan()
        self.assertEqual(results['image_name'], "test:latest")
        self.assertTrue(results['dockerfile_scan']['success'])

    @patch('docksec.docker_scanner.subprocess.run')
    def test_advanced_scan_success(self, mock_run):
        """Test successful advanced scan."""
        from docksec.docker_scanner import DockerSecurityScanner
        
        mock_run.return_value = Mock(returncode=0, stdout="Target: test\nvulnerabilities: 10", stderr="")
        
        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        scanner.image_name = "test:latest"
        
        results = scanner.advanced_scan()
        self.assertTrue(results['success'])
        self.assertIn("Target: test", results['output'])

    @patch('docksec.score_calculator.SecurityScoreCalculator')
    def test_get_security_score_local(self, mock_calc_class):
        """Test local security score calculation."""
        from docksec.docker_scanner import DockerSecurityScanner
        
        # Mock calculator instance and its method
        mock_calc = Mock()
        mock_calc.get_score_breakdown.return_value = {
            'dockerfile': 100.0,
            'vulnerabilities': 100.0,
            'configuration': 100.0,
            'overall': 100.0
        }
        mock_calc_class.return_value = mock_calc
        
        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        scanner.score_chain = None
        
        results = {
            'dockerfile_scan': {'success': True},
            'json_data': []
        }
        
        score = scanner.get_security_score(results)
        self.assertEqual(score, 100.0)

    @patch('docksec.report_generator.ReportGenerator')
    def test_generate_all_reports(self, mock_report_gen_class):
        """Test generating all report formats."""
        from docksec.docker_scanner import DockerSecurityScanner
    
        # Mock the generator instance and its return value
        mock_gen = Mock()
        mock_gen.generate_all_reports.return_value = {
            'json': 'report.json',
            'csv': 'report.csv',
            'pdf': 'report.pdf',
            'html': 'report.html'
        }
        mock_report_gen_class.return_value = mock_gen
    
        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        scanner.image_name = "test:latest"
        scanner.analysis_score = 90
        scanner.RESULTS_DIR = "/tmp"
    
        results = {'json_data': []}
        # Mock get_security_score to avoid LLM call
        with patch.object(DockerSecurityScanner, 'get_security_score', return_value=90.0):
            report_paths = scanner.generate_all_reports(results)
        
        self.assertEqual(report_paths['json'], "report.json")
        self.assertEqual(report_paths['html'], "report.html")
        mock_gen.generate_all_reports.assert_called_once_with(results)

    def test_calculate_local_score(self):
        """Test the local scoring logic."""
        from docksec.docker_scanner import DockerSecurityScanner
        from docksec.enums import Severity
        
        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        
        results = {
            'dockerfile_scan': {'success': False, 'output': 'DL3000\nDL3001'},
            'json_data': [
                {'Severity': Severity.CRITICAL},
                {'Severity': Severity.HIGH}
            ],
            'dockerfile_path': None
        }
        
        # We need to mock SecurityScoreCalculator because it's used inside
        with patch('docksec.score_calculator.SecurityScoreCalculator') as mock_calc_class:
            mock_calc = Mock()
            mock_calc.get_score_breakdown.return_value = {
                'dockerfile': 90.0,
                'vulnerabilities': 85.0,
                'configuration': 80.0,
                'overall': 85.5
            }
            mock_calc_class.return_value = mock_calc
            
            score = scanner._calculate_local_score(results)
            self.assertEqual(score, 85.5)


    # ------------------------------------------------------------------
    # Grype: _parse_grype_output
    # ------------------------------------------------------------------

    def _make_grype_match(self, cve_id="CVE-2024-1234", severity="High",
                          pkg_name="libssl", version="1.0.0"):
        """Return a minimal Grype match dict."""
        return {
            "vulnerability": {
                "id": cve_id,
                "severity": severity,
                "description": "A test vulnerability",
                "urls": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                "cvss": [{"version": "3.1", "metrics": {"baseScore": 7.5}}],
                "fix": {"state": "fixed"},
            },
            "artifact": {
                "name": pkg_name,
                "version": version,
                "type": "deb",
                "locations": [{"path": "/usr/lib/libssl.so"}],
            },
        }

    def test_parse_grype_output_with_vulns(self):
        """Test _parse_grype_output with a normal Grype JSON payload."""
        from docksec.docker_scanner import DockerSecurityScanner

        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        payload = json.dumps({"matches": [self._make_grype_match()]})

        results = scanner._parse_grype_output(payload)
        self.assertEqual(len(results), 1)
        vuln = results[0]
        self.assertEqual(vuln["VulnerabilityID"], "CVE-2024-1234")
        self.assertEqual(vuln["Severity"], "HIGH")
        self.assertEqual(vuln["PkgName"], "libssl")
        self.assertEqual(vuln["InstalledVersion"], "1.0.0")
        self.assertEqual(vuln["Status"], "fixed")
        self.assertAlmostEqual(vuln["CVSS"], 7.5)
        self.assertEqual(vuln["sources"], ["grype"])

    def test_parse_grype_output_empty_matches(self):
        """Test _parse_grype_output with no matches."""
        from docksec.docker_scanner import DockerSecurityScanner

        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        payload = json.dumps({"matches": []})
        results = scanner._parse_grype_output(payload)
        self.assertEqual(results, [])

    def test_parse_grype_output_severity_filter(self):
        """Test that _parse_grype_output filters by severity."""
        from docksec.docker_scanner import DockerSecurityScanner

        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        payload = json.dumps({
            "matches": [
                self._make_grype_match(cve_id="CVE-HIGH", severity="High"),
                self._make_grype_match(cve_id="CVE-LOW", severity="Low"),
            ]
        })

        results = scanner._parse_grype_output(payload, severity_filter={"HIGH"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["VulnerabilityID"], "CVE-HIGH")

    def test_parse_grype_output_invalid_json(self):
        """Test that _parse_grype_output handles invalid JSON gracefully."""
        from docksec.docker_scanner import DockerSecurityScanner

        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        results = scanner._parse_grype_output("not valid json")
        self.assertEqual(results, [])

    # ------------------------------------------------------------------
    # Grype: _deduplicate_vulnerabilities
    # ------------------------------------------------------------------

    def test_deduplicate_vulnerabilities_no_overlap(self):
        """Test deduplication when Trivy and Grype find different CVEs."""
        from docksec.docker_scanner import DockerSecurityScanner

        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        trivy = [{"VulnerabilityID": "CVE-001", "Severity": "HIGH"}]
        grype = [{"VulnerabilityID": "CVE-002", "Severity": "CRITICAL", "sources": ["grype"]}]

        merged = scanner._deduplicate_vulnerabilities(trivy, grype)
        ids = {v["VulnerabilityID"] for v in merged}
        self.assertEqual(ids, {"CVE-001", "CVE-002"})

    def test_deduplicate_vulnerabilities_with_overlap(self):
        """Test deduplication merges sources when both scanners find the same CVE."""
        from docksec.docker_scanner import DockerSecurityScanner

        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        trivy = [{"VulnerabilityID": "CVE-001", "Severity": "HIGH"}]
        grype = [{"VulnerabilityID": "CVE-001", "Severity": "HIGH", "sources": ["grype"]}]

        merged = scanner._deduplicate_vulnerabilities(trivy, grype)
        self.assertEqual(len(merged), 1)
        self.assertIn("trivy", merged[0]["sources"])
        self.assertIn("grype", merged[0]["sources"])

    def test_deduplicate_vulnerabilities_empty_inputs(self):
        """Test deduplication with empty lists."""
        from docksec.docker_scanner import DockerSecurityScanner

        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        self.assertEqual(scanner._deduplicate_vulnerabilities([], []), [])
        trivy = [{"VulnerabilityID": "CVE-001", "Severity": "HIGH"}]
        result = scanner._deduplicate_vulnerabilities(trivy, [])
        self.assertEqual(len(result), 1)

    # ------------------------------------------------------------------
    # Grype: scan_image_grype
    # ------------------------------------------------------------------

    @patch('docksec.docker_scanner.subprocess.run')
    def test_scan_image_grype_success(self, mock_run):
        """Test a successful Grype scan."""
        from docksec.docker_scanner import DockerSecurityScanner

        grype_json = json.dumps({
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2024-9999",
                    "severity": "Critical",
                    "description": "Test",
                    "urls": [],
                    "cvss": [],
                    "fix": {"state": "unknown"},
                },
                "artifact": {
                    "name": "openssl",
                    "version": "1.1.1",
                    "type": "deb",
                    "locations": [],
                },
            }]
        })
        mock_run.return_value = Mock(returncode=0, stdout=grype_json, stderr="")

        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        scanner.image_name = "test:latest"

        success, results = scanner.scan_image_grype()
        self.assertTrue(success)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["VulnerabilityID"], "CVE-2024-9999")
        self.assertEqual(results[0]["Severity"], "CRITICAL")

    @patch('docksec.docker_scanner.subprocess.run')
    def test_scan_image_grype_failure(self, mock_run):
        """Test Grype scan failure returns (False, None)."""
        from docksec.docker_scanner import DockerSecurityScanner

        mock_run.return_value = Mock(returncode=1, stdout="", stderr="grype error")

        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        scanner.image_name = "test:latest"

        success, results = scanner.scan_image_grype()
        self.assertFalse(success)
        self.assertIsNone(results)

    @patch('docksec.docker_scanner.subprocess.run')
    def test_run_full_scan_grype_mode(self, mock_run):
        """Test run_full_scan routes correctly for scanner='grype'."""
        from docksec.docker_scanner import DockerSecurityScanner

        grype_json = json.dumps({
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2024-0001",
                    "severity": "High",
                    "description": "",
                    "urls": [],
                    "cvss": [],
                    "fix": {"state": "unknown"},
                },
                "artifact": {
                    "name": "curl", "version": "7.0", "type": "deb", "locations": [],
                },
            }]
        })

        with patch.object(DockerSecurityScanner, 'scan_dockerfile', return_value=(True, None)), \
             patch.object(DockerSecurityScanner, 'scan_image_grype',
                          return_value=(True, [{"VulnerabilityID": "CVE-2024-0001",
                                                "Severity": "HIGH", "sources": ["grype"]}])):
            scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
            scanner.image_name = "test:latest"
            scanner.dockerfile_path = "Dockerfile"
            scanner.use_cache = False
            scanner.scanner = "grype"
            scanner._grype_available = True

            results = scanner.run_full_scan()

        self.assertEqual(len(results['json_data']), 1)
        self.assertEqual(results['json_data'][0]['sources'], ["grype"])

    # ------------------------------------------------------------------
    # Grype title extraction
    # ------------------------------------------------------------------

    def test_parse_grype_output_title_from_description(self):
        """_parse_grype_output derives title from first sentence of description."""
        from docksec.docker_scanner import DockerSecurityScanner

        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        match = self._make_grype_match()
        match["vulnerability"]["description"] = "Buffer overflow in libssl. Additional details here."
        payload = json.dumps({"matches": [match]})

        results = scanner._parse_grype_output(payload)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["Title"], "Buffer overflow in libssl")

    def test_parse_grype_output_title_fallback_to_id(self):
        """_parse_grype_output falls back to CVE ID when description is empty."""
        from docksec.docker_scanner import DockerSecurityScanner

        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        match = self._make_grype_match(cve_id="CVE-2024-5678")
        match["vulnerability"]["description"] = ""
        payload = json.dumps({"matches": [match]})

        results = scanner._parse_grype_output(payload)
        self.assertEqual(results[0]["Title"], "CVE-2024-5678")

    # ------------------------------------------------------------------
    # Report generator: _build_scanner_coverage
    # ------------------------------------------------------------------

    def test_build_scanner_coverage_trivy_only(self):
        """Coverage stats for Trivy-only results."""
        from docksec.report_generator import ReportGenerator

        gen = ReportGenerator.__new__(ReportGenerator)
        vulns = [
            {"VulnerabilityID": "CVE-001"},  # no sources tag → trivy
            {"VulnerabilityID": "CVE-002", "sources": ["trivy"]},
        ]
        cov = gen._build_scanner_coverage(vulns)
        self.assertEqual(cov["total"], 2)
        self.assertEqual(cov["trivy_only"], 2)
        self.assertEqual(cov["grype_only"], 0)
        self.assertEqual(cov["confirmed_by_both"], 0)
        self.assertEqual(cov["scanners_used"], ["trivy"])

    def test_build_scanner_coverage_mixed(self):
        """Coverage stats when both scanners contribute."""
        from docksec.report_generator import ReportGenerator

        gen = ReportGenerator.__new__(ReportGenerator)
        vulns = [
            {"VulnerabilityID": "CVE-001", "sources": ["trivy"]},
            {"VulnerabilityID": "CVE-002", "sources": ["grype"]},
            {"VulnerabilityID": "CVE-003", "sources": ["trivy", "grype"]},
        ]
        cov = gen._build_scanner_coverage(vulns)
        self.assertEqual(cov["total"], 3)
        self.assertEqual(cov["trivy_only"], 1)
        self.assertEqual(cov["grype_only"], 1)
        self.assertEqual(cov["confirmed_by_both"], 1)
        self.assertIn("trivy", cov["scanners_used"])
        self.assertIn("grype", cov["scanners_used"])

    def test_build_scanner_coverage_empty(self):
        """Coverage stats for an empty vulnerability list."""
        from docksec.report_generator import ReportGenerator

        gen = ReportGenerator.__new__(ReportGenerator)
        cov = gen._build_scanner_coverage([])
        self.assertEqual(cov["total"], 0)
        self.assertEqual(cov["confirmed_by_both"], 0)

    def test_get_scanner_badge_html_trivy(self):
        """Badge for a Trivy-only vuln."""
        from docksec.report_generator import ReportGenerator

        gen = ReportGenerator.__new__(ReportGenerator)
        badge = gen._get_scanner_badge_html({"sources": ["trivy"]})
        self.assertIn("scanner-trivy", badge)
        self.assertIn("Trivy", badge)

    def test_get_scanner_badge_html_grype(self):
        """Badge for a Grype-only vuln."""
        from docksec.report_generator import ReportGenerator

        gen = ReportGenerator.__new__(ReportGenerator)
        badge = gen._get_scanner_badge_html({"sources": ["grype"]})
        self.assertIn("scanner-grype", badge)
        self.assertIn("Grype", badge)

    def test_get_scanner_badge_html_both(self):
        """Badge for a vuln confirmed by both scanners."""
        from docksec.report_generator import ReportGenerator

        gen = ReportGenerator.__new__(ReportGenerator)
        badge = gen._get_scanner_badge_html({"sources": ["trivy", "grype"]})
        self.assertIn("scanner-both", badge)
        self.assertIn("Both", badge)

    # ------------------------------------------------------------------
    # DOCKSEC_SCANNER env var resolution
    # ------------------------------------------------------------------

    @patch('docksec.docker_scanner.subprocess.run')
    @patch('docksec.docker_scanner.get_llm')
    def test_init_scanner_param_default(self, mock_llm, mock_subprocess):
        """DockerSecurityScanner defaults to scanner='trivy'."""
        mock_subprocess.return_value = Mock(returncode=0, stdout="", stderr="")
        mock_llm.return_value = Mock()

        dockerfile = self.create_test_dockerfile()
        from docksec.docker_scanner import DockerSecurityScanner

        scanner = DockerSecurityScanner(dockerfile, None, scan_only=True)
        self.assertEqual(scanner.scanner, "trivy")

    @patch('docksec.docker_scanner.subprocess.run')
    @patch('docksec.docker_scanner.get_llm')
    def test_init_scanner_param_grype_unavailable_falls_back(self, mock_llm, mock_subprocess):
        """When scanner='grype' but grype is not installed, falls back to trivy."""
        # _check_tools() calls: trivy --version, hadolint --version (for dockerfile_path)
        # Then grype version check.
        mock_subprocess.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),   # trivy --version
            Mock(returncode=0, stdout="", stderr=""),   # hadolint --version
            FileNotFoundError(),                         # grype version check
        ]
        mock_llm.return_value = Mock()

        dockerfile = self.create_test_dockerfile()
        from docksec.docker_scanner import DockerSecurityScanner

        scanner = DockerSecurityScanner(dockerfile, None, scan_only=True, scanner="grype")
        # Should silently fall back to trivy
        self.assertEqual(scanner.scanner, "trivy")
        self.assertFalse(scanner._grype_available)

    @patch('docksec.docker_scanner.subprocess.run')
    @patch('docksec.docker_scanner.get_llm')
    def test_init_scanner_param_invalid_raises(self, mock_llm, mock_subprocess):
        """DockerSecurityScanner raises ValueError for unknown scanner name."""
        mock_subprocess.return_value = Mock(returncode=0, stdout="", stderr="")
        mock_llm.return_value = Mock()

        dockerfile = self.create_test_dockerfile()
        from docksec.docker_scanner import DockerSecurityScanner

        with self.assertRaises(ValueError):
            DockerSecurityScanner(dockerfile, None, scan_only=True, scanner="unknown_tool")

    @patch('docksec.docker_scanner.DockerSecurityScanner.scan_dockerfile')
    @patch('docksec.docker_scanner.DockerSecurityScanner.scan_image')
    @patch('docksec.docker_scanner.DockerSecurityScanner.scan_image_json')
    @patch('docksec.docker_scanner.DockerSecurityScanner.scan_image_grype')
    def test_run_full_scan_all_mode_deduplication(
        self, mock_grype, mock_json, mock_image, mock_dockerfile
    ):
        """Test run_full_scan deduplicates when scanner='all'."""
        from docksec.docker_scanner import DockerSecurityScanner

        mock_dockerfile.return_value = (True, None)
        mock_image.return_value = (True, "output")
        mock_json.return_value = (True, [
            {"VulnerabilityID": "CVE-SHARED", "Severity": "HIGH"},
            {"VulnerabilityID": "CVE-TRIVY-ONLY", "Severity": "HIGH"},
        ])
        mock_grype.return_value = (True, [
            {"VulnerabilityID": "CVE-SHARED", "Severity": "HIGH", "sources": ["grype"]},
            {"VulnerabilityID": "CVE-GRYPE-ONLY", "Severity": "CRITICAL", "sources": ["grype"]},
        ])

        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        scanner.image_name = "test:latest"
        scanner.dockerfile_path = "Dockerfile"
        scanner.use_cache = False
        scanner.scanner = "all"
        scanner._grype_available = True

        results = scanner.run_full_scan()
        ids = {v["VulnerabilityID"] for v in results['json_data']}
        self.assertEqual(ids, {"CVE-SHARED", "CVE-TRIVY-ONLY", "CVE-GRYPE-ONLY"})
        shared = next(v for v in results['json_data'] if v["VulnerabilityID"] == "CVE-SHARED")
        self.assertIn("trivy", shared["sources"])
        self.assertIn("grype", shared["sources"])


if __name__ == '__main__':
    unittest.main()

