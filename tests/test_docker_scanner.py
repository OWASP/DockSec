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
    @patch('docksec.docker_scanner.ui')
    def test_print_compact_vulnerability_summary_no_vulns(self, mock_ui, mock_defaultdict):
        """Test compact summary printing with no vulnerabilities."""
        from docksec.docker_scanner import DockerSecurityScanner

        # Mock defaultdict to return a plain dict
        mock_defaultdict.side_effect = lambda: {}

        scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
        scanner._print_compact_vulnerability_summary([])

        # Should report the no-vulnerabilities success message via the output layer
        mock_ui.success.assert_called()

    @patch('docksec.docker_scanner.ui')
    def test_print_compact_vulnerability_summary_with_vulns(self, mock_ui):
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

        # Should render the summary via the output layer
        mock_ui.detail.assert_called()
        combined_output = ' '.join(str(call) for call in mock_ui.detail.call_args_list)
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
        # Default run delegates with formats=None (all formats).
        mock_gen.generate_all_reports.assert_called_once_with(results, formats=None)

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


if __name__ == '__main__':
    unittest.main()

