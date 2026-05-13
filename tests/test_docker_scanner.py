"""Unit tests for DockerSecurityScanner class."""
import unittest
import os
import tempfile
from unittest.mock import Mock, patch, MagicMock
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
        
        # Valid severities
        valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        for sev in valid_severities:
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
        
        dockerfile = self.create_test_dockerfile()
        
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


if __name__ == '__main__':
    unittest.main()

