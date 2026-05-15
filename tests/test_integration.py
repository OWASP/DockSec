"""Integration tests for DockSec."""
import unittest
import os
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, Mock

# Import after mocking external dependencies
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestIntegration(unittest.TestCase):
    """Integration tests that test multiple components together."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.test_dockerfile = os.path.join(self.test_dir, "Dockerfile")
        with open(self.test_dockerfile, 'w') as f:
            f.write("FROM ubuntu:latest\nRUN echo 'test'")
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    @patch('docksec.docker_scanner.subprocess.run')
    @patch('docksec.docker_scanner.get_llm')
    @patch('docksec.config.get_openai_api_key')
    def test_full_scan_workflow(self, mock_api_key, mock_llm, mock_subprocess):
        """Test complete scanning workflow."""
        # Mock API key
        mock_api_key.return_value = "test-api-key"
        
        # Mock LLM responses
        mock_llm_instance = Mock()
        mock_llm.return_value = mock_llm_instance
        
        # Mock all subprocess calls
        def subprocess_side_effect(*args, **kwargs):
            if 'docker' in args[0] and 'inspect' in args[0]:
                return Mock(returncode=0, stdout='{"Id": "test"}', stderr='')
            elif '--version' in args[0]:
                return Mock(returncode=0, stdout='version 1.0', stderr='')
            else:
                return Mock(returncode=0, stdout='', stderr='')
        
        mock_subprocess.side_effect = subprocess_side_effect
        
        from docksec.docker_scanner import DockerSecurityScanner
        
        scanner = DockerSecurityScanner(self.test_dockerfile, "test:latest")
        
        # Verify initialization
        self.assertIsNotNone(scanner)
        # Compare resolved paths — on macOS tempfile returns /var/... but
        # _validate_file_path resolves it to /private/var/... via symlink.
        self.assertEqual(scanner.dockerfile_path, str(Path(self.test_dockerfile).resolve()))
        self.assertEqual(scanner.image_name, "test:latest")
    
    @patch('docksec.docker_scanner.subprocess.run')
    @patch('docksec.docker_scanner.get_llm')
    @patch('docksec.config.get_openai_api_key')
    def test_image_only_scan(self, mock_api_key, mock_llm, mock_subprocess):
        """Test image-only scanning without Dockerfile."""
        # Mock API key
        mock_api_key.return_value = "test-api-key"
        
        # Mock LLM
        mock_llm_instance = Mock()
        mock_llm.return_value = mock_llm_instance
        
        # Mock subprocess calls
        def subprocess_side_effect(*args, **kwargs):
            if 'docker' in args[0] and 'inspect' in args[0]:
                return Mock(returncode=0, stdout='{"Id": "test"}', stderr='')
            elif '--version' in args[0]:
                return Mock(returncode=0, stdout='version 1.0', stderr='')
            else:
                return Mock(returncode=0, stdout='[]', stderr='')
        
        mock_subprocess.side_effect = subprocess_side_effect
        
        from docksec.docker_scanner import DockerSecurityScanner
        
        # Should work without Dockerfile
        scanner = DockerSecurityScanner(None, "test:latest")
        self.assertIsNone(scanner.dockerfile_path)
        self.assertEqual(scanner.image_name, "test:latest")


if __name__ == '__main__':
    unittest.main()

