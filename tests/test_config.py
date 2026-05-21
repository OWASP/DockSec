"""Unit tests for configuration."""
import unittest
import os
from unittest.mock import patch


class TestConfig(unittest.TestCase):
    """Test cases for configuration."""
    
    @patch.dict(os.environ, {}, clear=True)
    def test_get_openai_api_key_missing(self):
        """Test API key retrieval when not set."""
        from docksec.config import get_openai_api_key
        
        with self.assertRaises(EnvironmentError):
            get_openai_api_key()
    
    @patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key-123'})
    def test_get_openai_api_key_present(self):
        """Test API key retrieval when set."""
        from docksec.config import get_openai_api_key
        
        api_key = get_openai_api_key()
        self.assertEqual(api_key, 'test-key-123')
    
    def test_prompt_templates_exist(self):
        """Test that prompt templates are defined."""
        from docksec.config import docker_agent_template, docker_score_template
        
        self.assertIsNotNone(docker_agent_template)
        self.assertIsNotNone(docker_score_template)
        self.assertIn("Dockerfile", docker_agent_template)
        self.assertIn("score", docker_score_template.lower())
    
    def test_truncate_dockerfile_by_lines(self):
        """Test Dockerfile truncation by line count."""
        from docksec.config import truncate_dockerfile
        
        dockerfile_content = "\n".join([f"RUN command {i}" for i in range(100)])
        truncated = truncate_dockerfile(dockerfile_content, max_lines=50)
        
        lines = truncated.split('\n')
        # Should have at most 50 original lines plus truncation marker
        self.assertLessEqual(len([line for line in lines if line.strip()]), 51)
        self.assertIn("truncated", truncated.lower())
    
    def test_truncate_dockerfile_by_chars(self):
        """Test Dockerfile truncation by character count."""
        from docksec.config import truncate_dockerfile
        
        dockerfile_content = "FROM ubuntu:latest\n" + ("RUN echo 'very long command' " * 200)
        truncated = truncate_dockerfile(dockerfile_content, max_lines=1000, max_chars=1000)
        
        self.assertLessEqual(len(truncated), 1100)  # Allow small margin for marker
        if len(dockerfile_content) > 1000:
            self.assertIn("truncated", truncated.lower())
    
    def test_truncate_dockerfile_short_content(self):
        """Test Dockerfile truncation with content shorter than limits."""
        from docksec.config import truncate_dockerfile
        
        dockerfile_content = "FROM ubuntu:latest\nRUN echo 'test'"
        truncated = truncate_dockerfile(dockerfile_content, max_lines=50, max_chars=2000)
        
        self.assertEqual(truncated, dockerfile_content)
        self.assertNotIn("truncated", truncated.lower())
    
    def test_summarize_vulnerabilities_empty_list(self):
        """Test vulnerability summarization with empty list."""
        from docksec.config import summarize_vulnerabilities
        
        summary = summarize_vulnerabilities([])
        self.assertIn("No vulnerabilities", summary)
    
    def test_summarize_vulnerabilities_single_severity(self):
        """Test vulnerability summarization with single severity type."""
        from docksec.config import summarize_vulnerabilities
        
        vulnerabilities = [
            {
                'VulnerabilityID': 'CVE-2023-1111',
                'Severity': 'CRITICAL',
                'PkgName': 'openssl',
                'Title': 'Buffer overflow'
            },
            {
                'VulnerabilityID': 'CVE-2023-2222',
                'Severity': 'CRITICAL',
                'PkgName': 'curl',
                'Title': 'Code execution'
            }
        ]
        
        summary = summarize_vulnerabilities(vulnerabilities)
        
        self.assertIn("Total: 2", summary)
        self.assertIn("CRITICAL: 2", summary)
        self.assertIn("CVE-2023-1111", summary)
    
    def test_summarize_vulnerabilities_mixed_severity(self):
        """Test vulnerability summarization with mixed severity levels."""
        from docksec.config import summarize_vulnerabilities
        
        vulnerabilities = [
            {'VulnerabilityID': 'CVE-1', 'Severity': 'CRITICAL', 'PkgName': 'pkg1'},
            {'VulnerabilityID': 'CVE-2', 'Severity': 'HIGH', 'PkgName': 'pkg2'},
            {'VulnerabilityID': 'CVE-3', 'Severity': 'HIGH', 'PkgName': 'pkg3'},
            {'VulnerabilityID': 'CVE-4', 'Severity': 'MEDIUM', 'PkgName': 'pkg4'},
        ]
        
        summary = summarize_vulnerabilities(vulnerabilities)
        
        self.assertIn("Total: 4", summary)
        self.assertIn("CRITICAL: 1", summary)
        self.assertIn("HIGH: 2", summary)
        self.assertIn("MEDIUM: 1", summary)
    
    def test_summarize_vulnerabilities_exceeds_max_count(self):
        """Test vulnerability summarization with more items than max_count."""
        from docksec.config import summarize_vulnerabilities
        
        # Create 30 vulnerabilities
        vulnerabilities = [
            {'VulnerabilityID': f'CVE-{i}', 'Severity': 'CRITICAL', 'PkgName': f'pkg{i}'}
            for i in range(30)
        ]
        
        summary = summarize_vulnerabilities(vulnerabilities, max_count=10)
        
        self.assertIn("Total: 30", summary)
        # Should show only 5 in detail (max per severity)
        self.assertIn("CVE-0", summary)
        self.assertIn("CVE-4", summary)
        self.assertNotIn("CVE-5", summary)
    
    def test_summarize_vulnerabilities_no_title(self):
        """Test vulnerability summarization with missing optional fields."""
        from docksec.config import summarize_vulnerabilities
        
        vulnerabilities = [
            {'VulnerabilityID': 'CVE-2023-9999', 'Severity': 'HIGH', 'PkgName': 'pkg'},
            # Missing Title field
        ]
        
        summary = summarize_vulnerabilities(vulnerabilities)
        
        self.assertIn("Total: 1", summary)
        self.assertIn("CVE-2023-9999", summary)
        self.assertIn("HIGH", summary)
    
    def test_optimized_prompts_are_shorter(self):
        """Test that optimized prompts are more concise than originals."""
        from docksec.config import docker_agent_template, docker_score_template
        
        # Optimized templates should be reasonably sized (not excessively long)
        self.assertLess(len(docker_agent_template), 500)
        self.assertLess(len(docker_score_template), 400)
        
        # They should still contain essential keywords
        self.assertIn("json", docker_agent_template.lower())
        self.assertIn("score", docker_score_template.lower())

    def test_get_html_template(self):
        """Test HTML template loading."""
        from docksec.config import get_html_template
        
        template = get_html_template()
        self.assertIsNotNone(template)
        self.assertIn("<html", template.lower())
        self.assertIn("Docker Security Report", template)


if __name__ == '__main__':
    unittest.main()

