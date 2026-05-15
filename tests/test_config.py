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


if __name__ == '__main__':
    unittest.main()

