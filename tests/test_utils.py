"""Unit tests for utility functions."""
import unittest
import os
import tempfile
from unittest.mock import patch, Mock

# Import after mocking external dependencies
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestUtils(unittest.TestCase):
    """Test cases for utility functions."""
    
    def test_get_custom_logger(self):
        """Test logger creation."""
        from docksec.utils import get_custom_logger
        
        logger = get_custom_logger('TestLogger')
        self.assertEqual(logger.name, 'TestLogger')
        self.assertEqual(logger.level, 20)  # INFO level
    
    def test_load_docker_file(self):
        """Test Dockerfile loading."""
        from docksec.utils import load_docker_file
        
        # Create temporary Dockerfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.dockerfile', delete=False) as f:
            f.write("FROM ubuntu:latest\nRUN echo 'test'")
            temp_path = f.name
        
        try:
            content = load_docker_file(temp_path)
            self.assertIn("FROM ubuntu:latest", content)
            self.assertIn("RUN echo 'test'", content)
        finally:
            os.unlink(temp_path)
    
    def test_load_docker_file_not_found(self):
        """Test Dockerfile loading when file doesn't exist."""
        from docksec.utils import load_docker_file
        
        result = load_docker_file("/nonexistent/path/Dockerfile")
        self.assertIsNone(result)
    
    @patch('docksec.utils.ChatOpenAI')
    @patch('docksec.config_manager.get_config')
    def test_get_llm(self, mock_get_config, mock_chatopenai):
        """Test LLM initialization with a mocked config and mocked ChatOpenAI."""
        from docksec.utils import get_llm

        mock_config = Mock()
        mock_config.llm_provider = "openai"
        mock_config.llm_model = "gpt-4o"
        mock_config.llm_temperature = 0.0
        mock_config.timeout_llm = 60
        mock_config.max_retries_llm = 2
        mock_config.get_api_key_for_provider.return_value = "test-api-key"
        mock_get_config.return_value = mock_config

        mock_llm_instance = Mock()
        mock_chatopenai.return_value = mock_llm_instance

        llm = get_llm()

        mock_chatopenai.assert_called_once()
        self.assertIsNotNone(llm)

    @patch('docksec.config_manager.get_config')
    def test_get_llm_no_api_key(self, mock_get_config):
        """Test LLM initialization raises EnvironmentError when API key is missing."""
        from docksec.utils import get_llm

        mock_config = Mock()
        mock_config.llm_provider = "openai"
        mock_config.llm_model = "gpt-4o"
        mock_config.llm_temperature = 0.0
        mock_config.timeout_llm = 60
        mock_config.max_retries_llm = 2
        mock_config.get_api_key_for_provider.side_effect = EnvironmentError("API key not found")
        mock_get_config.return_value = mock_config

        with self.assertRaises(EnvironmentError):
            get_llm()


if __name__ == '__main__':
    unittest.main()

