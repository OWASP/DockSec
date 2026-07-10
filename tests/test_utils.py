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
        import logging
        from docksec.utils import get_custom_logger

        # Clear CLI mode and level override to ensure default behavior
        old_cli_mode = os.environ.pop("DOCKSEC_CLI_MODE", None)
        old_level = os.environ.pop("DOCKSEC_LOG_LEVEL", None)
        try:
            logger = get_custom_logger('TestLogger')
            self.assertEqual(logger.name, 'TestLogger')
            self.assertEqual(logger.level, logging.INFO)
        finally:
            # Restore environment
            if old_cli_mode:
                os.environ["DOCKSEC_CLI_MODE"] = old_cli_mode
            if old_level:
                os.environ["DOCKSEC_LOG_LEVEL"] = old_level

    def test_get_custom_logger_cli_mode_is_quiet(self):
        """In CLI mode the raw logger stays at ERROR so it doesn't duplicate
        the tool's own user-facing messages."""
        import logging
        from docksec.utils import get_custom_logger

        old_cli_mode = os.environ.get("DOCKSEC_CLI_MODE")
        old_level = os.environ.pop("DOCKSEC_LOG_LEVEL", None)
        os.environ["DOCKSEC_CLI_MODE"] = "true"
        try:
            logger = get_custom_logger('TestLoggerCli')
            self.assertEqual(logger.level, logging.ERROR)
        finally:
            if old_cli_mode is None:
                os.environ.pop("DOCKSEC_CLI_MODE", None)
            else:
                os.environ["DOCKSEC_CLI_MODE"] = old_cli_mode
            if old_level:
                os.environ["DOCKSEC_LOG_LEVEL"] = old_level

    def test_get_custom_logger_level_override(self):
        """DOCKSEC_LOG_LEVEL overrides the context default, even in CLI mode."""
        import logging
        from docksec.utils import get_custom_logger

        old_cli_mode = os.environ.get("DOCKSEC_CLI_MODE")
        old_level = os.environ.get("DOCKSEC_LOG_LEVEL")
        os.environ["DOCKSEC_CLI_MODE"] = "true"
        os.environ["DOCKSEC_LOG_LEVEL"] = "debug"
        try:
            logger = get_custom_logger('TestLoggerOverride')
            self.assertEqual(logger.level, logging.DEBUG)
        finally:
            for key, val in (("DOCKSEC_CLI_MODE", old_cli_mode),
                             ("DOCKSEC_LOG_LEVEL", old_level)):
                if val is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = val

    def test_get_custom_logger_streams_to_stderr_without_duplicates(self):
        """Logs go to stderr (keeping stdout clean) and repeated calls for the
        same logger name must not stack duplicate handlers."""
        import sys
        import logging
        from docksec.utils import get_custom_logger

        get_custom_logger('TestLoggerHandlers')  # first call installs one handler
        logger = get_custom_logger('TestLoggerHandlers')  # second call, same name
        stream_handlers = [h for h in logger.handlers
                           if isinstance(h, logging.StreamHandler)]
        self.assertEqual(len(stream_handlers), 1)
        self.assertIs(stream_handlers[0].stream, sys.stderr)
        self.assertFalse(logger.propagate)

    def test_get_custom_logger_duplicates_to_log_file(self):
        """DOCKSEC_LOG_FILE (set by --log-file) mirrors log lines into the file
        while the stderr handler keeps emitting them."""
        import sys
        import logging
        from docksec.utils import get_custom_logger

        old_env = {key: os.environ.get(key) for key in
                   ("DOCKSEC_LOG_FILE", "DOCKSEC_LOG_LEVEL", "DOCKSEC_CLI_MODE")}
        logger = None
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                log_path = os.path.join(tmp_dir, 'docksec.log')
                os.environ["DOCKSEC_LOG_FILE"] = log_path
                os.environ["DOCKSEC_LOG_LEVEL"] = "INFO"
                os.environ.pop("DOCKSEC_CLI_MODE", None)

                logger = get_custom_logger('TestLoggerLogFile')
                logger.info("this line lands in the log file")

                file_handlers = [h for h in logger.handlers
                                 if isinstance(h, logging.FileHandler)]
                self.assertEqual(len(file_handlers), 1)
                with open(log_path, encoding='utf-8') as handle:
                    self.assertIn("this line lands in the log file", handle.read())

                # The stderr handler survives alongside the file handler.
                stream_handlers = [h for h in logger.handlers
                                   if isinstance(h, logging.StreamHandler)
                                   and not isinstance(h, logging.FileHandler)]
                self.assertEqual(len(stream_handlers), 1)
                self.assertIs(stream_handlers[0].stream, sys.stderr)

                # Release the file handle so the temp dir can be removed.
                for handler in list(logger.handlers):
                    handler.close()
                    logger.removeHandler(handler)
                logger = None
        finally:
            if logger is not None:
                for handler in list(logger.handlers):
                    handler.close()
                    logger.removeHandler(handler)
            for key, val in old_env.items():
                if val is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = val

    def test_get_custom_logger_without_log_file_adds_no_file_handler(self):
        """Without DOCKSEC_LOG_FILE the logger stays stderr-only, as before."""
        import logging
        from docksec.utils import get_custom_logger

        old_log_file = os.environ.pop("DOCKSEC_LOG_FILE", None)
        try:
            logger = get_custom_logger('TestLoggerNoLogFile')
            file_handlers = [h for h in logger.handlers
                             if isinstance(h, logging.FileHandler)]
            self.assertEqual(file_handlers, [])
        finally:
            if old_log_file is not None:
                os.environ["DOCKSEC_LOG_FILE"] = old_log_file

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
    
    def test_print_section_with_items(self):
        """Test print_section with list of items."""
        from docksec.utils import print_section
        
        items = ["Issue 1", "Issue 2", "Issue 3", "Issue 4", "Issue 5", "Issue 6"]
        
        # Capture output
        with patch('docksec.utils.console') as mock_console:
            print_section("Test Section", items, "red", max_items=3)
            
            # Should have been called multiple times
            self.assertGreater(mock_console.print.call_count, 0)
    
    def test_print_section_empty_items(self):
        """Test print_section with empty items list."""
        from docksec.utils import print_section
        
        with patch('docksec.utils.console') as mock_console:
            print_section("Empty Section", [], "blue")
            
            # Should indicate no items found
            mock_console.print.assert_called()
    
    def test_print_section_max_items_limit(self):
        """Test print_section respects max_items limit."""
        from docksec.utils import print_section
        
        items = [f"Item {i}" for i in range(20)]
        
        with patch('docksec.utils.console') as mock_console:
            print_section("Many Items", items, "green", max_items=5)
            
            # Should mention remaining items
            calls_str = str(mock_console.print.call_args_list)
            self.assertIn("and", calls_str.lower())
    
    def test_print_section_truncates_long_items(self):
        """Test print_section truncates long items."""
        from docksec.utils import print_section
        
        long_items = ["A" * 100, "B" * 100]
        
        with patch('docksec.utils.console') as mock_console:
            print_section("Long Items", long_items, "yellow")
            
            # Should be called
            mock_console.print.assert_called()
    
    def test_analyze_security_compact_mode(self):
        """Test analyze_security in compact mode."""
        from docksec.utils import analyze_security, AnalyzesResponse
        
        response = AnalyzesResponse(
            vulnerabilities=["Vuln 1", "Vuln 2"],
            best_practices=["Practice 1", "Practice 2", "Practice 3"],
            SecurityRisks=["Risk 1"],
            ExposedCredentials=[],
            remediation=["Fix 1", "Fix 2"]
        )
        
        with patch('docksec.utils.console'):
            with patch('docksec.utils.print_section') as mock_print_section:
                analyze_security(response, compact=True)
                
                # Should call print_section multiple times
                self.assertGreater(mock_print_section.call_count, 0)
                
                # Verify it's called with max_items=3 for compact mode
                calls = mock_print_section.call_args_list
                for call in calls:
                    if 'max_items' in call.kwargs:
                        self.assertEqual(call.kwargs['max_items'], 3)
    
    def test_analyze_security_full_mode(self):
        """Test analyze_security in full mode."""
        from docksec.utils import analyze_security, AnalyzesResponse
        
        response = AnalyzesResponse(
            vulnerabilities=["Vuln 1", "Vuln 2"],
            best_practices=["Practice 1"],
            SecurityRisks=["Risk 1"],
            ExposedCredentials=[],
            remediation=["Fix 1"]
        )
        
        with patch('docksec.utils.console'):
            with patch('docksec.utils.print_section') as mock_print_section:
                analyze_security(response, compact=False)
                
                # Should call print_section
                self.assertGreater(mock_print_section.call_count, 0)
                
                # In full mode, max_items should be 10
                calls = mock_print_section.call_args_list
                for call in calls:
                    if 'max_items' in call.kwargs:
                        self.assertEqual(call.kwargs['max_items'], 10)
    
    def test_analyze_security_with_all_fields(self):
        """Test analyze_security handles all response fields."""
        from docksec.utils import analyze_security, AnalyzesResponse
        
        response = AnalyzesResponse(
            vulnerabilities=["CVE-2023-0001"],
            best_practices=["Use secrets management"],
            SecurityRisks=["Privilege escalation"],
            ExposedCredentials=["AWS_KEY in ENV"],
            remediation=["Rotate credentials"]
        )
        
        with patch('docksec.utils.console'):
            with patch('docksec.utils.print_section') as mock_print_section:
                analyze_security(response, compact=True)
                
                # Should call print_section 5 times (one for each category)
                self.assertEqual(mock_print_section.call_count, 5)
    
    def test_analyze_security_prints_summary_header(self):
        """Test analyze_security prints summary header."""
        from docksec.utils import analyze_security, AnalyzesResponse
        
        response = AnalyzesResponse(
            vulnerabilities=[],
            best_practices=[],
            SecurityRisks=[],
            ExposedCredentials=[],
            remediation=[]
        )
        
        with patch('docksec.utils.console') as mock_console:
            analyze_security(response)
            
            # Should print header with AI results
            mock_console.print.assert_called()


if __name__ == '__main__':
    unittest.main()

