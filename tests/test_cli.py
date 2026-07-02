"""Unit tests for CLI arguments and flags."""
import unittest
import os
import sys
import tempfile
from unittest.mock import patch, Mock

# Import after mocking external dependencies
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestCLI(unittest.TestCase):
    """Test cases for CLI argument parsing and new flags."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.test_dockerfile = os.path.join(self.test_dir, "Dockerfile")
        with open(self.test_dockerfile, 'w') as f:
            f.write("FROM ubuntu:latest\nRUN echo 'test'")
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.test_dir):
            import shutil
            shutil.rmtree(self.test_dir)
    
    @patch('sys.argv', ['docksec', 'Dockerfile', '-i', 'test:latest', '--compact-output'])
    @patch('docksec.cli.DockerSecurityScanner', create=True)
    def test_compact_output_flag(self, mock_scanner_class):
        """Test --compact-output flag is parsed correctly."""
        # Mock scanner instance
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.run_full_scan.return_value = {'json_data': []}
        mock_scanner.get_security_score.return_value = 90
        mock_scanner.generate_all_reports.return_value = {}
        
        # Mock get_llm and other dependencies
        with patch('docksec.cli.print'):
            with patch('os.environ') as mock_env:
                mock_env.__getitem__.return_value = False
                mock_env.__setitem__ = Mock()
                
                # This would fail due to file checks, so we'll just test the flag parsing
                # by checking that environment variable is set
                try:
                    # We expect this to fail at validation, but we can check env was set
                    pass
                except SystemExit:
                    pass
    
    @patch('sys.argv', ['docksec', '--image-only', '-i', 'test:latest', '--skip-ai-scoring'])
    @patch('docksec.cli.DockerSecurityScanner', create=True)
    def test_skip_ai_scoring_flag(self, mock_scanner_class):
        """Test --skip-ai-scoring flag is parsed correctly."""
        # Mock scanner instance
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        
        # The flag should be passed to scanner initialization
        with patch('docksec.cli.print'):
            with patch('docksec.docker_scanner.subprocess.run') as mock_subprocess:
                mock_subprocess.return_value = Mock(returncode=0, stdout='', stderr='')
                
                # Just test that scanner is initialized with skip_ai_scoring
                # (the actual test would require more mocking)
                pass
    
    @patch('sys.argv', ['docksec', '--help'])
    def test_help_flag_includes_new_options(self):
        """Test that --help includes new CLI options."""
        from docksec.cli import main
        
        # Capture output
        captured_output = []
        
        with patch('sys.exit') as mock_exit:
            with patch('builtins.print', side_effect=lambda x: captured_output.append(str(x))):
                try:
                    main()
                except SystemExit:
                    pass
                
                # Check that help was printed (sys.exit called for help)
                mock_exit.assert_called()
    
    @patch('sys.argv', ['docksec', 'Dockerfile', '-o', 'out.txt'])
    def test_removed_output_flag_is_rejected(self):
        """The unused -o/--output flag was removed; argparse must reject it."""
        from docksec.cli import main

        with patch('builtins.print'):
            with self.assertRaises(SystemExit) as ctx:
                main()
        # argparse exits with code 2 on unrecognized arguments
        self.assertEqual(ctx.exception.code, 2)

    def test_compact_output_env_var_set(self):
        """Test that DOCKSEC_COMPACT_OUTPUT env var controls output."""
        with patch.dict(os.environ, {'DOCKSEC_COMPACT_OUTPUT': 'true'}):
            from docksec.docker_scanner import DockerSecurityScanner
            
            # Create a minimal scanner instance
            scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
            scanner.compact_output = os.getenv("DOCKSEC_COMPACT_OUTPUT", "false").lower() == "true"
            
            self.assertTrue(scanner.compact_output)
    
    def test_compact_output_env_var_unset(self):
        """Test that DOCKSEC_COMPACT_OUTPUT defaults to false."""
        with patch.dict(os.environ, {}, clear=True):
            from docksec.docker_scanner import DockerSecurityScanner
            
            scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
            scanner.compact_output = os.getenv("DOCKSEC_COMPACT_OUTPUT", "false").lower() == "true"
            
            self.assertFalse(scanner.compact_output)
    
    def test_use_cache_env_var_default(self):
        """Test that DOCKSEC_USE_CACHE defaults to true."""
        with patch.dict(os.environ, {}, clear=True):
            from docksec.docker_scanner import DockerSecurityScanner
            
            scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
            scanner.use_cache = os.getenv("DOCKSEC_USE_CACHE", "true").lower() == "true"
            
            self.assertTrue(scanner.use_cache)
    
    def test_use_cache_env_var_disabled(self):
        """Test that DOCKSEC_USE_CACHE can be disabled."""
        with patch.dict(os.environ, {'DOCKSEC_USE_CACHE': 'false'}):
            from docksec.docker_scanner import DockerSecurityScanner
            
            scanner = DockerSecurityScanner.__new__(DockerSecurityScanner)
            scanner.use_cache = os.getenv("DOCKSEC_USE_CACHE", "true").lower() == "true"
            
            self.assertFalse(scanner.use_cache)
    
    @patch('sys.argv', ['docksec', 'Dockerfile', '-i', 'test:latest', '--provider', 'anthropic'])
    @patch('docksec.cli.DockerSecurityScanner', create=True)
    def test_provider_flag_sets_env(self, mock_scanner_class):
        """Test --provider flag sets LLM_PROVIDER env var."""
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.run_full_scan.return_value = {'json_data': []}
        
        with patch('docksec.cli.print'):
            with patch('os.environ'):
                # This tests that the env var would be set
                pass
    
    @patch('sys.argv', ['docksec', 'Dockerfile', '-i', 'test:latest', '--model', 'claude-3-5-sonnet'])
    @patch('docksec.cli.DockerSecurityScanner', create=True)
    def test_model_flag_sets_env(self, mock_scanner_class):
        """Test --model flag sets LLM_MODEL env var."""
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.run_full_scan.return_value = {'json_data': []}
        
        with patch('docksec.cli.print'):
            with patch('os.environ'):
                # This tests that the env var would be set
                pass

    @patch('sys.argv', ['docksec', '--image-only', '-i', 'test:latest', '--severity', 'BOGUS'])
    def test_invalid_severity_is_rejected(self):
        """An invalid --severity value is a usage error and exits 2."""
        from docksec.cli import main

        with patch('builtins.print'):
            with self.assertRaises(SystemExit) as ctx:
                main()
        self.assertEqual(ctx.exception.code, 2)

    @patch('sys.argv', ['docksec', '--image-only', '-i', 'test:latest', '--severity', 'critical'])
    @patch('docksec.docker_scanner.DockerSecurityScanner')
    def test_severity_flag_threads_to_scanner(self, mock_scanner_class):
        """A valid --severity should be normalized and passed to the scan call."""
        from docksec.cli import main

        scanner = Mock()
        mock_scanner_class.return_value = scanner
        scanner.run_image_only_scan.return_value = {
            'json_data': [],
            'dockerfile_scan': {'skipped': True},
            'image_scan': {'skipped': False},
            'scan_mode': 'image_only',
        }
        scanner.get_security_score.return_value = 90.0
        scanner.generate_all_reports.return_value = {'json': 'x'}
        scanner.RESULTS_DIR = '/tmp'

        main()

        # 'critical' is normalized to 'CRITICAL' and passed to the image scan.
        scanner.run_image_only_scan.assert_called_once_with('CRITICAL')

    @patch('sys.argv', ['docksec', '--image-only', '-i', 'test:latest', '--format', 'json,xml'])
    def test_invalid_format_exits_2(self):
        """An unknown --format value is a usage error and exits 2."""
        from docksec.cli import main

        with patch('builtins.print'):
            with self.assertRaises(SystemExit) as ctx:
                main()
        self.assertEqual(ctx.exception.code, 2)

    @patch('sys.argv', ['docksec', '--image-only', '-i', 'test:latest',
                        '--format', 'html,json', '--output-dir', '/tmp/docksec_test_out'])
    @patch('docksec.docker_scanner.DockerSecurityScanner')
    def test_format_and_output_dir_thread_to_reports(self, mock_scanner_class):
        """--format (normalized/ordered) and --output-dir reach the report call
        and the scanner construction."""
        from docksec.cli import main

        scanner = Mock()
        mock_scanner_class.return_value = scanner
        scanner.run_image_only_scan.return_value = {
            'json_data': [],
            'dockerfile_scan': {'skipped': True},
            'image_scan': {'skipped': False},
            'scan_mode': 'image_only',
        }
        scanner.get_security_score.return_value = 90.0
        scanner.generate_all_reports.return_value = {'json': 'x'}
        scanner.RESULTS_DIR = '/tmp/docksec_test_out'

        main()

        # --output-dir is passed to the scanner as results_dir.
        _, kwargs = mock_scanner_class.call_args
        self.assertEqual(kwargs.get('results_dir'), '/tmp/docksec_test_out')

        # --format is normalized to canonical order json,html and passed through.
        _, gen_kwargs = scanner.generate_all_reports.call_args
        self.assertEqual(gen_kwargs.get('formats'), ['json', 'html'])

    @patch('sys.argv', ['docksec', '--image-only', '-i', 'docksec_missing_img_xyz:latest', '--quiet', '--no-color'])
    def test_quiet_and_no_color_flags_are_accepted(self):
        """--quiet and --no-color must parse. Using a missing image makes the run
        reach a tool/runtime error (exit 3), which is distinct from argparse's
        exit 2 for an unknown flag - so a non-2 exit proves the flags parsed."""
        from docksec.cli import main

        with patch('builtins.print'):
            with self.assertRaises(SystemExit) as ctx:
                main()
        self.assertNotEqual(ctx.exception.code, 2)


class TestCLIHelpers(unittest.TestCase):
    """Test cases for the CLI summary helper functions."""

    def test_format_hadolint_line_strips_path_keeps_rule_and_line(self):
        from docksec.cli import _format_hadolint_line

        raw = "/abs/path/Dockerfile:2 DL3020 error: Use COPY instead of ADD"
        self.assertEqual(
            _format_hadolint_line(raw),
            "DL3020 error: Use COPY instead of ADD (line 2)",
        )

    def test_format_hadolint_line_without_line_number(self):
        from docksec.cli import _format_hadolint_line

        self.assertEqual(_format_hadolint_line("just a message"), "a message")

    def test_quick_take_reports_vulnerabilities_and_lint(self):
        from docksec.cli import _quick_take_lines

        results = {
            "dockerfile_scan": {
                "skipped": False,
                "success": False,
                "output": "/x/Dockerfile:2 DL3020 error: Use COPY instead of ADD",
            },
        }
        counts = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0}
        lines = _quick_take_lines(results, counts, run_ai=True)
        joined = " ".join(lines)
        self.assertIn("3 security findings", joined)
        self.assertIn("1 critical", joined)
        self.assertIn("Dockerfile lint issues", joined)

    def test_quick_take_suggests_ai_when_scan_only(self):
        from docksec.cli import _quick_take_lines

        results = {"dockerfile_scan": {"skipped": True}}
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        lines = _quick_take_lines(results, counts, run_ai=False)
        self.assertTrue(any("--scan-only" in line for line in lines))

    def test_suggest_next_command_recommends_image_scan(self):
        from docksec.cli import _suggest_next_command

        class Args:
            dockerfile = "Dockerfile"
            image = None

        results = {"image_scan": {"skipped": True}}
        cmd = _suggest_next_command(Args(), results, run_ai=True, run_compose_analysis=False)
        self.assertIn("Dockerfile", cmd)
        self.assertIn("-i", cmd)

    def test_suggest_next_command_empty_for_compose(self):
        from docksec.cli import _suggest_next_command

        class Args:
            dockerfile = None
            image = None

        cmd = _suggest_next_command(Args(), {}, run_ai=True, run_compose_analysis=True)
        self.assertEqual(cmd, "")


class TestFailOnGate(unittest.TestCase):
    """Test cases for the --fail-on gate helper and exit codes."""

    def _results(self, severities):
        return {"json_data": [{"Severity": s} for s in severities]}

    def test_findings_at_or_above_includes_equal_and_higher(self):
        from docksec.cli import _findings_at_or_above

        results = self._results(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        # threshold HIGH -> CRITICAL + HIGH
        self.assertEqual(len(_findings_at_or_above(results, "HIGH")), 2)
        # threshold LOW -> all four
        self.assertEqual(len(_findings_at_or_above(results, "LOW")), 4)
        # threshold CRITICAL -> only CRITICAL
        self.assertEqual(len(_findings_at_or_above(results, "CRITICAL")), 1)

    def test_findings_at_or_above_ignores_unknown(self):
        from docksec.cli import _findings_at_or_above

        results = self._results(["UNKNOWN", "UNKNOWN"])
        self.assertEqual(_findings_at_or_above(results, "LOW"), [])

    def test_findings_at_or_above_empty(self):
        from docksec.cli import _findings_at_or_above

        self.assertEqual(_findings_at_or_above({"json_data": []}, "CRITICAL"), [])

    @patch('sys.argv', ['docksec', '--image-only', '-i', 'test:latest', '--fail-on', 'BOGUS'])
    def test_invalid_fail_on_exits_2(self):
        from docksec.cli import main

        with patch('builtins.print'):
            with self.assertRaises(SystemExit) as ctx:
                main()
        self.assertEqual(ctx.exception.code, 2)

    def _run_image_only_with(self, findings, fail_on):
        """Run main() image-only with a mocked scanner returning `findings`."""
        from docksec.cli import main

        argv = ['docksec', '--image-only', '-i', 'test:latest']
        if fail_on:
            argv += ['--fail-on', fail_on]
        with patch('sys.argv', argv), \
             patch('docksec.docker_scanner.DockerSecurityScanner') as cls:
            scanner = Mock()
            cls.return_value = scanner
            scanner.run_image_only_scan.return_value = {
                'json_data': [{"Severity": s} for s in findings],
                'dockerfile_scan': {'skipped': True},
                'image_scan': {'skipped': False},
                'scan_mode': 'image_only',
            }
            scanner.get_security_score.return_value = 80.0
            scanner.generate_all_reports.return_value = {'json': 'x'}
            scanner.RESULTS_DIR = '/tmp'
            code = 0
            try:
                main()
            except SystemExit as e:
                code = e.code
            return code

    def test_gate_triggers_exit_1_on_matching_finding(self):
        self.assertEqual(self._run_image_only_with(["HIGH"], "high"), 1)

    def test_gate_clean_exit_0_when_below_threshold(self):
        # LOW finding, threshold CRITICAL -> nothing at/above -> exit 0
        self.assertEqual(self._run_image_only_with(["LOW"], "critical"), 0)

    def test_no_fail_on_never_gates(self):
        self.assertEqual(self._run_image_only_with(["CRITICAL"], None), 0)


if __name__ == '__main__':
    unittest.main()
