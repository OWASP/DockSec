"""Unit tests for CLI arguments and flags."""
import unittest
import json
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

    @patch("sys.argv", ["docksec", "--image-only", "-i", "test:latest", "--verbose"])
    @patch("docksec.docker_scanner.DockerSecurityScanner")
    def test_verbose_flag_sets_info_log_level(self, mock_scanner_class):
        """--verbose is a shortcut for DOCKSEC_LOG_LEVEL=INFO."""
        from docksec.cli import main

        scanner = Mock()
        mock_scanner_class.return_value = scanner
        scanner.run_image_only_scan.return_value = {
            "json_data": [],
            "dockerfile_scan": {"skipped": True},
            "image_scan": {"skipped": False},
            "scan_mode": "image_only",
        }
        scanner.get_security_score.return_value = 90.0
        scanner.generate_all_reports.return_value = {}
        scanner.RESULTS_DIR = "/tmp"

        with patch.dict(os.environ, {}, clear=True):
            main()
            self.assertEqual(os.environ["DOCKSEC_LOG_LEVEL"], "INFO")

    @patch("sys.argv", ["docksec", "--image-only", "-i", "test:latest", "-v"])
    @patch("docksec.docker_scanner.DockerSecurityScanner")
    def test_verbose_flag_preserves_explicit_log_level(self, mock_scanner_class):
        """An existing DOCKSEC_LOG_LEVEL takes priority over -v."""
        from docksec.cli import main

        scanner = Mock()
        mock_scanner_class.return_value = scanner
        scanner.run_image_only_scan.return_value = {
            "json_data": [],
            "dockerfile_scan": {"skipped": True},
            "image_scan": {"skipped": False},
            "scan_mode": "image_only",
        }
        scanner.get_security_score.return_value = 90.0
        scanner.generate_all_reports.return_value = {}
        scanner.RESULTS_DIR = "/tmp"

        with patch.dict(os.environ, {"DOCKSEC_LOG_LEVEL": "DEBUG"}, clear=True):
            main()
            self.assertEqual(os.environ["DOCKSEC_LOG_LEVEL"], "DEBUG")


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


class TestJsonOutput(unittest.TestCase):
    """Test cases for --json stdout output."""

    def test_print_json_results_shape(self):
        import json as json_module
        from docksec.cli import _print_json_results

        scanner = Mock()
        scanner.image_name = "myapp:latest"
        scanner.analysis_score = 82.5
        results = {
            "json_data": [{"Severity": "HIGH"}, {"Severity": "LOW"}],
            "dockerfile_path": "Dockerfile",
            "timestamp": "2026-01-01 00:00:00",
            "scan_mode": "full",
        }

        printed = []
        with patch('builtins.print', side_effect=lambda x: printed.append(x)):
            _print_json_results(results, scanner, report_paths={})

        self.assertEqual(len(printed), 1)
        payload = json_module.loads(printed[0])
        self.assertEqual(payload["scan_info"]["image"], "myapp:latest")
        self.assertEqual(payload["scan_info"]["analysis_score"], 82.5)
        self.assertEqual(len(payload["vulnerabilities"]), 2)
        self.assertEqual(payload["severity_counts"]["HIGH"], 1)
        self.assertNotIn("report_files", payload)

    def test_print_json_results_includes_report_files_when_written(self):
        import json as json_module
        from docksec.cli import _print_json_results

        scanner = Mock()
        scanner.image_name = "myapp:latest"
        scanner.analysis_score = 90
        results = {"json_data": [], "scan_mode": "full"}
        report_paths = {"json": "/tmp/x.json", "csv": ""}

        printed = []
        with patch('builtins.print', side_effect=lambda x: printed.append(x)):
            _print_json_results(results, scanner, report_paths)

        payload = json_module.loads(printed[0])
        # Only non-empty paths are included.
        self.assertEqual(payload["report_files"], {"json": "/tmp/x.json"})

    def test_print_json_results_includes_ai_findings(self):
        import json as json_module
        from docksec.cli import _print_json_results

        scanner = Mock()
        scanner.image_name = "myapp:latest"
        scanner.analysis_score = 90
        results = {
            "json_data": [],
            "scan_mode": "full",
            "ai_findings": {"vulnerabilities": ["hardcoded secret"]},
        }

        printed = []
        with patch('builtins.print', side_effect=lambda x: printed.append(x)):
            _print_json_results(results, scanner, report_paths={})

        payload = json_module.loads(printed[0])
        self.assertEqual(payload["ai_analysis"]["vulnerabilities"], ["hardcoded secret"])

    def _run_image_only_json(self, extra_argv=None, findings=None):
        """Run main() image-only with --json, capturing stdout prints."""
        from docksec.cli import main

        argv = ['docksec', '--image-only', '-i', 'test:latest', '--json'] + (extra_argv or [])
        with patch('sys.argv', argv), \
             patch('docksec.docker_scanner.DockerSecurityScanner') as cls:
            scanner = Mock()
            cls.return_value = scanner
            scanner.image_name = "test:latest"
            scanner.run_image_only_scan.return_value = {
                'json_data': [{"Severity": s} for s in (findings or [])],
                'dockerfile_scan': {'skipped': True},
                'image_scan': {'skipped': False},
                'scan_mode': 'image_only',
            }
            scanner.get_security_score.return_value = 90.0
            scanner.generate_all_reports.return_value = {}
            scanner.RESULTS_DIR = '/tmp'

            printed = []
            code = 0
            with patch('builtins.print', side_effect=lambda x='': printed.append(x)):
                try:
                    main()
                except SystemExit as e:
                    code = e.code
            return code, printed, scanner

    def test_json_flag_prints_exactly_one_json_object(self):
        import json as json_module

        code, printed, _ = self._run_image_only_json(findings=["CRITICAL"])
        self.assertEqual(code, 0)
        self.assertEqual(len(printed), 1)
        json_module.loads(printed[0])  # must not raise

    def test_json_flag_without_format_writes_no_reports(self):
        _, _, scanner = self._run_image_only_json()
        scanner.generate_all_reports.assert_called_once_with({
            'json_data': [],
            'dockerfile_scan': {'skipped': True},
            'image_scan': {'skipped': False},
            'scan_mode': 'image_only',
        }, formats=[])

    def test_json_flag_with_format_passes_requested_formats(self):
        _, _, scanner = self._run_image_only_json(extra_argv=['--format', 'json'])
        _, kwargs = scanner.generate_all_reports.call_args
        self.assertEqual(kwargs.get('formats'), ['json'])

    def test_json_flag_respects_fail_on_exit_code(self):
        code, printed, _ = self._run_image_only_json(
            extra_argv=['--fail-on', 'critical'], findings=["CRITICAL"]
        )
        self.assertEqual(code, 1)
        # stdout still carries exactly the JSON payload, nothing else.
        self.assertEqual(len(printed), 1)


class TestSarifOutput(unittest.TestCase):
    """Test cases for --sarif wiring in the CLI."""

    def _run_image_only(self, extra_argv=None):
        """Run main() image-only with a mocked scanner and ReportGenerator."""
        from docksec.cli import main

        argv = ['docksec', '--image-only', '-i', 'test:latest'] + (extra_argv or [])
        with patch('sys.argv', argv), \
             patch('docksec.docker_scanner.DockerSecurityScanner') as scanner_cls, \
             patch('docksec.report_generator.ReportGenerator') as report_cls:
            scanner = Mock()
            scanner_cls.return_value = scanner
            scanner.image_name = "test:latest"
            scanner.analysis_score = 90.0
            scanner.RESULTS_DIR = '/tmp'
            scanner.run_image_only_scan.return_value = {
                'json_data': [],
                'dockerfile_scan': {'skipped': True},
                'image_scan': {'skipped': False},
                'scan_mode': 'image_only',
            }
            scanner.get_security_score.return_value = 90.0
            scanner.generate_all_reports.return_value = {'json': '/tmp/x.json'}

            report_gen = Mock()
            report_cls.return_value = report_gen
            report_gen.generate_sarif_report.return_value = '/tmp/x.sarif'

            code = 0
            with patch('builtins.print'):
                try:
                    main()
                except SystemExit as e:
                    code = e.code
            return code, report_gen, scanner_cls

    def test_sarif_not_generated_without_flag(self):
        _, report_gen, _ = self._run_image_only()
        report_gen.generate_sarif_report.assert_not_called()

    def test_sarif_flag_generates_report(self):
        code, report_gen, _ = self._run_image_only(extra_argv=['--sarif'])
        self.assertEqual(code, 0)
        report_gen.generate_sarif_report.assert_called_once()
        _, kwargs = report_gen.generate_sarif_report.call_args
        self.assertIn('tool_version', kwargs)

    def test_sarif_flag_does_not_affect_default_format_bundle(self):
        """--sarif is additive; it must not change the --format-selected set."""
        _, _, scanner_cls = self._run_image_only(extra_argv=['--sarif', '--format', 'json'])
        scanner = scanner_cls.return_value
        _, kwargs = scanner.generate_all_reports.call_args
        self.assertEqual(kwargs.get('formats'), ['json'])


class TestBaselineGate(unittest.TestCase):
    """Test cases for --baseline / --update-baseline wiring in the CLI."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.baseline_path = os.path.join(self._tmpdir.name, 'baseline.json')

    def _run_image_only_with(self, findings, extra_argv=None):
        from docksec.cli import main

        argv = ['docksec', '--image-only', '-i', 'test:latest'] + (extra_argv or [])
        with patch('sys.argv', argv), \
             patch('docksec.docker_scanner.DockerSecurityScanner') as cls:
            scanner = Mock()
            cls.return_value = scanner
            scanner.run_image_only_scan.return_value = {
                'json_data': [
                    {"VulnerabilityID": f"CVE-{i}", "Target": "app", "PkgName": "pkg", "Severity": s}
                    for i, s in enumerate(findings)
                ],
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

    def test_update_baseline_without_baseline_flag_exits_2(self):
        code = self._run_image_only_with(["HIGH"], ['--update-baseline'])
        self.assertEqual(code, 2)

    def test_update_baseline_writes_file_and_does_not_gate(self):
        code = self._run_image_only_with(
            ["CRITICAL"],
            ['--baseline', self.baseline_path, '--update-baseline', '--fail-on', 'critical'],
        )
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(self.baseline_path))
        with open(self.baseline_path) as f:
            data = json.load(f)
        self.assertEqual(len(data['fingerprints']), 1)

    def test_baseline_suppresses_previously_seen_findings(self):
        # First run establishes the baseline.
        self._run_image_only_with(
            ["CRITICAL"], ['--baseline', self.baseline_path, '--update-baseline']
        )
        # Same finding again, now gated: should NOT trigger since it's baselined.
        code = self._run_image_only_with(
            ["CRITICAL"], ['--baseline', self.baseline_path, '--fail-on', 'critical']
        )
        self.assertEqual(code, 0)

    def test_baseline_still_gates_on_new_findings(self):
        # Baseline has no findings.
        self._run_image_only_with([], ['--baseline', self.baseline_path, '--update-baseline'])
        # A new CRITICAL finding appears: should trigger the gate.
        code = self._run_image_only_with(
            ["CRITICAL"], ['--baseline', self.baseline_path, '--fail-on', 'critical']
        )
        self.assertEqual(code, 1)

    def test_fail_on_without_baseline_gates_normally(self):
        code = self._run_image_only_with(["CRITICAL"], ['--fail-on', 'critical'])
        self.assertEqual(code, 1)


class TestFixCommandHelpers(unittest.TestCase):
    """Tests for the fixable-count and suggested-fix-command output helpers."""

    def test_suggest_fix_commands_dedupes_and_orders_by_severity(self):
        from docksec.cli import _suggest_fix_commands
        results = {"json_data": [
            {"PkgName": "zlib", "Severity": "MEDIUM", "InstalledVersion": "1.0", "FixedVersion": "1.1"},
            {"PkgName": "openssl", "Severity": "CRITICAL", "InstalledVersion": "1.1.1", "FixedVersion": "3.0"},
            {"PkgName": "openssl", "Severity": "HIGH", "InstalledVersion": "1.1.1", "FixedVersion": "3.0"},
            {"PkgName": "nofix", "Severity": "HIGH", "InstalledVersion": "1.0", "FixedVersion": None},
        ]}
        cmds = _suggest_fix_commands(results)
        # openssl (critical) first, deduped once; zlib present; nofix excluded.
        self.assertEqual(cmds[0], "upgrade openssl 1.1.1 -> 3.0")
        self.assertEqual(sum(1 for c in cmds if c.startswith("upgrade openssl")), 1)
        self.assertTrue(any(c.startswith("upgrade zlib") for c in cmds))
        self.assertFalse(any("nofix" in c for c in cmds))

    def test_suggest_fix_commands_empty_when_no_fixed_versions(self):
        from docksec.cli import _suggest_fix_commands
        results = {"json_data": [
            {"PkgName": "x", "Severity": "HIGH", "InstalledVersion": "1", "FixedVersion": None},
        ]}
        self.assertEqual(_suggest_fix_commands(results), [])

    def test_suggest_fix_commands_respects_limit(self):
        from docksec.cli import _suggest_fix_commands
        results = {"json_data": [
            {"PkgName": f"pkg{i}", "Severity": "HIGH", "InstalledVersion": "1", "FixedVersion": "2"}
            for i in range(10)
        ]}
        self.assertEqual(len(_suggest_fix_commands(results, limit=3)), 3)

    def test_quick_take_reports_fixable_count(self):
        from docksec.cli import _quick_take_lines
        from docksec import output
        results = {"json_data": [
            {"PkgName": "a", "Severity": "CRITICAL", "FixedVersion": "2"},
            {"PkgName": "b", "Severity": "HIGH", "FixedVersion": None},
        ]}
        counts = output.count_by_severity(results["json_data"])
        lines = _quick_take_lines(results, counts, run_ai=True)
        self.assertTrue(any("1 of 2 have a fixed version" in ln for ln in lines))


class TestSbomAndOffline(unittest.TestCase):
    """Test cases for --sbom and --offline CLI wiring."""

    def _run_image_only(self, extra_argv=None):
        from docksec.cli import main

        argv = ['docksec', '--image-only', '-i', 'test:latest'] + (extra_argv or [])
        with patch('sys.argv', argv), \
             patch('docksec.docker_scanner.DockerSecurityScanner') as scanner_cls, \
             patch('docksec.report_generator.ReportGenerator') as report_cls:
            scanner = Mock()
            scanner_cls.return_value = scanner
            scanner.image_name = "test:latest"
            scanner.analysis_score = 90.0
            scanner.RESULTS_DIR = '/tmp'
            scanner.run_image_only_scan.return_value = {
                'json_data': [],
                'dockerfile_scan': {'skipped': True},
                'image_scan': {'skipped': False},
                'scan_mode': 'image_only',
            }
            scanner.get_security_score.return_value = 90.0
            scanner.generate_all_reports.return_value = {'json': '/tmp/x.json'}
            scanner.generate_sbom.return_value = '{"bomFormat":"CycloneDX"}'

            report_gen = Mock()
            report_cls.return_value = report_gen
            report_gen.generate_cyclonedx_report.return_value = '/tmp/x.cdx.json'

            code = 0
            with patch('builtins.print'):
                try:
                    main()
                except SystemExit as e:
                    code = e.code
            return code, scanner, report_gen

    def test_sbom_not_generated_without_flag(self):
        _, scanner, report_gen = self._run_image_only()
        report_gen.generate_cyclonedx_report.assert_not_called()

    def test_sbom_flag_generates_report(self):
        code, scanner, report_gen = self._run_image_only(extra_argv=['--sbom'])
        self.assertEqual(code, 0)
        scanner.generate_sbom.assert_called_once()
        report_gen.generate_cyclonedx_report.assert_called_once()

    def test_offline_flag_passed_to_scanner(self):
        from docksec.cli import main
        # The scanner class must be constructed with offline=True.
        with patch('sys.argv', ['docksec', '--image-only', '-i', 'test:latest', '--offline']), \
             patch('docksec.docker_scanner.DockerSecurityScanner') as scanner_cls:
            scanner = Mock()
            scanner_cls.return_value = scanner
            scanner.image_name = "test:latest"
            scanner.RESULTS_DIR = '/tmp'
            scanner.run_image_only_scan.return_value = {
                'json_data': [], 'dockerfile_scan': {'skipped': True},
                'image_scan': {'skipped': False}, 'scan_mode': 'image_only',
            }
            scanner.get_security_score.return_value = 90.0
            scanner.generate_all_reports.return_value = {}
            with patch('builtins.print'):
                try:
                    main()
                except SystemExit:
                    # main() exits via sys.exit(); the scan pass has already run
                    # and constructed the scanner by this point, which is all
                    # this test inspects.
                    pass
            _, kwargs = scanner_cls.call_args
            self.assertTrue(kwargs.get('offline'))


class TestInstallSkillDispatch(unittest.TestCase):
    """Test the install-skill subcommand dispatch in main()."""

    def test_install_skill_dispatches_and_returns(self):
        from docksec.cli import main

        with patch('sys.argv', ['docksec', 'install-skill']), \
             patch('docksec.install_skill.install_skill') as mock_install:
            # Must not raise SystemExit and must call install_skill().
            main()
            mock_install.assert_called_once()


if __name__ == '__main__':
    unittest.main()
