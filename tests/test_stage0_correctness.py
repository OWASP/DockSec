"""Regression tests for the Stage 0 correctness fixes.

Each class here covers a defect that shipped in a release, so the tests are
written against the observable behavior a user or a CI job would see rather than
against implementation details.
"""

import os
import tempfile
import unittest
from pathlib import Path



class TestComposeScanFailuresAreFatal(unittest.TestCase):
    """A compose run whose services could not be scanned must not exit 0.

    Scanning the bundled insecure example without the images pulled locally
    produced a full severity table, a confident score, and exit 0 - so CI passed
    on a scan that never inspected a single image.
    """

    def test_failed_service_names_deduplicates(self):
        """A service failing both its Dockerfile and image scan is recorded
        twice; it is still one service."""
        from docksec.cli import _failed_service_names

        entries = [
            {"service": "web", "reason": "Dockerfile scan failed"},
            {"service": "web", "reason": "Image scan failed"},
            {"service": "db", "reason": "Image scan failed"},
        ]
        self.assertEqual(_failed_service_names(entries), ["web", "db"])

    def test_no_failures_reports_empty(self):
        from docksec.cli import _failed_service_names

        self.assertEqual(_failed_service_names([]), [])
        self.assertEqual(_failed_service_names(None), [])

    def test_orchestrator_records_failures_for_missing_images(self):
        """The orchestrator must populate failed_services; the CLI's exit code
        depends on it."""
        from docksec.compose_scanner import ComposeOrchestrator

        orchestrator = ComposeOrchestrator(
            "examples/compose/docker-compose-insecure.yml",
            scan_only=True,
            skip_ai_scoring=True,
        )
        results = orchestrator.run_full_scan("CRITICAL,HIGH")

        # Images are not pulled in the test environment, so both services fail.
        self.assertTrue(
            results.get("failed_services"),
            "failed services must be recorded so the CLI can exit non-zero",
        )
        self.assertEqual(results.get("total_services"), 2)


class TestConfigFileFormats(unittest.TestCase):
    """`formats: [markdown]` in .docksec.yml was a hard exit-2 error.

    The CLI accepted `--format markdown`, and the README, the annotated example
    config, and the field's own description all documented markdown as valid -
    but the config validator's allow-list omitted it.
    """

    def test_markdown_is_accepted_in_the_config_file(self):
        from docksec.project_config import load_config_file

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, ".docksec.yml")
            with open(path, "w") as handle:
                handle.write("formats:\n  - markdown\n")
            config, _ = load_config_file(path)

        self.assertEqual(config.formats, ["markdown"])

    def test_config_formats_match_the_cli_choices(self):
        """Guards against the two lists drifting apart again."""
        import re

        from docksec.project_config import VALID_FORMATS

        source = Path("docksec/cli.py").read_text()
        match = re.search(r"valid_formats\s*=\s*\[([^\]]+)\]", source)
        self.assertIsNotNone(match, "could not locate valid_formats in cli.py")
        cli_formats = re.findall(r'"([a-z]+)"', match.group(1))

        self.assertEqual(
            sorted(cli_formats), sorted(VALID_FORMATS),
            "the CLI's --format choices and the config file's allow-list must "
            "stay in step",
        )

    def test_invalid_format_is_still_rejected(self):
        from docksec.project_config import ConfigFileError, load_config_file

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, ".docksec.yml")
            with open(path, "w") as handle:
                handle.write("formats:\n  - xml\n")
            with self.assertRaises(ConfigFileError):
                load_config_file(path)


class TestFilePathValidation(unittest.TestCase):
    """`docksec ../service/Dockerfile` was rejected as path traversal.

    The check substring-matched '..' before resolving, which blocked the
    standard monorepo invocation where each service has its own directory. It
    also protected nothing: the path comes from the user's own command line and
    is read with the user's own permissions, so there is no privilege boundary
    for a traversal check to defend. Validation now resolves the path and
    confirms it is a file.
    """

    def setUp(self):
        from docksec.docker_scanner import DockerSecurityScanner
        self.validate = DockerSecurityScanner._validate_file_path
        self._original_cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self._original_cwd)

    # Relative paths resolve against the real process working directory, so
    # these tests chdir rather than patching Path.cwd.
    def test_relative_parent_path_is_accepted(self):
        """The monorepo case: each service in its own directory."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "service-a").mkdir()
            (root / "service-b").mkdir()
            target = root / "service-b" / "Dockerfile"
            target.write_text("FROM alpine\n")

            os.chdir(root / "service-a")
            self.assertEqual(self.validate("../service-b/Dockerfile"), target)

    def test_simple_relative_paths_still_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            target = root / "Dockerfile"
            target.write_text("FROM alpine\n")

            os.chdir(root)
            self.assertEqual(self.validate("Dockerfile"), target)
            self.assertEqual(self.validate("./Dockerfile"), target)

    def test_absolute_path_outside_the_cwd_is_accepted(self):
        """Scanning a Dockerfile elsewhere on disk is ordinary usage, and is
        what CI systems and the test suite itself do."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp).resolve() / "Dockerfile"
            target.write_text("FROM alpine\n")
            self.assertEqual(self.validate(str(target)), target)

    def test_directory_is_rejected_with_a_useful_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError) as ctx:
                self.validate(tmp)
            self.assertIn("directory", str(ctx.exception))

    def test_empty_path_is_rejected(self):
        with self.assertRaises(ValueError):
            self.validate("")


if __name__ == "__main__":
    unittest.main()
