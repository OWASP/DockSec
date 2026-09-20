"""Tests for `docksec --fix`.

A tool that edits someone's Dockerfile has to be conservative in a way that is
verifiable, so most of what is asserted here is what --fix refuses to do.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from docksec import autofix
from docksec.remediation import build_plan


def _plan(rule_ids, dockerfile="Dockerfile"):
    findings = [
        {
            "VulnerabilityID": rule_id, "PkgName": "dockerfile",
            "Severity": "HIGH", "Line": 1, "Target": dockerfile,
            "Title": rule_id,
        }
        for rule_id in rule_ids
    ]
    return build_plan(findings, dockerfile)


def _write(tmp, content):
    path = os.path.join(tmp, "Dockerfile")
    Path(path).write_text(content)
    return path


class TestAddUser(unittest.TestCase):
    def test_user_is_inserted_before_cmd(self):
        """A USER line after CMD has no effect, so position matters."""
        lines = ["FROM alpine\n", "CMD [\"app\"]\n"]
        result, description = autofix._add_user(lines)
        joined = "".join(result)
        self.assertIn("USER appuser", joined)
        self.assertLess(joined.index("USER appuser"), joined.index("CMD"))
        self.assertIsNotNone(description)

    def test_explicit_root_is_replaced_not_appended(self):
        """Adding a second USER line below `USER root` would work, but leaves a
        confusing file."""
        lines = ["FROM alpine\n", "USER root\n", "CMD [\"app\"]\n"]
        result, _ = autofix._add_user(lines)
        joined = "".join(result)
        self.assertNotIn("USER root", joined)
        self.assertEqual(joined.count("USER "), 1)

    def test_existing_non_root_user_is_left_alone(self):
        lines = ["FROM alpine\n", "USER node\n", "CMD [\"app\"]\n"]
        result, description = autofix._add_user(lines)
        self.assertEqual(result, lines)
        self.assertIsNone(description)

    def test_file_with_no_cmd_still_gets_a_user(self):
        lines = ["FROM alpine\n", "RUN echo hi\n"]
        result, description = autofix._add_user(lines)
        self.assertIn("USER appuser", "".join(result))
        self.assertIsNotNone(description)


class TestAddHealthcheck(unittest.TestCase):
    def test_healthcheck_is_inserted_before_cmd(self):
        lines = ["FROM alpine\n", "CMD [\"app\"]\n"]
        result, _ = autofix._add_healthcheck(lines)
        joined = "".join(result)
        self.assertIn("HEALTHCHECK", joined)
        self.assertLess(joined.index("HEALTHCHECK"), joined.index("CMD ["))

    def test_existing_healthcheck_is_left_alone(self):
        lines = ["FROM alpine\n", "HEALTHCHECK CMD true\n", "CMD [\"app\"]\n"]
        result, description = autofix._add_healthcheck(lines)
        self.assertEqual(result, lines)
        self.assertIsNone(description)

    def test_inserted_healthcheck_tells_the_user_to_replace_it(self):
        """DockSec cannot know what this service considers healthy, so the
        placeholder must say so rather than look authoritative."""
        result, _ = autofix._add_healthcheck(["FROM alpine\n", "CMD [\"app\"]\n"])
        self.assertIn("replace this", "".join(result).lower())


class TestAptNoRecommends(unittest.TestCase):
    def test_flag_is_added(self):
        lines = ["RUN apt-get update && apt-get install -y curl\n"]
        result, description = autofix._apt_no_recommends(lines)
        self.assertIn("--no-install-recommends", result[0])
        self.assertIsNotNone(description)

    def test_existing_flag_is_not_duplicated(self):
        lines = ["RUN apt-get install --no-install-recommends -y curl\n"]
        result, description = autofix._apt_no_recommends(lines)
        self.assertEqual(result, lines)
        self.assertIsNone(description)
        self.assertEqual(result[0].count("--no-install-recommends"), 1)


class TestAddToCopy(unittest.TestCase):
    """ADD has behaviour COPY does not replicate, so only local paths convert."""

    def test_local_path_is_converted(self):
        result, description = autofix._add_to_copy(["ADD ./app /opt/app\n"])
        self.assertIn("COPY ./app", result[0])
        self.assertIsNotNone(description)

    def test_url_source_is_left_alone(self):
        """COPY cannot fetch a URL; converting would break the build."""
        lines = ["ADD https://example.com/f.tar.gz /tmp/\n"]
        result, description = autofix._add_to_copy(lines)
        self.assertEqual(result, lines)
        self.assertIsNone(description)

    def test_archive_source_is_left_alone(self):
        """ADD auto-extracts a local tarball; COPY does not."""
        lines = ["ADD release.tar.gz /opt/\n"]
        result, description = autofix._add_to_copy(lines)
        self.assertEqual(result, lines)
        self.assertIsNone(description)


class TestPlanFiltering(unittest.TestCase):
    def test_base_image_pin_is_never_applied(self):
        """Choosing a version is a judgement call, and a wrong tag breaks the
        build rather than leaving a finding in place."""
        applicable, needs_review = autofix.plan_edits(_plan(["DS001"]))
        self.assertEqual(applicable, [])
        self.assertEqual(len(needs_review), 1)
        self.assertIn("judgement", needs_review[0]["reason"])

    def test_secret_in_env_is_never_applied(self):
        applicable, _ = autofix.plan_edits(_plan(["DS031"]))
        self.assertEqual(applicable, [])

    def test_compose_changes_are_never_applied(self):
        """Editing a compose file changes runtime topology."""
        findings = [{
            "VulnerabilityID": "compose-privileged", "Severity": "CRITICAL",
            "Target": "c.yml:db:4", "PkgName": "docker-compose", "Title": "t",
        }]
        applicable, needs_review = autofix.plan_edits(build_plan(findings))
        self.assertEqual(applicable, [])
        self.assertTrue(any("topology" in e["reason"] for e in needs_review))

    def test_duplicate_edit_kinds_collapse(self):
        """DS002 and DL3002 both mean 'add a non-root USER' - one change."""
        applicable, _ = autofix.plan_edits(_plan(["DS002", "DL3002"]))
        self.assertEqual(len(applicable), 1)


class TestApplyToDockerfile(unittest.TestCase):
    CONTENT = (
        "FROM ubuntu:22.04\n"
        "RUN apt-get update && apt-get install -y curl\n"
        "ADD ./app /opt/app\n"
        "USER root\n"
        "CMD [\"/opt/app/start\"]\n"
    )

    def test_dry_run_does_not_touch_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, self.CONTENT)
            result = autofix.apply_to_dockerfile(
                path, _plan(["DS002", "DS029", "DL3020"]), dry_run=True
            )
            self.assertTrue(result.applied)
            self.assertEqual(Path(path).read_text(), self.CONTENT)
            self.assertIsNone(result.backup_path)
            self.assertTrue(result.diff())

    def test_apply_writes_the_file_and_keeps_a_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, self.CONTENT)
            result = autofix.apply_to_dockerfile(path, _plan(["DS002", "DS029"]))

            self.assertTrue(result.changed)
            self.assertNotEqual(Path(path).read_text(), self.CONTENT)
            self.assertIsNotNone(result.backup_path)
            self.assertEqual(Path(result.backup_path).read_text(), self.CONTENT)

    def test_applying_twice_is_a_no_op(self):
        """Re-running must not stack duplicate USER or HEALTHCHECK lines."""
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, self.CONTENT)
            autofix.apply_to_dockerfile(path, _plan(["DS002", "DS026"]))
            after_first = Path(path).read_text()

            second = autofix.apply_to_dockerfile(path, _plan(["DS002", "DS026"]))
            self.assertEqual(Path(path).read_text(), after_first)
            self.assertEqual(second.applied, [])

    def test_unapplicable_edits_are_reported_not_attempted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, self.CONTENT)
            result = autofix.apply_to_dockerfile(path, _plan(["DS001", "DS031"]))
            self.assertEqual(result.applied, [])
            self.assertTrue(result.skipped)
            self.assertEqual(Path(path).read_text(), self.CONTENT)

    def test_diff_is_a_readable_unified_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, self.CONTENT)
            result = autofix.apply_to_dockerfile(path, _plan(["DS002"]), dry_run=True)
            diff = result.diff("Dockerfile")
            self.assertIn("--- a/Dockerfile", diff)
            self.assertIn("+++ b/Dockerfile", diff)
            self.assertTrue(any(line.startswith("+") for line in diff.splitlines()))


class TestWorkingTreeGuard(unittest.TestCase):
    """git is the real undo, so --fix makes sure git can help."""

    def _repo(self, tmp):
        subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
        subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=tmp, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=tmp, check=True)
        path = _write(tmp, "FROM alpine\nCMD [\"x\"]\n")
        subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=tmp, check=True)
        return path

    def test_clean_tree_reports_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._repo(tmp)
            self.assertFalse(autofix.working_tree_is_dirty(path))

    def test_modified_file_reports_dirty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._repo(tmp)
            Path(path).write_text("FROM alpine\n# edited\nCMD [\"x\"]\n")
            self.assertTrue(autofix.working_tree_is_dirty(path))

    def test_outside_a_repository_returns_unknown(self):
        """None means 'the question does not apply', which the caller must not
        confuse with 'clean'."""
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "FROM alpine\n")
            self.assertIsNone(autofix.working_tree_is_dirty(path))


class TestRescan(unittest.TestCase):
    def test_rescan_counts_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "FROM ubuntu:latest\nUSER root\nCMD [\"x\"]\n")
            count = autofix.rescan(path)
            if count is None:
                self.skipTest("scanners not available in this environment")
            self.assertGreater(count, 0)

    def test_rescan_failure_returns_none_rather_than_raising(self):
        self.assertIsNone(autofix.rescan("/nonexistent/path/Dockerfile"))


if __name__ == "__main__":
    unittest.main()
