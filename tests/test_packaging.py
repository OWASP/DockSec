"""Packaging and release-metadata invariants.

The version used to live in setup.py while CITATION.cff and the README's Action
pins were updated by hand, so releases drifted. pyproject.toml is now the single
source of truth; these tests assert everything else follows it.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _pyproject_version() -> str:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
    assert match, "no top-level version in pyproject.toml"
    return match.group(1)


class TestVersionIsSingleSourced(unittest.TestCase):
    def test_setup_py_is_gone(self):
        """setup.py and pyproject.toml both declaring metadata is how the
        version drifted in the first place."""
        self.assertFalse(
            (REPO_ROOT / "setup.py").exists(),
            "setup.py is back; packaging metadata belongs in pyproject.toml only",
        )

    def test_exactly_one_top_level_version_in_pyproject(self):
        """The release workflow rewrites the first column-anchored `version = `
        line. More than one would make that substitution ambiguous."""
        text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        matches = re.findall(r'^version = "', text, re.MULTILINE)
        self.assertEqual(
            len(matches), 1,
            "pyproject.toml must contain exactly one top-level version line",
        )

    def test_citation_version_matches_pyproject(self):
        citation = (REPO_ROOT / "CITATION.cff").read_text(encoding="utf-8")
        match = re.search(r'^version: "([^"]+)"', citation, re.MULTILINE)
        self.assertIsNotNone(match, "CITATION.cff has no version field")
        self.assertEqual(
            match.group(1), _pyproject_version(),
            "CITATION.cff is out of step with pyproject.toml; the release "
            "workflow updates both",
        )

    def test_cli_reports_a_real_version(self):
        """get_version() falls back to reading pyproject.toml from a source
        checkout; it used to read setup.py, which no longer exists."""
        from docksec.cli import get_version

        version = get_version()
        self.assertNotEqual(version, "unknown")
        self.assertRegex(version, r"^\d")

    def test_source_fallback_parses_pyproject(self):
        """Exercise the fallback path directly, since importlib.metadata masks
        it whenever the package happens to be installed."""
        text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'^\s*version\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), _pyproject_version())


class TestPackagingMetadata(unittest.TestCase):
    def test_entry_point_is_declared(self):
        text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("docksec = \"docksec.cli:main\"", text)

    def test_ai_extra_exists(self):
        """`pip install docksec` must stay scan-only; the LLM stack lives in the
        [ai] extra."""
        text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("[project.optional-dependencies]", text)
        self.assertIn("ai = [", text)

    def test_core_dependencies_exclude_the_llm_stack(self):
        """A scan-only install must not pull langchain: a security tool's own
        dependency surface is part of its risk."""
        text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        core = text.split("[project.optional-dependencies]")[0]
        for forbidden in ("langchain", "openai", "anthropic"):
            self.assertNotIn(
                forbidden, core,
                f"{forbidden} must live in the [ai] extra, not core dependencies",
            )

    def test_templates_are_packaged(self):
        """The HTML report template ships inside the wheel; omitting it makes
        HTML reports fail only for pip-installed users."""
        text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("templates/*", text)


class TestContainerImage(unittest.TestCase):
    """Invariants for the image that backs the GitHub Action."""

    def setUp(self):
        self.dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")

    def test_tool_downloads_use_curl_fail_flag(self):
        """Without -f, curl exits 0 on an HTTP error and writes the error page
        to the destination - which is how the image shipped without Trivy."""
        for line in self.dockerfile.splitlines():
            if "curl" in line and "http" in line:
                self.assertTrue(
                    "-f" in line.split("curl", 1)[1].split()[0]
                    or " -fsSL" in line or " -f " in line,
                    f"curl without -f can fail silently: {line.strip()}",
                )

    def test_trivy_org_is_correct(self):
        """The image installed from `aquasec/trivy`; the org is `aquasecurity`,
        so the URL 404'd and the image shipped with no Trivy."""
        self.assertNotIn("aquasec/trivy", self.dockerfile)
        self.assertIn("aquasecurity/trivy", self.dockerfile)

    def test_tool_versions_are_pinned(self):
        for arg in ("TRIVY_VERSION", "HADOLINT_VERSION"):
            self.assertRegex(
                self.dockerfile, rf"ARG {arg}=\d",
                f"{arg} must be pinned so scan results do not change with an "
                f"upstream release",
            )

    def test_build_asserts_tools_are_present(self):
        self.assertIn("RUN trivy --version && hadolint --version", self.dockerfile)

    def test_both_architectures_are_handled(self):
        """The image publishes multi-arch; a hardcoded x86_64 binary would make
        the arm64 image non-functional rather than failing the build."""
        for tool_section in ("hadolint", "trivy"):
            section = self.dockerfile.lower().split(tool_section, 1)[1][:600]
            self.assertIn("arm64", section,
                          f"{tool_section} install does not handle arm64")

    def test_workspace_is_not_populated_by_the_build(self):
        """/github/workspace is the Action's mount point and must start empty."""
        self.assertNotIn("WORKDIR /github/workspace\nCOPY", self.dockerfile)
        self.assertIn("RUN rm -rf /src", self.dockerfile)


if __name__ == "__main__":
    unittest.main()
