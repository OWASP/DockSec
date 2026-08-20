"""Tests for the repo-level config file (.docksec.yml)."""

import json
import os
import shutil
import subprocess
import sys

import pytest
from pydantic import ValidationError

from docksec.project_config import (
    ConfigFileError,
    DocksecFileConfig,
    config_json_schema,
    find_config_file,
    load_config_file,
)


def write(path, text):
    path.write_text(text, encoding="utf-8")
    return str(path)


# The end-to-end tests below drive the real CLI, which refuses to start when its
# external scanners are missing. Not every environment installs them (the
# coverage workflow, for instance, does not), so those tests skip rather than
# fail there. The config-file logic itself is covered without them by
# TestMergeIntoArgs and the schema/discovery tests.
requires_scan_tools = pytest.mark.skipif(
    not (shutil.which("trivy") and shutil.which("hadolint")),
    reason="requires trivy and hadolint on PATH",
)


class TestSchemaValidation:
    def test_empty_config_leaves_everything_unset(self, tmp_path):
        config, warnings = load_config_file(write(tmp_path / ".docksec.yml", ""))
        assert config.severity is None
        assert config.fail_on is None
        assert config.offline is None
        assert config.rules.disabled == []
        assert warnings == []

    def test_unset_boolean_is_none_not_false(self):
        """An absent key must stay distinguishable from an explicit false, or the
        config file would clobber flags it never mentioned."""
        assert DocksecFileConfig().offline is None
        assert DocksecFileConfig(offline=False).offline is False

    def test_severity_is_normalized(self):
        assert DocksecFileConfig(severity=" high , critical ").severity == "HIGH,CRITICAL"

    def test_fail_on_is_normalized(self):
        assert DocksecFileConfig(fail_on="high").fail_on == "HIGH"

    def test_formats_normalized_to_canonical_order_without_duplicates(self):
        assert DocksecFileConfig(formats=["html", "json", "html"]).formats == ["json", "html"]

    def test_provider_is_lowercased(self):
        assert DocksecFileConfig(provider="ANTHROPIC").provider == "anthropic"

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"severity": "NOPE"},
            {"severity": ""},
            {"fail_on": "SEVERE"},
            {"formats": ["json", "xml"]},
            {"formats": []},
            {"provider": "cohere"},
        ],
    )
    def test_invalid_values_are_rejected(self, kwargs):
        with pytest.raises(ValidationError):
            DocksecFileConfig(**kwargs)

    def test_unknown_key_is_rejected(self):
        """extra=forbid turns a typo into an error instead of a silently
        ignored setting."""
        with pytest.raises(ValidationError):
            DocksecFileConfig(severty="HIGH")

    def test_unknown_nested_rules_key_is_rejected(self):
        with pytest.raises(ValidationError):
            DocksecFileConfig(rules={"disabeld": ["x"]})


class TestLoading:
    def test_loads_a_full_config(self, tmp_path):
        path = write(
            tmp_path / ".docksec.yml",
            "severity: MEDIUM,HIGH\n"
            "fail_on: HIGH\n"
            "formats: [json, html]\n"
            "output_dir: ./reports\n"
            "provider: anthropic\n"
            "model: claude-haiku-4-5\n"
            "offline: true\n"
            "rules:\n"
            "  disabled:\n"
            "    - compose-no-resource-limits\n",
        )
        config, warnings = load_config_file(path)
        assert config.severity == "MEDIUM,HIGH"
        assert config.fail_on == "HIGH"
        assert config.formats == ["json", "html"]
        assert config.output_dir == "./reports"
        assert config.provider == "anthropic"
        assert config.offline is True
        assert config.rules.disabled == ["compose-no-resource-limits"]
        assert warnings == []

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(ConfigFileError, match="not found"):
            load_config_file(str(tmp_path / "absent.yml"))

    def test_malformed_yaml_raises(self, tmp_path):
        path = write(tmp_path / ".docksec.yml", "severity: [unclosed\n")
        with pytest.raises(ConfigFileError, match="Could not parse"):
            load_config_file(path)

    def test_non_mapping_raises(self, tmp_path):
        path = write(tmp_path / ".docksec.yml", "- a\n- b\n")
        with pytest.raises(ConfigFileError, match="must contain a mapping"):
            load_config_file(path)

    def test_error_message_names_the_offending_key(self, tmp_path):
        path = write(tmp_path / ".docksec.yml", "severty: HIGH\nfail_on: NOPE\n")
        with pytest.raises(ConfigFileError) as exc:
            load_config_file(path)
        message = str(exc.value)
        assert "severty: unknown setting" in message
        assert "fail_on" in message
        assert path in message


class TestDiscovery:
    def test_finds_config_in_current_directory(self, tmp_path):
        path = write(tmp_path / ".docksec.yml", "severity: HIGH\n")
        assert find_config_file(str(tmp_path)) == path

    def test_accepts_the_yaml_extension(self, tmp_path):
        path = write(tmp_path / ".docksec.yaml", "severity: HIGH\n")
        assert find_config_file(str(tmp_path)) == path

    def test_walks_up_to_the_repository_root(self, tmp_path):
        """A monorepo subdirectory inherits the policy committed at the root."""
        (tmp_path / ".git").mkdir()
        path = write(tmp_path / ".docksec.yml", "severity: HIGH\n")
        deep = tmp_path / "services" / "api"
        deep.mkdir(parents=True)
        assert find_config_file(str(deep)) == path

    def test_stops_at_the_repository_boundary(self, tmp_path):
        """Discovery must not escape the repo and pick up an unrelated file
        from a parent checkout or the user's home directory."""
        write(tmp_path / ".docksec.yml", "severity: LOW\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        assert find_config_file(str(repo)) is None

    def test_nearest_config_wins(self, tmp_path):
        (tmp_path / ".git").mkdir()
        write(tmp_path / ".docksec.yml", "severity: LOW\n")
        nested = tmp_path / "service"
        nested.mkdir()
        nearest = write(nested / ".docksec.yml", "severity: HIGH\n")
        assert find_config_file(str(nested)) == nearest

    def test_returns_none_when_absent(self, tmp_path):
        (tmp_path / ".git").mkdir()
        assert find_config_file(str(tmp_path)) is None


class TestJsonSchema:
    def test_schema_has_expected_shape(self):
        schema = config_json_schema()
        assert schema["$schema"].startswith("http://json-schema.org/")
        assert schema["additionalProperties"] is False
        for key in ("severity", "fail_on", "formats", "output_dir", "rules"):
            assert key in schema["properties"]

    def test_committed_schema_is_up_to_date(self):
        """The committed schema is what editors fetch for autocomplete; if this
        fails, regenerate with `docksec --print-config-schema`."""
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        committed_path = os.path.join(repo_root, "docs", "docksec-config-schema.json")
        with open(committed_path, "r", encoding="utf-8") as handle:
            committed = json.load(handle)
        assert committed == config_json_schema(), (
            "docs/docksec-config-schema.json is stale; "
            "regenerate with 'docksec --print-config-schema'"
        )


class TestMergeIntoArgs:
    """Direct tests of cli._load_project_config.

    Settings that travel via environment variables (provider, model, severity)
    and the boolean flags are easiest to assert precisely here, rather than
    inferring them from scan output.
    """

    @staticmethod
    def blank_args(**overrides):
        import argparse

        defaults = {
            "no_config": False, "config_file": None, "severity": None, "fail_on": None,
            "output_dir": None, "ignore_file": None, "baseline": None, "offline": None,
            "skip_ai_scoring": None, "no_redact": None, "no_cache": None, "format": None,
        }
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    @pytest.fixture(autouse=True)
    def clean_env(self, monkeypatch):
        for key in ("LLM_PROVIDER", "LLM_MODEL", "DOCKSEC_DEFAULT_SEVERITY"):
            monkeypatch.delenv(key, raising=False)
        # These tests chdir into a tmp_path to exercise discovery; restore the
        # original directory so the rest of the suite is unaffected.
        original = os.getcwd()
        yield
        os.chdir(original)

    @staticmethod
    def load(tmp_path, text, args):
        from docksec import output
        from docksec.cli import _load_project_config

        write(tmp_path / ".docksec.yml", text)
        os.chdir(tmp_path)
        return _load_project_config(args, output)

    def test_booleans_are_applied(self, tmp_path):
        args = self.blank_args()
        self.load(tmp_path, "offline: true\nno_cache: true\nno_redact: true\n", args)
        assert args.offline is True
        assert args.no_cache is True
        assert args.no_redact is True

    def test_explicit_false_in_file_is_applied(self, tmp_path):
        """An explicit false must be distinguishable from an absent key."""
        args = self.blank_args()
        self.load(tmp_path, "offline: false\n", args)
        assert args.offline is False

    def test_cli_flag_is_not_overwritten(self, tmp_path):
        args = self.blank_args(offline=True, fail_on="CRITICAL")
        self.load(tmp_path, "offline: false\nfail_on: LOW\n", args)
        assert args.offline is True
        assert args.fail_on == "CRITICAL"

    def test_provider_and_model_reach_the_environment(self, tmp_path):
        self.load(
            tmp_path,
            "provider: anthropic\nmodel: claude-haiku-4-5\n",
            self.blank_args(),
        )
        assert os.environ["LLM_PROVIDER"] == "anthropic"
        assert os.environ["LLM_MODEL"] == "claude-haiku-4-5"

    def test_exported_provider_beats_the_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "openai")
        self.load(tmp_path, "provider: anthropic\n", self.blank_args())
        assert os.environ["LLM_PROVIDER"] == "openai"

    def test_exported_severity_beats_the_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DOCKSEC_DEFAULT_SEVERITY", "LOW")
        self.load(tmp_path, "severity: CRITICAL\n", self.blank_args())
        assert os.environ["DOCKSEC_DEFAULT_SEVERITY"] == "LOW"

    def test_formats_list_becomes_a_comma_string(self, tmp_path):
        args = self.blank_args()
        self.load(tmp_path, "formats: [html, json]\n", args)
        assert args.format == "json,html"

    def test_no_config_skips_the_file_entirely(self, tmp_path):
        args = self.blank_args(no_config=True)
        _, path = self.load(tmp_path, "offline: true\n", args)
        assert path is None
        assert args.offline is None


class TestCliIntegration:
    """End-to-end precedence checks through the real CLI process.

    These run the CLI as a subprocess because precedence depends on import
    order and environment state that an in-process call would not reproduce.
    """

    @staticmethod
    def run(cwd, *args, env=None):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        full_env = {**os.environ, "PYTHONPATH": repo_root, "NO_COLOR": "1"}
        # Keep the developer's own environment from leaking into precedence tests.
        for key in ("DOCKSEC_DEFAULT_SEVERITY", "LLM_PROVIDER", "LLM_MODEL"):
            full_env.pop(key, None)
        full_env.update(env or {})
        return subprocess.run(
            [sys.executable, "-m", "docksec.cli", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            env=full_env,
            timeout=120,
            check=False,  # these tests assert on non-zero exit codes
        )

    @pytest.fixture
    def project(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")
        return tmp_path

    def test_config_file_sets_severity(self, project):
        write(project / ".docksec.yml", "severity: MEDIUM,HIGH,CRITICAL\n")
        result = self.run(project, "Dockerfile", "--scan-only")
        assert "MEDIUM,HIGH,CRITICAL" in result.stdout
        assert ".docksec.yml" in result.stdout

    def test_cli_flag_overrides_config_file(self, project):
        write(project / ".docksec.yml", "severity: LOW\n")
        result = self.run(project, "Dockerfile", "--scan-only", "--severity", "CRITICAL")
        assert "Severity    CRITICAL" in result.stdout

    def test_env_var_overrides_config_file(self, project):
        write(project / ".docksec.yml", "severity: LOW\n")
        result = self.run(
            project, "Dockerfile", "--scan-only",
            env={"DOCKSEC_DEFAULT_SEVERITY": "CRITICAL"},
        )
        assert "Severity    CRITICAL" in result.stdout

    def test_no_config_ignores_the_file(self, project):
        write(project / ".docksec.yml", "severity: LOW\n")
        result = self.run(project, "Dockerfile", "--scan-only", "--no-config")
        assert "Severity    CRITICAL,HIGH" in result.stdout
        assert "Config" not in result.stdout

    def test_invalid_config_exits_2(self, project):
        write(project / ".docksec.yml", "severty: HIGH\n")
        result = self.run(project, "Dockerfile", "--scan-only")
        assert result.returncode == 2
        assert "unknown setting" in result.stdout + result.stderr

    def test_missing_explicit_config_exits_2(self, project):
        result = self.run(project, "Dockerfile", "--scan-only", "--config", "absent.yml")
        assert result.returncode == 2

    def test_subdirectory_inherits_root_config(self, project):
        write(project / ".docksec.yml", "severity: MEDIUM,HIGH,CRITICAL\n")
        nested = project / "services" / "api"
        nested.mkdir(parents=True)
        result = self.run(nested, "../../Dockerfile", "--scan-only")
        assert "MEDIUM,HIGH,CRITICAL" in result.stdout

    def test_print_config_schema_emits_valid_json(self, project):
        result = self.run(project, "--print-config-schema")
        assert result.returncode == 0
        assert json.loads(result.stdout)["properties"]["severity"]

    @requires_scan_tools
    def test_disabled_rules_are_dropped_everywhere(self, project):
        """A disabled rule must not reach --json, and by extension not the
        score, the reports, or the --fail-on gate."""
        compose = project / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  web:\n"
            "    image: nginx:latest\n"
            "    ports:\n"
            "      - '6379:6379'\n",
            encoding="utf-8",
        )

        before = self.run(project, "--compose", "docker-compose.yml", "--scan-only", "--json")
        ids_before = {
            item["VulnerabilityID"] for item in json.loads(before.stdout)["vulnerabilities"]
        }
        assert "compose-no-resource-limits" in ids_before

        write(
            project / ".docksec.yml",
            "rules:\n  disabled:\n    - compose-no-resource-limits\n",
        )
        after = self.run(project, "--compose", "docker-compose.yml", "--scan-only", "--json")
        ids_after = {
            item["VulnerabilityID"] for item in json.loads(after.stdout)["vulnerabilities"]
        }
        assert "compose-no-resource-limits" not in ids_after
        assert ids_after < ids_before

    @requires_scan_tools
    def test_disabled_rule_matching_is_case_insensitive(self, project):
        compose = project / "docker-compose.yml"
        compose.write_text(
            "services:\n  web:\n    image: nginx:latest\n", encoding="utf-8"
        )
        write(
            project / ".docksec.yml",
            "rules:\n  disabled:\n    - COMPOSE-LATEST-OR-UNTAGGED-IMAGE\n",
        )
        result = self.run(project, "--compose", "docker-compose.yml", "--scan-only", "--json")
        ids = {item["VulnerabilityID"] for item in json.loads(result.stdout)["vulnerabilities"]}
        assert "compose-latest-or-untagged-image" not in ids
