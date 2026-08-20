"""Repo-level configuration file (.docksec.yml).

DockSec has three configuration layers, split by lifetime and ownership:

- ``config.py``          - static paths, prompt templates, and helpers.
- ``config_manager.py``  - the process/environment layer (env vars, API keys,
                           timeouts), exposed via ``get_config()``.
- ``project_config.py``  - this module: the committed, repo-level policy file a
                           team checks into source control.

The file exists so a team's scan policy (severity threshold, CI gate, disabled
rules, report formats) lives in the repository next to the Dockerfiles it
governs, instead of being re-typed as flags by every developer and every CI job.

Resolution order, highest priority first:

    CLI flag  >  environment variable  >  .docksec.yml  >  built-in default

Discovery walks up from the working directory to the repository root (a
directory containing ``.git``) so that a monorepo subdirectory inherits the
policy committed at the top level. ``--config`` names a file explicitly and
``--no-config`` disables discovery entirely.

File format::

    # yaml-language-server: $schema=https://owasp.org/DockSec/docksec-config-schema.json
    severity: CRITICAL,HIGH
    fail_on: HIGH
    formats: [json, html]
    output_dir: ./security-reports
    provider: anthropic
    model: claude-haiku-4-5
    offline: false
    ignore_file: .docksec-ignore.yml
    baseline: .docksec-baseline.json
    rules:
      disabled:
        - compose-missing-healthcheck
        - compose-no-resource-limits

Unlike the ignore file - whose malformed entries are skipped with a warning
because suppression is advisory - a malformed config file is a hard error that
exits 2. Silently ignoring a broken policy file would mean scanning with the
wrong severity while the team believes their committed policy is in force.
"""

import os
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from docksec.enums import LLMProvider, Severity

CONFIG_FILENAMES = (".docksec.yml", ".docksec.yaml")

SCHEMA_URL = "https://owasp.org/DockSec/docksec-config-schema.json"

VALID_FORMATS = ("json", "csv", "pdf", "html")


class RulesConfig(BaseModel):
    """Per-rule controls.

    ``disabled`` lists rule IDs (compose rule IDs such as
    ``compose-missing-healthcheck``, or vulnerability IDs) that should be
    dropped from the results before scoring, reporting, and the --fail-on gate.
    This is the blunt, permanent instrument; ``.docksec-ignore.yml`` remains the
    right tool for auditable, per-finding waivers with a reason and an expiry.
    """

    model_config = ConfigDict(extra="forbid")

    disabled: List[str] = Field(
        default_factory=list,
        description="Rule IDs to disable entirely (compose rule IDs or vulnerability IDs).",
    )


class DocksecFileConfig(BaseModel):
    """Schema for .docksec.yml.

    Every field is optional. An unset field means "do not override" - it falls
    through to the environment variable, then to the built-in default. This is
    why booleans are ``Optional[bool]`` rather than defaulting to False: a
    missing key and an explicit ``false`` must remain distinguishable.
    """

    model_config = ConfigDict(extra="forbid")

    severity: Optional[str] = Field(
        default=None,
        description="Comma-separated severity levels to scan for, e.g. 'CRITICAL,HIGH'.",
    )
    fail_on: Optional[str] = Field(
        default=None,
        description="Exit 1 if any finding is at or above this severity.",
    )
    formats: Optional[List[str]] = Field(
        default=None,
        description="Report formats to write. Any of: json, csv, pdf, html.",
    )
    output_dir: Optional[str] = Field(
        default=None,
        description="Directory to write reports to.",
    )
    provider: Optional[str] = Field(
        default=None,
        description="LLM provider for the AI analysis pass.",
    )
    model: Optional[str] = Field(
        default=None,
        description="Model name for the configured provider.",
    )
    offline: Optional[bool] = Field(
        default=None,
        description="Run without network access; skips the AI pass and Docker Scout.",
    )
    skip_ai_scoring: Optional[bool] = Field(
        default=None,
        description="Use local scoring only, without an LLM scoring call.",
    )
    no_redact: Optional[bool] = Field(
        default=None,
        description="Do not mask secret-looking values before the AI call.",
    )
    no_cache: Optional[bool] = Field(
        default=None,
        description="Bypass the scan results cache.",
    )
    ignore_file: Optional[str] = Field(
        default=None,
        description="Path to a waiver file listing findings to suppress.",
    )
    baseline: Optional[str] = Field(
        default=None,
        description="Path to a baseline file for ratchet mode.",
    )
    rules: RulesConfig = Field(
        default_factory=RulesConfig,
        description="Per-rule controls.",
    )

    @field_validator("severity")
    @classmethod
    def _check_severity(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        levels = [item.strip().upper() for item in value.split(",") if item.strip()]
        invalid = [item for item in levels if item not in Severity.values()]
        if not levels or invalid:
            raise ValueError(
                f"invalid severity {value!r}; valid levels are "
                f"{', '.join(Severity.values())}"
            )
        return ",".join(levels)

    @field_validator("fail_on")
    @classmethod
    def _check_fail_on(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        level = value.strip().upper()
        if level not in Severity.gate_levels():
            raise ValueError(
                f"invalid fail_on {value!r}; choose one of "
                f"{', '.join(Severity.gate_levels())}"
            )
        return level

    @field_validator("formats")
    @classmethod
    def _check_formats(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return None
        requested = [item.strip().lower() for item in value if str(item).strip()]
        invalid = [item for item in requested if item not in VALID_FORMATS]
        if not requested or invalid:
            raise ValueError(
                f"invalid formats {value!r}; valid formats are "
                f"{', '.join(VALID_FORMATS)}"
            )
        # Normalize to the canonical order the CLI uses, dropping duplicates.
        return [fmt for fmt in VALID_FORMATS if fmt in requested]

    @field_validator("provider")
    @classmethod
    def _check_provider(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        provider = value.strip().lower()
        if provider not in LLMProvider.values():
            raise ValueError(
                f"invalid provider {value!r}; valid providers are "
                f"{', '.join(LLMProvider.values())}"
            )
        return provider


class ConfigFileError(Exception):
    """Raised when a config file exists but cannot be used as written."""


def find_config_file(start_dir: Optional[str] = None) -> Optional[str]:
    """Find the nearest .docksec.yml, walking up toward the repository root.

    Searching upward means a monorepo subdirectory inherits the policy committed
    at the repository root. The walk stops at the directory containing ``.git``
    (inclusive) so discovery never escapes the repository and picks up an
    unrelated file from a parent checkout or the user's home directory.
    """
    current = os.path.abspath(start_dir or os.getcwd())

    while True:
        for filename in CONFIG_FILENAMES:
            candidate = os.path.join(current, filename)
            if os.path.isfile(candidate):
                return candidate

        # Stop after checking the repository root itself.
        if os.path.isdir(os.path.join(current, ".git")):
            return None

        parent = os.path.dirname(current)
        if parent == current:  # filesystem root
            return None
        current = parent


def load_config_file(path: str) -> Tuple[DocksecFileConfig, List[str]]:
    """Load and validate a config file.

    Returns ``(config, warnings)``. Raises :class:`ConfigFileError` when the
    file cannot be read, is not valid YAML, is not a mapping, or fails schema
    validation - a broken policy file must stop the run rather than silently
    scan under different rules than the team committed.
    """
    from ruamel.yaml import YAML

    warnings: List[str] = []

    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = YAML(typ="safe").load(handle)
    except FileNotFoundError:
        raise ConfigFileError(f"Config file not found: {path}")
    except OSError as exc:
        raise ConfigFileError(f"Could not read config file {path}: {exc}")
    except Exception as exc:
        raise ConfigFileError(f"Could not parse config file {path}: {exc}")

    # An empty file is valid and means "no overrides".
    if data is None:
        return DocksecFileConfig(), warnings

    if not isinstance(data, dict):
        raise ConfigFileError(
            f"Config file {path} must contain a mapping of settings at the top level"
        )

    try:
        config = DocksecFileConfig(**data)
    except ValidationError as exc:
        raise ConfigFileError(_format_validation_error(path, exc))

    return config, warnings


def _format_validation_error(path: str, exc: ValidationError) -> str:
    """Render a Pydantic error as an actionable, key-by-key CLI message."""
    lines = [f"Invalid config file {path}:"]
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "(top level)"
        message = error.get("msg", "invalid value")
        # Pydantic prefixes custom ValueError messages; keep the message clean.
        message = message.removeprefix("Value error, ")
        if error.get("type") == "extra_forbidden":
            message = "unknown setting"
        lines.append(f"  {location}: {message}")
    return "\n".join(lines)


def config_json_schema() -> Dict:
    """Return the JSON Schema for .docksec.yml.

    Exported by ``docksec --print-config-schema`` and committed to
    ``docs/docksec-config-schema.json`` so editors can offer completion and
    inline validation via the yaml-language-server schema comment.
    """
    schema = DocksecFileConfig.model_json_schema()
    schema["$schema"] = "http://json-schema.org/draft-07/schema#"
    schema["$id"] = SCHEMA_URL
    schema["title"] = "DockSec configuration"
    schema["description"] = (
        "Repo-level configuration for DockSec (.docksec.yml). "
        "CLI flags and environment variables override these settings."
    )
    return schema
