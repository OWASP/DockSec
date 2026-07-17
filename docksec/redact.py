"""Redact secret-looking values from file content before it is sent to an LLM.

DockSec's AI pass sends Dockerfile / compose file content to the configured
LLM provider. Files under analysis frequently contain the very credentials
DockSec is meant to flag, so by default the values (never the keys) of
secret-looking assignments are masked before the content leaves the machine.
The key names stay visible, which is all the model needs to flag an exposed
credential; the secret material itself is replaced with a marker.

Disable with --no-redact (e.g. when scanning files known to hold only dummy
values and full-fidelity analysis is preferred).
"""

import re
from typing import Tuple

REDACTED = "[REDACTED-BY-DOCKSEC]"

# Key names that suggest the assigned value is a secret.
_SECRET_KEY = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|credential|auth)",
    re.IGNORECASE,
)

# Values that look like secret material regardless of the key name.
_SECRET_VALUE_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                    # AWS access key id
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),                # GitHub personal access token
    re.compile(r"gho_[A-Za-z0-9]{36,}"),                # GitHub OAuth token
    re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),        # GitHub fine-grained PAT
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),        # Slack token
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),               # OpenAI-style API key
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),  # JWT
]

_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)

# KEY=value pairs (Dockerfile ENV/ARG, compose list-style environment, .env
# lines). Values may be quoted; interpolations like ${VAR} are left alone.
_ASSIGN_EQ = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)=(?P<val>\"[^\"]*\"|'[^']*'|[^\s]+)"
)

# YAML mapping style: KEY: value (compose dict-style environment).
_ASSIGN_COLON = re.compile(
    r"^(?P<lead>\s*-?\s*)(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)\s*:\s+(?P<val>\"[^\"]*\"|'[^']*'|\S[^#\n]*)$"
)

# Dockerfile space form: ENV KEY value
_ENV_SPACE = re.compile(
    r"^(?P<lead>\s*(?:ENV|ARG)\s+)(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)\s+(?P<val>[^=\s].*)$",
    re.IGNORECASE,
)


def _is_placeholder(value: str) -> bool:
    """Interpolations and empty values carry no secret material."""
    stripped = value.strip().strip("\"'")
    return not stripped or stripped.startswith("${") or stripped.startswith("$(")


def redact_content(content: str) -> Tuple[str, int]:
    """Mask secret-looking values in content. Returns (redacted_text, count)."""
    count = 0

    def _sub_private_key(match: re.Match) -> str:
        nonlocal count
        count += 1
        return REDACTED

    content = _PRIVATE_KEY_BLOCK.sub(_sub_private_key, content)

    def _sub_eq(match: re.Match) -> str:
        nonlocal count
        key, val = match.group("key"), match.group("val")
        if _SECRET_KEY.search(key) and not _is_placeholder(val):
            count += 1
            return f"{key}={REDACTED}"
        return match.group(0)

    lines = []
    for line in content.split("\n"):
        original = line
        line = _ASSIGN_EQ.sub(_sub_eq, line)

        if line == original:
            m = _ASSIGN_COLON.match(line)
            if m and _SECRET_KEY.search(m.group("key")) and not _is_placeholder(m.group("val")):
                count += 1
                line = f"{m.group('lead')}{m.group('key')}: {REDACTED}"

        if line == original:
            m = _ENV_SPACE.match(line)
            if m and _SECRET_KEY.search(m.group("key")) and not _is_placeholder(m.group("val")):
                count += 1
                line = f"{m.group('lead')}{m.group('key')} {REDACTED}"

        # Value-shaped secrets (AWS keys, PATs, JWTs, ...) regardless of key name.
        for pattern in _SECRET_VALUE_PATTERNS:
            line, n = pattern.subn(REDACTED, line)
            count += n

        lines.append(line)

    return "\n".join(lines), count
