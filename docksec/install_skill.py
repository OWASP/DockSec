"""
install-skill subcommand.

Writes DockSec usage instructions into the well-known AI-assistant context
files for a project (Claude Code, Cursor, Codex/AGENTS.md, Gemini, GitHub
Copilot), so that an assistant working in that repo knows how to invoke DockSec
to scan Dockerfiles, images, and compose files. The files are plain text the
user can review and commit; nothing is executed.
"""

import os

from docksec import output

# The canonical DockSec instruction block shared across every assistant target.
# Kept intentionally short and command-first so an assistant can act on it.
SKILL_CONTENT = """\
DockSec is an AI-powered Docker security scanner (OWASP Lab Project). Use it to
scan Dockerfiles, built images, and Docker Compose stacks for vulnerabilities
and misconfigurations, with plain-English explanations and concrete fixes.

Common commands:

- Scan a Dockerfile with AI analysis:
    docksec Dockerfile
- Scan a Dockerfile and a built image together:
    docksec Dockerfile -i myapp:latest
- Scan only an image (no Dockerfile):
    docksec --image-only -i myapp:latest
- Scan a Docker Compose file and all its services:
    docksec --compose docker-compose.yml
- Fast local scan with no API key (no AI):
    docksec Dockerfile --scan-only
- Fail CI when a HIGH-or-worse finding is present:
    docksec -i myapp:latest --image-only --fail-on high
- Machine-readable output for scripts:
    docksec -i myapp:latest --image-only --json
- SARIF for GitHub Code Scanning:
    docksec Dockerfile --sarif
- CycloneDX SBOM of an image for supply-chain tooling:
    docksec --image-only -i myapp:latest --sbom
- Fully offline (local Trivy DB, no network, no AI):
    docksec --image-only -i myapp:latest --offline

Exit codes: 0 clean, 1 findings at/above --fail-on, 2 usage error,
3 tool/runtime error. Reports are written to ~/.docksec/results/ by default
(override with --output-dir). See https://owasp.org/DockSec/ for full docs.
"""

# Heading used when appending into a shared instructions file, so re-running
# install-skill updates the DockSec section in place instead of duplicating it.
_SECTION_MARKER = "## DockSec"


def _write_claude_code_skill(project_root: str) -> str:
    """Write a Claude Code slash-command file (/docksec)."""
    rel = os.path.join(".claude", "commands", "docksec.md")
    path = os.path.join(project_root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    content = f"<!-- Run this skill with /docksec in any Claude Code session -->\n\n{SKILL_CONTENT}\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return rel


def _write_cursor_skill(project_root: str) -> str:
    """Write a Cursor rules file."""
    rel = os.path.join(".cursor", "rules", "docksec.mdc")
    path = os.path.join(project_root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    front_matter = (
        "---\ndescription: DockSec Docker security scanning\nglobs: []\nalwaysApply: false\n---\n\n"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(front_matter + SKILL_CONTENT + "\n")
    return rel


def _write_append_skill(project_root: str, rel_path: str) -> str:
    """Write or update a '## DockSec' section in a shared instructions file.

    If the file does not exist it is created with just the DockSec section. If
    it exists and already has a DockSec section, that section is replaced in
    place (up to the next top-level heading); otherwise the section is appended.
    """
    section = f"{_SECTION_MARKER}\n\n{SKILL_CONTENT}\n"
    path = os.path.join(project_root, rel_path)

    if not os.path.exists(path):
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(section)
        return rel_path

    with open(path, "r", encoding="utf-8") as f:
        existing = f.read()

    idx = existing.find(_SECTION_MARKER)
    if idx == -1:
        sep = "\n" if existing.endswith("\n") else "\n\n"
        with open(path, "w", encoding="utf-8") as f:
            f.write(existing + sep + section)
        return rel_path

    # Replace from the marker to the next top-level heading (or end of file).
    after = existing.find("\n## ", idx + len(_SECTION_MARKER))
    before = existing[:idx]
    tail = "" if after == -1 else existing[after:]
    with open(path, "w", encoding="utf-8") as f:
        f.write(before + section + tail)
    return rel_path


def install_skill(project_root: str = None) -> None:
    """Install DockSec instruction files for common AI assistants."""
    project_root = project_root or os.getcwd()

    written = [
        ("Claude Code", _write_claude_code_skill(project_root)),
        ("Codex CLI", _write_append_skill(project_root, "AGENTS.md")),
        ("Gemini CLI", _write_append_skill(project_root, "GEMINI.md")),
        ("Cursor", _write_cursor_skill(project_root)),
        ("GitHub Copilot", _write_append_skill(
            project_root, os.path.join(".github", "copilot-instructions.md"))),
    ]

    output.section("DockSec assistant skills installed")
    for label, rel in written:
        output.success(f"{label:<16} {rel}")
    output.info("Commit these files to your repo to share them with your team.")
