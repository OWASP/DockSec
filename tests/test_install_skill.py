"""Unit tests for the install-skill subcommand."""

import os

from docksec.install_skill import install_skill, SKILL_CONTENT, _SECTION_MARKER


def _read(root, rel):
    with open(os.path.join(root, rel), "r", encoding="utf-8") as f:
        return f.read()


def test_install_skill_writes_all_targets(tmp_path):
    install_skill(str(tmp_path))

    expected = [
        os.path.join(".claude", "commands", "docksec.md"),
        os.path.join(".cursor", "rules", "docksec.mdc"),
        os.path.join(".github", "copilot-instructions.md"),
        "AGENTS.md",
        "GEMINI.md",
    ]
    for rel in expected:
        assert os.path.exists(os.path.join(tmp_path, rel)), f"missing {rel}"


def test_claude_skill_contains_docksec_commands(tmp_path):
    install_skill(str(tmp_path))
    content = _read(tmp_path, os.path.join(".claude", "commands", "docksec.md"))
    assert "docksec Dockerfile" in content
    assert "/docksec" in content


def test_cursor_skill_has_frontmatter(tmp_path):
    install_skill(str(tmp_path))
    content = _read(tmp_path, os.path.join(".cursor", "rules", "docksec.mdc"))
    assert content.startswith("---")
    assert "DockSec" in content


def test_install_skill_is_idempotent(tmp_path):
    install_skill(str(tmp_path))
    install_skill(str(tmp_path))
    agents = _read(tmp_path, "AGENTS.md")
    # Section marker must appear exactly once after a second run.
    assert agents.count(_SECTION_MARKER) == 1


def test_install_skill_appends_to_existing_file(tmp_path):
    # A pre-existing AGENTS.md with unrelated content should be preserved and
    # the DockSec section appended, not overwritten.
    existing = "# Project agents\n\nSome existing instructions.\n"
    agents_path = tmp_path / "AGENTS.md"
    agents_path.write_text(existing, encoding="utf-8")

    install_skill(str(tmp_path))
    content = agents_path.read_text(encoding="utf-8")
    assert "Some existing instructions." in content
    assert _SECTION_MARKER in content


def test_install_skill_replaces_stale_section_in_place(tmp_path):
    # An existing DockSec section followed by later content: re-running must
    # replace the section but keep the trailing content.
    agents_path = tmp_path / "AGENTS.md"
    agents_path.write_text(
        f"{_SECTION_MARKER}\n\nOLD CONTENT\n\n## Other tool\n\nkeep me\n",
        encoding="utf-8",
    )
    install_skill(str(tmp_path))
    content = agents_path.read_text(encoding="utf-8")
    assert "OLD CONTENT" not in content
    assert "## Other tool" in content
    assert "keep me" in content
    assert content.count(_SECTION_MARKER) == 1


def test_skill_content_mentions_new_features():
    # The skill block should teach the assistant the newer flags.
    for token in ("--sbom", "--offline", "--sarif", "--fail-on"):
        assert token in SKILL_CONTENT
