"""Apply the safe subset of a fix plan to a Dockerfile.

The fix plan tells a user what to change. This applies the changes that are
mechanical enough to make without judgement, re-scans, and reports the delta.

The conservatism is the point. Three rules govern what is applied:

- **Only unambiguous edits.** Adding a missing ``USER`` line is mechanical.
  Choosing which base image version to pin to is not, and picking one wrongly
  breaks a build. Anything requiring a decision is listed for review instead.
- **Never silently destructive.** The original is kept as ``.bak``, ``--dry-run``
  prints a diff without touching anything, and a dirty working tree is refused
  unless forced - git is the real undo, so the tool makes sure git is in a
  position to help.
- **Verified, not assumed.** The file is re-scanned after editing and the
  before/after finding counts are reported. An edit that does not reduce
  findings is worth knowing about.
"""

import difflib
import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple

from docksec.utils import get_custom_logger

logger = get_custom_logger(__name__)

# Edit kinds this module knows how to apply. A fix plan entry whose edit_kind is
# absent from here is reported as needing review rather than attempted.
APPLICABLE_EDITS = {"add_user", "add_healthcheck", "apt_no_recommends", "add_to_copy"}

# Deliberately excluded, with reasons:
#
#   pin_base_image - requires choosing a version. Picking one is a judgement
#       call about what the project supports, and getting it wrong breaks the
#       build rather than just leaving a finding in place.
#   DS031 (secret in ENV) - the fix is to move the value somewhere else, which
#       means knowing where the project keeps secrets.
#   DS017 / DL3059 (combine RUN layers) - rewriting shell across lines risks
#       changing behaviour.
UNSAFE_EDITS = {
    "pin_base_image": "choosing a version is a judgement call; an inapplicable tag breaks the build",
}

DEFAULT_USER = "appuser"


class FixResult:
    """What an autofix run changed, and what it left alone."""

    def __init__(self):
        self.applied: List[Dict] = []
        self.skipped: List[Dict] = []
        self.original_content: str = ""
        self.new_content: str = ""
        self.backup_path: Optional[str] = None
        self.findings_before: Optional[int] = None
        self.findings_after: Optional[int] = None

    @property
    def changed(self) -> bool:
        return bool(self.applied) and self.new_content != self.original_content

    @property
    def delta(self) -> Optional[int]:
        """How many findings the edits removed, when a rescan ran."""
        if self.findings_before is None or self.findings_after is None:
            return None
        return self.findings_before - self.findings_after

    def diff(self, path: str = "Dockerfile") -> str:
        return "".join(
            difflib.unified_diff(
                self.original_content.splitlines(keepends=True),
                self.new_content.splitlines(keepends=True),
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
            )
        )


def working_tree_is_dirty(path: str) -> Optional[bool]:
    """Whether the file has uncommitted changes.

    Returns None when the question does not apply - not a git repository, or git
    is unavailable - so the caller can distinguish "clean" from "unknown".
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    try:
        inside = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=directory, capture_output=True, text=True, timeout=10,
        )
        if inside.returncode != 0 or inside.stdout.strip() != "true":
            return None

        status = subprocess.run(
            ["git", "status", "--porcelain", "--", os.path.abspath(path)],
            cwd=directory, capture_output=True, text=True, timeout=10,
        )
        if status.returncode != 0:
            return None
        return bool(status.stdout.strip())
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        return None


def _find_last_instruction_index(lines: List[str], instructions: Tuple[str, ...]) -> int:
    """Index of the last line starting with one of these instructions, or -1."""
    found = -1
    for index, line in enumerate(lines):
        stripped = line.strip().upper()
        if any(stripped.startswith(f"{name} ") or stripped == name for name in instructions):
            found = index
    return found


def _add_user(lines: List[str]) -> Tuple[List[str], Optional[str]]:
    """Insert a non-root USER before the final CMD/ENTRYPOINT.

    A USER line placed after CMD has no effect, so position matters. When the
    image has no CMD or ENTRYPOINT at all the line is appended, which is still
    correct.
    """
    if any(line.strip().upper().startswith("USER ") and
           line.strip().split()[1].lower() not in ("root", "0")
           for line in lines if len(line.strip().split()) > 1):
        return lines, None

    # Replace an explicit `USER root` rather than adding a second USER line.
    for index, line in enumerate(lines):
        parts = line.strip().split()
        if len(parts) > 1 and parts[0].upper() == "USER" and parts[1].lower() in ("root", "0"):
            new_lines = list(lines)
            new_lines[index] = f"USER {DEFAULT_USER}\n"
            return new_lines, f"replaced 'USER {parts[1]}' with 'USER {DEFAULT_USER}' on line {index + 1}"

    insert_at = _find_last_instruction_index(lines, ("CMD", "ENTRYPOINT"))
    block = [
        "# Added by docksec --fix: run as a non-root user\n",
        f"RUN useradd --create-home --shell /bin/false {DEFAULT_USER} || "
        f"adduser -D -s /bin/false {DEFAULT_USER}\n",
        f"USER {DEFAULT_USER}\n",
    ]
    new_lines = list(lines)
    if insert_at == -1:
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] += "\n"
        new_lines.extend(block)
        return new_lines, f"appended 'USER {DEFAULT_USER}'"

    new_lines[insert_at:insert_at] = block
    return new_lines, f"inserted 'USER {DEFAULT_USER}' before line {insert_at + 1}"


def _add_healthcheck(lines: List[str]) -> Tuple[List[str], Optional[str]]:
    """Insert a HEALTHCHECK before the final CMD/ENTRYPOINT.

    The command is deliberately generic: DockSec cannot know what this service
    considers healthy, so the inserted line checks that the main process is
    alive and carries a comment telling the user to replace it.
    """
    if any(line.strip().upper().startswith("HEALTHCHECK") for line in lines):
        return lines, None

    insert_at = _find_last_instruction_index(lines, ("CMD", "ENTRYPOINT"))
    block = [
        "# Added by docksec --fix: replace this with a real readiness check\n",
        "HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \\\n",
        "  CMD [ -d /proc/1 ] || exit 1\n",
    ]
    new_lines = list(lines)
    if insert_at == -1:
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] += "\n"
        new_lines.extend(block)
        return new_lines, "appended a placeholder HEALTHCHECK"

    new_lines[insert_at:insert_at] = block
    return new_lines, f"inserted a placeholder HEALTHCHECK before line {insert_at + 1}"


def _apt_no_recommends(lines: List[str]) -> Tuple[List[str], Optional[str]]:
    """Add --no-install-recommends to apt-get install invocations."""
    pattern = re.compile(r"(apt-get\s+(?:-[\w-]+\s+)*install)(?!\s+[^\n]*--no-install-recommends)")
    new_lines, touched = [], []
    for index, line in enumerate(lines):
        if "apt-get" in line and "install" in line and "--no-install-recommends" not in line:
            replaced = pattern.sub(r"\1 --no-install-recommends", line, count=1)
            if replaced != line:
                touched.append(index + 1)
                new_lines.append(replaced)
                continue
        new_lines.append(line)

    if not touched:
        return lines, None
    return new_lines, f"added --no-install-recommends on line(s) {', '.join(map(str, touched))}"


def _add_to_copy(lines: List[str]) -> Tuple[List[str], Optional[str]]:
    """Convert ADD to COPY for local sources only.

    ADD from a URL or of a tarball has behaviour COPY does not replicate
    (fetching, auto-extraction), so those are left alone - converting them would
    silently change what the build produces.
    """
    new_lines, touched = [], []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.upper().startswith("ADD "):
            new_lines.append(line)
            continue
        arguments = stripped[4:].strip()
        if re.match(r"https?://|git@|github\.com", arguments, re.IGNORECASE):
            new_lines.append(line)
            continue
        if re.search(r"\.(tar|tgz|tar\.gz|tar\.bz2|tar\.xz|zip)\b", arguments, re.IGNORECASE):
            new_lines.append(line)
            continue
        new_lines.append(line.replace("ADD ", "COPY ", 1).replace("add ", "COPY ", 1))
        touched.append(index + 1)

    if not touched:
        return lines, None
    return new_lines, f"converted ADD to COPY on line(s) {', '.join(map(str, touched))}"


EDIT_HANDLERS = {
    "add_user": _add_user,
    "add_healthcheck": _add_healthcheck,
    "apt_no_recommends": _apt_no_recommends,
    "add_to_copy": _add_to_copy,
}


def plan_edits(fix_plan) -> Tuple[List[Dict], List[Dict]]:
    """Split a fix plan into edits that can be applied and edits that cannot.

    Returns ``(applicable, needs_review)``. Deduplicated by edit kind: two rules
    recommending a non-root USER are one change.
    """
    applicable, needs_review, seen = [], [], set()

    for edit in getattr(fix_plan, "dockerfile_edits", []):
        kind = edit.get("edit_kind")
        if kind in APPLICABLE_EDITS:
            if kind in seen:
                continue
            seen.add(kind)
            applicable.append(edit)
        else:
            reason = UNSAFE_EDITS.get(kind) if kind else "no mechanical edit is defined"
            needs_review.append({**edit, "reason": reason or "needs a judgement call"})

    # Compose changes and package upgrades are never applied: editing a compose
    # file changes runtime topology, and installing packages means running a
    # build.
    for edit in getattr(fix_plan, "compose_edits", []):
        needs_review.append({
            **edit,
            "reason": "compose changes alter runtime topology; apply them yourself",
        })

    return applicable, needs_review


def apply_to_dockerfile(
    dockerfile_path: str, fix_plan, dry_run: bool = False, backup: bool = True
) -> FixResult:
    """Apply the safe subset of a fix plan to a Dockerfile.

    With ``dry_run`` the file is not touched and the result carries the diff.
    """
    result = FixResult()

    with open(dockerfile_path, "r", encoding="utf-8") as handle:
        result.original_content = handle.read()

    lines = result.original_content.splitlines(keepends=True)
    applicable, needs_review = plan_edits(fix_plan)
    result.skipped = needs_review

    for edit in applicable:
        handler = EDIT_HANDLERS.get(edit["edit_kind"])
        if not handler:
            continue
        new_lines, description = handler(lines)
        if description is None:
            # The condition was already satisfied - nothing to do, and saying
            # otherwise would overstate what the run changed.
            continue
        lines = new_lines
        result.applied.append({
            "rule": edit.get("rule"),
            "edit_kind": edit["edit_kind"],
            "description": description,
            "severity": edit.get("severity"),
        })

    result.new_content = "".join(lines)

    if dry_run or not result.changed:
        return result

    if backup:
        backup_path = f"{dockerfile_path}.bak"
        shutil.copy2(dockerfile_path, backup_path)
        result.backup_path = backup_path

    with open(dockerfile_path, "w", encoding="utf-8") as handle:
        handle.write(result.new_content)

    return result


def rescan(dockerfile_path: str, offline: bool = False) -> Optional[int]:
    """Count findings in the file as it now stands.

    Returns None when the scan could not run. A failed scan reports zero
    findings, which would otherwise render as "7 -> 0 (7 resolved)" and claim a
    success that did not happen.
    """
    if not os.path.isfile(dockerfile_path):
        logger.debug(f"Re-scan skipped: {dockerfile_path} does not exist")
        return None

    try:
        from docksec import findings as findings_mod

        found, errors = findings_mod.scan_dockerfile_findings(
            dockerfile_path, offline=offline
        )
        if errors:
            # A scanner that failed means findings may be missing, so the count
            # is not comparable with the one taken before the edit.
            logger.debug(f"Re-scan reported errors: {errors}")
            return None
        return len(found)
    except Exception as exc:  # noqa: BLE001 - a failed rescan is not a failed fix
        logger.debug(f"Re-scan failed: {exc}")
        return None
