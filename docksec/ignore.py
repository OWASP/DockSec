"""Targeted, auditable suppression of findings via an ignore file.

Baseline mode (--baseline) snapshots everything at a point in time; the ignore
file is the complement: an explicit, reviewable list of individual findings a
team has triaged and accepted, each with a reason and an optional expiry date.

File format (.docksec-ignore.yml, or any path via --ignore-file):

    ignores:
      - id: CVE-2023-45853          # Trivy vulnerability ID or DockSec rule ID
        reason: "zlib CVE; not reachable, vendor fix pending"
        expires: 2026-12-31          # optional; entry stops applying after this date
      - id: compose-missing-healthcheck
        reason: "healthchecks handled by the platform"

Suppressed findings are removed before scoring, reports, JSON output, and the
--fail-on gate. Entries match on VulnerabilityID (case-insensitive).
"""

import os
from datetime import date, datetime
from typing import Dict, List, Optional, Tuple

from docksec.utils import get_custom_logger

logger = get_custom_logger(__name__)

DEFAULT_IGNORE_FILE = ".docksec-ignore.yml"


def find_default_ignore_file(directory: Optional[str] = None) -> Optional[str]:
    """Return the default ignore file path if one exists in the directory."""
    path = os.path.join(directory or os.getcwd(), DEFAULT_IGNORE_FILE)
    return path if os.path.isfile(path) else None


def load_ignore_file(path: str) -> Tuple[List[Dict], List[str]]:
    """Load and validate an ignore file.

    Returns (active_entries, warnings). Malformed or expired entries are
    dropped and reported as warnings rather than failing the scan.
    """
    from ruamel.yaml import YAML

    warnings: List[str] = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = YAML(typ='safe').load(f)
    except FileNotFoundError:
        return [], [f"Ignore file not found: {path}"]
    except Exception as e:
        return [], [f"Failed to parse ignore file {path}: {e}"]

    if not isinstance(data, dict) or not isinstance(data.get('ignores'), list):
        return [], [f"Ignore file {path} must contain a top-level 'ignores' list"]

    active: List[Dict] = []
    for i, entry in enumerate(data['ignores'], start=1):
        if not isinstance(entry, dict) or not entry.get('id'):
            warnings.append(f"Ignore entry {i} has no 'id'; skipped")
            continue
        entry_id = str(entry['id']).strip()
        if not entry.get('reason'):
            warnings.append(f"Ignore entry '{entry_id}' has no 'reason'; add one for auditability")

        expires = entry.get('expires')
        if expires is not None:
            expiry = _parse_date(expires)
            if expiry is None:
                warnings.append(f"Ignore entry '{entry_id}' has invalid 'expires' date '{expires}'; entry skipped")
                continue
            if expiry < date.today():
                warnings.append(f"Ignore entry '{entry_id}' expired on {expiry.isoformat()}; no longer applied")
                continue

        active.append({'id': entry_id, 'reason': entry.get('reason'), 'expires': expires})

    return active, warnings


def _parse_date(value) -> Optional[date]:
    if isinstance(value, date):
        return value
    try:
        return datetime.strptime(str(value).strip(), "%Y-%m-%d").date()
    except ValueError:
        return None


def apply_ignores(findings: List[Dict], entries: List[Dict]) -> Tuple[List[Dict], int]:
    """Filter suppressed findings out. Returns (kept_findings, suppressed_count)."""
    if not entries:
        return findings, 0
    ignored_ids = {e['id'].upper() for e in entries}
    kept = [f for f in findings
            if str(f.get('VulnerabilityID', '')).upper() not in ignored_ids]
    return kept, len(findings) - len(kept)
