"""Structured Dockerfile findings from Hadolint and Trivy's config scanner.

Hadolint output used to be a raw text blob: not in ``json_data``, not gated by
``--fail-on``, absent from SARIF and ``--json``. CI could pass on a root-user,
ADD-from-URL Dockerfile. Trivy's ``config`` scanner - which detects the same
class of issue with stable IDs and real severities - was not run at all.

Both now produce findings in the same shape as image vulnerabilities, so they
travel through scoring, reports, ``--json``, SARIF, waivers, and the
``--fail-on`` gate like everything else.

Running both is deliberate. Neither is a superset:

- Hadolint alone catches unpinned apt versions (DL3008), uncleaned apt lists
  (DL3009), consecutive RUN instructions (DL3059).
- Trivy alone catches a bare ``apt-get update`` (DS017), a missing HEALTHCHECK
  (DS026), and secrets in ENV (DS031) - the last at CRITICAL.

Where they overlap, the Trivy finding wins: its IDs are stable and externally
documented at avd.aquasec.com, and it carries a real severity. Hadolint's
info/warning/error are lint levels, and mapping them onto CRITICAL..LOW means
inventing a scale - which is how a ``--fail-on`` gate becomes untrustworthy.
"""

import json
import os
import re
import subprocess
from typing import Dict, List, Optional, Tuple

from docksec import output as ui
from docksec.enums import Severity
from docksec.utils import get_custom_logger

logger = get_custom_logger(__name__)

# Hadolint rules that duplicate a Trivy config check. When both fire, the
# Hadolint finding is dropped and its line number is carried onto the Trivy
# finding if Trivy did not supply one.
#
# Verified against both tools' output on the same Dockerfile rather than from
# documentation; see tests/test_findings.py. Extend deliberately - a wrong entry
# silently hides a finding.
HADOLINT_TRIVY_COLLISIONS = {
    "DL3007": "DS001",  # :latest tag
    "DL3002": "DS002",  # last USER should not be root
    "DL3003": "DS013",  # RUN cd ... to change directory
    "DL3015": "DS029",  # apt-get missing --no-install-recommends
}

# Hadolint reports lint levels, not risk levels. This mapping is deliberately
# conservative: inflating lint noise into HIGH is how a gate gets switched off.
HADOLINT_SEVERITY = {
    "error": Severity.HIGH.value,
    "warning": Severity.MEDIUM.value,
    "info": Severity.LOW.value,
    "style": Severity.LOW.value,
}

HADOLINT_TIMEOUT = 300
TRIVY_CONFIG_TIMEOUT = 300

# Trivy has changed its misconfiguration ID format between releases: 0.68 emits
# "DS001" with an AVDID of "AVD-DS-0002", while 0.74 emits "DS-0001" and no
# AVDID at all. Left alone, the collision map and the fix table - both keyed on
# one spelling - silently stop matching when Trivy is upgraded, which is how the
# pinned container produced 16 findings where a local run produced 10.
_TRIVY_ID_PATTERN = re.compile(r"^(?:AVD-)?([A-Z]{2,4})-?0*(\d+)$")


def normalize_rule_id(rule_id: str) -> str:
    """Canonicalize a Trivy misconfiguration ID to the compact form.

    ``DS-0001``, ``DS001``, and ``AVD-DS-0001`` all normalize to ``DS001``.
    Anything that does not look like a Trivy rule (a CVE, a Hadolint code) is
    returned unchanged.
    """
    candidate = str(rule_id or "").strip().upper()
    if not candidate or candidate.startswith(("CVE-", "DL", "SC", "GHSA")):
        return candidate
    match = _TRIVY_ID_PATTERN.match(candidate)
    if not match:
        return candidate
    prefix, number = match.groups()
    return f"{prefix}{int(number):03d}"


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    target: str,
    line: Optional[int] = None,
    remediation: str = "",
    url: str = "",
    source: str = "",
) -> Dict:
    """Build a finding in the shape the rest of the pipeline consumes.

    Mirrors the keys ``DockerSecurityScanner._filter_scan_results`` emits for
    image vulnerabilities, so report writers, the score calculator, waivers, and
    the SARIF mapper need no special cases. ``Line`` and ``Source`` are
    additions; every consumer reads them with ``.get()``.
    """
    return {
        "VulnerabilityID": rule_id,
        "Target": target,
        "PkgName": "dockerfile",
        "InstalledVersion": "N/A",
        "FixedVersion": None,
        "Severity": severity,
        "Title": title,
        "Description": description,
        "Status": "affected",
        "CVSS": None,
        "PrimaryURL": url,
        "Remediation": remediation,
        "Line": line,
        "Source": source,
    }


def parse_hadolint_json(raw: str, target: str) -> List[Dict]:
    """Convert ``hadolint -f json`` output into structured findings."""
    if not raw or not raw.strip():
        return []

    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning(f"Could not parse Hadolint JSON output: {exc}")
        return []

    if not isinstance(entries, list):
        return []

    findings = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        code = str(entry.get("code") or "").strip()
        if not code:
            continue
        level = str(entry.get("level") or "").strip().lower()
        line = entry.get("line")
        findings.append(
            _finding(
                rule_id=code,
                severity=HADOLINT_SEVERITY.get(level, Severity.LOW.value),
                title=str(entry.get("message") or code),
                description=str(entry.get("message") or ""),
                target=target,
                line=line if isinstance(line, int) and line > 0 else None,
                url=f"https://github.com/hadolint/hadolint/wiki/{code}",
                source="hadolint",
            )
        )
    return findings


def parse_trivy_config_json(
    raw: str, target: str, target_basename: Optional[str] = None
) -> List[Dict]:
    """Convert ``trivy config -f json`` output into structured findings.

    ``trivy config`` scans a directory, so its output can include other config
    files that happen to sit beside the Dockerfile. ``target_basename`` limits
    the results to the file actually being scanned.
    """
    if not raw or not raw.strip():
        return []

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning(f"Could not parse Trivy config JSON output: {exc}")
        return []

    findings = []
    for result in (payload or {}).get("Results") or []:
        if target_basename:
            result_target = str(result.get("Target") or "")
            if os.path.basename(result_target) != target_basename:
                continue
        for misconfig in result.get("Misconfigurations") or []:
            rule_id = normalize_rule_id(
                misconfig.get("ID") or misconfig.get("AVDID") or ""
            )
            if not rule_id:
                continue
            cause = misconfig.get("CauseMetadata") or {}
            start_line = cause.get("StartLine")
            findings.append(
                _finding(
                    rule_id=rule_id,
                    severity=str(misconfig.get("Severity") or Severity.UNKNOWN.value).upper(),
                    title=str(misconfig.get("Title") or rule_id),
                    description=str(misconfig.get("Description") or ""),
                    target=target,
                    line=start_line if isinstance(start_line, int) and start_line > 0 else None,
                    remediation=str(misconfig.get("Resolution") or ""),
                    url=str(misconfig.get("PrimaryURL") or ""),
                    source="trivy-config",
                )
            )
    return findings


def deduplicate(
    hadolint_findings: List[Dict], trivy_findings: List[Dict]
) -> Tuple[List[Dict], int]:
    """Merge both scanners' findings, dropping Hadolint duplicates.

    Returns ``(findings, dropped_count)``. A Hadolint finding is dropped when
    its rule maps to a Trivy rule that also fired; the Hadolint line number is
    transferred first when Trivy did not report one, so position data is not
    lost along with the duplicate.
    """
    trivy_by_rule = {}
    for finding in trivy_findings:
        trivy_by_rule.setdefault(finding["VulnerabilityID"], finding)

    kept = []
    dropped = 0
    for finding in hadolint_findings:
        counterpart_id = HADOLINT_TRIVY_COLLISIONS.get(finding["VulnerabilityID"])
        counterpart = trivy_by_rule.get(counterpart_id) if counterpart_id else None
        if counterpart is None:
            kept.append(finding)
            continue
        if counterpart.get("Line") is None and finding.get("Line") is not None:
            counterpart["Line"] = finding["Line"]
        dropped += 1

    return trivy_findings + kept, dropped


def run_hadolint(dockerfile_path: str) -> Tuple[bool, List[Dict], Optional[str]]:
    """Run Hadolint and return ``(ok, findings, error)``.

    ``ok`` is False only when Hadolint could not be run or produced unusable
    output - findings themselves are a normal result, not a failure.
    """
    try:
        result = subprocess.run(
            ["hadolint", "-f", "json", dockerfile_path],
            capture_output=True, text=True, timeout=HADOLINT_TIMEOUT, shell=False,
        )
    except FileNotFoundError:
        return False, [], "Hadolint not found in PATH"
    except subprocess.TimeoutExpired:
        return False, [], f"Hadolint timed out after {HADOLINT_TIMEOUT}s"
    except (subprocess.SubprocessError, OSError) as exc:
        return False, [], f"Hadolint failed: {exc}"

    # Hadolint exits non-zero when it finds issues, which is not an error.
    # Empty stdout with a non-zero exit is.
    if not (result.stdout or "").strip():
        if result.returncode != 0:
            detail = (result.stderr or "").strip()[:200] or f"exit {result.returncode}"
            return False, [], f"Hadolint produced no output: {detail}"
        return True, [], None

    return True, parse_hadolint_json(result.stdout, dockerfile_path), None


def run_trivy_config(dockerfile_path: str, offline: bool = False) -> Tuple[bool, List[Dict], Optional[str]]:
    """Run ``trivy config`` against the Dockerfile's directory.

    ``trivy config`` only accepts a directory - given a file it prints its usage
    text and exits 0, which parses as "no findings" rather than an error. The
    directory is scanned and the results are then filtered back down to the
    target file. ``--file-patterns`` narrows the scan so an unusually named
    Dockerfile (``Dockerfile.prod``) is still analyzed as one.
    """
    directory = os.path.dirname(os.path.abspath(dockerfile_path)) or "."
    basename = os.path.basename(dockerfile_path)

    cmd = [
        "trivy", "config", "-f", "json", "--quiet", "--skip-version-check",
        "--file-patterns", f"dockerfile:{basename}",
    ]
    if offline:
        cmd.append("--skip-check-update")
    cmd.append(directory)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8",
            timeout=TRIVY_CONFIG_TIMEOUT, shell=False,
        )
    except FileNotFoundError:
        return False, [], "Trivy not found in PATH"
    except subprocess.TimeoutExpired:
        return False, [], f"Trivy config scan timed out after {TRIVY_CONFIG_TIMEOUT}s"
    except (subprocess.SubprocessError, OSError) as exc:
        return False, [], f"Trivy config scan failed: {exc}"

    stdout = (result.stdout or "").strip()
    if not stdout:
        if result.returncode != 0:
            detail = (result.stderr or "").strip()[:200] or f"exit {result.returncode}"
            return False, [], f"Trivy config scan produced no output: {detail}"
        return True, [], None

    # Trivy prints its usage text on stdout for an argument error while still
    # exiting 0, which would otherwise be read as a clean scan.
    if not stdout.startswith("{"):
        return False, [], "Trivy config scan returned unexpected output (not JSON)"

    return True, parse_trivy_config_json(stdout, dockerfile_path, basename), None


def scan_dockerfile_findings(
    dockerfile_path: str, offline: bool = False
) -> Tuple[List[Dict], List[str]]:
    """Run both Dockerfile scanners and return ``(findings, errors)``.

    Errors are returned rather than raised: one scanner failing should degrade
    coverage, not abort the run. The caller records them as detection gaps so
    the shortfall is reported rather than silently absorbed.
    """
    errors: List[str] = []

    hadolint_ok, hadolint_findings, hadolint_error = run_hadolint(dockerfile_path)
    if not hadolint_ok:
        errors.append(hadolint_error or "Hadolint failed")
        hadolint_findings = []

    trivy_ok, trivy_findings, trivy_error = run_trivy_config(dockerfile_path, offline=offline)
    if not trivy_ok:
        errors.append(trivy_error or "Trivy config scan failed")
        trivy_findings = []

    findings, dropped = deduplicate(hadolint_findings, trivy_findings)
    if dropped:
        logger.debug(f"Dropped {dropped} Hadolint finding(s) duplicated by Trivy config")

    findings.sort(
        key=lambda f: (-Severity.rank(f.get("Severity")), f.get("Line") or 0,
                       f.get("VulnerabilityID") or "")
    )
    return findings, errors


def summarize(findings: List[Dict]) -> str:
    """One-line severity summary for the scan output."""
    if not findings:
        return "No Dockerfile issues found."
    counts: Dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("Severity", Severity.UNKNOWN.value)).upper()
        counts[severity] = counts.get(severity, 0) + 1
    ordered = [
        f"{level}: {counts[level]}"
        for level in (s.value for s in Severity.scored_levels())
        if counts.get(level)
    ]
    return f"{len(findings)} Dockerfile issue(s) - {' | '.join(ordered)}"


def report(findings: List[Dict], errors: List[str]) -> None:
    """Print a short human-readable summary of the Dockerfile scan."""
    for error in errors:
        ui.warn(error)
    if not findings:
        ui.success("No Dockerfile issues found.")
        return
    ui.info(summarize(findings))
    for finding in findings[:3]:
        location = f" (line {finding['Line']})" if finding.get("Line") else ""
        ui.detail(
            f"  [{finding['Severity']}] {finding['VulnerabilityID']}: "
            f"{finding['Title']}{location}"
        )
    if len(findings) > 3:
        ui.detail(f"  ... and {len(findings) - 3} more")
