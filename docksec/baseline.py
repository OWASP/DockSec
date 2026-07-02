"""Baseline/ratchet mode: compare a scan's findings against a stored baseline
so --fail-on only gates on newly introduced findings.

The baseline file is a flat JSON list of finding fingerprints. A fingerprint
identifies a finding by VulnerabilityID + Target + PkgName, which is stable
across scans of the same Dockerfile/image even as unrelated findings appear
or disappear.
"""

import json
from typing import Dict, List


def fingerprint(vuln: Dict) -> str:
    """Build a stable identity for a finding from its VulnerabilityID, Target,
    and PkgName, so the same underlying issue matches across scans."""
    vuln_id = str(vuln.get("VulnerabilityID") or "UNKNOWN")
    target = str(vuln.get("Target") or "")
    pkg = str(vuln.get("PkgName") or "")
    return f"{vuln_id}|{target}|{pkg}"


def load_baseline(path: str) -> List[str]:
    """Load a baseline file's fingerprints. Returns [] if the file doesn't exist."""
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        return []
    return list(data.get("fingerprints", []))


def save_baseline(path: str, results: Dict) -> None:
    """Write the current scan's findings to the baseline file as fingerprints."""
    vulnerabilities = results.get("json_data", [])
    fingerprints = sorted({fingerprint(v) for v in vulnerabilities})
    with open(path, "w") as f:
        json.dump({"fingerprints": fingerprints}, f, indent=2)


def new_findings(results: Dict, baseline_fingerprints: List[str]) -> List[Dict]:
    """Return the findings in results that are not present in the baseline."""
    baseline_set = set(baseline_fingerprints)
    vulnerabilities = results.get("json_data", [])
    return [v for v in vulnerabilities if fingerprint(v) not in baseline_set]
