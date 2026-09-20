"""What the scan could not determine.

A scanner that hides its own blind spots cannot be trusted as a merge gate.
DockSec used to print a confident score on runs where every compose service had
failed to scan, with the failure visible only as a stray line on stderr.

Two kinds of gap are tracked, because they mean different things to a reader:

- **detection**: a scanner did not run or failed, so findings may be missing.
  The absence of findings is not evidence of their absence.
- **remediation**: findings were detected, but the data needed to act on them
  (fix versions, EPSS scores) was unavailable. The list is complete; the advice
  attached to it is not.

Coverage notes are separate: they state what DockSec does not examine at all,
regardless of whether anything failed, so an evaluator is not left inferring
scope from silence.
"""

from typing import Dict, List, Optional

DETECTION = "detection"
REMEDIATION = "remediation"


class ScanCompleteness:
    """Accumulates gaps encountered during a scan."""

    def __init__(self):
        self.gaps: List[Dict[str, str]] = []

    def add(self, impact: str, code: str, message: str) -> None:
        """Record a gap. ``impact`` is DETECTION or REMEDIATION."""
        self.gaps.append({"impact": impact, "code": code, "message": message})

    def detection_gap(self, code: str, message: str) -> None:
        self.add(DETECTION, code, message)

    def remediation_gap(self, code: str, message: str) -> None:
        self.add(REMEDIATION, code, message)

    @property
    def has_detection_gap(self) -> bool:
        return any(gap["impact"] == DETECTION for gap in self.gaps)

    @property
    def has_remediation_gap(self) -> bool:
        return any(gap["impact"] == REMEDIATION for gap in self.gaps)

    @property
    def is_complete(self) -> bool:
        return not self.gaps

    def to_dict(self) -> Dict:
        """Serializable form for the JSON payload and reports."""
        return {
            "complete": self.is_complete,
            "has_detection_gap": self.has_detection_gap,
            "has_remediation_gap": self.has_remediation_gap,
            "gaps": list(self.gaps),
        }

    def messages(self) -> List[str]:
        return [gap["message"] for gap in self.gaps]


def coverage_notes(results: Dict, ai_ran: bool = False) -> List[str]:
    """State what this scan did not examine.

    Deliberately unconditional: these are the limits of the tool, not failures,
    and an evaluator should not have to infer them from an empty findings list.
    """
    notes = [
        "Findings are matched against advisory data; exploitability and runtime "
        "reachability are not proven.",
    ]

    scan_mode = results.get("scan_mode", "full")
    image_skipped = results.get("image_scan", {}).get("skipped", False)

    if image_skipped and scan_mode != "compose":
        notes.append(
            "No image was scanned, so operating-system and language package "
            "vulnerabilities were not checked. Pass -i <image> to include them."
        )
    if scan_mode == "image_only":
        notes.append(
            "Image-only scan: the Dockerfile was not analyzed for "
            "misconfigurations."
        )
    if scan_mode == "compose":
        notes.append(
            "Compose scan: services are analyzed individually. Cross-service "
            "exposure is not yet modeled."
        )
    if not ai_ran:
        notes.append(
            "AI analysis did not run, so there is no plain-English explanation "
            "or contextual remediation in this report."
        )

    notes.append("Secrets committed elsewhere in the build context are not scanned.")
    return notes


def build(
    results: Dict,
    dockerfile_errors: Optional[List[str]] = None,
    epss_enabled: bool = True,
    epss_annotated: int = 0,
    epss_candidates: int = 0,
) -> ScanCompleteness:
    """Derive the completeness record from a finished scan."""
    completeness = ScanCompleteness()

    for error in dockerfile_errors or []:
        completeness.detection_gap(
            "DOCKERFILE_SCANNER_FAILED",
            f"Dockerfile analysis is incomplete: {error}",
        )

    failed_services = results.get("failed_services") or []
    if failed_services:
        names = []
        for entry in failed_services:
            name = entry.get("service") if isinstance(entry, dict) else entry
            if name and name not in names:
                names.append(str(name))
        total = results.get("total_services")
        scope = f"{len(names)} of {total}" if isinstance(total, int) and total else str(len(names))
        completeness.detection_gap(
            "COMPOSE_SERVICE_SCAN_FAILED",
            f"{scope} compose service(s) could not be scanned "
            f"({', '.join(names)}); their images were not inspected.",
        )

    image_scan = results.get("image_scan", {})
    if not image_scan.get("skipped") and not image_scan.get("success"):
        completeness.detection_gap(
            "IMAGE_SCAN_FAILED",
            "The image vulnerability scan failed; package vulnerabilities may "
            "be missing from these results.",
        )

    # Remediation gaps: findings are known but acting on them is harder.
    vulnerabilities = results.get("json_data") or []
    unfixable = sum(
        1 for v in vulnerabilities
        if str(v.get("VulnerabilityID", "")).upper().startswith("CVE-")
        and not v.get("FixedVersion")
    )
    if unfixable:
        completeness.remediation_gap(
            "NO_FIXED_VERSION",
            f"{unfixable} finding(s) have no fixed version available upstream; "
            f"no upgrade will resolve them yet.",
        )

    if epss_enabled and epss_candidates and not epss_annotated:
        completeness.remediation_gap(
            "EPSS_UNAVAILABLE",
            "EPSS exploitation scores could not be retrieved, so findings are "
            "ranked by severity alone.",
        )

    return completeness
