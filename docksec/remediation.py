"""Copy-and-run fix commands, and an honest completion claim.

DockSec's output used to end at a severity table and a score. The user still had
to work out what to actually do. This module turns findings into instructions
that can be pasted or applied directly, and then states plainly how many
findings those instructions resolve - so the user knows when they are done, and
what is left over.

A fix is only emitted when it is concrete and derived from scan data. Where a
finding has no mechanical fix (no upstream version, a judgement call about
architecture), it is counted as unresolved rather than papered over with generic
advice.
"""

import re
from typing import Dict, List, Optional

from docksec.enums import Severity

# Dockerfile rules with a deterministic edit. Maps a rule ID to a short
# instruction and, where the change is mechanical enough to apply
# automatically, an edit kind that `--fix` can act on later.
#
# Keyed by both Trivy (DS***) and Hadolint (DL****) IDs because either scanner
# may be the one that reports a given issue.
DOCKERFILE_FIXES = {
    "DS002": ("Add a non-root USER before CMD/ENTRYPOINT", "add_user"),
    "DL3002": ("Add a non-root USER before CMD/ENTRYPOINT", "add_user"),
    "DS026": ("Add a HEALTHCHECK instruction", "add_healthcheck"),
    "DS001": ("Pin the base image to an explicit version instead of :latest", "pin_base_image"),
    "DL3007": ("Pin the base image to an explicit version instead of :latest", "pin_base_image"),
    "DS017": ("Combine 'apt-get update' with 'apt-get install' in one RUN layer", None),
    "DS029": ("Add --no-install-recommends to apt-get install", "apt_no_recommends"),
    "DL3015": ("Add --no-install-recommends to apt-get install", "apt_no_recommends"),
    "DL3008": ("Pin apt package versions (pkg=version)", None),
    "DL3009": ("Delete /var/lib/apt/lists after installing packages", None),
    "DL3013": ("Pin pip package versions (pkg==version)", None),
    "DL3016": ("Pin npm package versions (pkg@version)", None),
    "DL3003": ("Use WORKDIR instead of 'RUN cd'", None),
    "DL3020": ("Use COPY instead of ADD for local files", "add_to_copy"),
    "DS031": ("Move the secret out of ENV; inject it at runtime or use a build secret", None),
    "DL4006": ("Set SHELL with pipefail before using a pipe in RUN", None),
    "DL3059": ("Combine consecutive RUN instructions into one layer", None),
}

# Compose rules and the edit that resolves them.
COMPOSE_FIXES = {
    "compose-docker-socket-mount": "Remove the /var/run/docker.sock mount, or front it with a scoped socket proxy",
    "compose-privileged": "Remove 'privileged: true' and grant only the specific cap_add capabilities needed",
    "compose-host-network": "Remove 'network_mode: host' and publish only the ports required",
    "compose-host-namespace": "Remove 'pid: host' / 'ipc: host'",
    "compose-sensitive-host-mount": "Scope the bind mount to a specific subpath, read-only where possible",
    "compose-dangerous-capabilities": "Drop the added capability and grant least privilege",
    "compose-plaintext-secret-env": "Move the value to a Docker secret and reference it with a _FILE variable",
    "compose-disabled-security-opt": "Remove the 'unconfined' security_opt entry",
    "compose-port-bound-all-interfaces": "Bind the port to 127.0.0.1, or use 'expose' for internal-only traffic",
    "compose-no-non-root-user": "Set a non-root 'user:' on the service",
    "compose-latest-or-untagged-image": "Pin the image to an explicit version or digest",
    "compose-writable-root-fs": "Set 'read_only: true' and add tmpfs mounts where writes are needed",
    "compose-no-new-privileges": "Add 'no-new-privileges:true' to security_opt",
    "compose-no-resource-limits": "Set deploy.resources.limits for cpu and memory",
    "compose-missing-healthcheck": "Add a healthcheck to the service",
    "compose-env-file-secret-risk": "Keep the env_file out of version control and use a secret manager",
    "compose-no-network-segmentation": "Define separate networks and connect only services that must talk",
}


class FixPlan:
    """The set of actions that resolve a scan's findings."""

    def __init__(self):
        self.package_upgrades: List[Dict] = []
        self.dockerfile_edits: List[Dict] = []
        self.compose_edits: List[Dict] = []
        self.unresolved: List[Dict] = []

    @property
    def resolved_count(self) -> int:
        return (
            sum(item["finding_count"] for item in self.package_upgrades)
            + len(self.dockerfile_edits)
            + len(self.compose_edits)
        )

    @property
    def total_count(self) -> int:
        return self.resolved_count + len(self.unresolved)

    @property
    def is_empty(self) -> bool:
        return not (self.package_upgrades or self.dockerfile_edits or self.compose_edits)

    def completion_claim(self) -> str:
        """State what applying the plan achieves, including what it does not.

        The unresolved count is the honest half: a plan that claims to fix
        everything while leaving findings behind is worse than no claim.
        """
        if self.total_count == 0:
            return ""
        resolved = self.resolved_count
        if resolved == 0:
            return (
                f"No mechanical fix is available for the {self.total_count} "
                f"finding(s) above; each needs a judgement call."
            )
        if not self.unresolved:
            return (
                f"Applying all of the above resolves all {resolved} "
                f"finding(s)."
            )
        remaining = len(self.unresolved)
        verb = "has" if remaining == 1 else "have"
        return (
            f"Applying all of the above resolves {resolved} of "
            f"{self.total_count} finding(s); {remaining} {verb} no "
            f"mechanical fix yet."
        )


def _package_manager_hint(finding: Dict) -> Optional[str]:
    """Guess the package manager from a Trivy target string.

    Trivy names the target after the ecosystem it came from, so the upgrade
    command can be concrete rather than generic.
    """
    target = str(finding.get("Target") or "").lower()
    if any(token in target for token in ("debian", "ubuntu", "apt")):
        return "apt"
    if any(token in target for token in ("alpine", "apk")):
        return "apk"
    if any(token in target for token in ("redhat", "centos", "rocky", "alma", "amazon", "rpm")):
        return "yum"
    if "node" in target or "package-lock" in target or "yarn" in target:
        return "npm"
    if "python" in target or "pipfile" in target or "requirements" in target:
        return "pip"
    if "gobinary" in target or "go.mod" in target:
        return "go"
    return None


def _parse_version_key(version: str):
    """Sort key for version strings: numeric segments compared numerically.

    Good enough to pick the highest of a set of candidate fix versions, without
    taking on a full PEP 440 / semver dependency for a display concern.
    """
    return [
        int(part) if part.isdigit() else part
        for part in re.split(r"[.\-+~_]", version.strip())
        if part
    ]


def _best_fixed_version(raw: str) -> str:
    """Pick a single version from Trivy's FixedVersion field.

    Trivy reports every fixed version across an advisory's affected ranges, so
    for npm packages this arrives as "10.2.1, 9.0.6, 8.0.5, ...". Pasting the
    whole list produces a command that cannot run; the highest version is the
    one a user upgrading today wants.
    """
    candidates = [part.strip() for part in str(raw).split(",") if part.strip()]
    if len(candidates) <= 1:
        return candidates[0] if candidates else str(raw).strip()
    try:
        return max(candidates, key=_parse_version_key)
    except TypeError:
        # Mixed numeric/string segments are not orderable; fall back to the
        # first entry, which Trivy lists as the primary fix.
        return candidates[0]


def _upgrade_command(package: str, version: str, manager: Optional[str]) -> str:
    """Render a concrete upgrade command for the detected ecosystem."""
    if manager == "apt":
        return f"apt-get install --only-upgrade -y {package}={version}"
    if manager == "apk":
        return f"apk add --no-cache {package}={version}"
    if manager == "yum":
        return f"yum update -y {package}-{version}"
    if manager == "npm":
        return f"npm install {package}@{version}"
    if manager == "pip":
        return f"pip install --upgrade {package}=={version}"
    if manager == "go":
        return f"go get {package}@v{version.lstrip('v')}"
    # Unknown ecosystem: still say exactly what needs to change.
    return f"upgrade {package} to {version}"


def build_plan(findings: List[Dict], dockerfile_path: Optional[str] = None) -> FixPlan:
    """Turn findings into an ordered, deduplicated fix plan."""
    plan = FixPlan()

    # Package upgrades, grouped by package rather than by package+version.
    # Different CVEs against the same package report different fix versions, so
    # grouping by version produced eight separate `npm install tar@...` lines
    # for one package. One command per package, at the highest version any
    # finding requires, resolves them together.
    by_package: Dict[str, Dict] = {}
    for finding in findings:
        fixed_raw = finding.get("FixedVersion")
        package = finding.get("PkgName")
        if not fixed_raw or not package or package == "dockerfile":
            continue
        fixed = _best_fixed_version(fixed_raw)
        entry = by_package.setdefault(package, {
            "package": package,
            "installed": finding.get("InstalledVersion") or "current",
            "fixed": fixed,
            "manager": _package_manager_hint(finding),
            "severity": finding.get("Severity"),
            "finding_count": 0,
            "ids": [],
        })
        entry["finding_count"] += 1
        vuln_id = finding.get("VulnerabilityID")
        if vuln_id and len(entry["ids"]) < 3:
            entry["ids"].append(vuln_id)
        if Severity.rank(finding.get("Severity")) > Severity.rank(entry["severity"]):
            entry["severity"] = finding.get("Severity")
        # Upgrading once must satisfy every finding against this package.
        try:
            if _parse_version_key(fixed) > _parse_version_key(entry["fixed"]):
                entry["fixed"] = fixed
        except TypeError:
            pass

    for entry in by_package.values():
        entry["command"] = _upgrade_command(
            entry["package"], entry["fixed"], entry["manager"]
        )
        plan.package_upgrades.append(entry)
    plan.package_upgrades.sort(
        key=lambda e: (-Severity.rank(e["severity"]), e["package"])
    )

    # Dockerfile and compose edits, deduplicated by rule.
    seen_rules = set()
    for finding in findings:
        rule_id = str(finding.get("VulnerabilityID") or "")
        if not rule_id or rule_id in seen_rules:
            continue

        if rule_id in DOCKERFILE_FIXES:
            seen_rules.add(rule_id)
            instruction, edit_kind = DOCKERFILE_FIXES[rule_id]
            plan.dockerfile_edits.append({
                "rule": rule_id,
                "severity": finding.get("Severity"),
                "line": finding.get("Line"),
                "instruction": instruction,
                "edit_kind": edit_kind,
                "file": dockerfile_path or finding.get("Target"),
            })
        elif rule_id in COMPOSE_FIXES:
            seen_rules.add(rule_id)
            plan.compose_edits.append({
                "rule": rule_id,
                "severity": finding.get("Severity"),
                "instruction": COMPOSE_FIXES[rule_id],
                "service": _service_from_target(finding.get("Target")),
            })

    plan.dockerfile_edits.sort(key=lambda e: (-Severity.rank(e["severity"]), e["line"] or 0))
    plan.compose_edits.sort(key=lambda e: -Severity.rank(e["severity"]))

    # Anything with no mechanical fix. Package findings without a fixed version
    # and rules with no known edit both land here.
    for finding in findings:
        rule_id = str(finding.get("VulnerabilityID") or "")
        package = finding.get("PkgName")
        if rule_id in DOCKERFILE_FIXES or rule_id in COMPOSE_FIXES:
            continue
        if finding.get("FixedVersion") and package and package != "dockerfile":
            continue
        plan.unresolved.append({
            "id": rule_id,
            "severity": finding.get("Severity"),
            "title": finding.get("Title"),
        })

    return plan


def _service_from_target(target) -> Optional[str]:
    """Extract the service name from a compose finding's target.

    Compose findings encode location as ``file:service:line``.
    """
    if not target:
        return None
    parts = str(target).split(":")
    return parts[1] if len(parts) >= 3 else None


def suggest_base_image_pin(dockerfile_path: str) -> Optional[str]:
    """Read the Dockerfile and suggest a concrete FROM replacement.

    Only returns something when the base image genuinely uses a mutable tag, so
    the suggestion is never speculative.
    """
    try:
        with open(dockerfile_path, "r", encoding="utf-8", errors="ignore") as handle:
            content = handle.read()
    except OSError:
        return None

    match = re.search(
        r"^\s*FROM\s+(?P<image>[^\s:@]+)(?::(?P<tag>[^\s@]+))?",
        content, re.MULTILINE | re.IGNORECASE,
    )
    if not match:
        return None

    image = match.group("image")
    tag = match.group("tag")
    if tag and tag != "latest":
        return None
    return (
        f"FROM {image}:<explicit-version>   "
        f"# replace '{image}{':' + tag if tag else ''}' with a pinned tag or digest"
    )
