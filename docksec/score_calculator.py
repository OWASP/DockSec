"""
Security Score Calculator Module

Computes the 0-100 security score from scan results. Deterministic by design:
identical inputs always produce an identical score, because a CI gate and a
compliance report both depend on that number.
"""

import re
from typing import Dict
from docksec.enums import Severity
from docksec.utils import get_custom_logger

# Initialize logger
logger = get_custom_logger(__name__)


# Version of the scoring model. Bumped whenever a change moves scores for
# unchanged inputs, so anything tracking the score over time can tell a model
# change from a real regression. Emitted as `score_version` in the JSON payload
# and the JSON report.
#
#   1: original additive model (through 2026.8.19)
#   2: severity-weighted with ceilings; unmeasured axes excluded; compose
#      misconfigurations scored on the configuration axis
SCORE_VERSION = 2


class SecurityScoreCalculator:
    """
    Calculates a deterministic security score for Docker images and Dockerfiles.

    Scoring does not call a model. It previously asked an LLM to "Score Docker
    security 1-100" from a count summary, so two runs over identical inputs
    could disagree - indefensible for a number a CI gate and a compliance report
    both depend on. The weighted breakdown below is the only path.
    """

    def __init__(self, skip_llm: bool = True):
        """Initialize the calculator.

        ``skip_llm`` is retained for call-site compatibility and has no effect:
        scoring is always local. It is accepted rather than removed so an
        existing caller does not break on an unexpected keyword.
        """
        logger.debug("Initializing SecurityScoreCalculator (deterministic)")

    def calculate_score(self, results: Dict) -> float:
        """Return the overall score for a scan result."""
        return self.get_score_breakdown(results)['overall']

    
    def get_score_breakdown(self, results: Dict) -> Dict[str, float]:
        """
        Get a detailed breakdown of the security score by category.
        
        Args:
            results: Scan results dictionary
            
        Returns:
            Dictionary with score breakdown by category:
                - 'dockerfile': Score for Dockerfile quality (0-100)
                - 'vulnerabilities': Score for vulnerability severity (0-100)
                - 'configuration': Score for security configuration (0-100)
                - 'overall': Overall security score (0-100)
        """
        logger.info("Calculating detailed score breakdown")

        breakdown = {
            'dockerfile': 0.0,
            'vulnerabilities': 0.0,
            'configuration': 0.0,
            'overall': 0.0
        }

        dockerfile_content = self._read_dockerfile(results.get('dockerfile_path', ''))
        vulnerabilities = results.get('json_data', [])
        image_scan_skipped = results.get('image_scan', {}).get('skipped', False)
        dockerfile_measured = self._dockerfile_was_scanned(results)

        # Dockerfile lint axis. Only scored when a Dockerfile was actually
        # linted: an unmeasured axis must not contribute a near-perfect score,
        # which is what let a compose stack with no Dockerfile score 95 here.
        if dockerfile_measured:
            breakdown['dockerfile'] = self._calculate_dockerfile_score(results)
        else:
            breakdown['dockerfile'] = None

        # Vulnerability axis. Scored whenever findings exist, or when an image
        # scan ran and legitimately found nothing.
        if vulnerabilities:
            breakdown['vulnerabilities'] = self._calculate_vulnerability_score(vulnerabilities)
        elif image_scan_skipped:
            breakdown['vulnerabilities'] = None
        else:
            breakdown['vulnerabilities'] = 100.0

        # Configuration axis: Dockerfile instructions plus compose
        # misconfiguration findings, so a compose-only scan is still scored on
        # its configuration rather than defaulting to a clean 100.
        breakdown['configuration'] = self._calculate_config_score(results, dockerfile_content)

        # Weighted average over the axes that were actually measured. Weights
        # are renormalized across the measured set so an unmeasured axis is
        # neither a free 100 nor a penalty.
        weights = {'dockerfile': 0.3, 'vulnerabilities': 0.5, 'configuration': 0.2}
        measured = {k: v for k, v in breakdown.items()
                    if k in weights and v is not None}
        total_weight = sum(weights[k] for k in measured)
        if total_weight > 0:
            breakdown['overall'] = sum(
                value * weights[key] for key, value in measured.items()
            ) / total_weight
        else:
            breakdown['overall'] = 0.0

        # Severity ceilings. A weighted average can rate a stack "fair" while it
        # ships an unambiguous compromise - a mounted Docker socket, a
        # privileged container, a plaintext password. These cap the overall
        # score so the headline number cannot contradict the findings list.
        ceiling = self._severity_ceiling(vulnerabilities, dockerfile_content)
        if ceiling is not None:
            breakdown['overall'] = min(breakdown['overall'], ceiling)

        # Unmeasured axes are reported as 0.0 rather than None so the payload
        # shape stays stable for existing consumers; `measured_axes` says which
        # numbers are real.
        breakdown['measured_axes'] = sorted(measured)
        for key in ('dockerfile', 'vulnerabilities', 'configuration'):
            if breakdown[key] is None:
                breakdown[key] = 0.0

        breakdown['overall'] = round(breakdown['overall'], 1)
        logger.info(f"Score breakdown: {breakdown}")
        return breakdown

    @staticmethod
    def _dockerfile_was_scanned(results: Dict) -> bool:
        """Whether a Dockerfile was actually linted in this run.

        The compose orchestrator sets `skipped` based on whether any lint output
        accumulated, so a compose run with no buildable services reports
        skipped=True. A missing dockerfile_path means there was nothing to lint.
        """
        scan = results.get('dockerfile_scan', {})
        if scan.get('skipped'):
            return False
        path = results.get('dockerfile_path') or ''
        if not path or path.startswith('N/A'):
            return False
        return True

    @staticmethod
    def _calculate_dockerfile_score(results: Dict) -> float:
        """Score the Dockerfile lint axis from Hadolint output.

        Counts only non-empty lines that look like findings, so blank lines and
        the compose orchestrator's '--- Service: x ---' separators do not read
        as additional issues.
        """
        scan = results.get('dockerfile_scan', {})
        if scan.get('success'):
            return 100.0
        output = scan.get('output') or ''
        issues = [
            line for line in output.splitlines()
            if line.strip() and not line.strip().startswith('---')
        ]
        return max(0.0, 100.0 - (len(issues) * 5))

    @staticmethod
    def _calculate_vulnerability_score(vulnerabilities: list) -> float:
        """Score the vulnerability axis so severity dominates volume.

        The previous purely additive model let fifteen LOW findings outweigh
        three CRITICALs. Two changes fix that ordering:

        - Deductions per severity are damped (square root of the count), so the
          first finding at a severity costs the most and the hundredth adds
          little. A long tail of LOW findings can no longer dominate.
        - Each severity present imposes a ceiling, so any CRITICAL caps this
          axis well below any number of LOW findings.
        """
        import math

        counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
        }
        for vuln in vulnerabilities:
            severity = str(vuln.get('Severity', '')).strip().upper()
            for level in counts:
                if severity == level.value:
                    counts[level] += 1
                    break

        # Per-finding cost at each severity, damped by count.
        scale = {
            Severity.CRITICAL: 30.0,
            Severity.HIGH: 15.0,
            Severity.MEDIUM: 6.0,
            Severity.LOW: 3.0,
        }
        deduction = sum(
            scale[level] * math.sqrt(count)
            for level, count in counts.items() if count
        )
        score = max(0.0, 100.0 - deduction)

        # Ceilings: the most severe finding present bounds this axis.
        if counts[Severity.CRITICAL]:
            score = min(score, 20.0)
        elif counts[Severity.HIGH]:
            score = min(score, 45.0)
        elif counts[Severity.MEDIUM]:
            score = min(score, 70.0)

        return score

    def _severity_ceiling(self, vulnerabilities: list, dockerfile_content: str):
        """Cap the overall score when a finding is severe on its own.

        Returns the ceiling, or None when nothing warrants one. Applies to both
        Dockerfile credentials and the compose rules that represent an
        unambiguous compromise of the container boundary.
        """
        ceiling = None

        def apply(value):
            nonlocal ceiling
            ceiling = value if ceiling is None else min(ceiling, value)

        if self._has_exposed_credentials(dockerfile_content):
            apply(20.0)

        rule_ids = {
            str(v.get('VulnerabilityID', '')).strip().lower()
            for v in vulnerabilities
        }

        # Container-escape-class misconfigurations: each grants host access or
        # removes the isolation boundary outright.
        if rule_ids & {
            'compose-docker-socket-mount',
            'compose-privileged',
            'compose-host-network',
            'compose-host-namespace',
            'compose-sensitive-host-mount',
            'compose-dangerous-capabilities',
        }:
            apply(15.0)

        # Plaintext credentials anywhere in the stack, not just a Dockerfile ENV.
        if 'compose-plaintext-secret-env' in rule_ids:
            apply(20.0)

        # Any CRITICAL finding keeps the headline number out of "fair" territory.
        if any(str(v.get('Severity', '')).strip().upper() == Severity.CRITICAL.value
               for v in vulnerabilities):
            apply(35.0)

        return ceiling

    @staticmethod
    def _read_dockerfile(dockerfile_path: str) -> str:
        """Read Dockerfile content for config scoring, or '' if unavailable."""
        if not dockerfile_path:
            return ''
        try:
            with open(dockerfile_path, 'r', encoding='utf-8', errors='ignore') as fh:
                return fh.read()
        except (OSError, IOError) as e:
            logger.debug("Could not read Dockerfile for config scoring: %s", e)
            return ''

    @staticmethod
    def _has_exposed_credentials(dockerfile_content: str) -> bool:
        """Check whether the Dockerfile sets a credential-looking ENV var."""
        if not dockerfile_content:
            return False
        credential_pattern = re.compile(
            r'^\s*ENV\s+\S*(?:PASSWORD|SECRET|API_KEY|TOKEN|PASSWD|PRIVATE_KEY|AUTH_KEY|ACCESS_KEY)\S*'
            r'\s*[=\s]\s*\S+',
            re.MULTILINE | re.IGNORECASE,
        )
        return bool(credential_pattern.search(dockerfile_content))

    # Compose misconfiguration rules that describe a configuration weakness, and
    # the points each deducts from the configuration axis. Keyed by rule ID so a
    # renamed rule fails loudly in tests rather than silently scoring zero.
    COMPOSE_CONFIG_PENALTIES = {
        'compose-docker-socket-mount': 40,
        'compose-privileged': 35,
        'compose-host-network': 30,
        'compose-host-namespace': 30,
        'compose-sensitive-host-mount': 30,
        'compose-dangerous-capabilities': 25,
        'compose-plaintext-secret-env': 30,
        'compose-disabled-security-opt': 20,
        'compose-port-bound-all-interfaces': 15,
        'compose-no-non-root-user': 15,
        'compose-env-file-secret-risk': 10,
        'compose-latest-or-untagged-image': 10,
        'compose-writable-root-fs': 5,
        'compose-no-new-privileges': 5,
        'compose-no-resource-limits': 5,
        'compose-missing-healthcheck': 5,
        'compose-no-network-segmentation': 5,
    }

    def _calculate_config_score(self, results: Dict, dockerfile_content: str = None) -> float:
        """
        Calculate a configuration security score from Dockerfile content,
        Hadolint output, and compose misconfiguration findings.

        Dockerfile checks (and points deducted):
            - Container running as root (no USER directive, or USER root/0): -25
            - Exposed credentials via ENV (password/secret/token/key patterns): -30
            - Mutable base image tag (:latest or no tag): -15
            - Missing HEALTHCHECK directive: -10
            - Sensitive port exposure (22, 3306, 5432, 27017): -10
            - ADD used instead of COPY (DL3020): -5
            - Privileged flag present: -20

        For a compose scan there is no single Dockerfile to read, so the axis is
        derived from the compose rule findings instead (see
        COMPOSE_CONFIG_PENALTIES). Without this a compose stack mounting the
        Docker socket scored a clean 100 on configuration.

        Args:
            results: Scan results dictionary containing 'dockerfile_path',
                     'dockerfile_scan', and 'json_data' keys.

        Returns:
            float: Configuration score between 0 and 100 (higher is better).
        """
        score = 100.0
        hadolint_output = results.get('dockerfile_scan', {}).get('output', '')

        if dockerfile_content is None:
            dockerfile_content = self._read_dockerfile(results.get('dockerfile_path', ''))

        content_lower = dockerfile_content.lower()

        # Compose misconfigurations. Each distinct rule is counted once, however
        # many services trip it: the weakness is a property of the stack's
        # configuration, and charging per service would let a large stack score
        # arbitrarily badly for a single mistake.
        compose_rules = {
            str(v.get('VulnerabilityID', '')).strip().lower()
            for v in results.get('json_data', [])
        }
        compose_deduction = sum(
            penalty for rule, penalty in self.COMPOSE_CONFIG_PENALTIES.items()
            if rule in compose_rules
        )
        if compose_deduction:
            logger.debug("Config score: compose misconfigurations (-%s)", compose_deduction)
            score -= compose_deduction

        # ------------------------------------------------------------------
        # Check 1: Running as root (-25 points)
        # A Dockerfile with no USER directive, or with USER root / USER 0,
        # runs the container process as root — the highest-risk misconfiguration.
        # ------------------------------------------------------------------
        if dockerfile_content:
            has_user = bool(re.search(r'^\s*USER\s+\S+', dockerfile_content, re.MULTILINE | re.IGNORECASE))
            explicit_root = bool(re.search(r'^\s*USER\s+(root|0)\s*$', dockerfile_content, re.MULTILINE | re.IGNORECASE))
            if not has_user or explicit_root:
                logger.debug("Config score: running as root detected (-25)")
                score -= 25
        elif 'DL3002' in hadolint_output or 'last user should not be root' in hadolint_output.lower():
            score -= 25

        # ------------------------------------------------------------------
        # Check 2: Exposed credentials in ENV (-30 points)
        # ENV instructions that set variables with names matching common
        # credential patterns and assign a non-empty value are flagged.
        # ------------------------------------------------------------------
        if self._has_exposed_credentials(dockerfile_content):
            logger.debug("Config score: exposed credentials in ENV detected (-30)")
            score -= 30

        # ------------------------------------------------------------------
        # Check 3: Mutable base image tag (-15 points)
        # :latest or a completely untagged FROM means the build is not
        # reproducible and may pull a future image with unknown vulnerabilities.
        # ------------------------------------------------------------------
        if dockerfile_content:
            if re.search(r'^\s*FROM\s+\S+:latest', dockerfile_content, re.MULTILINE | re.IGNORECASE):
                logger.debug("Config score: :latest base image tag detected (-15)")
                score -= 15
            elif re.search(r'^\s*FROM\s+[^\s:@]+\s*(?:#.*)?$', dockerfile_content, re.MULTILINE | re.IGNORECASE):
                # FROM with no tag and no digest
                logger.debug("Config score: untagged base image detected (-10)")
                score -= 10
        elif 'DL3007' in hadolint_output or 'using latest' in hadolint_output.lower():
            score -= 15

        # ------------------------------------------------------------------
        # Check 4: Missing HEALTHCHECK (-10 points)
        # Without a HEALTHCHECK, orchestrators cannot detect unhealthy
        # containers and restart them automatically.
        # ------------------------------------------------------------------
        if dockerfile_content and 'healthcheck' not in content_lower:
            logger.debug("Config score: HEALTHCHECK missing (-10)")
            score -= 10

        # ------------------------------------------------------------------
        # Check 5: Sensitive port exposure (-10 points)
        # Exposing ports associated with remote access or databases increases
        # the attack surface significantly.
        # ------------------------------------------------------------------
        sensitive_ports = {'22', '23', '3306', '5432', '27017', '6379', '9200'}
        if dockerfile_content:
            exposed = set(re.findall(r'^\s*EXPOSE\s+(\d+)', dockerfile_content, re.MULTILINE | re.IGNORECASE))
            if exposed & sensitive_ports:
                logger.debug("Config score: sensitive ports exposed %s (-10)", exposed & sensitive_ports)
                score -= 10

        # ------------------------------------------------------------------
        # Check 6: ADD instead of COPY (-5 points)
        # ADD has implicit tar-extraction and remote-URL fetch semantics that
        # make its behaviour harder to audit. COPY is always preferred for
        # local file copies (Hadolint DL3020).
        # ------------------------------------------------------------------
        if dockerfile_content and re.search(r'^\s*ADD\s+', dockerfile_content, re.MULTILINE | re.IGNORECASE):
            logger.debug("Config score: ADD used instead of COPY (-5)")
            score -= 5

        # ------------------------------------------------------------------
        # Check 7: Privileged flag (-20 points)
        # --privileged in a docker run comment or label is a strong signal
        # that the container requires elevated host access.
        # ------------------------------------------------------------------
        if '--privileged' in content_lower:
            logger.debug("Config score: --privileged flag detected (-20)")
            score -= 20

        final_score = max(0.0, score)
        logger.info("Configuration score: %.1f", final_score)
        return final_score

