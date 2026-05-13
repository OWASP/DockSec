"""
Security Score Calculator Module

This module handles the calculation of security scores based on scan results.
It uses LLM-based analysis to provide comprehensive security scoring.
"""

import logging
import re
from typing import Dict
from docksec.config import docker_score_prompt
from docksec.utils import ScoreResponse, get_llm, get_custom_logger

# Initialize logger
logger = get_custom_logger(__name__)


class SecurityScoreCalculator:
    """
    Calculates security scores for Docker images and Dockerfiles.
    
    Uses LLM-based analysis to evaluate security posture based on:
    - Vulnerability severity and count
    - Dockerfile best practices
    - Security misconfigurations
    - CVE scores
    """
    
    def __init__(self):
        """Initialize the security score calculator with LLM chain."""
        logger.info("Initializing SecurityScoreCalculator")
        llm = get_llm()
        self.score_chain = docker_score_prompt | llm.with_structured_output(
            ScoreResponse, 
            method="json_mode"
        )
    
    def calculate_score(self, results: Dict) -> float:
        """
        Calculate the security score based on scan results.
        
        This method analyzes:
        - Dockerfile scan results (linting issues)
        - Image vulnerability scan results
        - Vulnerability severities and counts
        - Overall security posture
        
        Args:
            results: Dictionary containing scan results with keys:
                - 'dockerfile_scan': Dockerfile linting results
                - 'image_scan': Image vulnerability results
                - 'json_data': Structured vulnerability data
                - 'timestamp': Scan timestamp
                - 'image_name': Docker image name
                - 'dockerfile_path': Path to Dockerfile
        
        Returns:
            float: Security score between 0-100 (higher is better)
            
        Raises:
            Exception: If LLM call fails or score calculation errors occur
        """
        logger.info("Calculating security score from scan results")
        
        try:
            # Invoke LLM with scan results
            score_response = self.score_chain.invoke({"results": results})
            score = score_response.score
            
            logger.info(f"Security score calculated: {score}")
            print(f"Security Score: {score}/100")
            
            # Provide contextual feedback based on score
            if score >= 90:
                print("[EXCELLENT] Excellent security posture!")
            elif score >= 70:
                print("[GOOD] Good security, but some improvements recommended")
            elif score >= 50:
                print("[FAIR] Fair security - multiple issues need attention")
            else:
                print("[POOR] Poor security - immediate action required")
            
            return score
            
        except Exception as e:
            logger.error(f"Error calculating security score: {e}", exc_info=True)
            print(f"\n[ERROR] Error calculating security score: {e}")
            print("\nTroubleshooting:")
            print("  1. Check your OpenAI API key and credits")
            print("  2. Verify network connectivity")
            print("  3. Review scan results format")
            # Return a default score in case of error
            logger.warning("Returning default score of 0 due to calculation error")
            return 0.0
    
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
        
        # Calculate Dockerfile score (based on linting results)
        if results.get('dockerfile_scan', {}).get('success', False):
            breakdown['dockerfile'] = 100.0
        else:
            # Deduct based on number of issues (simplified logic)
            output = results.get('dockerfile_scan', {}).get('output', '')
            issue_count = len(output.split('\n')) if output else 0
            breakdown['dockerfile'] = max(0, 100 - (issue_count * 5))
        
        # Calculate vulnerability score
        vulnerabilities = results.get('json_data', [])
        if not vulnerabilities:
            breakdown['vulnerabilities'] = 100.0
        else:
            # Weighted by severity
            critical_count = sum(1 for v in vulnerabilities if v.get('Severity') == 'CRITICAL')
            high_count = sum(1 for v in vulnerabilities if v.get('Severity') == 'HIGH')
            medium_count = sum(1 for v in vulnerabilities if v.get('Severity') == 'MEDIUM')
            low_count = sum(1 for v in vulnerabilities if v.get('Severity') == 'LOW')
            
            # Simplified scoring: deduct more for higher severity
            deduction = (critical_count * 10) + (high_count * 5) + (medium_count * 2) + (low_count * 1)
            breakdown['vulnerabilities'] = max(0, 100 - deduction)
        
        # Configuration score derived from actual Dockerfile analysis
        breakdown['configuration'] = self._calculate_config_score(results)

        # Overall score (weighted average)
        breakdown['overall'] = (
            breakdown['dockerfile'] * 0.3 +
            breakdown['vulnerabilities'] * 0.5 +
            breakdown['configuration'] * 0.2
        )

        logger.info(f"Score breakdown: {breakdown}")
        return breakdown

    def _calculate_config_score(self, results: Dict) -> float:
        """
        Calculate a configuration security score from Dockerfile content and
        Hadolint output.

        Checks performed (and points deducted):
            - Container running as root (no USER directive, or USER root/0): -25
            - Exposed credentials via ENV (password/secret/token/key patterns): -30
            - Mutable base image tag (:latest or no tag): -15
            - Missing HEALTHCHECK directive: -10
            - Sensitive port exposure (22, 3306, 5432, 27017): -10
            - ADD used instead of COPY (DL3020): -5
            - Privileged flag present: -20

        Args:
            results: Scan results dictionary containing 'dockerfile_path' and
                     'dockerfile_scan' keys.

        Returns:
            float: Configuration score between 0 and 100 (higher is better).
        """
        score = 100.0
        dockerfile_path = results.get('dockerfile_path', '')
        hadolint_output = results.get('dockerfile_scan', {}).get('output', '')

        # Read the Dockerfile content if a path is available
        dockerfile_content = ''
        if dockerfile_path:
            try:
                with open(dockerfile_path, 'r', encoding='utf-8', errors='ignore') as fh:
                    dockerfile_content = fh.read()
            except (OSError, IOError) as e:
                logger.debug("Could not read Dockerfile for config scoring: %s", e)

        content_lower = dockerfile_content.lower()

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
        if dockerfile_content:
            credential_pattern = re.compile(
                r'^\s*ENV\s+\S*(?:PASSWORD|SECRET|API_KEY|TOKEN|PASSWD|PRIVATE_KEY|AUTH_KEY|ACCESS_KEY)\S*'
                r'\s*[=\s]\s*\S+',
                re.MULTILINE | re.IGNORECASE,
            )
            if credential_pattern.search(dockerfile_content):
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

