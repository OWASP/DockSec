"""Tests for the security score.

The score is the headline number a user sees, so the properties asserted here
are mostly about ordering and ceilings rather than exact values: a stack that
mounts the Docker socket must never outrank a clean one, however the weights are
later retuned.
"""

import unittest

from docksec.score_calculator import SecurityScoreCalculator


def _results(vulnerabilities=None, dockerfile_path="N/A - compose",
             dockerfile_skipped=True, image_skipped=True,
             dockerfile_output="", dockerfile_success=True):
    """Build a minimal results dict in the shape the scanner produces."""
    return {
        "dockerfile_scan": {
            "success": dockerfile_success,
            "output": dockerfile_output,
            "skipped": dockerfile_skipped,
        },
        "image_scan": {
            "success": True,
            "output": "",
            "skipped": image_skipped,
        },
        "json_data": vulnerabilities or [],
        "dockerfile_path": dockerfile_path,
    }


def _finding(severity, rule_id="CVE-0000-0000"):
    return {"Severity": severity, "VulnerabilityID": rule_id}


class TestSeverityDominatesVolume(unittest.TestCase):
    """Severity must outweigh finding count.

    The previous model deducted a flat amount per finding, so fifteen LOW
    findings (15 points) outscored three CRITICALs (30 points) only narrowly and
    fifty LOWs beat them outright. Severity now dominates.
    """

    def setUp(self):
        self.calc = SecurityScoreCalculator(skip_llm=True)

    def _score(self, vulnerabilities):
        results = _results(vulnerabilities, image_skipped=False)
        return self.calc.get_score_breakdown(results)["overall"]

    def test_one_critical_scores_worse_than_many_lows(self):
        one_critical = self._score([_finding("CRITICAL")])
        fifty_lows = self._score([_finding("LOW", f"CVE-{i}") for i in range(50)])
        self.assertLess(
            one_critical, fifty_lows,
            "a single CRITICAL must score worse than fifty LOW findings",
        )

    def test_score_is_monotonic_by_severity(self):
        scores = [self._score([_finding(level)])
                  for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")]
        self.assertEqual(
            scores, sorted(scores, reverse=True),
            f"scores must fall as severity rises, got {scores}",
        )

    def test_more_findings_at_a_severity_never_improve_the_score(self):
        few = self._score([_finding("HIGH", f"CVE-{i}") for i in range(2)])
        many = self._score([_finding("HIGH", f"CVE-{i}") for i in range(20)])
        self.assertLessEqual(many, few)

    def test_clean_scan_scores_full_marks(self):
        self.assertEqual(self._score([]), 100.0)


class TestUnmeasuredAxes(unittest.TestCase):
    """An axis that was not evaluated must not contribute a score.

    A compose stack has no single Dockerfile, but the Dockerfile axis used to
    fall through to a near-perfect 95 and drag the overall score up with it.
    """

    def setUp(self):
        self.calc = SecurityScoreCalculator(skip_llm=True)

    def test_dockerfile_axis_is_not_scored_without_a_dockerfile(self):
        breakdown = self.calc.get_score_breakdown(_results())
        self.assertNotIn("dockerfile", breakdown["measured_axes"])

    def test_dockerfile_axis_is_scored_when_one_was_linted(self):
        results = _results(
            dockerfile_path="Dockerfile",
            dockerfile_skipped=False,
            dockerfile_success=True,
        )
        breakdown = self.calc.get_score_breakdown(results)
        self.assertIn("dockerfile", breakdown["measured_axes"])

    def test_vulnerability_axis_is_not_scored_when_no_image_was_scanned(self):
        breakdown = self.calc.get_score_breakdown(_results(image_skipped=True))
        self.assertNotIn("vulnerabilities", breakdown["measured_axes"])

    def test_vulnerability_axis_counts_when_an_image_scan_found_nothing(self):
        breakdown = self.calc.get_score_breakdown(_results(image_skipped=False))
        self.assertIn("vulnerabilities", breakdown["measured_axes"])
        self.assertEqual(breakdown["vulnerabilities"], 100.0)

    def test_service_separators_are_not_counted_as_lint_issues(self):
        """The compose orchestrator joins per-service output with '--- Service: x ---'
        separators; those lines are not findings."""
        results = _results(
            dockerfile_path="Dockerfile",
            dockerfile_skipped=False,
            dockerfile_success=False,
            dockerfile_output="--- Service: web ---\n\nDL3002 warning: root\n",
        )
        breakdown = self.calc.get_score_breakdown(results)
        self.assertEqual(breakdown["dockerfile"], 95.0)


class TestSeverityCeilings(unittest.TestCase):
    """Unambiguous compromises cap the headline number.

    Without ceilings a weighted average rates a socket-mounted, privileged,
    host-networked stack as merely "fair".
    """

    def setUp(self):
        self.calc = SecurityScoreCalculator(skip_llm=True)

    def _score(self, rule_id, severity="CRITICAL"):
        return self.calc.get_score_breakdown(
            _results([_finding(severity, rule_id)])
        )["overall"]

    def test_container_escape_rules_cap_the_score(self):
        for rule in (
            "compose-docker-socket-mount",
            "compose-privileged",
            "compose-host-network",
            "compose-host-namespace",
            "compose-sensitive-host-mount",
            "compose-dangerous-capabilities",
        ):
            with self.subTest(rule=rule):
                self.assertLessEqual(
                    self._score(rule), 15.0,
                    f"{rule} grants host access and must cap the score",
                )

    def test_compose_plaintext_secret_caps_the_score(self):
        """The credential cap used to inspect only Dockerfile ENV, so a compose
        file with a plaintext password was never capped."""
        self.assertLessEqual(
            self._score("compose-plaintext-secret-env", severity="HIGH"), 20.0
        )

    def test_any_critical_finding_caps_the_score(self):
        self.assertLessEqual(self._score("CVE-2024-99999"), 35.0)

    def test_ceilings_are_keyed_to_real_rule_ids(self):
        """Guards against a rule rename silently disabling a ceiling."""
        from docksec.compose_scanner import ComposeScanner

        source = open(ComposeScanner.__module__.replace(".", "/") + ".py").read()
        for rule in SecurityScoreCalculator.COMPOSE_CONFIG_PENALTIES:
            with self.subTest(rule=rule):
                self.assertIn(
                    f'"{rule}"', source,
                    f"{rule} is scored but no longer emitted by the scanner",
                )


class TestComposeConfigurationAxis(unittest.TestCase):
    """Compose misconfigurations must reach the configuration axis.

    It previously read Dockerfile content only, so a compose-only scan always
    scored a clean 100 on configuration no matter what the stack did.
    """

    def setUp(self):
        self.calc = SecurityScoreCalculator(skip_llm=True)

    def test_compose_findings_reduce_the_configuration_score(self):
        clean = self.calc.get_score_breakdown(_results())["configuration"]
        dirty = self.calc.get_score_breakdown(
            _results([_finding("CRITICAL", "compose-docker-socket-mount")])
        )["configuration"]
        self.assertEqual(clean, 100.0)
        self.assertLess(dirty, clean)

    def test_a_rule_is_charged_once_regardless_of_service_count(self):
        """The weakness is a property of the configuration; charging per service
        would let a large stack score arbitrarily badly for one mistake."""
        one = self.calc.get_score_breakdown(
            _results([_finding("MEDIUM", "compose-no-non-root-user")])
        )["configuration"]
        five = self.calc.get_score_breakdown(
            _results([_finding("MEDIUM", "compose-no-non-root-user")] * 5)
        )["configuration"]
        self.assertEqual(one, five)


class TestBundledExamples(unittest.TestCase):
    """End-to-end regression on the examples shipped with the project.

    These are what an evaluator runs first, so their scores are part of the
    product. The insecure stack scored 60.5/100 "FAIR" before this change.
    """

    @classmethod
    def setUpClass(cls):
        from docksec.compose_scanner import ComposeScanner
        cls.ComposeScanner = ComposeScanner

    def _score_compose(self, path):
        scanner = self.ComposeScanner(path)
        self.assertTrue(scanner.parse(), f"failed to parse {path}")
        findings = scanner.scan()
        calc = SecurityScoreCalculator(skip_llm=True)
        results = _results(findings, dockerfile_path=path)
        return calc.get_score_breakdown(results)["overall"], findings

    def test_insecure_example_scores_poorly(self):
        score, findings = self._score_compose(
            "examples/compose/docker-compose-insecure.yml"
        )
        self.assertLess(
            score, 25.0,
            f"a stack with a mounted Docker socket, privileged: true, host "
            f"networking and plaintext passwords scored {score}",
        )
        self.assertTrue(findings)

    def test_secure_example_scores_well(self):
        score, _ = self._score_compose(
            "examples/compose/docker-compose-secure.yml"
        )
        self.assertGreater(
            score, 70.0,
            f"the hardened example scored {score}; a secure stack must not be "
            f"penalized or the score carries no signal",
        )

    def test_secure_example_outranks_insecure_example(self):
        secure, _ = self._score_compose(
            "examples/compose/docker-compose-secure.yml"
        )
        insecure, _ = self._score_compose(
            "examples/compose/docker-compose-insecure.yml"
        )
        self.assertGreater(secure, insecure)


class TestScoreVersion(unittest.TestCase):
    """The scoring model is versioned in machine-readable output.

    Changing the model moves scores for unchanged inputs, which looks like a
    regression to anything tracking the number over time. `score_version` lets a
    consumer tell the two apart.
    """

    def test_json_report_carries_the_score_version(self):
        from docksec.report_generator import ReportGenerator
        from docksec.score_calculator import SCORE_VERSION
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            generator = ReportGenerator("test-image", tmp)
            generator.set_analysis_score(42.0)
            path = generator.generate_json_report(_results())
            with open(path) as handle:
                payload = json.load(handle)

        self.assertEqual(payload["scan_info"]["score_version"], SCORE_VERSION)

    def test_score_version_is_at_least_two(self):
        """Guards against the constant being reverted alongside the model."""
        from docksec.score_calculator import SCORE_VERSION

        self.assertGreaterEqual(SCORE_VERSION, 2)


class TestSecretFileIndirection(unittest.TestCase):
    """`*_FILE` variables hold a path to a secret, not a secret.

    POSTGRES_PASSWORD_FILE=/run/secrets/db_password is the Docker secrets
    pattern - the recommended alternative to a plaintext value - and flagging it
    penalized the hardened example for doing the right thing.
    """

    def setUp(self):
        from docksec.compose_scanner import ComposeScanner
        self.scanner = ComposeScanner.__new__(ComposeScanner)

    def test_secret_file_indirection_is_not_flagged(self):
        for key in ("POSTGRES_PASSWORD_FILE", "API_KEY_FILE", "DB_SECRET_PATH"):
            with self.subTest(key=key):
                self.assertFalse(self.scanner._is_secret_key(key))

    def test_plain_secret_keys_are_still_flagged(self):
        for key in ("POSTGRES_PASSWORD", "DB_PASSWORD", "API_KEY", "AUTH_TOKEN"):
            with self.subTest(key=key):
                self.assertTrue(self.scanner._is_secret_key(key))


if __name__ == "__main__":
    unittest.main()
