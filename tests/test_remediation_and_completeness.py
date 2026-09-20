"""Tests for the fix plan and the completeness record.

Together these turn "here is a severity table" into "here is what to run, and
here is what I could not check".
"""

import unittest

from docksec import completeness as completeness_mod
from docksec.remediation import (
    _best_fixed_version,
    _upgrade_command,
    build_plan,
)


def _vuln(pkg, installed, fixed, severity="HIGH", vuln_id="CVE-0000-0001", target="debian"):
    return {
        "VulnerabilityID": vuln_id, "PkgName": pkg, "InstalledVersion": installed,
        "FixedVersion": fixed, "Severity": severity, "Target": target,
    }


def _rule(rule_id, severity="HIGH", line=None, target="Dockerfile"):
    return {
        "VulnerabilityID": rule_id, "PkgName": "dockerfile", "Severity": severity,
        "Line": line, "Target": target, "Title": rule_id,
    }


class TestFixedVersionSelection(unittest.TestCase):
    """Trivy reports every fixed version across an advisory's ranges, so npm
    findings arrive as "10.2.1, 9.0.6, 8.0.5, ...". Pasting the list produces a
    command that cannot run."""

    def test_single_version_passes_through(self):
        self.assertEqual(_best_fixed_version("1.2.3"), "1.2.3")

    def test_highest_of_several_is_chosen(self):
        self.assertEqual(
            _best_fixed_version("10.2.1, 9.0.6, 8.0.5, 7.4.7, 3.1.3"), "10.2.1"
        )

    def test_numeric_segments_compare_numerically(self):
        """String comparison would rank 9.0.6 above 10.2.1."""
        self.assertEqual(_best_fixed_version("9.0.6, 10.2.1"), "10.2.1")

    def test_debian_style_versions_are_handled(self):
        self.assertEqual(
            _best_fixed_version("1.5.2-6+deb12u1, 1.5.2-6+deb12u2"),
            "1.5.2-6+deb12u2",
        )


class TestUpgradeCommands(unittest.TestCase):
    def test_commands_are_runnable_per_ecosystem(self):
        cases = {
            "apt": "apt-get install --only-upgrade -y openssl=1.1.1w",
            "apk": "apk add --no-cache openssl=1.1.1w",
            "npm": "npm install openssl@1.1.1w",
            "pip": "pip install --upgrade openssl==1.1.1w",
        }
        for manager, expected in cases.items():
            with self.subTest(manager=manager):
                self.assertEqual(_upgrade_command("openssl", "1.1.1w", manager), expected)

    def test_unknown_ecosystem_still_states_the_change(self):
        command = _upgrade_command("openssl", "1.1.1w", None)
        self.assertIn("openssl", command)
        self.assertIn("1.1.1w", command)


class TestFixPlan(unittest.TestCase):
    def test_one_command_per_package_not_per_cve(self):
        """Eight CVEs against tar produced eight `npm install tar@...` lines."""
        findings = [
            _vuln("tar", "6.2.1", "7.5.3", vuln_id="CVE-1", target="node-pkg"),
            _vuln("tar", "6.2.1", "7.5.21", vuln_id="CVE-2", target="node-pkg"),
            _vuln("tar", "6.2.1", "7.5.10", vuln_id="CVE-3", target="node-pkg"),
        ]
        plan = build_plan(findings)
        self.assertEqual(len(plan.package_upgrades), 1)
        # One upgrade must satisfy every finding against the package.
        self.assertEqual(plan.package_upgrades[0]["fixed"], "7.5.21")
        self.assertEqual(plan.package_upgrades[0]["finding_count"], 3)

    def test_dockerfile_rules_produce_edits(self):
        plan = build_plan([_rule("DS002", line=7), _rule("DS026", "LOW")])
        rules = [edit["rule"] for edit in plan.dockerfile_edits]
        self.assertIn("DS002", rules)
        self.assertIn("DS026", rules)

    def test_compose_rules_produce_edits(self):
        finding = _rule("compose-privileged", "CRITICAL", target="compose.yml:db:4")
        plan = build_plan([finding])
        self.assertEqual(len(plan.compose_edits), 1)
        self.assertEqual(plan.compose_edits[0]["service"], "db")

    def test_edits_are_deduplicated_by_rule(self):
        """A rule firing on three services is still one change to make."""
        findings = [_rule("compose-no-non-root-user", target=f"c.yml:svc{i}:1") for i in range(3)]
        self.assertEqual(len(build_plan(findings).compose_edits), 1)

    def test_findings_without_a_mechanical_fix_are_counted_unresolved(self):
        findings = [
            _vuln("zlib", "1.2.11", None, vuln_id="CVE-NOFIX"),
            _vuln("openssl", "1.1.1", "1.1.1w", vuln_id="CVE-FIX"),
        ]
        plan = build_plan(findings)
        self.assertEqual(len(plan.unresolved), 1)
        self.assertEqual(plan.unresolved[0]["id"], "CVE-NOFIX")

    def test_edits_are_ordered_by_severity(self):
        plan = build_plan([_rule("DS026", "LOW"), _rule("DS002", "HIGH"), _rule("DS031", "CRITICAL")])
        severities = [edit["severity"] for edit in plan.dockerfile_edits]
        self.assertEqual(severities, ["CRITICAL", "HIGH", "LOW"])


class TestCompletionClaim(unittest.TestCase):
    """The user needs to know when they are done, and what is left."""

    def test_claim_when_everything_is_fixable(self):
        plan = build_plan([_vuln("openssl", "1.1.1", "1.1.1w")])
        self.assertIn("resolves all 1", plan.completion_claim())

    def test_claim_names_the_remainder(self):
        plan = build_plan([
            _vuln("openssl", "1.1.1", "1.1.1w", vuln_id="CVE-A"),
            _vuln("zlib", "1.2.11", None, vuln_id="CVE-B"),
        ])
        claim = plan.completion_claim()
        self.assertIn("resolves 1 of 2", claim)
        self.assertIn("1 has no", claim)

    def test_claim_pluralizes_correctly(self):
        plan = build_plan([
            _vuln("openssl", "1.1.1", "1.1.1w", vuln_id="CVE-A"),
            _vuln("zlib", "1.2.11", None, vuln_id="CVE-B"),
            _vuln("curl", "7.0", None, vuln_id="CVE-C"),
        ])
        self.assertIn("2 have no", plan.completion_claim())

    def test_no_claim_when_there_are_no_findings(self):
        self.assertEqual(build_plan([]).completion_claim(), "")

    def test_claim_is_honest_when_nothing_is_fixable(self):
        plan = build_plan([_vuln("zlib", "1.2.11", None, vuln_id="CVE-B")])
        self.assertIn("No mechanical fix", plan.completion_claim())


class TestCompleteness(unittest.TestCase):
    """A scanner that hides its blind spots cannot be trusted as a merge gate."""

    def test_clean_scan_is_complete(self):
        results = {
            "json_data": [], "image_scan": {"skipped": False, "success": True},
            "scan_mode": "image_only",
        }
        record = completeness_mod.build(results)
        self.assertTrue(record.is_complete)
        self.assertFalse(record.has_detection_gap)

    def test_failed_compose_services_are_a_detection_gap(self):
        results = {
            "json_data": [],
            "image_scan": {"skipped": True},
            "failed_services": [{"service": "web"}, {"service": "db"}],
            "total_services": 2,
        }
        record = completeness_mod.build(results)
        self.assertTrue(record.has_detection_gap)
        self.assertIn("2 of 2", " ".join(record.messages()))

    def test_scanner_error_is_a_detection_gap(self):
        record = completeness_mod.build(
            {"json_data": [], "image_scan": {"skipped": True}},
            dockerfile_errors=["Hadolint not found in PATH"],
        )
        self.assertTrue(record.has_detection_gap)

    def test_unfixable_findings_are_a_remediation_gap_not_a_detection_gap(self):
        """The findings list is complete; only the advice attached to it is
        short."""
        results = {
            "json_data": [
                {"VulnerabilityID": "CVE-1", "FixedVersion": None},
                {"VulnerabilityID": "CVE-2", "FixedVersion": None},
            ],
            "image_scan": {"skipped": False, "success": True},
        }
        record = completeness_mod.build(results)
        self.assertTrue(record.has_remediation_gap)
        self.assertFalse(record.has_detection_gap)

    def test_epss_failure_is_a_remediation_gap(self):
        record = completeness_mod.build(
            {"json_data": [], "image_scan": {"skipped": False, "success": True}},
            epss_enabled=True, epss_annotated=0, epss_candidates=5,
        )
        self.assertTrue(record.has_remediation_gap)

    def test_disabled_epss_is_not_a_gap(self):
        """Opting out is a choice, not a shortfall."""
        record = completeness_mod.build(
            {"json_data": [], "image_scan": {"skipped": False, "success": True}},
            epss_enabled=False, epss_annotated=0, epss_candidates=5,
        )
        self.assertFalse(record.has_remediation_gap)

    def test_serialized_form_carries_the_flags(self):
        record = completeness_mod.build(
            {"json_data": [], "image_scan": {"skipped": True}},
            dockerfile_errors=["boom"],
        )
        payload = record.to_dict()
        self.assertFalse(payload["complete"])
        self.assertTrue(payload["has_detection_gap"])
        self.assertTrue(payload["gaps"])

    def test_coverage_notes_state_limits_unconditionally(self):
        """These are the tool's standing limits, not failures - an evaluator
        should not have to infer scope from an empty findings list."""
        notes = completeness_mod.coverage_notes(
            {"scan_mode": "image_only", "image_scan": {"skipped": False}}, ai_ran=False
        )
        joined = " ".join(notes)
        self.assertIn("reachability", joined)
        self.assertIn("Dockerfile was not analyzed", joined)
        self.assertIn("AI analysis did not run", joined)

    def test_coverage_notes_drop_the_ai_note_when_ai_ran(self):
        notes = completeness_mod.coverage_notes(
            {"scan_mode": "full", "image_scan": {"skipped": False}}, ai_ran=True
        )
        self.assertNotIn("AI analysis did not run", " ".join(notes))


if __name__ == "__main__":
    unittest.main()
