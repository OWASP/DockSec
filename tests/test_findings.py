"""Tests for structured Dockerfile findings.

Hadolint output was a text blob excluded from the gate, SARIF, and --json, and
Trivy's config scanner was not run at all - so CI could pass on a root-user,
secret-carrying Dockerfile.
"""

import json
import unittest

from docksec.findings import (
    HADOLINT_SEVERITY,
    HADOLINT_TRIVY_COLLISIONS,
    deduplicate,
    parse_hadolint_json,
    parse_trivy_config_json,
    summarize,
)


def _hadolint(code, level="warning", line=1, message="msg"):
    return {"code": code, "level": level, "line": line, "message": message,
            "file": "Dockerfile", "column": 1}


def _trivy_result(misconfigs, target="Dockerfile"):
    return json.dumps({"Results": [{"Target": target, "Misconfigurations": misconfigs}]})


def _misconfig(rule_id, severity="HIGH", line=None, title="t", resolution="fix it"):
    return {
        "ID": rule_id,
        "AVDID": f"AVD-{rule_id}",
        "Title": title,
        "Description": "d",
        "Severity": severity,
        "Resolution": resolution,
        "PrimaryURL": f"https://avd.aquasec.com/misconfig/{rule_id.lower()}",
        "CauseMetadata": {"StartLine": line} if line else {},
    }


class TestHadolintParsing(unittest.TestCase):
    def test_findings_use_the_shared_shape(self):
        """Report writers, the score calculator, waivers, and the SARIF mapper
        all read one shape; a Dockerfile finding must not need special cases."""
        findings = parse_hadolint_json(json.dumps([_hadolint("DL3002")]), "Dockerfile")
        self.assertEqual(len(findings), 1)
        for key in ("VulnerabilityID", "Severity", "Title", "Target", "PkgName"):
            self.assertIn(key, findings[0])

    def test_severity_mapping_is_conservative(self):
        """Hadolint reports lint levels. Inflating them into HIGH is how a gate
        gets switched off."""
        self.assertEqual(HADOLINT_SEVERITY["error"], "HIGH")
        self.assertEqual(HADOLINT_SEVERITY["warning"], "MEDIUM")
        self.assertEqual(HADOLINT_SEVERITY["info"], "LOW")
        self.assertEqual(HADOLINT_SEVERITY["style"], "LOW")

    def test_unknown_level_falls_back_to_low(self):
        findings = parse_hadolint_json(
            json.dumps([_hadolint("DL9999", level="mystery")]), "Dockerfile"
        )
        self.assertEqual(findings[0]["Severity"], "LOW")

    def test_line_numbers_are_preserved(self):
        findings = parse_hadolint_json(json.dumps([_hadolint("DL3002", line=7)]), "Dockerfile")
        self.assertEqual(findings[0]["Line"], 7)

    def test_empty_and_malformed_input_are_survivable(self):
        for raw in ("", "   ", "[]", "not json", '{"not": "a list"}'):
            with self.subTest(raw=raw):
                self.assertEqual(parse_hadolint_json(raw, "Dockerfile"), [])


class TestTrivyConfigParsing(unittest.TestCase):
    def test_severity_and_resolution_are_carried(self):
        raw = _trivy_result([_misconfig("DS002", "HIGH", 7, resolution="Add USER")])
        findings = parse_trivy_config_json(raw, "Dockerfile")
        self.assertEqual(findings[0]["Severity"], "HIGH")
        self.assertEqual(findings[0]["Remediation"], "Add USER")
        self.assertEqual(findings[0]["Line"], 7)

    def test_missing_line_is_none_not_zero(self):
        """Whole-file rules such as DS026 have no line; 0 would render as a real
        position."""
        raw = _trivy_result([_misconfig("DS026", "LOW")])
        self.assertIsNone(parse_trivy_config_json(raw, "Dockerfile")[0]["Line"])

    def test_results_for_other_files_are_filtered_out(self):
        """trivy config scans a directory, so it can report on files beside the
        Dockerfile."""
        payload = json.dumps({"Results": [
            {"Target": "Dockerfile", "Misconfigurations": [_misconfig("DS002")]},
            {"Target": "other.yaml", "Misconfigurations": [_misconfig("DS999")]},
        ]})
        findings = parse_trivy_config_json(payload, "Dockerfile", target_basename="Dockerfile")
        self.assertEqual([f["VulnerabilityID"] for f in findings], ["DS002"])

    def test_malformed_input_is_survivable(self):
        for raw in ("", "not json", "{}", '{"Results": null}'):
            with self.subTest(raw=raw):
                self.assertEqual(parse_trivy_config_json(raw, "Dockerfile"), [])


class TestDeduplication(unittest.TestCase):
    """Both scanners run because neither is a superset; where they overlap the
    Trivy finding wins, since its IDs are stable and its severities are real."""

    def test_overlapping_hadolint_finding_is_dropped(self):
        hadolint = parse_hadolint_json(json.dumps([_hadolint("DL3002", line=7)]), "Dockerfile")
        trivy = parse_trivy_config_json(_trivy_result([_misconfig("DS002", "HIGH", 7)]), "Dockerfile")
        merged, dropped = deduplicate(hadolint, trivy)
        ids = [f["VulnerabilityID"] for f in merged]
        self.assertIn("DS002", ids)
        self.assertNotIn("DL3002", ids)
        self.assertEqual(dropped, 1)

    def test_unique_hadolint_findings_are_kept(self):
        """Hadolint alone catches unpinned apt versions and uncleaned apt
        lists; dropping it wholesale would lose real coverage."""
        hadolint = parse_hadolint_json(
            json.dumps([_hadolint("DL3008"), _hadolint("DL3009", level="info")]),
            "Dockerfile",
        )
        trivy = parse_trivy_config_json(_trivy_result([_misconfig("DS002")]), "Dockerfile")
        merged, dropped = deduplicate(hadolint, trivy)
        ids = [f["VulnerabilityID"] for f in merged]
        self.assertIn("DL3008", ids)
        self.assertIn("DL3009", ids)
        self.assertEqual(dropped, 0)

    def test_hadolint_line_is_transferred_when_trivy_lacks_one(self):
        """Position data must not be lost along with the duplicate."""
        hadolint = parse_hadolint_json(json.dumps([_hadolint("DL3002", line=12)]), "Dockerfile")
        trivy = parse_trivy_config_json(_trivy_result([_misconfig("DS002", "HIGH")]), "Dockerfile")
        merged, _ = deduplicate(hadolint, trivy)
        ds002 = next(f for f in merged if f["VulnerabilityID"] == "DS002")
        self.assertEqual(ds002["Line"], 12)

    def test_hadolint_kept_when_the_trivy_counterpart_did_not_fire(self):
        hadolint = parse_hadolint_json(json.dumps([_hadolint("DL3002")]), "Dockerfile")
        merged, dropped = deduplicate(hadolint, [])
        self.assertEqual([f["VulnerabilityID"] for f in merged], ["DL3002"])
        self.assertEqual(dropped, 0)

    def test_collision_map_targets_look_like_trivy_rules(self):
        for hadolint_id, trivy_id in HADOLINT_TRIVY_COLLISIONS.items():
            with self.subTest(rule=hadolint_id):
                self.assertTrue(hadolint_id.startswith("DL"))
                self.assertTrue(trivy_id.startswith("DS"))


class TestRuleIdNormalization(unittest.TestCase):
    """Trivy changed its misconfiguration ID format between releases.

    0.68 emits "DS001" with an AVDID; 0.74 emits "DS-0001" and no AVDID. The
    collision map and the fix table are keyed on one spelling, so without
    normalization an upgrade silently stops both from matching - which is how
    the pinned container produced 16 findings where a local run produced 10.
    """

    def test_both_trivy_formats_normalize_to_one(self):
        from docksec.findings import normalize_rule_id

        for raw in ("DS001", "DS-0001", "AVD-DS-0001", "ds-0001"):
            with self.subTest(raw=raw):
                self.assertEqual(normalize_rule_id(raw), "DS001")

    def test_zero_padding_is_canonicalized(self):
        from docksec.findings import normalize_rule_id

        self.assertEqual(normalize_rule_id("DS-0026"), "DS026")
        self.assertEqual(normalize_rule_id("DS026"), "DS026")

    def test_non_trivy_ids_pass_through(self):
        from docksec.findings import normalize_rule_id

        for raw in ("CVE-2021-44228", "DL3002", "GHSA-xxxx-yyyy"):
            with self.subTest(raw=raw):
                self.assertEqual(normalize_rule_id(raw), raw.upper())

    def test_new_format_findings_still_deduplicate(self):
        """The end-to-end consequence: with the new ID format, a DL3002/DS002
        collision must still be caught."""
        hadolint = parse_hadolint_json(json.dumps([_hadolint("DL3002", line=7)]), "Dockerfile")
        trivy_new_format = parse_trivy_config_json(
            json.dumps({"Results": [{"Target": "Dockerfile", "Misconfigurations": [{
                "ID": "DS-0002", "Title": "t", "Severity": "HIGH",
                "CauseMetadata": {"StartLine": 7},
            }]}]}),
            "Dockerfile",
        )
        merged, dropped = deduplicate(hadolint, trivy_new_format)
        self.assertEqual(dropped, 1, "new-format Trivy ID failed to match the collision map")
        self.assertEqual([f["VulnerabilityID"] for f in merged], ["DS002"])

    def test_fix_table_keys_match_normalized_ids(self):
        """The remediation table is keyed the same way, so a normalized ID must
        find its entry."""
        from docksec.findings import normalize_rule_id
        from docksec.remediation import DOCKERFILE_FIXES

        self.assertIn(normalize_rule_id("DS-0002"), DOCKERFILE_FIXES)
        self.assertIn(normalize_rule_id("DS-0031"), DOCKERFILE_FIXES)


class TestSummary(unittest.TestCase):
    def test_empty_summary(self):
        self.assertIn("No Dockerfile issues", summarize([]))

    def test_summary_counts_by_severity(self):
        findings = [
            {"Severity": "CRITICAL"}, {"Severity": "HIGH"}, {"Severity": "HIGH"},
        ]
        text = summarize(findings)
        self.assertIn("3 Dockerfile issue(s)", text)
        self.assertIn("CRITICAL: 1", text)
        self.assertIn("HIGH: 2", text)


if __name__ == "__main__":
    unittest.main()
