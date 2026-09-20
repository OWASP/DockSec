"""Golden-file guards for the machine-readable output contracts.

Teams build automation on `--json` and on SARIF. A field that quietly changes
name or disappears breaks that automation without breaking any test, so the
shape is pinned here. These assert structure, not values: a new finding or a
changed score must not fail the suite, but a renamed key must.

When a change here is intentional, update the expected keys in the same commit
as the code - that edit is the record that the contract changed on purpose.
"""

import json
import tempfile
import unittest

from docksec.report_generator import ReportGenerator

# Keys every finding carries, whatever produced it. Report writers, the score
# calculator, waivers, baseline fingerprinting, and the SARIF mapper all read
# from this set.
REQUIRED_FINDING_KEYS = {
    "VulnerabilityID", "Target", "PkgName", "InstalledVersion",
    "FixedVersion", "Severity", "Title", "Description", "Status",
    "CVSS", "PrimaryURL",
}

REQUIRED_SCAN_INFO_KEYS = {
    "image", "dockerfile", "scan_time", "analysis_score",
    "score_version", "scan_mode",
}


def _results():
    return {
        "dockerfile_scan": {"success": False, "output": "1 issue", "skipped": False},
        "image_scan": {"success": True, "output": "", "skipped": False},
        "json_data": [
            {
                "VulnerabilityID": "CVE-2021-44228", "Target": "java",
                "PkgName": "log4j", "InstalledVersion": "2.14.1",
                "FixedVersion": "2.17.1", "Severity": "CRITICAL",
                "Title": "Log4Shell", "Description": "d", "Status": "fixed",
                "CVSS": 10.0, "PrimaryURL": "https://example.test",
                "EPSS": 0.97, "EPSSPercentile": 0.99, "Priority": "fix_now",
            },
            {
                "VulnerabilityID": "DS002", "Target": "Dockerfile",
                "PkgName": "dockerfile", "InstalledVersion": "N/A",
                "FixedVersion": None, "Severity": "HIGH",
                "Title": "Image user should not be 'root'", "Description": "d",
                "Status": "affected", "CVSS": None, "PrimaryURL": "",
                "Remediation": "Add USER", "Line": 7, "Source": "trivy-config",
            },
        ],
        "timestamp": "2026-01-01 00:00:00",
        "image_name": "test:latest",
        "dockerfile_path": "Dockerfile",
        "scan_mode": "full",
    }


class TestJsonReportContract(unittest.TestCase):
    def setUp(self):
        self.results = _results()

    def _report(self):
        with tempfile.TemporaryDirectory() as tmp:
            generator = ReportGenerator("test:latest", tmp)
            generator.set_analysis_score(42.0)
            path = generator.generate_json_report(self.results)
            with open(path) as handle:
                return json.load(handle)

    def test_top_level_keys(self):
        payload = self._report()
        for key in ("scan_info", "vulnerabilities", "severity_counts"):
            self.assertIn(key, payload)

    def test_scan_info_keys(self):
        scan_info = self._report()["scan_info"]
        missing = REQUIRED_SCAN_INFO_KEYS - set(scan_info)
        self.assertFalse(missing, f"scan_info lost keys: {missing}")

    def test_every_finding_carries_the_shared_keys(self):
        """Dockerfile findings and image vulnerabilities must be
        indistinguishable in shape, or downstream consumers need special
        cases."""
        for finding in self._report()["vulnerabilities"]:
            missing = REQUIRED_FINDING_KEYS - set(finding)
            self.assertFalse(
                missing,
                f"{finding.get('VulnerabilityID')} is missing {missing}",
            )

    def test_severity_counts_cover_every_level(self):
        counts = self._report()["severity_counts"]
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            self.assertIn(level, counts)


class TestSarifContract(unittest.TestCase):
    def setUp(self):
        self.results = _results()

    def _sarif(self):
        with tempfile.TemporaryDirectory() as tmp:
            generator = ReportGenerator("test:latest", tmp)
            generator.set_analysis_score(42.0)
            path = generator.generate_sarif_report(self.results, tool_version="test")
            with open(path) as handle:
                return json.load(handle)

    def test_sarif_envelope(self):
        sarif = self._sarif()
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("$schema", sarif)
        self.assertEqual(len(sarif["runs"]), 1)

    def test_every_finding_becomes_a_result(self):
        sarif = self._sarif()
        self.assertEqual(len(sarif["runs"][0]["results"]), len(self.results["json_data"]))

    def test_dockerfile_finding_is_anchored_to_its_line(self):
        """Without a region, GitHub cannot annotate the pull request line that
        caused the finding."""
        results = self._sarif()["runs"][0]["results"]
        ds002 = next(r for r in results if r["ruleId"] == "DS002")
        region = ds002["locations"][0]["physicalLocation"].get("region")
        self.assertIsNotNone(region, "Dockerfile findings must carry a line region")
        self.assertEqual(region["startLine"], 7)

    def test_image_vulnerability_has_no_spurious_region(self):
        """A package CVE has no line in any file; inventing one would point
        reviewers at unrelated code."""
        results = self._sarif()["runs"][0]["results"]
        cve = next(r for r in results if r["ruleId"] == "CVE-2021-44228")
        self.assertIsNone(cve["locations"][0]["physicalLocation"].get("region"))

    def test_rules_are_declared_for_every_result(self):
        run = self._sarif()["runs"][0]
        declared = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        used = {result["ruleId"] for result in run["results"]}
        self.assertTrue(used <= declared, f"undeclared rules: {used - declared}")


class TestFindingShapeParity(unittest.TestCase):
    """The scanners must agree on the finding shape.

    A Dockerfile finding that omitted a key the image path provides would fail
    only in whichever writer happened to read it.
    """

    def test_dockerfile_findings_match_the_image_finding_shape(self):
        from docksec.findings import parse_trivy_config_json

        raw = json.dumps({"Results": [{
            "Target": "Dockerfile",
            "Misconfigurations": [{
                "ID": "DS002", "Title": "t", "Description": "d",
                "Severity": "HIGH", "Resolution": "r",
                "PrimaryURL": "u", "CauseMetadata": {"StartLine": 7},
            }],
        }]})
        finding = parse_trivy_config_json(raw, "Dockerfile")[0]
        missing = REQUIRED_FINDING_KEYS - set(finding)
        self.assertFalse(missing, f"Dockerfile finding is missing {missing}")

    def test_compose_findings_match_the_image_finding_shape(self):
        from docksec.compose_scanner import ComposeScanner

        scanner = ComposeScanner("examples/compose/docker-compose-insecure.yml")
        self.assertTrue(scanner.parse())
        findings = scanner.scan()
        self.assertTrue(findings)
        for finding in findings:
            missing = REQUIRED_FINDING_KEYS - set(finding)
            self.assertFalse(missing, f"compose finding is missing {missing}")

    def test_baseline_fingerprint_works_across_finding_types(self):
        """Ratchet mode keys on a fingerprint built from three fields; a finding
        type missing any of them would silently never match its baseline."""
        from docksec.baseline import fingerprint

        for finding in _results()["json_data"]:
            self.assertTrue(fingerprint(finding))


if __name__ == "__main__":
    unittest.main()
