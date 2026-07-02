import json
import os
import tempfile
import unittest

from docksec import baseline


class TestFingerprint(unittest.TestCase):
    def test_fingerprint_stable_for_same_finding(self):
        v = {"VulnerabilityID": "CVE-2024-1", "Target": "app", "PkgName": "openssl"}
        self.assertEqual(baseline.fingerprint(v), baseline.fingerprint(dict(v)))

    def test_fingerprint_differs_on_any_field(self):
        base = {"VulnerabilityID": "CVE-2024-1", "Target": "app", "PkgName": "openssl"}
        other = {"VulnerabilityID": "CVE-2024-2", "Target": "app", "PkgName": "openssl"}
        self.assertNotEqual(baseline.fingerprint(base), baseline.fingerprint(other))

    def test_fingerprint_handles_missing_fields(self):
        self.assertEqual(baseline.fingerprint({}), "UNKNOWN||")


class TestLoadSaveBaseline(unittest.TestCase):
    def test_load_missing_file_returns_empty(self):
        self.assertEqual(baseline.load_baseline("/nonexistent/path/baseline.json"), [])

    def test_save_then_load_round_trips(self):
        results = {
            "json_data": [
                {"VulnerabilityID": "CVE-1", "Target": "a", "PkgName": "pkg1", "Severity": "HIGH"},
                {"VulnerabilityID": "CVE-2", "Target": "a", "PkgName": "pkg2", "Severity": "LOW"},
            ]
        }
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "baseline.json")
            baseline.save_baseline(path, results)
            loaded = baseline.load_baseline(path)
            self.assertEqual(len(loaded), 2)
            self.assertIn(baseline.fingerprint(results["json_data"][0]), loaded)

    def test_save_dedupes_identical_findings(self):
        vuln = {"VulnerabilityID": "CVE-1", "Target": "a", "PkgName": "pkg1", "Severity": "HIGH"}
        results = {"json_data": [vuln, dict(vuln)]}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "baseline.json")
            baseline.save_baseline(path, results)
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(len(data["fingerprints"]), 1)

    def test_save_writes_valid_json_structure(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "baseline.json")
            baseline.save_baseline(path, {"json_data": []})
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(data, {"fingerprints": []})


class TestNewFindings(unittest.TestCase):
    def test_new_findings_excludes_baselined(self):
        v1 = {"VulnerabilityID": "CVE-1", "Target": "a", "PkgName": "pkg1"}
        v2 = {"VulnerabilityID": "CVE-2", "Target": "a", "PkgName": "pkg2"}
        results = {"json_data": [v1, v2]}
        baseline_fps = [baseline.fingerprint(v1)]
        result = baseline.new_findings(results, baseline_fps)
        self.assertEqual(result, [v2])

    def test_new_findings_all_new_when_baseline_empty(self):
        v1 = {"VulnerabilityID": "CVE-1", "Target": "a", "PkgName": "pkg1"}
        results = {"json_data": [v1]}
        self.assertEqual(baseline.new_findings(results, []), [v1])

    def test_new_findings_empty_when_all_baselined(self):
        v1 = {"VulnerabilityID": "CVE-1", "Target": "a", "PkgName": "pkg1"}
        results = {"json_data": [v1]}
        self.assertEqual(baseline.new_findings(results, [baseline.fingerprint(v1)]), [])

    def test_new_findings_handles_no_findings(self):
        self.assertEqual(baseline.new_findings({"json_data": []}, []), [])


if __name__ == '__main__':
    unittest.main()
