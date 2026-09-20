"""Tests for the EPSS priority signal.

Severity says how bad a finding would be; EPSS says whether anyone is actually
exploiting it. No test here makes a network call - live behavior is covered by
the manual verification recorded in the changelog.
"""

import json
import tempfile
import time
import unittest
from unittest.mock import patch

from docksec import epss


class TestPriorityTiers(unittest.TestCase):
    def test_high_severity_and_high_exploitation_is_fix_now(self):
        self.assertEqual(epss.compute_priority("CRITICAL", 0.99), epss.FIX_NOW)
        self.assertEqual(epss.compute_priority("HIGH", 0.95), epss.FIX_NOW)

    def test_high_severity_alone_is_fix_soon(self):
        self.assertEqual(epss.compute_priority("CRITICAL", 0.50), epss.FIX_SOON)
        self.assertEqual(epss.compute_priority("HIGH", 0.10), epss.FIX_SOON)

    def test_low_severity_but_exploited_is_monitor(self):
        self.assertEqual(epss.compute_priority("MEDIUM", 0.99), epss.MONITOR)
        self.assertEqual(epss.compute_priority("LOW", 0.92), epss.MONITOR)

    def test_low_severity_and_unexploited_is_low_priority(self):
        self.assertEqual(epss.compute_priority("MEDIUM", 0.2), epss.LOW_PRIORITY)

    def test_threshold_boundary_is_inclusive(self):
        self.assertEqual(epss.compute_priority("HIGH", 0.90), epss.FIX_NOW)
        self.assertEqual(epss.compute_priority("HIGH", 0.8999), epss.FIX_SOON)

    def test_missing_score_leaves_the_finding_untiered(self):
        """A missing EPSS score is not evidence of low risk, so the finding is
        left untiered rather than given an optimistic tier."""
        self.assertIsNone(epss.compute_priority("CRITICAL", None))

    def test_priority_rank_orders_most_urgent_first(self):
        ranks = [epss.priority_rank(t) for t in epss.PRIORITY_ORDER]
        self.assertEqual(ranks, sorted(ranks, reverse=True))
        self.assertLess(epss.priority_rank(None), epss.priority_rank(epss.LOW_PRIORITY))


class TestAnnotation(unittest.TestCase):
    def _findings(self):
        return [
            {"VulnerabilityID": "CVE-2021-44228", "Severity": "CRITICAL"},
            {"VulnerabilityID": "CVE-2020-0001", "Severity": "MEDIUM"},
            {"VulnerabilityID": "DS002", "Severity": "HIGH"},
        ]

    def test_only_cve_ids_are_requested(self):
        """Rule IDs such as DS002 are not CVEs and must not be sent."""
        findings = self._findings()
        with patch("docksec.epss.fetch_scores", return_value={}) as mock_fetch:
            epss.annotate(findings, cache_dir=None)
        requested = list(mock_fetch.call_args[0][0])
        self.assertIn("CVE-2021-44228", requested)
        self.assertNotIn("DS002", requested)

    def test_annotation_attaches_score_and_tier(self):
        findings = self._findings()
        scores = {
            "CVE-2021-44228": {"epss": 0.97, "percentile": 0.99},
            "CVE-2020-0001": {"epss": 0.01, "percentile": 0.30},
        }
        with patch("docksec.epss.fetch_scores", return_value=scores):
            annotated = epss.annotate(findings, cache_dir=None)

        self.assertEqual(annotated, 2)
        self.assertEqual(findings[0]["Priority"], epss.FIX_NOW)
        self.assertEqual(findings[1]["Priority"], epss.LOW_PRIORITY)
        # The non-CVE finding is untouched.
        self.assertNotIn("Priority", findings[2])

    def test_disabled_annotation_is_a_no_op(self):
        findings = self._findings()
        with patch("docksec.epss.fetch_scores") as mock_fetch:
            self.assertEqual(epss.annotate(findings, enabled=False), 0)
        mock_fetch.assert_not_called()

    def test_lookup_failure_degrades_silently(self):
        """A failed EPSS lookup must never fail the scan - findings simply keep
        their severity-only ordering."""
        findings = self._findings()
        with patch("docksec.epss.fetch_scores", return_value={}):
            self.assertEqual(epss.annotate(findings), 0)
        for finding in findings:
            self.assertNotIn("Priority", finding)

    def test_counts_by_priority(self):
        findings = [
            {"Priority": epss.FIX_NOW}, {"Priority": epss.FIX_NOW},
            {"Priority": epss.MONITOR}, {},
        ]
        counts = epss.counts_by_priority(findings)
        self.assertEqual(counts[epss.FIX_NOW], 2)
        self.assertEqual(counts[epss.MONITOR], 1)
        self.assertEqual(counts[epss.LOW_PRIORITY], 0)


class TestFetchAndCache(unittest.TestCase):
    def test_non_cve_ids_short_circuit_the_request(self):
        with patch("docksec.epss._fetch_batch") as mock_batch:
            self.assertEqual(epss.fetch_scores(["DS002", "DL3002"]), {})
        mock_batch.assert_not_called()

    def test_cached_scores_avoid_a_second_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            scores = {"CVE-2021-44228": {"epss": 0.97, "percentile": 0.99}}
            with patch("docksec.epss._fetch_batch", return_value=scores) as mock_batch:
                epss.fetch_scores(["CVE-2021-44228"], cache_dir=tmp)
                self.assertEqual(mock_batch.call_count, 1)
                epss.fetch_scores(["CVE-2021-44228"], cache_dir=tmp)
                self.assertEqual(mock_batch.call_count, 1, "second call should hit the cache")

    def test_expired_cache_entries_are_refetched(self):
        with tempfile.TemporaryDirectory() as tmp:
            stale = {
                "CVE-2021-44228": {
                    "epss": 0.5, "percentile": 0.5,
                    "fetched_at": time.time() - (epss.CACHE_TTL_SECONDS + 60),
                }
            }
            with open(epss._cache_path(tmp), "w") as handle:
                json.dump(stale, handle)

            fresh = {"CVE-2021-44228": {"epss": 0.97, "percentile": 0.99}}
            with patch("docksec.epss._fetch_batch", return_value=fresh) as mock_batch:
                result = epss.fetch_scores(["CVE-2021-44228"], cache_dir=tmp)
            mock_batch.assert_called_once()
            self.assertEqual(result["CVE-2021-44228"]["percentile"], 0.99)

    def test_requests_are_batched(self):
        """The API pages at 100; a larger finding set must not silently
        truncate."""
        cves = [f"CVE-2021-{i:05d}" for i in range(250)]
        with patch("docksec.epss._fetch_batch", return_value={}) as mock_batch:
            epss.fetch_scores(cves)
        self.assertEqual(mock_batch.call_count, 3)

    def test_unknown_cves_are_simply_absent(self):
        """The API omits CVEs it does not know, so the response is not a 1:1
        mapping of the request."""
        with patch("docksec.epss._fetch_batch", return_value={
            "CVE-2021-44228": {"epss": 0.9, "percentile": 0.9}
        }):
            result = epss.fetch_scores(["CVE-2021-44228", "CVE-9999-99999"])
        self.assertIn("CVE-2021-44228", result)
        self.assertNotIn("CVE-9999-99999", result)

    def test_unwritable_cache_dir_does_not_raise(self):
        scores = {"CVE-2021-44228": {"epss": 0.9, "percentile": 0.9}}
        with patch("docksec.epss._fetch_batch", return_value=scores):
            # A cache write failure must never fail a scan.
            result = epss.fetch_scores(["CVE-2021-44228"], cache_dir="/proc/nonexistent")
        self.assertIn("CVE-2021-44228", result)


class TestFormatting(unittest.TestCase):
    def test_unscored_finding_formats_empty(self):
        self.assertEqual(epss.format_epss({}), "")

    def test_scored_finding_reports_probability_and_percentile(self):
        text = epss.format_epss({"EPSS": 0.085, "EPSSPercentile": 0.948})
        self.assertIn("8.5%", text)
        self.assertIn("top", text)


if __name__ == "__main__":
    unittest.main()
