"""Unit tests for the terminal output layer (docksec.output)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from docksec import output


def _capture(fn, *args, no_color=True, quiet=False):
    """Run an output helper and return what it printed to the console."""
    output.configure(quiet=quiet, no_color=no_color)
    console = output.get_console()
    with console.capture() as cap:
        fn(*args)
    return cap.get()


def test_count_by_severity_counts_each_level():
    vulns = [
        {"Severity": "CRITICAL"},
        {"Severity": "critical"},  # case-insensitive
        {"Severity": "HIGH"},
        {"Severity": "LOW"},
        {},  # missing -> UNKNOWN
    ]
    counts = output.count_by_severity(vulns)
    assert counts["CRITICAL"] == 2
    assert counts["HIGH"] == 1
    assert counts["LOW"] == 1
    assert counts["MEDIUM"] == 0
    assert counts["UNKNOWN"] == 1


def test_count_by_severity_empty():
    assert output.count_by_severity([])["CRITICAL"] == 0
    assert output.count_by_severity(None)["HIGH"] == 0


def test_severity_table_shows_headers_and_counts():
    counts = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 0, "LOW": 1}
    rendered = _capture(output.severity_table, counts)
    for header in ("Critical", "High", "Medium", "Low"):
        assert header in rendered
    assert "3" in rendered and "2" in rendered and "1" in rendered


def test_score_band_thresholds():
    assert output._score_band(95)[0] == "EXCELLENT"
    assert output._score_band(75)[0] == "GOOD"
    assert output._score_band(55)[0] == "FAIR"
    assert output._score_band(20)[0] == "POOR"


def test_score_renders_band_label():
    assert "GOOD" in _capture(output.score, 73.5)
    assert "POOR" in _capture(output.score, 10)


def test_score_handles_non_numeric():
    assert "N/A" in _capture(output.score, None)


def test_quiet_suppresses_info_but_not_error():
    assert _capture(output.info, "hello", quiet=True) == ""
    assert "boom" in _capture(output.error, "boom", quiet=True)


def test_quiet_keeps_severity_table_and_score():
    assert "Critical" in _capture(output.severity_table, {"CRITICAL": 1}, quiet=True)
    assert "GOOD" in _capture(output.score, 80, quiet=True)


def test_no_color_strips_ansi_escapes():
    rendered = _capture(output.severity_table, {"CRITICAL": 1}, no_color=True)
    assert "\x1b[" not in rendered


def test_report_results_lists_written_formats():
    rendered = _capture(
        output.report_results, {"json": "a.json", "csv": "", "pdf": "c.pdf"}, "/tmp/out"
    )
    assert "JSON" in rendered and "PDF" in rendered
    assert "CSV" not in rendered  # empty path is not listed
    assert "/tmp/out" in rendered
