# tests/test_report_generator.py
"""Unit tests for ReportGenerator covering JSON, CSV, PDF, and HTML report generation."""

import csv
import json
import os

from docksec.report_generator import ReportGenerator


def make_results(vulnerabilities, scan_info=None):
    """Helper to construct a minimal results dict for ReportGenerator methods."""
    if scan_info is None:
        scan_info = {
            "image": "python:3.9-slim",
            "scan_date": "2024-01-01T00:00:00",
            "scanner": "trivy",
        }
    return {
        "json_data": vulnerabilities,
        "dockerfile_path": "Dockerfile",
        "timestamp": "2024-01-01T00:00:00",
        "scan_mode": "full",
        "dockerfile_scan": {"skipped": True, "success": True, "output": ""},
    }


# ---------- JSON REPORT TESTS ----------


def test_json_report_file_is_created(
    tmp_path, sample_vulnerabilities, sample_scan_info
):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results(sample_vulnerabilities, sample_scan_info)
    output_path = rg.generate_json_report(results)
    assert os.path.exists(output_path)


def test_json_report_has_required_keys(
    tmp_path, sample_vulnerabilities, sample_scan_info
):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results(sample_vulnerabilities, sample_scan_info)
    output_path = rg.generate_json_report(results)
    with open(output_path) as f:
        data = json.load(f)
    for key in ["scan_info", "vulnerabilities", "severity_counts"]:
        assert key in data


def test_json_severity_counts_are_correct(
    tmp_path, sample_vulnerabilities, sample_scan_info
):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results(sample_vulnerabilities, sample_scan_info)
    output_path = rg.generate_json_report(results)
    with open(output_path) as f:
        data = json.load(f)
    counts = data["severity_counts"]
    assert counts.get("CRITICAL", 0) == 1
    for sev in ["HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        assert counts.get(sev, 0) == 0


def test_json_empty_vulnerabilities_no_crash(tmp_path, sample_scan_info):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results([], sample_scan_info)
    output_path = rg.generate_json_report(results)
    assert os.path.exists(output_path)
    with open(output_path) as f:
        data = json.load(f)
    assert data["vulnerabilities"] == []


# ---------- CSV REPORT TESTS ----------


def test_csv_report_file_is_created(tmp_path, sample_vulnerabilities, sample_scan_info):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results(sample_vulnerabilities, sample_scan_info)
    output_path = rg.generate_csv_report(results)
    assert os.path.exists(output_path)


def test_csv_header_row_is_correct(tmp_path, sample_vulnerabilities, sample_scan_info):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results(sample_vulnerabilities, sample_scan_info)
    output_path = rg.generate_csv_report(results)
    with open(output_path, newline="") as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)
    expected = [
        "ID",
        "Severity",
        "Package",
        "Version",
        "Title",
        "CVSS",
        "Status",
        "Target",
        "URL",
    ]
    assert header == expected


def test_csv_vulnerability_data_maps_correctly(
    tmp_path, sample_vulnerabilities, sample_scan_info
):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results(sample_vulnerabilities, sample_scan_info)
    output_path = rg.generate_csv_report(results)
    with open(output_path, newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        rows = list(reader)
    assert len(rows) == 1
    row = rows[0]
    assert row["ID"] == "CVE-2023-1234"
    assert row["Severity"] == "CRITICAL"
    assert row["Package"] == "openssl"


def test_csv_empty_input_header_only(tmp_path, sample_scan_info):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results([], sample_scan_info)
    output_path = rg.generate_csv_report(results)
    assert os.path.exists(output_path)
    with open(output_path, newline="") as csvfile:
        reader = csv.reader(csvfile)
        rows = list(reader)
    assert len(rows) == 1
    expected = [
        "ID",
        "Severity",
        "Package",
        "Version",
        "Title",
        "CVSS",
        "Status",
        "Target",
        "URL",
    ]
    assert rows[0] == expected


# ---------- PDF REPORT TESTS ----------


def test_pdf_report_file_is_created(tmp_path, sample_vulnerabilities, sample_scan_info):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results(sample_vulnerabilities, sample_scan_info)
    output_path = rg.generate_pdf_report(results)
    assert os.path.exists(output_path)


def test_pdf_file_is_non_empty(tmp_path, sample_vulnerabilities, sample_scan_info):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results(sample_vulnerabilities, sample_scan_info)
    output_path = rg.generate_pdf_report(results)
    assert os.path.getsize(output_path) > 0


def test_pdf_no_exception_on_valid_input(
    tmp_path, sample_vulnerabilities, sample_scan_info
):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results(sample_vulnerabilities, sample_scan_info)
    rg.generate_pdf_report(results)


# ---------- HTML REPORT TESTS ----------


def test_html_report_file_is_created(
    tmp_path, sample_vulnerabilities, sample_scan_info
):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results(sample_vulnerabilities, sample_scan_info)
    output_path = rg.generate_html_report(results)
    assert os.path.exists(output_path)


def test_html_no_unfilled_placeholders(
    tmp_path, sample_vulnerabilities, sample_scan_info
):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results(sample_vulnerabilities, sample_scan_info)
    output_path = rg.generate_html_report(results)
    with open(output_path) as f:
        content = f.read()
    assert "{{" not in content
    assert "}}" not in content


def test_html_special_characters_are_escaped(tmp_path):
    vuln = {
        "VulnerabilityID": "CVE-2023-9999",
        "Severity": "HIGH",
        "PkgName": "example",
        "InstalledVersion": "1.2.3",
        "Title": "<script>alert('xss')</script>",
        "CVSS": 5.0,
        "Status": "fixed",
        "Target": "python:3.9-slim",
        "PrimaryURL": "https://example.com",
    }
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results([vuln])
    output_path = rg.generate_html_report(results)
    with open(output_path) as f:
        content = f.read()
    assert "<script>" not in content
    assert "&lt;script&gt;" in content
