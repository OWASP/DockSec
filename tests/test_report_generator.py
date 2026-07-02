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
    # Verify it's in the correct directory
    assert os.path.dirname(output_path) == str(tmp_path)


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


def test_pdf_handles_non_latin1_characters(tmp_path, sample_scan_info):
    """Core fpdf fonts only encode latin-1; report text must be sanitized so
    bullets, smart quotes, em dashes, and emoji never raise UnicodeEncodeError."""
    tricky = [
        {
            "VulnerabilityID": "CVE-2024-9999",
            "Severity": "CRITICAL",
            "PkgName": "openssl",
            "InstalledVersion": "1.0.0",
            "Title": "Heap overflow — smart quotes ‘x’ bullet • emoji \U0001f525",
            "CVSS": 9.8,
            "Status": "affected",
            "Target": "image",
            "PrimaryURL": "",
        }
    ]
    results = make_results(tricky, sample_scan_info)
    results["dockerfile_scan"] = {
        "skipped": False,
        "success": False,
        "output": "Dockerfile line with unicode ✓ and accent é",
    }
    results["config_analysis"] = {
        "high_risk": ["Running as root • privileged"],
        "medium_risk": [],
        "low_risk": [],
    }
    results["ai_findings"] = {
        "vulnerabilities": ["Hardcoded key — leaked"],
        "best_practices": [],
        "security_risks": [],
        "exposed_credentials": [],
        "remediation": ["Use secrets…"],
    }
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    rg.set_analysis_score(75.0)
    output_path = rg.generate_pdf_report(results)
    assert output_path, "PDF generation returned empty path (it likely raised)"
    assert os.path.getsize(output_path) > 0


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


# ---------- FORMAT SELECTION TESTS ----------


def test_generate_all_reports_default_writes_all_formats(
    tmp_path, sample_vulnerabilities, sample_scan_info
):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results(sample_vulnerabilities, sample_scan_info)
    paths = rg.generate_all_reports(results)
    assert set(paths) == {"json", "csv", "pdf", "html"}
    for path in paths.values():
        assert os.path.exists(path)


def test_generate_all_reports_writes_only_requested_formats(
    tmp_path, sample_vulnerabilities, sample_scan_info
):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results(sample_vulnerabilities, sample_scan_info)
    paths = rg.generate_all_reports(results, formats=["json", "html"])
    assert set(paths) == {"json", "html"}
    # The unrequested formats must not be written to disk.
    written = {p.rsplit(".", 1)[-1] for p in os.listdir(tmp_path)}
    assert "csv" not in written
    assert "pdf" not in written


def test_generate_all_reports_empty_formats_writes_nothing(tmp_path, sample_scan_info):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results([], sample_scan_info)
    paths = rg.generate_all_reports(results, formats=[])
    assert paths == {}
