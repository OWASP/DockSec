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


# ---------- SARIF REPORT TESTS ----------


def test_sarif_report_file_is_created(tmp_path, sample_vulnerabilities, sample_scan_info):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results(sample_vulnerabilities, sample_scan_info)
    output_path = rg.generate_sarif_report(results, tool_version="1.2.3")
    assert os.path.exists(output_path)
    assert output_path.endswith(".sarif")


def test_sarif_report_has_valid_2_1_0_structure(
    tmp_path, sample_vulnerabilities, sample_scan_info
):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results(sample_vulnerabilities, sample_scan_info)
    output_path = rg.generate_sarif_report(results, tool_version="1.2.3")
    with open(output_path) as f:
        doc = json.load(f)

    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "DockSec"
    assert run["tool"]["driver"]["version"] == "1.2.3"


def test_sarif_report_maps_one_result_per_vulnerability(
    tmp_path, sample_vulnerabilities, sample_scan_info
):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results(sample_vulnerabilities, sample_scan_info)
    output_path = rg.generate_sarif_report(results, tool_version="1.2.3")
    with open(output_path) as f:
        doc = json.load(f)

    run = doc["runs"][0]
    assert len(run["results"]) == len(sample_vulnerabilities)
    result = run["results"][0]
    assert result["ruleId"] == sample_vulnerabilities[0]["VulnerabilityID"]
    assert result["level"] == "error"  # CRITICAL -> error
    assert sample_vulnerabilities[0]["PkgName"] in result["message"]["text"]
    assert (
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "Dockerfile"
    )


def test_sarif_report_dedupes_rules_by_vulnerability_id(tmp_path, sample_scan_info):
    vulns = [
        {
            "VulnerabilityID": "CVE-2023-0001",
            "Severity": "HIGH",
            "PkgName": "openssl",
            "InstalledVersion": "1.0.0",
            "Title": "Issue A",
            "Target": "img (pkg)",
        },
        {
            "VulnerabilityID": "CVE-2023-0001",
            "Severity": "HIGH",
            "PkgName": "openssl",
            "InstalledVersion": "1.0.1",
            "Title": "Issue A",
            "Target": "img (pkg)",
        },
    ]
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results(vulns, sample_scan_info)
    output_path = rg.generate_sarif_report(results, tool_version="1.2.3")
    with open(output_path) as f:
        doc = json.load(f)

    run = doc["runs"][0]
    # Same VulnerabilityID -> one rule, but each finding still gets its own result.
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 2


def test_sarif_report_empty_vulnerabilities_no_crash(tmp_path, sample_scan_info):
    rg = ReportGenerator(image_name="test-image", results_dir=str(tmp_path))
    results = make_results([], sample_scan_info)
    output_path = rg.generate_sarif_report(results, tool_version="1.2.3")
    with open(output_path) as f:
        doc = json.load(f)
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_severity_level_mapping():
    assert ReportGenerator._sarif_level("CRITICAL") == "error"
    assert ReportGenerator._sarif_level("HIGH") == "error"
    assert ReportGenerator._sarif_level("MEDIUM") == "warning"
    assert ReportGenerator._sarif_level("LOW") == "note"
    assert ReportGenerator._sarif_level("UNKNOWN") == "note"
    assert ReportGenerator._sarif_level(None) == "note"
    assert ReportGenerator._sarif_level("not-a-real-severity") == "note"


def test_sarif_region_parses_compose_target_line_number():
    region = ReportGenerator._sarif_region("docker-compose.yml:web:12")
    assert region == {"startLine": 12}


def test_sarif_region_none_for_non_numeric_target():
    # Trivy image-vulnerability targets carry a package path, not a line number.
    assert ReportGenerator._sarif_region("python:3.9-slim (debian 11)") is None
    assert ReportGenerator._sarif_region(None) is None
    assert ReportGenerator._sarif_region("") is None


def test_sarif_artifact_uri_uses_dockerfile_basename(tmp_path, sample_scan_info):
    rg = ReportGenerator(image_name="myapp:latest", results_dir=str(tmp_path))
    results = {"dockerfile_path": "/some/deep/path/Dockerfile"}
    assert rg._sarif_artifact_uri(results) == "Dockerfile"


def test_sarif_artifact_uri_falls_back_to_image_name_for_image_only_scans(tmp_path):
    rg = ReportGenerator(image_name="myapp:latest", results_dir=str(tmp_path))
    results = {"dockerfile_path": "N/A - Image-only scan"}
    assert rg._sarif_artifact_uri(results) == "myapp:latest"


def test_sarif_rule_includes_help_uri_when_primary_url_present():
    vuln = {
        "VulnerabilityID": "CVE-2023-0001",
        "Severity": "HIGH",
        "Title": "Issue",
        "PrimaryURL": "https://nvd.nist.gov/vuln/CVE-2023-0001",
    }
    rule = ReportGenerator._sarif_rule("CVE-2023-0001", vuln)
    assert rule["helpUri"] == "https://nvd.nist.gov/vuln/CVE-2023-0001"


def test_sarif_rule_omits_help_uri_when_no_primary_url():
    vuln = {"VulnerabilityID": "compose-x", "Severity": "LOW", "Title": "Issue"}
    rule = ReportGenerator._sarif_rule("compose-x", vuln)
    assert "helpUri" not in rule


# ---------- CYCLONEDX SBOM TESTS ----------


def test_cyclonedx_report_writes_file_and_stamps_docksec(tmp_path):
    rg = ReportGenerator(image_name="myapp:latest", results_dir=str(tmp_path))
    trivy_bom = json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"tools": {"components": []}},
        "components": [{"type": "library", "name": "openssl", "version": "1.1.1"}],
    })
    path = rg.generate_cyclonedx_report(trivy_bom, tool_version="9.9.9")
    assert os.path.exists(path)
    assert path.endswith(".cdx.json")
    written = json.loads(open(path).read())
    assert written["bomFormat"] == "CycloneDX"
    # DockSec stamped into the 1.5-style tools.components list.
    names = [c.get("name") for c in written["metadata"]["tools"]["components"]]
    assert "DockSec" in names


def test_cyclonedx_report_handles_1_4_tools_list(tmp_path):
    rg = ReportGenerator(image_name="myapp:latest", results_dir=str(tmp_path))
    trivy_bom = json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {"tools": [{"vendor": "aquasecurity", "name": "trivy", "version": "0.68"}]},
        "components": [],
    })
    path = rg.generate_cyclonedx_report(trivy_bom, tool_version="1.0")
    written = json.loads(open(path).read())
    vendors = [t.get("name") for t in written["metadata"]["tools"]]
    assert "trivy" in vendors and "DockSec" in vendors


def test_cyclonedx_report_rejects_invalid_json(tmp_path):
    rg = ReportGenerator(image_name="myapp:latest", results_dir=str(tmp_path))
    assert rg.generate_cyclonedx_report("not json {", tool_version="1.0") == ""
