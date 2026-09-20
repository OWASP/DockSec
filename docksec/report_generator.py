"""
Report Generator Module

This module handles the generation of security scan reports in multiple formats:
- JSON: Structured data for programmatic access
- CSV: Tabular format for spreadsheet analysis
- PDF: Professional document format
- HTML: Interactive web-based report
- Markdown: Readable format for pull request comments and CI/CD job summaries

Each report format is optimized for its specific use case while maintaining
consistent data representation.
"""

import csv
import json
import os
import re
import warnings
from datetime import datetime
from typing import Dict, List, Optional

from docksec import output
from docksec.config import RESULTS_DIR, TEMPLATES_DIR
from docksec.score_calculator import SCORE_VERSION
from docksec.utils import get_custom_logger
from jinja2 import Environment, FileSystemLoader, select_autoescape

# fpdf2 emits a UserWarning at import time when the legacy PyFPDF package shares
# the same module namespace. It is environmental noise that is not actionable
# from a normal DockSec run, so install the filter before importing fpdf. The
# import must follow this statement, hence the E402 exemption.
warnings.filterwarnings("ignore", message=r".*PyFPDF & fpdf2.*")
from fpdf import FPDF  # noqa: E402

# Initialize logger
logger = get_custom_logger(__name__)


class ReportGenerator:
    """
    Generates security scan reports in multiple formats.

    Supports:
    - JSON reports for machine-readable output
    - CSV reports for spreadsheet analysis
    - PDF reports for professional documentation
    - HTML reports for interactive viewing
    - Markdown reports for CI/CD platforms (pull request comments, job summaries)
    """

    def __init__(self, image_name: str, results_dir: str = RESULTS_DIR):
        """
        Initialize the report generator.

        Args:
            image_name: Name of the Docker image being scanned
            results_dir: Directory to store generated reports
        """
        self.image_name = image_name
        self.results_dir = results_dir
        self.analysis_score: Optional[float] = None

        # Ensure results directory exists
        try:
            os.makedirs(self.results_dir, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create results directory {self.results_dir}: {e}")
            
        logger.info(f"ReportGenerator initialized. Reports will be saved to: {self.results_dir}")

    def set_analysis_score(self, score: float) -> None:
        """
        Set the security analysis score for reports.

        Args:
            score: Security score (0-100)
        """
        self.analysis_score = score
        logger.debug(f"Analysis score set to: {score}")

    def _get_safe_filename(self, extension: str) -> str:
        """
        Generate a safe filename from image name.

        Args:
            extension: File extension (e.g., 'json', 'csv', 'pdf', 'html')

        Returns:
            Safe filename with proper extension
        """
        safe_name = re.sub(r"[:/.\-]", "_", self.image_name)
        return os.path.join(self.results_dir, f"{safe_name}_scan_results.{extension}")

    def generate_json_report(self, results: Dict) -> str:
        """
        Generate JSON format report.

        Args:
            results: Scan results dictionary

        Returns:
            Path to the generated JSON file, or empty string on failure
        """
        output_file = self._get_safe_filename("json")
        logger.info(f"Generating JSON report: {output_file}")

        json_results = results.get("json_data", [])
        report_data = {
            "scan_info": {
                "image": self.image_name,
                "dockerfile": results.get("dockerfile_path", "N/A"),
                "scan_time": results.get(
                    "timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ),
                "analysis_score": self.analysis_score,
                "score_version": SCORE_VERSION,
                "scan_mode": results.get("scan_mode", "full"),
            },
            "vulnerabilities": json_results,
            "severity_counts": self._count_by_severity(json_results),
        }
        
        # Add AI findings if available
        if "ai_findings" in results:
            report_data["ai_analysis"] = results["ai_findings"]

        try:
            with open(output_file, "w") as f:
                json.dump(report_data, f, indent=4)
            logger.info("JSON report saved successfully")
            return output_file
        except Exception as e:
            logger.error(f"Error saving JSON report: {e}", exc_info=True)
            output.error(f"Failed to save JSON report: {e}")
            return ""

    def generate_sarif_report(self, results: Dict, tool_version: str = "unknown") -> str:
        """
        Generate a SARIF 2.1.0 report so findings can be uploaded to GitHub Code
        Scanning (or any other SARIF-compatible consumer).

        Each unique VulnerabilityID/rule-id becomes one SARIF rule, and each
        finding becomes one SARIF result pointing at the scanned Dockerfile or
        compose file. Findings with no source file to point at (e.g. an
        image-only scan) still get a result, using the image name as a
        synthetic artifact so they are not silently dropped.

        Args:
            results: Scan results dictionary
            tool_version: DockSec version string to embed in the SARIF driver

        Returns:
            Path to the generated SARIF file, or empty string on failure
        """
        output_file = self._get_safe_filename("sarif")
        logger.info(f"Generating SARIF report: {output_file}")

        vulnerabilities = results.get("json_data", [])
        artifact_uri = self._sarif_artifact_uri(results)

        rules: Dict[str, Dict] = {}
        sarif_results = []
        for vuln in vulnerabilities:
            rule_id = str(vuln.get("VulnerabilityID") or "UNKNOWN")
            if rule_id not in rules:
                rules[rule_id] = self._sarif_rule(rule_id, vuln)
            sarif_results.append(self._sarif_result(rule_id, vuln, artifact_uri))

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "DockSec",
                            "informationUri": "https://owasp.org/DockSec/",
                            "version": tool_version,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }

        try:
            with open(output_file, "w") as f:
                json.dump(sarif_doc, f, indent=2)
            logger.info(f"SARIF report saved successfully with {len(sarif_results)} results")
            return output_file
        except Exception as e:
            logger.error(f"Error saving SARIF report: {e}", exc_info=True)
            output.error(f"Failed to save SARIF report: {e}")
            return ""

    def generate_cyclonedx_report(self, sbom_json: str, tool_version: str = "unknown") -> str:
        """
        Write a CycloneDX SBOM to disk.

        The SBOM document itself is produced by Trivy (see
        DockerSecurityScanner.generate_sbom), which emits a spec-compliant
        CycloneDX BOM covering the full package inventory of the image. This
        method validates it is JSON, stamps DockSec into the tool metadata so
        downstream consumers can see which scanner emitted it, and writes it to
        a ``.cdx.json`` file next to the other reports.

        Args:
            sbom_json: Raw CycloneDX JSON string from Trivy.
            tool_version: DockSec version string to record in BOM metadata.

        Returns:
            Path to the generated SBOM file, or empty string on failure.
        """
        output_file = self._get_safe_filename("cdx.json")
        logger.info(f"Generating CycloneDX SBOM: {output_file}")

        try:
            bom = json.loads(sbom_json)
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"SBOM is not valid JSON: {e}")
            output.error(f"Failed to parse SBOM: {e}")
            return ""

        # Record DockSec in the tool metadata without disturbing Trivy's own
        # entry, so the BOM credits both the emitter and the wrapper.
        try:
            metadata = bom.setdefault("metadata", {})
            tools = metadata.get("tools")
            docksec_tool = {"vendor": "OWASP", "name": "DockSec", "version": tool_version}
            if isinstance(tools, dict):
                # CycloneDX 1.5+ shape: {"components": [...]}
                components = tools.setdefault("components", [])
                if isinstance(components, list):
                    components.append({
                        "type": "application",
                        "author": "OWASP",
                        "name": "DockSec",
                        "version": tool_version,
                    })
            elif isinstance(tools, list):
                # CycloneDX 1.4 shape: [{"vendor","name","version"}]
                tools.append(docksec_tool)
            else:
                metadata["tools"] = [docksec_tool]
        except Exception as e:  # metadata stamping is best-effort, never fatal
            logger.debug(f"Could not stamp DockSec into SBOM metadata: {e}")

        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(bom, f, indent=2)
            component_count = len(bom.get("components", []) or [])
            logger.info(f"CycloneDX SBOM saved with {component_count} components")
            return output_file
        except Exception as e:
            logger.error(f"Error saving SBOM: {e}", exc_info=True)
            output.error(f"Failed to save SBOM: {e}")
            return ""

    def _sarif_artifact_uri(self, results: Dict) -> str:
        """Resolve the file SARIF results should point at.

        Falls back to the image name when there is no Dockerfile/compose file
        on disk (image-only scans), so results still have a valid location.
        """
        dockerfile_path = results.get("dockerfile_path")
        if dockerfile_path and not str(dockerfile_path).startswith("N/A"):
            return os.path.basename(str(dockerfile_path))
        return self.image_name or "docksec-scan"

    @staticmethod
    def _sarif_level(severity) -> str:
        """Map DockSec severities to SARIF result levels."""
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "UNKNOWN": "note",
        }
        return mapping.get(str(severity or "UNKNOWN").upper(), "note")

    @staticmethod
    def _sarif_rule(rule_id: str, vuln: Dict) -> Dict:
        """Build the SARIF rule (reportingDescriptor) for one finding type."""
        rule = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": vuln.get("Title") or rule_id},
            "fullDescription": {"text": vuln.get("Description") or vuln.get("Title") or rule_id},
            "defaultConfiguration": {"level": ReportGenerator._sarif_level(vuln.get("Severity"))},
            "properties": {"security-severity": str(vuln.get("CVSS") or "")},
        }
        primary_url = vuln.get("PrimaryURL")
        if primary_url:
            rule["helpUri"] = primary_url
        return rule

    @staticmethod
    def _sarif_result(rule_id: str, vuln: Dict, artifact_uri: str) -> Dict:
        """Build one SARIF result for a finding."""
        pkg = vuln.get("PkgName")
        version = vuln.get("InstalledVersion")
        message = vuln.get("Title") or rule_id
        if pkg:
            message = f"{message} ({pkg}{'@' + version if version else ''})"

        region = ReportGenerator._sarif_region(vuln.get("Target"), vuln.get("Line"))
        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": artifact_uri},
            }
        }
        if region:
            location["physicalLocation"]["region"] = region

        return {
            "ruleId": rule_id,
            "level": ReportGenerator._sarif_level(vuln.get("Severity")),
            "message": {"text": message},
            "locations": [location],
        }

    @staticmethod
    def _sarif_region(target, line=None) -> Optional[Dict]:
        """Build a SARIF region for a finding, when its position is known.

        Two sources, in order of reliability:

        - ``line``: set directly by the Dockerfile scanners. Without this, a
          Dockerfile finding lands on the file with no position and GitHub
          cannot annotate the pull request line that caused it.
        - a compose ``Target`` of the form ``file:service:line``.

        Trivy image-vulnerability targets carry a package path rather than a
        line number, so those correctly produce no region.
        """
        if isinstance(line, int) and line > 0:
            return {"startLine": line}
        if not target:
            return None
        parts = str(target).rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            return {"startLine": max(1, int(parts[1]))}
        return None

    def generate_csv_report(self, results: Dict) -> str:
        """
        Generate CSV format report for vulnerability data.

        Args:
            results: Scan results dictionary

        Returns:
            Path to the generated CSV file, or empty string on failure
        """
        output_file = self._get_safe_filename("csv")
        logger.info(f"Generating CSV report: {output_file}")

        vulnerabilities = results.get("json_data", [])
        if not vulnerabilities:
            logger.warning(
                "No vulnerability data to save to CSV, creating header-only file"
            )

        try:
            # Map internal keys to expected CSV headers
            header_mapping = {
                "VulnerabilityID": "ID",
                "Severity": "Severity",
                "PkgName": "Package",
                "InstalledVersion": "Version",
                "Title": "Title",
                "CVSS": "CVSS",
                "Status": "Status",
                "Target": "Target",
                "PrimaryURL": "URL",
            }

            with open(output_file, "w", newline="") as csvfile:
                writer = csv.DictWriter(
                    csvfile, fieldnames=list(header_mapping.values())
                )
                writer.writeheader()

                for vuln in vulnerabilities:
                    row = {header_mapping[k]: vuln.get(k, "") for k in header_mapping}
                    writer.writerow(row)

            logger.info(
                f"CSV report saved successfully with {len(vulnerabilities)} vulnerabilities"
            )
            return output_file

        except Exception as e:
            logger.error(f"Error saving CSV report: {e}", exc_info=True)
            output.error(f"Failed to save CSV report: {e}")
            return ""

    def generate_pdf_report(self, results: Dict) -> str:
        """
        Generate PDF format report with professional formatting.

        Args:
            results: Scan results dictionary

        Returns:
            Path to the generated PDF file, or empty string on failure
        """
        output_file = self._get_safe_filename("pdf")
        logger.info(f"Generating PDF report: {output_file}")

        try:
            from fpdf.enums import XPos, YPos
            # Create custom PDF class with text wrapping
            class PDF(FPDF):
                def __init__(self):
                    super().__init__()
                    self.set_auto_page_break(True, margin=15)

                @staticmethod
                def _safe(text) -> str:
                    # Core fpdf fonts (helvetica/courier) only encode latin-1.
                    # Map the common typographic characters to ASCII equivalents
                    # and replace anything else that is out of range so PDF
                    # generation never raises UnicodeEncodeError on scanner
                    # output, vulnerability titles, or AI findings.
                    if text is None:
                        return ""
                    return (
                        str(text)
                        .replace("—", "--")
                        .replace("–", "-")
                        .replace("‘", "'")
                        .replace("’", "'")
                        .replace("“", '"')
                        .replace("”", '"')
                        .replace("…", "...")
                        .replace("•", "-")
                        .encode("latin-1", errors="replace")
                        .decode("latin-1")
                    )

                def cell(self, w=0, h=0, text="", *args, **kwargs):
                    return super().cell(w, h, self._safe(text), *args, **kwargs)

                def multi_cell(self, w=0, h=0, text="", *args, **kwargs):
                    return super().multi_cell(w, h, self._safe(text), *args, **kwargs)

                def multi_cell_with_title(self, title, content, title_w=40):
                    """Create title-content pair with multi-line support"""
                    self.set_font("helvetica", "B", 10)
                    x_start = self.get_x()
                    y_start = self.get_y()
                    self.cell(title_w, 7, title)
                    self.set_font("helvetica", "", 10)
                    self.set_xy(x_start + title_w, y_start)
                    self.multi_cell(0, 7, self._safe(content), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    self.ln(2)

                def add_section_header(self, title):
                    """Add a section header"""
                    self.set_font("helvetica", "B", 12)
                    self.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    self.ln(2)

            pdf = PDF()
            pdf.add_page()

            # Title
            pdf.set_font("helvetica", "B", 16)
            scan_mode = results.get("scan_mode", "full")
            title = f"Docker Security Scan Report ({scan_mode.upper()})"
            pdf.cell(0, 10, title, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(5)

            # Scan Information
            pdf.add_section_header("Scan Information")
            pdf.multi_cell_with_title("Image:", self.image_name)
            pdf.multi_cell_with_title("Scan Mode:", scan_mode.replace("_", " ").title())
            pdf.multi_cell_with_title(
                "Dockerfile:", results.get("dockerfile_path", "N/A")
            )
            pdf.multi_cell_with_title("Scan Date:", results.get("timestamp", ""))
            pdf.multi_cell_with_title("Analysis Score:", str(self.analysis_score))
            pdf.ln(5)

            # AI Dockerfile Analysis (if available)
            if "ai_findings" in results:
                ai_findings = results["ai_findings"]
                pdf.add_section_header("AI Dockerfile Analysis")
                
                # Vulnerabilities
                if ai_findings.get("vulnerabilities"):
                    pdf.set_font("helvetica", "B", 10)
                    pdf.cell(0, 7, "Vulnerabilities:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_font("helvetica", "", 9)
                    for i, vuln in enumerate(ai_findings["vulnerabilities"], 1):
                        pdf.multi_cell(0, 5, pdf._safe(f"{i}. {vuln}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.ln(2)
                
                # Best Practices
                if ai_findings.get("best_practices"):
                    pdf.set_font("helvetica", "B", 10)
                    pdf.cell(0, 7, "Best Practices:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_font("helvetica", "", 9)
                    for i, practice in enumerate(ai_findings["best_practices"], 1):
                        pdf.multi_cell(0, 5, pdf._safe(f"{i}. {practice}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.ln(2)
                
                # Security Risks
                if ai_findings.get("security_risks"):
                    pdf.set_font("helvetica", "B", 10)
                    pdf.cell(0, 7, "Security Risks:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_font("helvetica", "", 9)
                    for i, risk in enumerate(ai_findings["security_risks"], 1):
                        pdf.multi_cell(0, 5, pdf._safe(f"{i}. {risk}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.ln(2)
                
                # Exposed Credentials
                if ai_findings.get("exposed_credentials"):
                    pdf.set_font("helvetica", "B", 10)
                    pdf.cell(0, 7, "Exposed Credentials:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_font("helvetica", "", 9)
                    for i, cred in enumerate(ai_findings["exposed_credentials"], 1):
                        pdf.multi_cell(0, 5, pdf._safe(f"{i}. {cred}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.ln(2)
                
                # Remediation Steps
                if ai_findings.get("remediation"):
                    pdf.set_font("helvetica", "B", 10)
                    pdf.cell(0, 7, "Remediation Steps:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_font("helvetica", "", 9)
                    for i, step in enumerate(ai_findings["remediation"], 1):
                        pdf.multi_cell(0, 5, pdf._safe(f"{i}. {step}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.ln(5)

            # Image Information (if available)
            if "image_info" in results:
                pdf.add_section_header("Image Information")
                image_info = results["image_info"]

                if image_info.get("size"):
                    size_mb = round(image_info["size"] / (1024 * 1024), 2)
                    pdf.multi_cell_with_title("Size:", f"{size_mb} MB")

                if image_info.get("created"):
                    pdf.multi_cell_with_title("Created:", image_info["created"][:19])

                if image_info.get("architecture"):
                    pdf.multi_cell_with_title("Architecture:", image_info["architecture"])

                if image_info.get("os"):
                    pdf.multi_cell_with_title("OS:", image_info["os"])

                pdf.ln(5)

            # Configuration Analysis (if available)
            if "config_analysis" in results:
                pdf.add_section_header("Configuration Analysis")
                config_analysis = results["config_analysis"]

                # Count issues
                high_count = len(config_analysis.get("high_risk", []))
                medium_count = len(config_analysis.get("medium_risk", []))
                low_count = len(config_analysis.get("low_risk", []))
                total_count = high_count + medium_count + low_count

                pdf.multi_cell_with_title("Total Issues:", str(total_count))
                if high_count > 0:
                    pdf.multi_cell_with_title("High Risk:", str(high_count))
                if medium_count > 0:
                    pdf.multi_cell_with_title("Medium Risk:", str(medium_count))
                if low_count > 0:
                    pdf.multi_cell_with_title("Low Risk:", str(low_count))

                # Add issue details
                if high_count > 0:
                    pdf.ln(3)
                    pdf.set_font("helvetica", "B", 10)
                    pdf.cell(0, 7, "High-Risk Issues:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_font("helvetica", "", 9)
                    for issue in config_analysis["high_risk"]:
                        pdf.multi_cell(0, 5, f"• {issue}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                if medium_count > 0:
                    pdf.ln(3)
                    pdf.set_font("helvetica", "B", 10)
                    pdf.cell(0, 7, "Medium-Risk Issues:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_font("helvetica", "", 9)
                    for issue in config_analysis["medium_risk"]:
                        pdf.multi_cell(0, 5, f"• {issue}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                if low_count > 0:
                    pdf.ln(3)
                    pdf.set_font("helvetica", "B", 10)
                    pdf.cell(0, 7, "Low-Risk Issues:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_font("helvetica", "", 9)
                    for issue in config_analysis["low_risk"]:
                        pdf.multi_cell(0, 5, f"• {issue}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                pdf.ln(5)

            # Dockerfile scan results (if not skipped)
            if not results["dockerfile_scan"].get("skipped", False):
                pdf.add_section_header("Dockerfile Scan Results")

                if results["dockerfile_scan"]["success"]:
                    pdf.set_font("helvetica", "", 10)
                    pdf.cell(0, 7, "No Dockerfile linting issues found.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                else:
                    pdf.set_font("helvetica", "", 10)
                    pdf.cell(0, 7, "Dockerfile linting issues:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.ln(2)
                    pdf.set_font("courier", "", 8)

                    if results["dockerfile_scan"]["output"]:
                        for line in results["dockerfile_scan"]["output"].split("\n")[
                            :20
                        ]:
                            pdf.multi_cell(0, 5, line, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                pdf.ln(5)

            # Vulnerability summary
            pdf.add_section_header("Vulnerability Summary")
            vulnerabilities = results.get("json_data", [])

            if not vulnerabilities:
                pdf.set_font("helvetica", "", 10)
                pdf.cell(0, 7, "No vulnerabilities found.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            else:
                severity_counts = self._count_by_severity(vulnerabilities)

                pdf.set_font("helvetica", "", 10)
                pdf.cell(0, 7, f"Total vulnerabilities: {len(vulnerabilities)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                for severity, count in severity_counts.items():
                    pdf.cell(0, 7, f"{severity}: {count}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                pdf.ln(5)

                # Top vulnerabilities
                if len(vulnerabilities) > 0:
                    pdf.add_section_header("Top Vulnerabilities")

                    for i, vuln in enumerate(vulnerabilities[:20]):
                        if pdf.get_y() > pdf.h - 40:
                            pdf.add_page()

                        pdf.set_font("helvetica", "B", 9)
                        pdf.cell(
                            0,
                            6,
                            f"{i+1}. {vuln.get('VulnerabilityID', 'N/A')} ({vuln.get('Severity', 'N/A')})",
                            new_x=XPos.LMARGIN,
                            new_y=YPos.NEXT,
                        )

                        pdf.set_font("helvetica", "", 8)
                        pdf.multi_cell(
                            0,
                            4,
                            f"Package: {vuln.get('PkgName', 'N/A')} ({vuln.get('InstalledVersion', 'N/A')})",
                            new_x=XPos.LMARGIN,
                            new_y=YPos.NEXT,
                        )

                        title = vuln.get("Title", "")
                        if title:
                            pdf.multi_cell(
                                0,
                                4,
                                f"Title: {title[:100]}{'...' if len(title) > 100 else ''}",
                                new_x=XPos.LMARGIN,
                                new_y=YPos.NEXT,
                            )

                        pdf.ln(2)

                    if len(vulnerabilities) > 20:
                        pdf.ln(3)
                        pdf.set_font("helvetica", "I", 9)
                        pdf.cell(
                            0,
                            5,
                            f"Showing 20 of {len(vulnerabilities)} vulnerabilities. See CSV/JSON for complete list.",
                            new_x=XPos.LMARGIN,
                            new_y=YPos.NEXT,
                        )

            pdf.output(output_file)
            logger.info("PDF report saved successfully")
            return output_file

        except Exception as e:
            logger.error(f"Error saving PDF report: {e}", exc_info=True)
            output.error(f"Failed to save PDF report: {e}")
            return ""

    def generate_html_report(self, results: Dict) -> str:
        """
        Generate HTML format report with interactive features.

        Args:
            results: Scan results dictionary

        Returns:
            Path to the generated HTML file, or empty string on failure
        """
        output_file = self._get_safe_filename("html")
        logger.info(f"Generating HTML report: {output_file}")

        try:
            vulnerabilities = results.get("json_data", [])
            scan_mode = results.get("scan_mode", "full")
            severity_counts = self._count_by_severity(vulnerabilities)

            env = Environment(
                loader=FileSystemLoader(TEMPLATES_DIR),
                autoescape=select_autoescape(["html", "htm", "xml", "j2"]),
            )
            template = env.get_template("report.html.j2")
            html_content = template.render(
                image_name=self.image_name,
                scan_mode=scan_mode.replace("_", " ").title(),
                scan_mode_title=f"{scan_mode.replace('_', ' ').title()} Scan",
                dockerfile_path=results.get("dockerfile_path", "N/A"),
                scan_date=results.get("timestamp", ""),
                analysis_score=self.analysis_score,
                image_info=results.get("image_info"),
                config_analysis=results.get("config_analysis"),
                ai_findings=results.get("ai_findings"),
                dockerfile_scan=results.get("dockerfile_scan", {"skipped": True}),
                vulnerabilities=vulnerabilities,
                severity_counts=severity_counts,
                suppressed_count=results.get("suppressed_count"),
                ignore_file=results.get("ignore_file"),
            )

            # Save the HTML file
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)

            logger.info("HTML report saved successfully")
            return output_file

        except Exception as e:
            logger.error(f"Error saving HTML report: {e}", exc_info=True)
            output.error(f"Failed to save HTML report: {e}")
            return ""

    def generate_markdown_report(self, results: Dict) -> str:
        """
        Generate Markdown format report for CI/CD pipelines.

        Markdown renders natively in pull request comments and job summaries,
        so scan results can be shared without leaving the platform. The report
        reuses the same normalized vulnerability data as the other formats:
        severity counts plus a readable table of findings with fixed versions.

        Args:
            results: Scan results dictionary

        Returns:
            Path to the generated .md file, or empty string on failure
        """
        output_file = self._get_safe_filename("md")
        logger.info(f"Generating Markdown report: {output_file}")

        try:
            vulnerabilities = results.get("json_data", [])
            scan_mode = results.get("scan_mode", "full")
            severity_counts = self._count_by_severity(vulnerabilities)

            lines = [
                "# Docker Security Scan Report",
                "",
                f"**Image:** {self._escape_markdown(self.image_name)}",
                "**Scan Mode:** "
                f"{self._escape_markdown(scan_mode.replace('_', ' ').title())}",
                "**Dockerfile:** "
                f"{self._escape_markdown(results.get('dockerfile_path', 'N/A'))}",
                "**Scan Date:** "
                f"{self._escape_markdown(results.get('timestamp', 'N/A'))}",
                "**Analysis Score:** "
                f"{self.analysis_score if self.analysis_score is not None else 'N/A'}",
                "",
                "## Severity Summary",
                "",
                "| Severity | Count |",
                "|----------|-------|",
            ]

            # Zero-count severities are omitted so the summary stays compact.
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
                count = severity_counts.get(severity, 0)
                if count:
                    lines.append(f"| {severity} | {count} |")
            if not any(severity_counts.values()):
                lines.append("| No vulnerabilities found | 0 |")
            lines.append("")

            lines.extend(["## Vulnerabilities", ""])
            if not vulnerabilities:
                lines.append("No vulnerabilities found.")
                suppressed = results.get("suppressed_count")
                if suppressed:
                    ignore_file = self._escape_markdown(
                        str(results.get("ignore_file", ""))
                    )
                    lines.extend(
                        [
                            "",
                            f"> **Waived:** {suppressed} triaged finding(s) "
                            f"suppressed via ignore file `{ignore_file}`",
                        ]
                    )
            else:
                lines.append(
                    f"**Total vulnerabilities:** {len(vulnerabilities)}"
                )
                lines.append("")
                lines.append(
                    "| ID | Severity | Package | Installed Version | "
                    "Fixed Version | Title |"
                )
                lines.append(
                    "|----|----------|---------|-------------------|"
                    "---------------|-------|"
                )

                for vuln in vulnerabilities[:50]:
                    vuln_id = self._escape_markdown(
                        str(vuln.get("VulnerabilityID") or "N/A")
                    )
                    severity = self._escape_markdown(
                        str(vuln.get("Severity") or "N/A")
                    )
                    pkg_name = self._escape_markdown(
                        str(vuln.get("PkgName") or "N/A")
                    )
                    installed_version = self._escape_markdown(
                        str(vuln.get("InstalledVersion") or "N/A")
                    )
                    fixed_version = self._escape_markdown(
                        str(vuln.get("FixedVersion") or "none yet")
                    )
                    title = self._escape_markdown(str(vuln.get("Title") or "N/A"))
                    if len(title) > 80:
                        title = title[:80] + "..."
                    lines.append(
                        f"| {vuln_id} | {severity} | {pkg_name} | "
                        f"{installed_version} | {fixed_version} | {title} |"
                    )

                if len(vulnerabilities) > 50:
                    lines.extend(
                        [
                            "",
                            f"> Showing 50 of {len(vulnerabilities)} vulnerabilities. "
                            "See JSON/CSV for the complete list.",
                        ]
                    )

            with open(output_file, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")

            logger.info("Markdown report saved successfully")
            return output_file

        except Exception as e:
            logger.error(f"Error saving Markdown report: {e}", exc_info=True)
            output.error(f"Failed to save Markdown report: {e}")
            return ""

    def _escape_markdown(self, text) -> str:
        """
        Make text safe for Markdown tables.

        Table cells break on the pipe character and on line breaks, so those
        are escaped or flattened before a value is embedded in a row.

        Args:
            text: Text to sanitize

        Returns:
            Table-safe text
        """
        if not text:
            return ""
        return (
            str(text)
            .replace("\\", "\\\\")
            .replace("|", "\\|")
            .replace("\n", " ")
        )
    def _count_by_severity(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """
        Count vulnerabilities by severity level.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Dictionary mapping severity to count
        """
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0,
        }
        for vuln in vulnerabilities:
            severity = vuln.get("Severity", "UNKNOWN")
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["UNKNOWN"] += 1
        return severity_counts

    def generate_all_reports(self, results: Dict, formats=None) -> Dict[str, str]:
        """
        Generate report formats.

        Writing files is effectively instant, so this runs silently and returns
        the written paths; the CLI renders a single report summary from the
        return value (see docksec.output.report_results).

        Args:
            results: Scan results dictionary
            formats: Iterable of formats to write ('json', 'csv', 'pdf', 'html',
                     'markdown'). When None, the default four formats are
                     written.

        Returns:
            Dictionary mapping the requested format(s) to their file path
        """
        writers = {
            "json": self.generate_json_report,
            "csv": self.generate_csv_report,
            "pdf": self.generate_pdf_report,
            "html": self.generate_html_report,
            "markdown": self.generate_markdown_report,
        }
        # Markdown is opt-in: the default bundle keeps the original four
        # formats so existing workflows are untouched. Users opt in with
        # `--format markdown` (alone or alongside any of the others).
        default_formats = ["json", "csv", "pdf", "html"]
        selected = (
            list(default_formats)
            if formats is None
            else [f for f in writers if f in formats]
        )

        logger.info(f"Generating report formats: {', '.join(selected) or 'none'}")
        report_paths = {fmt: writers[fmt](results) for fmt in selected}
        logger.info(f"Reports generated: {report_paths}")
        return report_paths
