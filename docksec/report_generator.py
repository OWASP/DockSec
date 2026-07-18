"""
Report Generator Module

This module handles the generation of security scan reports in multiple formats:
- JSON: Structured data for programmatic access
- CSV: Tabular format for spreadsheet analysis
- PDF: Professional document format
- HTML: Interactive web-based report

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
from docksec.config import RESULTS_DIR, get_html_template
from docksec.utils import get_custom_logger

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

        region = ReportGenerator._sarif_region(vuln.get("Target"))
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
    def _sarif_region(target) -> Optional[Dict]:
        """Extract a line-number region from a compose Target ('file:service:line').

        Trivy image-vulnerability targets carry a package path, not a line
        number, so this only produces a region for compose findings.
        """
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
            template_vars = self._prepare_html_template_vars(results)

            # Replace placeholders in template
            html_content = get_html_template()
            for key, value in template_vars.items():
                html_content = html_content.replace(f"{{{{{key}}}}}", str(value))

            # Save the HTML file
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)

            logger.info("HTML report saved successfully")
            return output_file

        except Exception as e:
            logger.error(f"Error saving HTML report: {e}", exc_info=True)
            output.error(f"Failed to save HTML report: {e}")
            return ""

    def _prepare_html_template_vars(self, results: Dict) -> Dict[str, str]:
        """
        Prepare variables for HTML template replacement.

        Args:
            results: Scan results dictionary

        Returns:
            Dictionary of template variables
        """
        vulnerabilities = results.get("json_data", [])
        scan_mode = results.get("scan_mode", "full")

        template_vars = {
            "IMAGE_NAME": self.image_name,
            "SCAN_MODE": scan_mode.replace("_", " ").title(),
            "SCAN_MODE_TITLE": f"{scan_mode.replace('_', ' ').title()} Scan",
            "DOCKERFILE_PATH": results.get("dockerfile_path", "N/A"),
            "SCAN_DATE": results.get("timestamp", ""),
            "ANALYSIS_SCORE": (
                str(self.analysis_score) if self.analysis_score else "N/A"
            ),
        }

        # Security Score Section (rating bands match the terminal summary in
        # docksec.output._score_band)
        score_rating_html = ""
        if self.analysis_score is not None:
            score = float(self.analysis_score)
            if score >= 90:
                rating, rating_class = "Excellent", "rating-excellent"
            elif score >= 70:
                rating, rating_class = "Good", "rating-good"
            elif score >= 50:
                rating, rating_class = "Fair", "rating-fair"
            else:
                rating, rating_class = "Poor", "rating-poor"
            score_rating_html = f'<div class="score-rating {rating_class}">{rating}</div>'

        template_vars["SECURITY_SCORE_SECTION"] = f"""
        <div class="section">
            <h2>Security Score</h2>
            <div class="score-container">
                <div class="score-label">Overall Security Score</div>
                <div class="score-value">{self.analysis_score if self.analysis_score is not None else 'N/A'}/100</div>
                {score_rating_html}
            </div>
        </div>
        """

        # Image Information Section
        if "image_info" in results:
            image_info = results["image_info"]
            size_mb = (
                round(image_info.get("size", 0) / (1024 * 1024), 2)
                if image_info.get("size")
                else "N/A"
            )

            template_vars["IMAGE_INFO_SECTION"] = f"""
            <div class="section">
                <h2>Image Information</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Size</div>
                        <div class="info-value">{size_mb} MB</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Created</div>
                        <div class="info-value">{image_info.get('created', 'N/A')[:19]}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Architecture</div>
                        <div class="info-value">{image_info.get('architecture', 'N/A')}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">OS</div>
                        <div class="info-value">{image_info.get('os', 'N/A')}</div>
                    </div>
                </div>
            </div>
            """
        else:
            template_vars["IMAGE_INFO_SECTION"] = ""

        # Configuration Analysis Section
        if "config_analysis" in results:
            config_analysis = results["config_analysis"]
            config_html = (
                '<div class="section"><h2>Configuration Analysis</h2><div class="config-issues">'
            )

            # High risk issues
            if config_analysis.get("high_risk"):
                config_html += '<div class="config-category"><h4>High-Risk Issues</h4><ul class="config-list high">'
                for issue in config_analysis["high_risk"]:
                    config_html += f"<li>{self._escape_html(issue)}</li>"
                config_html += "</ul></div>"

            # Medium risk issues
            if config_analysis.get("medium_risk"):
                config_html += '<div class="config-category"><h4>Medium-Risk Issues</h4><ul class="config-list medium">'
                for issue in config_analysis["medium_risk"]:
                    config_html += f"<li>{self._escape_html(issue)}</li>"
                config_html += "</ul></div>"

            # Low risk issues
            if config_analysis.get("low_risk"):
                config_html += '<div class="config-category"><h4>Low-Risk Issues</h4><ul class="config-list low">'
                for issue in config_analysis["low_risk"]:
                    config_html += f"<li>{self._escape_html(issue)}</li>"
                config_html += "</ul></div>"

            config_html += "</div></div>"
            template_vars["CONFIG_ANALYSIS_SECTION"] = config_html
        else:
            template_vars["CONFIG_ANALYSIS_SECTION"] = ""

        # AI Dockerfile Analysis Section. Renders the full LLM findings (the
        # terminal shows only a truncated preview), so this is where the user
        # reads the complete list. Empty when no AI analysis ran.
        template_vars["AI_ANALYSIS_SECTION"] = self._build_ai_analysis_html(
            results.get("ai_findings")
        )

        # Dockerfile Section
        if not results["dockerfile_scan"].get("skipped", False):
            if results["dockerfile_scan"]["success"]:
                dockerfile_content = (
                    '<div class="no-issues">No Dockerfile linting issues found</div>'
                )
            else:
                dockerfile_output = results["dockerfile_scan"].get("output", "")
                dockerfile_content = f'<pre class="mono-block">{self._escape_html(dockerfile_output[:2000])}</pre>'
                if len(dockerfile_output) > 2000:
                    dockerfile_content += (
                        "<p><em>Output truncated for display...</em></p>"
                    )

            template_vars["DOCKERFILE_SECTION"] = f"""
            <div class="section">
                <h2>Dockerfile Scan Results</h2>
                {dockerfile_content}
            </div>
            """
        else:
            template_vars["DOCKERFILE_SECTION"] = ""

        # Vulnerability Summary
        if not vulnerabilities:
            no_issues_html = '<div class="no-issues">No vulnerabilities found</div>'
            suppressed = results.get("suppressed_count")
            if suppressed:
                ignore_file = self._escape_html(str(results.get("ignore_file", "")))
                no_issues_html += (
                    f"<p><strong>Waived:</strong> {suppressed} triaged finding(s) "
                    f"suppressed via ignore file {ignore_file}</p>"
                )
            template_vars["VULNERABILITY_SUMMARY"] = no_issues_html
            template_vars["DETAILED_VULNERABILITIES_SECTION"] = ""
        else:
            severity_counts = self._count_by_severity(vulnerabilities)

            severity_html = f"""
            <div class="severity-stats">
                <div class="severity-item severity-critical">
                    <div class="severity-count">{severity_counts.get('CRITICAL', 0)}</div>
                    <div class="severity-label">Critical</div>
                </div>
                <div class="severity-item severity-high">
                    <div class="severity-count">{severity_counts.get('HIGH', 0)}</div>
                    <div class="severity-label">High</div>
                </div>
                <div class="severity-item severity-medium">
                    <div class="severity-count">{severity_counts.get('MEDIUM', 0)}</div>
                    <div class="severity-label">Medium</div>
                </div>
                <div class="severity-item severity-low">
                    <div class="severity-count">{severity_counts.get('LOW', 0)}</div>
                    <div class="severity-label">Low</div>
                </div>
            </div>
            <p><strong>Total vulnerabilities:</strong> {len(vulnerabilities)}</p>
            """

            fixable = sum(1 for v in vulnerabilities if v.get("FixedVersion"))
            if fixable:
                severity_html += (
                    f"<p><strong>Fix available:</strong> {fixable} of "
                    f"{len(vulnerabilities)} findings have a fixed version upstream</p>"
                )
            suppressed = results.get("suppressed_count")
            if suppressed:
                ignore_file = self._escape_html(str(results.get("ignore_file", "")))
                severity_html += (
                    f"<p><strong>Waived:</strong> {suppressed} triaged finding(s) "
                    f"suppressed via ignore file {ignore_file}</p>"
                )

            template_vars["VULNERABILITY_SUMMARY"] = severity_html

            # Detailed vulnerabilities table
            table_html = """
            <div class="section">
                <h2>Detailed Vulnerabilities</h2>
                <div class="table-scroll">
                <table class="vulnerability-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Severity</th>
                            <th>Package</th>
                            <th>Installed</th>
                            <th>Fixed In</th>
                            <th>Title</th>
                            <th>CVSS</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
            """

            for vuln in vulnerabilities[:50]:
                severity = vuln.get("Severity", "UNKNOWN").lower()
                severity_class = (
                    f"badge-{severity}"
                    if severity in ["critical", "high", "medium", "low"]
                    else "badge-low"
                )

                status = vuln.get("Status", "affected")
                status_class = (
                    "status-fixed" if status == "fixed" else "status-affected"
                )

                cvss_score = vuln.get("CVSS", "N/A")
                if cvss_score and cvss_score != "N/A":
                    cvss_score = (
                        f"{cvss_score:.1f}"
                        if isinstance(cvss_score, (int, float))
                        else str(cvss_score)
                    )

                vuln_id = vuln.get('VulnerabilityID') or 'N/A'
                pkg_name = vuln.get('PkgName') or 'N/A'
                installed_version = vuln.get('InstalledVersion') or 'N/A'
                fixed_version = vuln.get('FixedVersion') or ''
                fixed_cell = (
                    f'<span class="fixed-version">{self._escape_html(fixed_version)}</span>'
                    if fixed_version else '<span class="no-fix">none yet</span>'
                )
                title = vuln.get('Title') or 'N/A'
                display_title = (title[:80] + '...') if len(title) > 80 else title

                table_html += f"""
                        <tr>
                            <td><strong>{self._escape_html(vuln_id)}</strong></td>
                            <td><span class="severity-badge {severity_class}">{vuln.get('Severity', 'N/A')}</span></td>
                            <td>{self._escape_html(pkg_name)}</td>
                            <td>{self._escape_html(installed_version)}</td>
                            <td>{fixed_cell}</td>
                            <td>{self._escape_html(display_title)}</td>
                            <td>{cvss_score}</td>
                            <td><span class="status-badge {status_class}">{status}</span></td>
                        </tr>
                """

            table_html += """
                    </tbody>
                </table>
                </div>
            """

            if len(vulnerabilities) > 50:
                table_html += f'<p class="table-note">Showing 50 of {len(vulnerabilities)} vulnerabilities. See CSV/JSON for complete list.</p>'

            table_html += "</div>"
            template_vars["DETAILED_VULNERABILITIES_SECTION"] = table_html

        return template_vars

    def _build_ai_analysis_html(self, ai_findings: Optional[Dict]) -> str:
        """
        Build the AI Dockerfile Analysis HTML section from LLM findings.

        Renders every finding in full (unlike the truncated terminal preview)
        so the report is the authoritative place to read the complete list.

        Args:
            ai_findings: The "ai_findings" dict produced by analyze_security,
                or None when no AI analysis ran.

        Returns:
            HTML string for the section, or "" when there are no findings.
        """
        if not ai_findings:
            return ""

        # (key, heading, config-list severity class) for each category.
        categories = [
            ("vulnerabilities", "Vulnerabilities", "high"),
            ("security_risks", "Security Risks", "high"),
            ("exposed_credentials", "Exposed Credentials", "high"),
            ("best_practices", "Best Practices", "medium"),
            ("remediation", "Remediation Steps", "low"),
        ]

        blocks = []
        for key, heading, list_class in categories:
            items = ai_findings.get(key) or []
            if not items:
                continue
            list_items = "".join(
                f"<li>{self._escape_html(str(item))}</li>" for item in items
            )
            blocks.append(
                f'<div class="config-category">'
                f"<h4>{self._escape_html(heading)} ({len(items)})</h4>"
                f'<ul class="config-list {list_class}">{list_items}</ul>'
                f"</div>"
            )

        if not blocks:
            return ""

        return (
            '<div class="section"><h2>AI Dockerfile Analysis</h2>'
            '<div class="config-issues">' + "".join(blocks) + "</div></div>"
        )

    def _escape_html(self, text: str) -> str:
        """
        Escape HTML special characters in text.

        Uses Python's built-in html.escape() for complete HTML5
        entity handling, replacing the previous hand-rolled table.

        Args:
            text: Text to escape

        Returns:
            HTML-escaped text
        """
        import html

        if not text:
            return ""
        return html.escape(str(text), quote=True)

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
            formats: Iterable of formats to write ('json', 'csv', 'pdf', 'html').
                     When None, all four formats are written.

        Returns:
            Dictionary mapping the requested format(s) to their file path
        """
        writers = {
            "json": self.generate_json_report,
            "csv": self.generate_csv_report,
            "pdf": self.generate_pdf_report,
            "html": self.generate_html_report,
        }
        selected = list(writers) if formats is None else [f for f in writers if f in formats]

        logger.info(f"Generating report formats: {', '.join(selected) or 'none'}")
        report_paths = {fmt: writers[fmt](results) for fmt in selected}
        logger.info(f"Reports generated: {report_paths}")
        return report_paths
