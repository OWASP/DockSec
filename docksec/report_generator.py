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

import os
import json
import csv
import re
import logging
from typing import Dict, List, Optional
from datetime import datetime
from fpdf import FPDF
from pathlib import Path

from docksec.config import RESULTS_DIR, html_template
from docksec.utils import get_custom_logger

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
        os.makedirs(self.results_dir, exist_ok=True)
        logger.info(f"ReportGenerator initialized for image: {image_name}")
    
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
        safe_name = re.sub(r'[:/.\-]', '_', self.image_name)
        return os.path.join(self.results_dir, f"{safe_name}_scan_results.{extension}")
    
    def generate_json_report(self, results: Dict) -> str:
        """
        Generate JSON format report.
        
        Args:
            results: Scan results dictionary
            
        Returns:
            Path to the generated JSON file, or empty string on failure
        """
        output_file = self._get_safe_filename('json')
        logger.info(f"Generating JSON report: {output_file}")
        
        json_results = results.get('json_data', [])
        report_data = {
            "scan_info": {
                "image": self.image_name,
                "dockerfile": results.get('dockerfile_path', 'N/A'),
                "scan_time": results.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                "analysis_score": self.analysis_score,
                "scan_mode": results.get('scan_mode', 'full')
            },
            "vulnerabilities": json_results,
            "summary": {
                "total_vulnerabilities": len(json_results),
                "by_severity": self._count_by_severity(json_results)
            }
        }
        
        try:
            with open(output_file, "w") as f:
                json.dump(report_data, f, indent=4)
            logger.info(f"JSON report saved successfully")
            print(f"[SUCCESS] JSON report saved to {output_file}")
            return output_file
        except Exception as e:
            logger.error(f"Error saving JSON report: {e}", exc_info=True)
            print(f"[ERROR] Error saving JSON report: {e}")
            return ""
    
    def generate_csv_report(self, results: Dict) -> str:
        """
        Generate CSV format report for vulnerability data.
        
        Args:
            results: Scan results dictionary
            
        Returns:
            Path to the generated CSV file, or empty string on failure
        """
        output_file = self._get_safe_filename('csv')
        logger.info(f"Generating CSV report: {output_file}")
        
        vulnerabilities = results.get('json_data', [])
        if not vulnerabilities:
            logger.warning("No vulnerability data to save to CSV")
            print("[WARNING] No vulnerability data to save to CSV")
            return ""
        
        try:
            fieldnames = [
                "VulnerabilityID", "Severity", "PkgName", "InstalledVersion",
                "Title", "Description", "CVSS", "Status", "Target", "PrimaryURL"
            ]
            
            with open(output_file, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for vuln in vulnerabilities:
                    filtered_vuln = {k: vuln.get(k, "") for k in fieldnames}
                    writer.writerow(filtered_vuln)
            
            logger.info(f"CSV report saved successfully with {len(vulnerabilities)} vulnerabilities")
            print(f"[SUCCESS] CSV report saved to {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Error saving CSV report: {e}", exc_info=True)
            print(f"[ERROR] Error saving CSV report: {e}")
            return ""
    
    def generate_pdf_report(self, results: Dict) -> str:
        """
        Generate PDF format report with professional formatting.
        
        Args:
            results: Scan results dictionary
            
        Returns:
            Path to the generated PDF file, or empty string on failure
        """
        output_file = self._get_safe_filename('pdf')
        logger.info(f"Generating PDF report: {output_file}")
        
        try:
            # Create custom PDF class with text wrapping
            class PDF(FPDF):
                def __init__(self):
                    super().__init__()
                    self.set_auto_page_break(True, margin=15)
                
                def multi_cell_with_title(self, title, content, title_w=40):
                    """Create title-content pair with multi-line support"""
                    self.set_font('Arial', 'B', 10)
                    x_start = self.get_x()
                    y_start = self.get_y()
                    self.cell(title_w, 7, title)
                    self.set_font('Arial', '', 10)
                    self.set_xy(x_start + title_w, y_start)
                    self.multi_cell(0, 7, content)
                    self.ln(2)
                
                def add_section_header(self, title):
                    """Add a section header"""
                    self.set_font('Arial', 'B', 12)
                    self.cell(0, 10, title, 0, 1)
                    self.ln(2)
            
            pdf = PDF()
            pdf.add_page()
            
            # Title
            pdf.set_font('Arial', 'B', 16)
            scan_mode = results.get('scan_mode', 'full')
            title = f'Docker Security Scan Report ({scan_mode.upper()})'
            pdf.cell(0, 10, title, 0, 1, 'C')
            pdf.ln(5)
            
            # Scan Information
            pdf.add_section_header('Scan Information')
            pdf.multi_cell_with_title('Image:', self.image_name)
            pdf.multi_cell_with_title('Scan Mode:', scan_mode.replace('_', ' ').title())
            pdf.multi_cell_with_title('Dockerfile:', results.get('dockerfile_path', 'N/A'))
            pdf.multi_cell_with_title('Scan Date:', results.get('timestamp', ''))
            pdf.multi_cell_with_title('Analysis Score:', str(self.analysis_score))
            pdf.ln(5)
            
            # Dockerfile scan results (if not skipped)
            if not results['dockerfile_scan'].get('skipped', False):
                pdf.add_section_header('Dockerfile Scan Results')
                
                if results['dockerfile_scan']['success']:
                    pdf.set_font('Arial', '', 10)
                    pdf.cell(0, 7, 'No Dockerfile linting issues found.', 0, 1)
                else:
                    pdf.set_font('Arial', '', 10)
                    pdf.cell(0, 7, 'Dockerfile linting issues:', 0, 1)
                    pdf.ln(2)
                    pdf.set_font('Courier', '', 8)
                    
                    if results['dockerfile_scan']['output']:
                        for line in results['dockerfile_scan']['output'].split('\n')[:20]:
                            pdf.multi_cell(0, 5, line)
                
                pdf.ln(5)
            
            # Vulnerability summary
            pdf.add_section_header('Vulnerability Summary')
            vulnerabilities = results.get('json_data', [])
            
            if not vulnerabilities:
                pdf.set_font('Arial', '', 10)
                pdf.cell(0, 7, 'No vulnerabilities found.', 0, 1)
            else:
                severity_counts = self._count_by_severity(vulnerabilities)
                
                pdf.set_font('Arial', '', 10)
                pdf.cell(0, 7, f'Total vulnerabilities: {len(vulnerabilities)}', 0, 1)
                
                for severity, count in severity_counts.items():
                    pdf.cell(0, 7, f'{severity}: {count}', 0, 1)
                
                pdf.ln(5)
                
                # Top vulnerabilities
                if len(vulnerabilities) > 0:
                    pdf.add_section_header('Top Vulnerabilities')
                    
                    for i, vuln in enumerate(vulnerabilities[:20]):
                        if pdf.get_y() > pdf.h - 40:
                            pdf.add_page()
                        
                        pdf.set_font('Arial', 'B', 9)
                        pdf.cell(0, 6, f"{i+1}. {vuln.get('VulnerabilityID', 'N/A')} ({vuln.get('Severity', 'N/A')})", 0, 1)
                        
                        pdf.set_font('Arial', '', 8)
                        pdf.multi_cell(0, 4, f"Package: {vuln.get('PkgName', 'N/A')} ({vuln.get('InstalledVersion', 'N/A')})")
                        
                        title = vuln.get('Title', '')
                        if title:
                            pdf.multi_cell(0, 4, f"Title: {title[:100]}{'...' if len(title) > 100 else ''}")
                        
                        pdf.ln(2)
                    
                    if len(vulnerabilities) > 20:
                        pdf.ln(3)
                        pdf.set_font('Arial', 'I', 9)
                        pdf.cell(0, 5, f'Showing 20 of {len(vulnerabilities)} vulnerabilities. See CSV/JSON for complete list.', 0, 1)
            
            pdf.output(output_file)
            logger.info(f"PDF report saved successfully")
            print(f"[SUCCESS] PDF report saved to {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Error saving PDF report: {e}", exc_info=True)
            print(f"[ERROR] Error saving PDF report: {e}")
            return ""
    
    def generate_html_report(self, results: Dict) -> str:
        """
        Generate HTML format report with interactive features.
        
        Args:
            results: Scan results dictionary
            
        Returns:
            Path to the generated HTML file, or empty string on failure
        """
        output_file = self._get_safe_filename('html')
        logger.info(f"Generating HTML report: {output_file}")
        
        try:
            template_vars = self._prepare_html_template_vars(results)
            
            # Replace placeholders in template
            html_content = html_template
            for key, value in template_vars.items():
                html_content = html_content.replace(f'{{{{{key}}}}}', str(value))
            
            # Save the HTML file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report saved successfully")
            print(f"[SUCCESS] HTML report saved to {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Error saving HTML report: {e}", exc_info=True)
            print(f"[ERROR] Error saving HTML report: {e}")
            return ""
    
    def _prepare_html_template_vars(self, results: Dict) -> Dict[str, str]:
        """
        Prepare variables for HTML template replacement.
        
        Args:
            results: Scan results dictionary
            
        Returns:
            Dictionary of template variables
        """
        vulnerabilities = results.get('json_data', [])
        scan_mode = results.get('scan_mode', 'full')
        
        template_vars = {
            'IMAGE_NAME': self.image_name,
            'SCAN_MODE': scan_mode.replace('_', ' ').title(),
            'SCAN_MODE_TITLE': f"{scan_mode.replace('_', ' ').title()} Scan",
            'DOCKERFILE_PATH': results.get('dockerfile_path', 'N/A'),
            'SCAN_DATE': results.get('timestamp', ''),
            'ANALYSIS_SCORE': str(self.analysis_score) if self.analysis_score else 'N/A'
        }
        
        # Security Score Section (placeholder for now)
        template_vars['SECURITY_SCORE_SECTION'] = ""
        template_vars['IMAGE_INFO_SECTION'] = ""
        template_vars['CONFIG_ANALYSIS_SECTION'] = ""
        
        # Dockerfile Section
        if not results['dockerfile_scan'].get('skipped', False):
            if results['dockerfile_scan']['success']:
                dockerfile_content = '<div class="no-issues">No Dockerfile linting issues found</div>'
            else:
                dockerfile_output = results['dockerfile_scan'].get('output', '')
                dockerfile_content = f'<pre style="background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; font-size: 0.9em;">{self._escape_html(dockerfile_output[:2000])}</pre>'
                if len(dockerfile_output) > 2000:
                    dockerfile_content += '<p><em>Output truncated for display...</em></p>'
            
            template_vars['DOCKERFILE_SECTION'] = f"""
            <div class="section">
                <h2>Dockerfile Scan Results</h2>
                {dockerfile_content}
            </div>
            """
        else:
            template_vars['DOCKERFILE_SECTION'] = ""
        
        # Vulnerability Summary
        if not vulnerabilities:
            template_vars['VULNERABILITY_SUMMARY'] = '<div class="no-issues">No vulnerabilities found</div>'
            template_vars['DETAILED_VULNERABILITIES_SECTION'] = ""
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
            
            template_vars['VULNERABILITY_SUMMARY'] = severity_html
            
            # Detailed vulnerabilities table
            table_html = """
            <div class="section">
                <h2>Detailed Vulnerabilities</h2>
                <table class="vulnerability-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Severity</th>
                            <th>Package</th>
                            <th>Version</th>
                            <th>Title</th>
                            <th>CVSS</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for vuln in vulnerabilities[:50]:
                severity = vuln.get('Severity', 'UNKNOWN').lower()
                severity_class = f'badge-{severity}' if severity in ['critical', 'high', 'medium', 'low'] else 'badge-low'
                
                status = vuln.get('Status', 'affected')
                status_class = 'status-fixed' if status == 'fixed' else 'status-affected'
                
                cvss_score = vuln.get('CVSS', 'N/A')
                if cvss_score and cvss_score != 'N/A':
                    cvss_score = f"{cvss_score:.1f}" if isinstance(cvss_score, (int, float)) else str(cvss_score)
                
                table_html += f"""
                        <tr>
                            <td><strong>{self._escape_html(vuln.get('VulnerabilityID', 'N/A'))}</strong></td>
                            <td><span class="severity-badge {severity_class}">{vuln.get('Severity', 'N/A')}</span></td>
                            <td>{self._escape_html(vuln.get('PkgName', 'N/A'))}</td>
                            <td>{self._escape_html(vuln.get('InstalledVersion', 'N/A'))}</td>
                            <td>{self._escape_html((vuln.get('Title', '')[:80] + '...') if len(vuln.get('Title', '')) > 80 else vuln.get('Title', 'N/A'))}</td>
                            <td>{cvss_score}</td>
                            <td><span class="status-badge {status_class}">{status}</span></td>
                        </tr>
                """
            
            table_html += """
                    </tbody>
                </table>
            """
            
            if len(vulnerabilities) > 50:
                table_html += f'<p style="margin-top: 15px; font-style: italic; color: #666;">Showing 50 of {len(vulnerabilities)} vulnerabilities. See CSV/JSON for complete list.</p>'
            
            table_html += '</div>'
            template_vars['DETAILED_VULNERABILITIES_SECTION'] = table_html
        
        return template_vars
    
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
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('Severity', 'UNKNOWN')
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts['UNKNOWN'] += 1
        return severity_counts
    
    def generate_all_reports(self, results: Dict) -> Dict[str, str]:
        """
        Generate all report formats.
        
        Args:
            results: Scan results dictionary
            
        Returns:
            Dictionary mapping format to file path
        """
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
        
        logger.info("Generating all report formats")
        print("\n=== Generating Reports ===")
        
        report_paths = {
            'json': '',
            'csv': '',
            'pdf': '',
            'html': ''
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=None
        ) as progress:
            # JSON report
            json_task = progress.add_task("[cyan]Generating JSON report...", total=1)
            json_path = self.generate_json_report(results)
            if json_path:
                report_paths['json'] = json_path
            progress.update(json_task, advance=1)
            
            # CSV report
            csv_task = progress.add_task("[cyan]Generating CSV report...", total=1)
            csv_path = self.generate_csv_report(results)
            if csv_path:
                report_paths['csv'] = csv_path
            progress.update(csv_task, advance=1)
            
            # PDF report
            pdf_task = progress.add_task("[cyan]Generating PDF report...", total=1)
            pdf_path = self.generate_pdf_report(results)
            if pdf_path:
                report_paths['pdf'] = pdf_path
            progress.update(pdf_task, advance=1)
            
            # HTML report
            html_task = progress.add_task("[cyan]Generating HTML report...", total=1)
            html_path = self.generate_html_report(results)
            if html_path:
                report_paths['html'] = html_path
            progress.update(html_task, advance=1)
        
        print("\n[SUCCESS] All reports generated successfully!")
        logger.info(f"All reports generated: {report_paths}")
        return report_paths

