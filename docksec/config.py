from dotenv import load_dotenv
import os
from typing import Optional, Dict, List, Any
from collections import defaultdict


load_dotenv()


# Lazy-load API key to allow scan-only mode without API key
def get_openai_api_key() -> str:
    """
    Get OpenAI API key, raising error only when AI features are needed.
    
    Returns:
        str: The OpenAI API key from environment variables
        
    Raises:
        EnvironmentError: If OPENAI_API_KEY is not set
    """
    api_key: Optional[str] = os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        error_message = """
[ERROR] No OpenAI API Key provided.

You can fix this by setting the `OPENAI_API_KEY` in one of the following ways:

- PowerShell (Windows):
    $env:OPENAI_API_KEY = "your-secret-key"

- Command Prompt (CMD on Windows):
    set OPENAI_API_KEY=your-secret-key

- Bash/Zsh (Linux/macOS):
    export OPENAI_API_KEY="your-secret-key"

- Or create a `.env` file with:
    OPENAI_API_KEY=your-secret-key


[SECURITY] Reminder: Never hardcode your API key in public code or repositories. It is necessary to use DockSec AI features.

Note: You can use scan-only mode (--scan-only) without an API key.
"""
        raise EnvironmentError(error_message.strip())
    return api_key

# Set environment variable if key exists (for backward compatibility)
# But don't raise error if missing - let get_openai_api_key() handle that
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
if OPENAI_API_KEY:
    os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY

BASE_DIR: str = os.path.abspath(os.path.dirname(__file__))

# Results directory configuration
# Priority: 1. Environment variable, 2. Home directory (default), 3. Local directory (fallback)
# Users can customize by setting: export DOCKSEC_RESULTS_DIR=/custom/path
DEFAULT_RESULTS_DIR: str = os.path.join(os.path.expanduser("~"), ".docksec", "results")
RESULTS_DIR: str = os.getenv("DOCKSEC_RESULTS_DIR", DEFAULT_RESULTS_DIR)
TEMPLATES_DIR: str = os.path.join(BASE_DIR, "templates")

# Create results directory if it doesn't exist
try:
    os.makedirs(RESULTS_DIR, exist_ok=True)
except Exception:
    # Fallback to local directory if home directory is not writable
    RESULTS_DIR = os.path.join(os.getcwd(), "docksec_results")
    os.makedirs(RESULTS_DIR, exist_ok=True)


def get_html_template() -> str:
    """
    Load the HTML report template from the templates directory.
    """
    template_path = os.path.join(TEMPLATES_DIR, "report_template.html")
    try:
        if os.path.exists(template_path):
            with open(template_path, 'r', encoding='utf-8') as f:
                return f.read()
        else:
            # Fallback for when running from a location where templates might not be correctly linked
            # This is a safety measure
            return "<html><body><h1>Docker Security Report</h1><p>Template missing at " + template_path + "</p></body></html>"
    except Exception as e:
        return f"<html><body><h1>Error</h1><p>{str(e)}</p></body></html>"


# For backward compatibility with existing code that imports html_template
html_template = get_html_template()


# Helper functions for token optimization
def truncate_dockerfile(content: str, max_lines: int = 400, max_chars: int = 16000) -> str:
    """
    Truncate Dockerfile to reduce token usage for LLM analysis.
    Keeps first N lines and limits total characters.
    """
    lines = content.split('\n')
    is_truncated = False
    
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        is_truncated = True
        
    truncated = '\n'.join(lines)
    
    if len(truncated) > max_chars:
        truncated = truncated[:max_chars]
        is_truncated = True
    
    if is_truncated:
        truncated += "\n... [truncated]"
    
    return truncated

def summarize_vulnerabilities(vulnerabilities: List[Dict[str, Any]], max_count: int = 10) -> str:
    """
    Create an extremely concise summary of vulnerabilities for LLM scoring.
    Reduces token usage by grouping and limiting details.
    """
    if not vulnerabilities:
        return "No vulnerabilities found."
    
    # Count by severity
    severity_counts = {}
    # Group by severity to pick top ones
    by_severity = defaultdict(list)
    
    for vuln in vulnerabilities:
        severity = vuln.get('Severity', 'UNKNOWN')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if severity in ['CRITICAL', 'HIGH']:
            by_severity[severity].append(f"{vuln.get('PkgName', 'N/A')} ({vuln.get('VulnerabilityID', 'N/A')})")
    
    # Build summary
    summary = f"Total: {len(vulnerabilities)}. "
    summary += f"Breakdown: {', '.join(f'{k}: {v}' for k, v in sorted(severity_counts.items()))}. "
    
    # Add only top few critical and high issues
    details = []
    for sev in ['CRITICAL', 'HIGH']:
        if by_severity[sev]:
            top_issues = by_severity[sev][:5] # Max 5 per severity
            details.append(f"Top {sev}: {', '.join(top_issues)}")
    
    if details:
        summary += " | ".join(details)
    
    return summary

docker_agent_template = """
Analyze Dockerfile for security. Output ONLY JSON:
{{
    "vulnerabilities": [],
    "best_practices": [],
    "SecurityRisks": [],
    "ExposedCredentials": [],
    "remediation": []
}}
Dockerfile:
{filecontent}
"""

docker_score_template = """
Score Docker security 1-100. Output ONLY JSON: {{"score": N}}
90-100: Excellent, 70-89: Good, 50-69: Fair, 0-49: Poor.
Summary:
{results}
"""


def _build_prompt(template: str, input_variables: List[str]):
    """Build a LangChain PromptTemplate on demand.

    langchain-core is part of the optional [ai] extra, so the import lives
    here rather than at module level: the core (scan-only) install imports
    docksec.config for RESULTS_DIR and helpers without pulling in LangChain.
    """
    try:
        from langchain_core.prompts import PromptTemplate
    except ImportError:
        raise ImportError(
            "AI analysis requested but the AI dependencies are not installed. "
            "Install them with: pip install \"docksec[ai]\""
        )
    return PromptTemplate(input_variables=input_variables, template=template)


def __getattr__(name: str):
    # PEP 562 lazy attributes: prompts are only materialized (and LangChain
    # only imported) when an AI code path actually asks for them.
    if name == "docker_agent_prompt":
        return _build_prompt(docker_agent_template, ["filecontent"])
    if name == "docker_score_prompt":
        return _build_prompt(docker_score_template, ["results"])
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
