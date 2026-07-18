import logging
import sys
import os
from typing import Union, List, Optional, Dict

# All LLM providers are optional: the core (scan-only) install ships without
# the AI dependency stack. Install AI support with: pip install "docksec[ai]"
try:
    from langchain_openai import ChatOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    ChatOpenAI = None
    OPENAI_AVAILABLE = False

try:
    from langchain_anthropic import ChatAnthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    from langchain_google_genai import ChatGoogleGenerativeAI
    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False

try:
    from langchain_ollama import ChatOllama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
from docksec.config import (
    BASE_DIR
)
from docksec.enums import LLMProvider
try:
    from pydantic import BaseModel, Field
except ImportError:
    try:
        from langchain_core.pydantic_v1 import BaseModel, Field
    except ImportError:
        raise ImportError(
            "Either 'pydantic' or 'langchain-core' must be installed. "
            "Install with: pip install pydantic langchain-core"
        )
from colorama import init
from rich.console import Console

def get_custom_logger(name: str = 'Docksec', user_facing: bool = False):
    logger = logging.getLogger(name)

    # Resolve the log level.
    # Priority: explicit DOCKSEC_LOG_LEVEL override, then context defaults.
    # In CLI mode the tool prints its own user-facing [INFO]/[WARNING]/[ERROR]
    # messages, so the raw logger stays quiet (ERROR) to avoid cluttering output
    # with duplicated, location-tagged log lines. Library/programmatic use keeps
    # the more verbose INFO default.
    cli_mode = os.getenv("DOCKSEC_CLI_MODE", "false").lower() == "true"
    override = os.getenv("DOCKSEC_LOG_LEVEL")
    if override:
        log_level = getattr(logging, override.strip().upper(), logging.INFO)
    elif user_facing or cli_mode:
        log_level = logging.ERROR
    else:
        log_level = logging.INFO

    logger.setLevel(log_level)
    # Logs go to stderr so stdout stays clean for user-facing output and any
    # machine-readable results piped to other tools.
    formatter = logging.Formatter('%(levelname)s - %(name)s - Line %(lineno)d: %(message)s')
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    # DOCKSEC_LOG_FILE (set by --log-file) duplicates log output to a file so a
    # CI run can collect it as an artifact. Handlers append: every module builds
    # its own logger, so several FileHandlers share one path and truncating here
    # would let them clobber each other.
    log_file = os.getenv("DOCKSEC_LOG_FILE")
    if log_file and not any(isinstance(h, logging.FileHandler) for h in logger.handlers):
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    for handler in logger.handlers:
        handler.setLevel(log_level)
    # Don't propagate to the root logger; prevents duplicate emission.
    logger.propagate = False

    return logger


logger = get_custom_logger(name=__name__)

# Load docker file from the provided directory path if not provided get it from the BASE_DIR

def load_docker_file(docker_file_path: Optional[str] = None) -> Optional[str]:
    """
    Load Dockerfile content from the specified path.
    
    Args:
        docker_file_path: Path to the Dockerfile. If None, defaults to BASE_DIR/Dockerfile
        
    Returns:
        str: Content of the Dockerfile, or None if file not found
    """
    if not docker_file_path:
        docker_file_path = BASE_DIR + "/Dockerfile"
    try:
        with open(docker_file_path, "r") as file:
            docker_file: str = file.read()
    except FileNotFoundError:
        logger.error(f"File not found at path: {docker_file_path}")
        return None
    return docker_file

class AnalyzesResponse(BaseModel):
    vulnerabilities: List[str] = Field(description="List of vulnerabilities found in the Dockerfile")
    best_practices: List[str] = Field(description="Best practices to follow to mitigate these vulnerabilities")
    SecurityRisks: List[str] = Field(description= "security risks associated with Dockerfile")
    ExposedCredentials: List[str] = Field(description="List of exposed credentials in the Dockerfile")
    remediation: List[str] = Field(description="List of remediation steps to fix the vulnerabilities")

class ScoreResponse(BaseModel):
    score: float = Field(description="Security score for the Dockerfile")

def get_llm() -> Union['ChatOpenAI', 'ChatAnthropic', 'ChatGoogleGenerativeAI', 'ChatOllama']:
    """
    Get LLM instance with retry logic and rate limiting support.
    
    This function checks for API key availability and returns a configured
    LLM instance based on the configured provider. All calls through this LLM 
    will have automatic retry logic with exponential backoff for transient 
    failures and rate limiting.
    
    Supported providers:
    - OpenAI (gpt-4o, gpt-4-turbo, gpt-3.5-turbo)
    - Anthropic (claude-3-5-sonnet-20241022, claude-3-opus-20240229)
    - Google (gemini-1.5-pro, gemini-1.5-flash)
    - Ollama (llama3.1, mistral, phi3, local models)
    
    Returns:
        LLM instance (ChatOpenAI, ChatAnthropic, ChatGoogleGenerativeAI, or ChatOllama)
        
    Raises:
        EnvironmentError: If API key is not set for the provider
        ValueError: If provider or model is unsupported
        ImportError: If required package for provider is not installed
        
    Note:
        - Retries up to 3 times on transient errors
        - Uses exponential backoff: 2s, 4s, 8s
        - Handles rate limiting automatically
    """
    from docksec.config_manager import get_config
    
    try:
        config = get_config()
        provider = config.llm_provider
        model = config.llm_model
        temperature = config.llm_temperature
        timeout = config.timeout_llm
        max_retries = config.max_retries_llm
        
        logger.info(f"Initializing LLM with provider: {provider}, model: {model}")
        
        if provider == LLMProvider.OPENAI:
            if not OPENAI_AVAILABLE:
                raise ImportError(
                    "AI analysis requested but the AI dependencies are not installed. "
                    "Install them with: pip install \"docksec[ai]\" "
                    "(or use --scan-only for local scanning without AI)"
                )
            api_key = config.get_api_key_for_provider()
            if not os.getenv("OPENAI_API_KEY"):
                os.environ["OPENAI_API_KEY"] = api_key

            llm = ChatOpenAI(
                model=model,
                temperature=temperature,
                request_timeout=timeout,
                max_retries=max_retries
            )
            logger.info("OpenAI LLM initialized successfully")
            return llm

        elif provider == LLMProvider.ANTHROPIC:
            if not ANTHROPIC_AVAILABLE:
                raise ImportError(
                    "Anthropic provider requested but langchain-anthropic is not installed. "
                    "Install it with: pip install langchain-anthropic (or: pip install \"docksec[ai]\")"
                )
            api_key = config.get_api_key_for_provider()
            if not os.getenv("ANTHROPIC_API_KEY"):
                os.environ["ANTHROPIC_API_KEY"] = api_key

            # Remove temperature if using newer models that don't support it
            llm_kwargs = {
                "model": model,
                "timeout": timeout,
                "max_retries": max_retries
            }
            if not any(model.startswith(prefix) for prefix in ["claude-opus-4", "claude-sonnet-4", "claude-haiku-4"]):
                llm_kwargs["temperature"] = temperature

            llm = ChatAnthropic(**llm_kwargs)
            logger.info("Anthropic Claude LLM initialized successfully")
            return llm

        elif provider == LLMProvider.GOOGLE:
            if not GOOGLE_AVAILABLE:
                raise ImportError(
                    "Google provider requested but langchain-google-genai is not installed. "
                    "Install it with: pip install langchain-google-genai (or: pip install \"docksec[ai]\")"
                )
            api_key = config.get_api_key_for_provider()
            if not os.getenv("GOOGLE_API_KEY"):
                os.environ["GOOGLE_API_KEY"] = api_key

            # Remove temperature if using newer models that don't support it
            llm_kwargs = {
                "model": model,
                "timeout": timeout,
                "max_retries": max_retries
            }
            if not any(model.startswith(prefix) for prefix in ["gemini-1.5", "gemini-2.0"]):
                llm_kwargs["temperature"] = temperature

            llm = ChatGoogleGenerativeAI(**llm_kwargs)
            logger.info("Google Gemini LLM initialized successfully")
            return llm

        elif provider == LLMProvider.OLLAMA:
            if not OLLAMA_AVAILABLE:
                raise ImportError(
                    "Ollama provider requested but langchain-ollama is not installed. "
                    "Install it with: pip install langchain-ollama (or: pip install \"docksec[ai]\")"
                )
            llm = ChatOllama(
                model=model,
                temperature=temperature,
                base_url=config.ollama_base_url,
                timeout=timeout
            )
            logger.info(f"Ollama LLM initialized successfully with base URL: {config.ollama_base_url}")
            return llm

        else:
            raise ValueError(f"Unsupported LLM provider: {provider}. Supported: {LLMProvider.values()}")
        
    except Exception as e:
        # Route through the shared output layer rather than a module-level
        # Rich console. get_llm() runs before the module-level `console` below
        # is defined, so referencing it here raised NameError and masked the
        # real initialization error with the troubleshooting steps never shown.
        from docksec import output
        logger.error(f"Failed to initialize LLM: {str(e)}")
        output.error(f"Error initializing AI features: {str(e)}")
        output.info("Troubleshooting steps:")
        output.detail("  1. Verify your API key is correct for the selected provider")
        output.detail("  2. Check your internet connection")
        output.detail("  3. Verify your account has available credits")
        output.detail("  4. Try using --scan-only mode if you don't need AI features")
        output.detail(f"  5. Current provider: {config.llm_provider if 'config' in locals() else 'unknown'}")
        output.detail("  6. Set LLM_PROVIDER environment variable to change provider (openai/anthropic/google/ollama)")
        raise




# Initialize colorama for Windows compatibility
init(autoreset=True)

# Initialize Rich Console
console = Console()

def print_section(title: str, items: List[str], color: str, max_items: int = 5) -> None:
    """
    Print a compact formatted section with title and limited items.
    
    Args:
        title: Section title
        items: List of items to display
        color: Color for the section (e.g., 'red', 'green', 'yellow')
        max_items: Maximum number of items to display (default 5)
    """
    if not items:
        console.print(f"\n[bold {color}]{title}:[/] [green]None found[/]")
        return
    
    console.print(f"\n[bold {color}]{title}:[/] ({len(items)} found)")
    # Show only top max_items
    for i, item in enumerate(items[:max_items], start=1):
        # Truncate long items
        display_item = item[:80] + "..." if len(item) > 80 else item
        console.print(f"  {i}. [{color}]{display_item}[/]")
    
    if len(items) > max_items:
        console.print(f"  [dim]... and {len(items) - max_items} more[/]")

def analyze_security(response: AnalyzesResponse, compact: bool = True, report_path: str = "") -> Dict:
    """
    Analyze and display security findings from Dockerfile analysis.
    
    Args:
        response: AnalyzesResponse object containing vulnerability findings
        compact: If True, show only top items; if False, show all
        report_path: Path to the generated reports directory
        
    Returns:
        Dictionary containing all findings for report generation
    """
    max_items = 3 if compact else 10

    vulnerabilities = response.vulnerabilities
    best_practices = response.best_practices
    security_risks = response.SecurityRisks
    exposed_credentials = response.ExposedCredentials
    remediation = response.remediation

    console.print("\n[bold cyan]=== AI Dockerfile Analysis Results ===[/]\n")
    
    # Quick summary
    print_section("Vulnerabilities", vulnerabilities, "red", max_items)
    print_section("Best Practices", best_practices, "blue", max_items)
    print_section("Security Risks", security_risks, "yellow", max_items)
    print_section("Exposed Credentials", exposed_credentials, "magenta", max_items)
    print_section("Remediation Steps", remediation, "green", max_items)
    
    # Note: the "reports written" message is emitted by the CLI after reports
    # are actually generated (see cli.py), so it isn't printed here where we
    # don't yet know whether a report file will be written for this run.

    # Return findings for report generation
    return {
        "vulnerabilities": vulnerabilities,
        "best_practices": best_practices,
        "security_risks": security_risks,
        "exposed_credentials": exposed_credentials,
        "remediation": remediation
    }
    
    



