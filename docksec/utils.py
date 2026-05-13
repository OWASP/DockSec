import logging
import sys
import os
from typing import Union

# Import OpenAI (required)
try:
    from langchain_openai import ChatOpenAI
except ImportError as e:
    raise ImportError(
        f"Failed to import langchain_openai: {e}. "
        "Please install: pip install langchain-openai"
    )

# Import optional providers
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
    BASE_DIR,
    OPENAI_API_KEY
)
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
from typing import List, Optional, Any
import time
from tqdm import tqdm
from colorama import Fore, Style, init
from rich.console import Console
from rich.table import Table
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
    after_log
)
from openai import (
    APIError,
    RateLimitError,
    APIConnectionError,
    APITimeoutError
)

def get_custom_logger(name: str = 'Docksec'):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(levelname)s - %(name)s - Line %(lineno)d: %(message)s')
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

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

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((APIError, APIConnectionError, APITimeoutError, RateLimitError)),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    after=after_log(logger, logging.INFO)
)
def _call_llm_with_retry(llm, *args, **kwargs):
    """
    Internal function to call LLM with retry logic.
    Retries on transient errors with exponential backoff.
    """
    return llm.invoke(*args, **kwargs)


def get_llm() -> Union[ChatOpenAI, 'ChatAnthropic', 'ChatGoogleGenerativeAI', 'ChatOllama']:
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
        
        if provider == "openai":
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
        
        elif provider == "anthropic":
            if not ANTHROPIC_AVAILABLE:
                raise ImportError(
                    "Anthropic provider requested but langchain-anthropic is not installed. "
                    "Install it with: pip install langchain-anthropic"
                )
            api_key = config.get_api_key_for_provider()
            if not os.getenv("ANTHROPIC_API_KEY"):
                os.environ["ANTHROPIC_API_KEY"] = api_key
            
            llm = ChatAnthropic(
                model=model,
                temperature=temperature,
                timeout=timeout,
                max_retries=max_retries
            )
            logger.info("Anthropic Claude LLM initialized successfully")
            return llm
        
        elif provider == "google":
            if not GOOGLE_AVAILABLE:
                raise ImportError(
                    "Google provider requested but langchain-google-genai is not installed. "
                    "Install it with: pip install langchain-google-genai"
                )
            api_key = config.get_api_key_for_provider()
            if not os.getenv("GOOGLE_API_KEY"):
                os.environ["GOOGLE_API_KEY"] = api_key
            
            llm = ChatGoogleGenerativeAI(
                model=model,
                temperature=temperature,
                timeout=timeout,
                max_retries=max_retries
            )
            logger.info("Google Gemini LLM initialized successfully")
            return llm
        
        elif provider == "ollama":
            if not OLLAMA_AVAILABLE:
                raise ImportError(
                    "Ollama provider requested but langchain-ollama is not installed. "
                    "Install it with: pip install langchain-ollama"
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
            raise ValueError(f"Unsupported LLM provider: {provider}. Supported: openai, anthropic, google, ollama")
        
    except Exception as e:
        logger.error(f"Failed to initialize LLM: {str(e)}")
        console.print(f"\n[red]Error initializing AI features:[/red] {str(e)}")
        console.print("\n[yellow]Troubleshooting steps:[/yellow]")
        console.print("1. Verify your API key is correct for the selected provider")
        console.print("2. Check your internet connection")
        console.print("3. Verify your account has available credits")
        console.print("4. Try using --scan-only mode if you don't need AI features")
        console.print(f"5. Current provider: {config.llm_provider if 'config' in locals() else 'unknown'}")
        console.print("6. Set LLM_PROVIDER environment variable to change provider (openai/anthropic/google/ollama)")
        raise




# Initialize colorama for Windows compatibility
init(autoreset=True)

# Initialize Rich Console
console = Console()

def print_section(title: str, items: List[str], color: str) -> None:
    """
    Print a formatted section with title and items using rich console.
    
    Args:
        title: Section title
        items: List of items to display
        color: Color for the section (e.g., 'red', 'green', 'yellow')
    """
    console.print(f"\n[bold {color}]{'=' * (len(title) + 4)}[/]")
    console.print(f"[bold {color}]| {title} |[/]")
    console.print(f"[bold {color}]{'=' * (len(title) + 4)}[/]")
    if items:
        for i, item in enumerate(items, start=1):
            console.print(f"[{color}]{i}. {item}[/]")
    else:
        console.print("[green]No issues found![/]")

def analyze_security(response: AnalyzesResponse) -> None:
    """
    Analyze and display security findings from Dockerfile analysis.
    
    Args:
        response: AnalyzesResponse object containing vulnerability findings
    """

    vulnerabilities = response.vulnerabilities
    best_practices = response.best_practices
    security_risks = response.SecurityRisks
    exposed_credentials = response.ExposedCredentials
    remediation = response.remediation

    # Simulating scanning with tqdm
    with tqdm(total=100, bar_format="{l_bar}{bar} {n_fmt}/{total_fmt} {elapsed}s[/]") as pbar:
        console.print("\n[cyan]Scanning Dockerfile...[/]")
        time.sleep(1)
        pbar.update(20)

        console.print("[cyan]Analyzing vulnerabilities...[/]")
        time.sleep(1)
        pbar.update(20)

        console.print("[cyan]Checking security risks...[/]")
        time.sleep(1)
        pbar.update(20)

        console.print("[cyan]Reviewing best practices...[/]")
        time.sleep(1)
        pbar.update(20)

        console.print("[cyan]Checking for exposed credentials...[/]")
        time.sleep(1)
        pbar.update(20)

    # Print Sections
    print_section("Vulnerabilities", vulnerabilities, "red")
    print_section("Best Practices", best_practices, "blue")
    print_section("Security Risks", security_risks, "yellow")
    print_section("Exposed Credentials", exposed_credentials, "magenta")
    print_section("Remediation Steps", remediation, "green")
    



