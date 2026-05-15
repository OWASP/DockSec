"""
Configuration Manager Module

This module provides centralized configuration management for DockSec.
It handles environment variables, validation, and provides a clean interface
for accessing configuration values throughout the application.
"""

import os
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, field

# Set up logger
logger = logging.getLogger(__name__)


@dataclass
class DocksecConfig:
    """
    Configuration class for DockSec application.
    
    Manages all configuration settings including:
    - API keys and credentials
    - Directory paths
    - Tool settings
    - Scan parameters
    
    Attributes:
        llm_provider: LLM provider to use (openai, anthropic, google, ollama)
        openai_api_key: OpenAI API key for AI features
        anthropic_api_key: Anthropic API key for Claude
        google_api_key: Google API key for Gemini
        ollama_base_url: Base URL for Ollama server (local models)
        base_dir: Base directory of the application
        results_dir: Directory for storing scan results
        timeout_hadolint: Timeout for Hadolint scans (seconds)
        timeout_trivy: Timeout for Trivy scans (seconds)
        timeout_docker_scout: Timeout for Docker Scout scans (seconds)
        timeout_llm: Timeout for LLM API calls (seconds)
        max_retries_llm: Maximum number of retry attempts for LLM calls
        llm_model: Model name to use (e.g., gpt-4o, claude-3-5-sonnet-20241022, gemini-pro, llama3.1)
        llm_temperature: Temperature setting for LLM (0-1)
    """
    
    # LLM Provider Configuration
    llm_provider: str = "openai"
    
    # API Configuration
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    google_api_key: Optional[str] = None
    ollama_base_url: str = "http://localhost:11434"
    
    # Directory Configuration
    base_dir: str = field(default_factory=lambda: os.path.abspath(os.path.dirname(__file__)))
    results_dir: str = field(default_factory=lambda: os.path.join(os.getcwd(), "results"))
    
    # Timeout Configuration (in seconds)
    timeout_hadolint: int = 300
    timeout_trivy: int = 600
    timeout_docker_scout: int = 300
    timeout_llm: int = 60
    
    # LLM Configuration
    max_retries_llm: int = 2
    llm_model: str = "gpt-4o"
    llm_temperature: float = 0.0
    
    # Retry Configuration
    retry_attempts: int = 3
    retry_min_wait: int = 2
    retry_max_wait: int = 10
    
    # Scan Configuration
    default_severity: str = "CRITICAL,HIGH"
    max_file_size_mb: int = 10
    
    def __post_init__(self):
        """
        Post-initialization validation and setup.
        Creates necessary directories and validates configuration.
        """
        # Load from environment if not set
        if not self.openai_api_key:
            self.openai_api_key = os.getenv("OPENAI_API_KEY", "")
        
        if not self.anthropic_api_key:
            self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY", "")
        
        if not self.google_api_key:
            self.google_api_key = os.getenv("GOOGLE_API_KEY", "")
        
        # Load provider from environment
        self.llm_provider = os.getenv("LLM_PROVIDER", self.llm_provider).lower()
        
        # Load Ollama base URL from environment
        self.ollama_base_url = os.getenv("OLLAMA_BASE_URL", self.ollama_base_url)
        
        # Ensure results directory exists
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Set environment variables for backward compatibility
        if self.openai_api_key:
            os.environ["OPENAI_API_KEY"] = self.openai_api_key
        if self.anthropic_api_key:
            os.environ["ANTHROPIC_API_KEY"] = self.anthropic_api_key
        if self.google_api_key:
            os.environ["GOOGLE_API_KEY"] = self.google_api_key
        
        # Validate configuration
        self._validate()
    
    def _validate(self) -> None:
        """
        Validate configuration values.
        
        Raises:
            ValueError: If configuration values are invalid
        """
        # Validate LLM provider
        valid_providers = ['openai', 'anthropic', 'google', 'ollama']
        if self.llm_provider not in valid_providers:
            raise ValueError(f"Invalid llm_provider: {self.llm_provider}. Valid options: {valid_providers}")
        
        # Validate timeouts
        if self.timeout_hadolint <= 0:
            raise ValueError(f"Invalid timeout_hadolint: {self.timeout_hadolint}. Must be positive.")
        
        if self.timeout_trivy <= 0:
            raise ValueError(f"Invalid timeout_trivy: {self.timeout_trivy}. Must be positive.")
        
        if self.timeout_llm <= 0:
            raise ValueError(f"Invalid timeout_llm: {self.timeout_llm}. Must be positive.")
        
        # Validate LLM settings
        if not 0 <= self.llm_temperature <= 1:
            raise ValueError(f"Invalid llm_temperature: {self.llm_temperature}. Must be between 0 and 1.")
        
        if self.max_retries_llm < 0:
            raise ValueError(f"Invalid max_retries_llm: {self.max_retries_llm}. Must be non-negative.")
        
        # Validate retry settings
        if self.retry_attempts <= 0:
            raise ValueError(f"Invalid retry_attempts: {self.retry_attempts}. Must be positive.")
        
        if self.retry_min_wait <= 0 or self.retry_max_wait <= 0:
            raise ValueError("Retry wait times must be positive.")
        
        if self.retry_min_wait > self.retry_max_wait:
            raise ValueError(f"retry_min_wait ({self.retry_min_wait}) cannot be greater than retry_max_wait ({self.retry_max_wait}).")
        
        # Validate file size
        if self.max_file_size_mb <= 0:
            raise ValueError(f"Invalid max_file_size_mb: {self.max_file_size_mb}. Must be positive.")
        
        # Validate severity levels
        valid_severities = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'}
        severity_list = [s.strip() for s in self.default_severity.split(',')]
        for severity in severity_list:
            if severity not in valid_severities:
                raise ValueError(f"Invalid severity level: {severity}. Valid: {valid_severities}")
        
        logger.info("Configuration validated successfully")
    
    def get_openai_api_key(self) -> str:
        """
        Get OpenAI API key with validation.
        
        Returns:
            str: The OpenAI API key
            
        Raises:
            EnvironmentError: If API key is not set
        """
        if not self.openai_api_key:
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
        return self.openai_api_key
    
    def get_api_key_for_provider(self) -> str:
        """
        Get API key for the configured LLM provider.
        
        Returns:
            str: The API key for the current provider
            
        Raises:
            EnvironmentError: If API key is not set for the provider
        """
        if self.llm_provider == "openai":
            if not self.openai_api_key:
                raise EnvironmentError(
                    "OpenAI API key not found. Set OPENAI_API_KEY environment variable or use --scan-only mode."
                )
            return self.openai_api_key
        
        elif self.llm_provider == "anthropic":
            if not self.anthropic_api_key:
                raise EnvironmentError(
                    "Anthropic API key not found. Set ANTHROPIC_API_KEY environment variable or use --scan-only mode."
                )
            return self.anthropic_api_key
        
        elif self.llm_provider == "google":
            if not self.google_api_key:
                raise EnvironmentError(
                    "Google API key not found. Set GOOGLE_API_KEY environment variable or use --scan-only mode."
                )
            return self.google_api_key
        
        elif self.llm_provider == "ollama":
            return ""
        
        else:
            raise ValueError(f"Unsupported LLM provider: {self.llm_provider}")
    
    def update(self, **kwargs: Any) -> None:
        """
        Update configuration values.
        
        Args:
            **kwargs: Configuration key-value pairs to update
            
        Raises:
            ValueError: If invalid configuration key or value
        """
        for key, value in kwargs.items():
            if not hasattr(self, key):
                raise ValueError(f"Unknown configuration key: {key}")
            setattr(self, key, value)
        
        # Re-validate after update
        self._validate()
        logger.info(f"Configuration updated: {list(kwargs.keys())}")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.
        
        Returns:
            Dictionary of configuration values
        """
        return {
            'llm_provider': self.llm_provider,
            'base_dir': self.base_dir,
            'results_dir': self.results_dir,
            'timeout_hadolint': self.timeout_hadolint,
            'timeout_trivy': self.timeout_trivy,
            'timeout_docker_scout': self.timeout_docker_scout,
            'timeout_llm': self.timeout_llm,
            'max_retries_llm': self.max_retries_llm,
            'llm_model': self.llm_model,
            'llm_temperature': self.llm_temperature,
            'retry_attempts': self.retry_attempts,
            'retry_min_wait': self.retry_min_wait,
            'retry_max_wait': self.retry_max_wait,
            'default_severity': self.default_severity,
            'max_file_size_mb': self.max_file_size_mb,
            'ollama_base_url': self.ollama_base_url,
            'has_openai_key': bool(self.openai_api_key),
            'has_anthropic_key': bool(self.anthropic_api_key),
            'has_google_key': bool(self.google_api_key)
        }
    
    @classmethod
    def from_env(cls) -> 'DocksecConfig':
        """
        Create configuration from environment variables.
        
        Returns:
            DocksecConfig instance with values from environment
        """
        return cls(
            llm_provider=os.getenv("LLM_PROVIDER", "openai").lower(),
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            google_api_key=os.getenv("GOOGLE_API_KEY"),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            results_dir=os.getenv("DOCKSEC_RESULTS_DIR", os.path.join(os.getcwd(), "results")),
            timeout_hadolint=int(os.getenv("DOCKSEC_TIMEOUT_HADOLINT", "300")),
            timeout_trivy=int(os.getenv("DOCKSEC_TIMEOUT_TRIVY", "600")),
            timeout_docker_scout=int(os.getenv("DOCKSEC_TIMEOUT_DOCKER_SCOUT", "300")),
            timeout_llm=int(os.getenv("DOCKSEC_TIMEOUT_LLM", "60")),
            max_retries_llm=int(os.getenv("DOCKSEC_MAX_RETRIES_LLM", "2")),
            llm_model=os.getenv("LLM_MODEL", "gpt-4o"),
            llm_temperature=float(os.getenv("LLM_TEMPERATURE", "0.0")),
            retry_attempts=int(os.getenv("DOCKSEC_RETRY_ATTEMPTS", "3")),
            retry_min_wait=int(os.getenv("DOCKSEC_RETRY_MIN_WAIT", "2")),
            retry_max_wait=int(os.getenv("DOCKSEC_RETRY_MAX_WAIT", "10")),
            default_severity=os.getenv("DOCKSEC_DEFAULT_SEVERITY", "CRITICAL,HIGH"),
            max_file_size_mb=int(os.getenv("DOCKSEC_MAX_FILE_SIZE_MB", "10"))
        )
    
    def __repr__(self) -> str:
        """String representation of configuration."""
        config_dict = self.to_dict()
        return f"DocksecConfig({', '.join(f'{k}={v}' for k, v in config_dict.items())})"


# Global configuration instance
_config: Optional[DocksecConfig] = None


def get_config() -> DocksecConfig:
    """
    Get the global configuration instance.
    Creates it from environment if it doesn't exist.
    
    Returns:
        DocksecConfig: The global configuration instance
    """
    global _config
    if _config is None:
        from dotenv import load_dotenv
        load_dotenv()
        _config = DocksecConfig.from_env()
        logger.info("Global configuration initialized")
    return _config


def set_config(config: DocksecConfig) -> None:
    """
    Set the global configuration instance.
    
    Args:
        config: DocksecConfig instance to set as global
    """
    global _config
    _config = config
    logger.info("Global configuration updated")


def reset_config() -> None:
    """Reset the global configuration to None (forces reload on next get_config)."""
    global _config
    _config = None
    logger.info("Global configuration reset")

