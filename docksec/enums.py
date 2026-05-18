from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def values(cls) -> list:
        return [e.value for e in cls]

    @classmethod
    def scored_levels(cls) -> list:
        """Severities that affect the security score."""
        return [cls.CRITICAL, cls.HIGH, cls.MEDIUM, cls.LOW]


class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    OLLAMA = "ollama"

    @classmethod
    def values(cls) -> list:
        return [e.value for e in cls]
