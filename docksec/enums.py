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

    @classmethod
    def gate_levels(cls) -> list:
        """Severities usable as a --fail-on threshold, most severe first."""
        return [cls.CRITICAL.value, cls.HIGH.value, cls.MEDIUM.value, cls.LOW.value]

    @classmethod
    def rank(cls, value) -> int:
        """Numeric ordering for comparisons (higher is more severe).

        Unknown or unrecognized values rank 0 so they never trip a
        --fail-on threshold set to a real severity level.
        """
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
        return order.get(str(value).strip().upper(), 0)


class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    OLLAMA = "ollama"

    @classmethod
    def values(cls) -> list:
        return [e.value for e in cls]
