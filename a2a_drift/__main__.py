"""Entry point for ``python -m a2a_drift``."""

from a2a_drift import (
    AgentCardChecker,
    DriftFinding,
    EndpointProber,
    ValidationResult,
)
from a2a_drift.cli import main

__all__ = [
    "AgentCardChecker",
    "EndpointProber",
    "ValidationResult",
    "DriftFinding",
    "main",
]

if __name__ == "__main__":
    main()
