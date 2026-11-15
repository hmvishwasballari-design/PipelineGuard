"""Centralized constants, exit codes, versioning, and maps for PipelineGuard.

Provides a single source of truth for:
- Tool name, package version (derived via importlib.metadata with safe fallback)
- Schema versions (Event schema, SARIF 2.1.0 schema)
- Exit codes (ExitCode IntEnum)
- Default path exclusions
- Severity ordering and weight tables
- SARIF level mapping
- Risk scoring thresholds
"""

from __future__ import annotations

import importlib.metadata
from enum import IntEnum
from typing import Final

from security.workflow.rules import Severity

# --- Tool Identity and Versioning ---
TOOL_NAME: Final[str] = "PipelineGuard"
FALLBACK_PACKAGE_VERSION: Final[str] = "1.0.0"


def get_package_version() -> str:
    """Read package version from metadata with safe static fallback.

    Returns:
        Version string (e.g. '1.0.0').
    """
    try:
        return importlib.metadata.version("pipelineguard")
    except (importlib.metadata.PackageNotFoundError, Exception):
        return FALLBACK_PACKAGE_VERSION


TOOL_VERSION: Final[str] = get_package_version()

# --- Schema Standards ---
EVENT_SCHEMA_VERSION: Final[str] = "1.0.0"
SARIF_SCHEMA_VERSION: Final[str] = "2.1.0"
SARIF_SCHEMA_URL: Final[str] = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
SARIF_INFORMATION_URI: Final[str] = "https://pipelineguard.io"


# --- Exit Codes ---
class ExitCode(IntEnum):
    """Enumeration of CLI and analyzer process exit codes."""

    SUCCESS = 0  # Clean scan or findings allowed by threshold / baseline
    BLOCK = 1    # Action: BLOCK finding detected and above threshold
    WARN = 2     # Action: WARN findings detected (when fail-on is warn)
    ERROR = 3    # Usage, configuration, parser or runtime error


# --- Scanner Defaults ---
DEFAULT_PATH_EXCLUDES: Final[tuple[str, ...]] = (
    ".git/**",
    ".venv/**",
    "venv/**",
    "node_modules/**",
    "__pycache__/**",
    ".tox/**",
)

# --- Severity Mappings and Orders ---
SARIF_LEVEL_MAP: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

SEVERITY_ORDER: Final[dict[Severity, int]] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

SEVERITY_WEIGHTS: Final[dict[Severity, float]] = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 25.0,
    Severity.MEDIUM: 15.0,
    Severity.LOW: 6.0,
    Severity.INFO: 2.0,
}

TRIGGER_MULTIPLIERS: Final[dict[str, float]] = {
    "pull_request_target": 1.4,
    "issue_comment": 1.3,
    "workflow_run": 1.3,
    "pull_request": 1.1,
    "push": 1.0,
}

CONFIDENCE_MULTIPLIERS: Final[dict[str, float]] = {
    "HIGH": 1.0,
    "MEDIUM": 0.8,
    "LOW": 0.5,
}

# --- Risk Letter Grade Thresholds ---
GRADE_A_MAX_SCORE: Final[int] = 15
GRADE_B_MAX_SCORE: Final[int] = 35
GRADE_C_MAX_SCORE: Final[int] = 55
GRADE_D_MAX_SCORE: Final[int] = 75
MAX_RISK_SCORE: Final[int] = 100

__all__ = [
    "CONFIDENCE_MULTIPLIERS",
    "DEFAULT_PATH_EXCLUDES",
    "EVENT_SCHEMA_VERSION",
    "FALLBACK_PACKAGE_VERSION",
    "GRADE_A_MAX_SCORE",
    "GRADE_B_MAX_SCORE",
    "GRADE_C_MAX_SCORE",
    "GRADE_D_MAX_SCORE",
    "MAX_RISK_SCORE",
    "SARIF_INFORMATION_URI",
    "SARIF_LEVEL_MAP",
    "SARIF_SCHEMA_URL",
    "SARIF_SCHEMA_VERSION",
    "SEVERITY_ORDER",
    "SEVERITY_WEIGHTS",
    "TOOL_NAME",
    "TOOL_VERSION",
    "TRIGGER_MULTIPLIERS",
    "ExitCode",
    "get_package_version",
]
