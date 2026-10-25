"""Resource, buffer, and parsing limits for PipelineGuard workflow security.

Provides frozen constants and a dataclass representing configurable and
hard internal limits to defend against resource exhaustion, hostile YAML,
and unbounded memory consumption.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

# Default scanner boundary limits
DEFAULT_MAX_FILE_COUNT: Final[int] = 1000
DEFAULT_MAX_FILE_SIZE_BYTES: Final[int] = 1_048_576  # 1 MB
DEFAULT_MAX_CONFIG_SIZE_BYTES: Final[int] = 65_536  # 64 KB

# Snippet and rendering limits
MAX_SNIPPET_LENGTH_CHARS: Final[int] = 512
SNIPPET_TRUNCATION_LIMIT_CHARS: Final[int] = 509  # Leaves room for "..."

# Hostile YAML structure boundaries
MAX_YAML_DEPTH: Final[int] = 100
MAX_YAML_ALIASES: Final[int] = 100
MAX_YAML_NODES: Final[int] = 50_000

# Expression and token lengths
MAX_EXPRESSION_LENGTH_CHARS: Final[int] = 2000
MAX_ACTION_REF_LENGTH_CHARS: Final[int] = 250


@dataclass(frozen=True)
class Limits:
    """Configurable scanner limits."""

    max_file_count: int = DEFAULT_MAX_FILE_COUNT
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES
    max_config_size_bytes: int = DEFAULT_MAX_CONFIG_SIZE_BYTES
    max_snippet_length_chars: int = MAX_SNIPPET_LENGTH_CHARS


__all__ = [
    "DEFAULT_MAX_CONFIG_SIZE_BYTES",
    "DEFAULT_MAX_FILE_COUNT",
    "DEFAULT_MAX_FILE_SIZE_BYTES",
    "MAX_ACTION_REF_LENGTH_CHARS",
    "MAX_EXPRESSION_LENGTH_CHARS",
    "MAX_SNIPPET_LENGTH_CHARS",
    "MAX_YAML_ALIASES",
    "MAX_YAML_DEPTH",
    "MAX_YAML_NODES",
    "SNIPPET_TRUNCATION_LIMIT_CHARS",
    "Limits",
]
