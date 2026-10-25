"""Configuration loader and strict validator for PipelineGuard workflow security.

Supports rule enable/disable, severity and action overrides, domain allowlists,
fail_on threshold, glob path excludes, and scanner resource limits.
Strictly rejects unknown keys and malformed structures with exit code 3 (ConfigError).
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from security.workflow.constants import ExitCode
from security.workflow.limits import (
    DEFAULT_MAX_CONFIG_SIZE_BYTES,
    DEFAULT_MAX_FILE_COUNT,
    DEFAULT_MAX_FILE_SIZE_BYTES,
)
from security.workflow.rules import REGISTRY, Action, Severity

__all__ = ["Config", "ConfigError", "MAX_CONFIG_SIZE", "load_config", "parse_config_dict"]

MAX_CONFIG_SIZE: int = DEFAULT_MAX_CONFIG_SIZE_BYTES

_VALID_FAIL_ON: frozenset[str] = frozenset({"block", "warn", "never"})
_VALID_TOP_LEVEL_KEYS: frozenset[str] = frozenset(
    {
        "rules",
        "domain_allowlist",
        "network",
        "fail_on",
        "path_excludes",
        "exclude",
        "limits",
        "max_file_count",
        "max_file_size",
    }
)
_VALID_RULE_KEYS: frozenset[str] = frozenset({"enabled", "severity", "action"})
_VALID_NETWORK_KEYS: frozenset[str] = frozenset({"domain_allowlist"})
_VALID_LIMIT_KEYS: frozenset[str] = frozenset({"max_file_count", "max_file_size"})


class ConfigError(Exception):
    """Raised when configuration validation fails."""

    exit_code: int = ExitCode.ERROR


@dataclass(frozen=True)
class Config:
    """Configuration for workflow security analysis."""

    enabled_rules: frozenset[str] | None = None
    disabled_rules: frozenset[str] = field(default_factory=frozenset)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    action_overrides: dict[str, Action] = field(default_factory=dict)
    domain_allowlist: tuple[str, ...] = field(default_factory=tuple)
    fail_on: str = "block"
    path_excludes: tuple[str, ...] = field(default_factory=tuple)
    max_file_count: int = DEFAULT_MAX_FILE_COUNT
    max_file_size: int = DEFAULT_MAX_FILE_SIZE_BYTES

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Check whether a rule is enabled under this configuration."""
        if rule_id in self.disabled_rules:
            return False
        if self.enabled_rules is not None:
            return rule_id in self.enabled_rules
        return True

    def get_severity(self, rule_id: str) -> Severity:
        """Get the effective severity for a rule."""
        if rule_id in self.severity_overrides:
            return self.severity_overrides[rule_id]
        from security.workflow.rules import lookup

        return lookup(rule_id).severity

    def get_action(self, rule_id: str) -> Action:
        """Get the effective action for a rule."""
        if rule_id in self.action_overrides:
            return self.action_overrides[rule_id]
        from security.workflow.rules import lookup

        return lookup(rule_id).action


def _parse_rule_severity(rule_id: str, sev_raw: Any) -> Severity:
    if not isinstance(sev_raw, str):
        raise ConfigError(f"'severity' in rule '{rule_id}' must be a string")
    try:
        return Severity[sev_raw.upper()]
    except KeyError:
        valid_sevs = ", ".join(s.name for s in Severity)
        raise ConfigError(
            f"Invalid severity '{sev_raw}' for rule '{rule_id}'. "
            f"Must be one of: {valid_sevs}"
        ) from None


def _parse_rule_action(rule_id: str, act_raw: Any) -> Action:
    if not isinstance(act_raw, str):
        raise ConfigError(f"'action' in rule '{rule_id}' must be a string")
    try:
        return Action[act_raw.upper()]
    except KeyError:
        valid_acts = ", ".join(a.name for a in Action)
        raise ConfigError(
            f"Invalid action '{act_raw}' for rule '{rule_id}'. "
            f"Must be one of: {valid_acts}"
        ) from None


def _validate_rule_id(rule_id: Any) -> str:
    """Validate rule ID type and pattern or registry presence."""
    if not isinstance(rule_id, str):
        raise ConfigError(f"Rule ID must be a string, got {type(rule_id).__name__}")
    rule_id_upper = rule_id.upper()
    if rule_id_upper not in REGISTRY and not re.match(r"^PG-WF-\d{3}$", rule_id_upper):
        raise ConfigError(f"Unknown rule ID in 'rules': '{rule_id}'")
    return rule_id_upper


def _parse_rule_mapping(
    rule_id: str,
    rule_id_upper: str,
    rule_conf: dict[str, Any],
    disabled_rules_set: set[str],
    severity_overrides: dict[str, Severity],
    action_overrides: dict[str, Action],
) -> None:
    """Parse a rule dict containing optional enabled/severity/action keys."""
    for rk in rule_conf:
        if rk not in _VALID_RULE_KEYS:
            raise ConfigError(f"Unknown key in rule '{rule_id}' configuration: '{rk}'")

    if "enabled" in rule_conf:
        en = rule_conf["enabled"]
        if not isinstance(en, bool):
            raise ConfigError(f"'enabled' in rule '{rule_id}' must be a boolean")
        if not en:
            disabled_rules_set.add(rule_id_upper)

    if "severity" in rule_conf:
        severity_overrides[rule_id_upper] = _parse_rule_severity(rule_id, rule_conf["severity"])

    if "action" in rule_conf:
        action_overrides[rule_id_upper] = _parse_rule_action(rule_id, rule_conf["action"])


def _parse_rule_item(
    rule_id: str,
    rule_conf: Any,
    disabled_rules_set: set[str],
    severity_overrides: dict[str, Severity],
    action_overrides: dict[str, Action],
) -> None:
    rule_id_upper = _validate_rule_id(rule_id)

    if isinstance(rule_conf, bool):
        if not rule_conf:
            disabled_rules_set.add(rule_id_upper)
        return

    if not isinstance(rule_conf, dict):
        raise ConfigError(
            f"Configuration for rule '{rule_id}' must be a mapping or boolean"
        )

    _parse_rule_mapping(
        rule_id,
        rule_id_upper,
        rule_conf,
        disabled_rules_set,
        severity_overrides,
        action_overrides,
    )


def _parse_rules_config(
    data: dict[str, Any],
) -> tuple[frozenset[str], dict[str, Severity], dict[str, Action]]:
    disabled_rules_set: set[str] = set()
    severity_overrides: dict[str, Severity] = {}
    action_overrides: dict[str, Action] = {}

    if "rules" in data:
        rules_val = data["rules"]
        if not isinstance(rules_val, dict):
            raise ConfigError("'rules' must be a mapping of rule IDs to settings")
        for rule_id, rule_conf in rules_val.items():
            _parse_rule_item(
                rule_id,
                rule_conf,
                disabled_rules_set,
                severity_overrides,
                action_overrides,
            )

    return frozenset(disabled_rules_set), severity_overrides, action_overrides


def _parse_network_config(data: dict[str, Any]) -> tuple[str, ...]:
    domain_allowlist: list[str] = []
    if "domain_allowlist" in data:
        raw_list = data["domain_allowlist"]
        if not isinstance(raw_list, list) or not all(isinstance(x, str) for x in raw_list):
            raise ConfigError("'domain_allowlist' must be a list of domain strings")
        domain_allowlist.extend(raw_list)

    if "network" in data:
        net_val = data["network"]
        if not isinstance(net_val, dict):
            raise ConfigError("'network' must be a mapping")
        for nk in net_val:
            if nk not in _VALID_NETWORK_KEYS:
                raise ConfigError(f"Unknown key in 'network': '{nk}'")
        if "domain_allowlist" in net_val:
            raw_list = net_val["domain_allowlist"]
            if not isinstance(raw_list, list) or not all(isinstance(x, str) for x in raw_list):
                raise ConfigError("'network.domain_allowlist' must be a list of domain strings")
            domain_allowlist.extend(raw_list)

    return tuple(domain_allowlist)


def _parse_fail_on(data: dict[str, Any]) -> str:
    if "fail_on" not in data:
        return "block"
    fo_val = data["fail_on"]
    if not isinstance(fo_val, str) or fo_val.lower() not in _VALID_FAIL_ON:
        raise ConfigError(
            f"Invalid 'fail_on' value: '{fo_val}'. Must be one of: block, warn, never"
        )
    return fo_val.lower()


def _parse_path_excludes(data: dict[str, Any]) -> tuple[str, ...]:
    excludes_key = (
        "path_excludes" if "path_excludes" in data else ("exclude" if "exclude" in data else None)
    )
    if not excludes_key:
        return ()

    raw_ex = data[excludes_key]
    if not isinstance(raw_ex, list) or not all(
        isinstance(x, str) and x.strip() for x in raw_ex
    ):
        raise ConfigError(f"'{excludes_key}' must be a list of non-empty glob strings")

    path_excludes: list[str] = []
    for pat in raw_ex:
        try:
            re.compile(fnmatch.translate(pat))
        except re.error as exc:
            raise ConfigError(
                f"Invalid glob pattern '{pat}' in '{excludes_key}': {exc}"
            ) from None
        path_excludes.append(pat)

    return tuple(path_excludes)


def _parse_positive_int(val: Any, key_desc: str) -> int:
    """Validate that val is a positive integer (rejecting booleans)."""
    if not isinstance(val, int) or isinstance(val, bool) or val <= 0:
        raise ConfigError(f"{key_desc} must be a positive integer")
    return val


def _parse_limits_config(data: dict[str, Any]) -> tuple[int, int]:
    max_file_count = DEFAULT_MAX_FILE_COUNT
    max_file_size = DEFAULT_MAX_FILE_SIZE_BYTES

    if "limits" in data:
        limits_val = data["limits"]
        if not isinstance(limits_val, dict):
            raise ConfigError("'limits' must be a mapping")
        for lk in limits_val:
            if lk not in _VALID_LIMIT_KEYS:
                raise ConfigError(f"Unknown key in 'limits': '{lk}'")
        if "max_file_count" in limits_val:
            max_file_count = _parse_positive_int(
                limits_val["max_file_count"], "'max_file_count' in 'limits'"
            )
        if "max_file_size" in limits_val:
            max_file_size = _parse_positive_int(
                limits_val["max_file_size"], "'max_file_size' in 'limits'"
            )

    if "max_file_count" in data:
        max_file_count = _parse_positive_int(data["max_file_count"], "'max_file_count'")

    if "max_file_size" in data:
        max_file_size = _parse_positive_int(data["max_file_size"], "'max_file_size'")

    return max_file_count, max_file_size


def parse_config_dict(data: Any) -> Config:
    """Parse and strictly validate a configuration dictionary.

    Args:
        data: Parsed configuration dictionary or None.

    Returns:
        A validated :class:`Config` instance.

    Raises:
        ConfigError: If any key or type is invalid.
    """
    if data is None:
        return Config()
    if not isinstance(data, dict):
        raise ConfigError("Configuration root must be a mapping")

    # Reject unknown top-level keys
    for k in data:
        if k not in _VALID_TOP_LEVEL_KEYS:
            raise ConfigError(f"Unknown configuration key: '{k}'")

    disabled_rules, severity_overrides, action_overrides = _parse_rules_config(data)
    domain_allowlist = _parse_network_config(data)
    fail_on = _parse_fail_on(data)
    path_excludes = _parse_path_excludes(data)
    max_file_count, max_file_size = _parse_limits_config(data)

    return Config(
        enabled_rules=None,
        disabled_rules=disabled_rules,
        severity_overrides=severity_overrides,
        action_overrides=action_overrides,
        domain_allowlist=domain_allowlist,
        fail_on=fail_on,
        path_excludes=path_excludes,
        max_file_count=max_file_count,
        max_file_size=max_file_size,
    )


def load_config(path: str | Path | None = None) -> Config:
    """Load configuration from a file or fallback to defaults.

    Args:
        path: Path to configuration YAML file, or None to search default locations.

    Returns:
        A validated :class:`Config` instance.

    Raises:
        ConfigError: On validation failure, invalid YAML, missing file, or size limit.
    """
    if path is None:
        for candidate in ("pipelineguard.yml", "pipelineguard.yaml", ".pipelineguard.yml"):
            p = Path(candidate)
            if p.is_file():
                path = p
                break
        else:
            return Config()

    cfg_path = Path(path)
    if not cfg_path.is_file():
        raise ConfigError(f"Configuration file not found: {cfg_path}")

    try:
        size = cfg_path.stat().st_size
    except OSError as exc:
        raise ConfigError(f"Cannot access configuration file '{cfg_path}': {exc}") from None

    if size > MAX_CONFIG_SIZE:
        raise ConfigError(
            f"Configuration file '{cfg_path}' size ({size} bytes) exceeds limit of {MAX_CONFIG_SIZE} bytes"
        )

    try:
        content = cfg_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"Configuration file '{cfg_path}' is not valid UTF-8: {exc}") from None
    except OSError as exc:
        raise ConfigError(f"Failed to read configuration file '{cfg_path}': {exc}") from None

    try:
        parsed = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Malformed YAML in '{cfg_path}': {exc}") from None

    return parse_config_dict(parsed)
