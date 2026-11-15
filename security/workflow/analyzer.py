"""Workflow security analysis orchestrator and path scanner.

Orchestrates running registered detectors on parsed GitHub Actions workflows,
handles internal detector isolation, deduplicates findings, filters suppressions,
enforces security limits, and performs safe recursive filesystem scans.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NamedTuple

from security.workflow.config import Config
from security.workflow.detectors import ALL_DETECTORS
from security.workflow.finding import CONFIDENCE_HIGH, Finding
from security.workflow.models import ParseResult
from security.workflow.parser import parse_workflow_text

__all__ = [
    "AnalysisResult",
    "SuppressedFinding",
    "analyze_paths",
    "analyze_workflow",
    "check_suppression",
]

logger = logging.getLogger(__name__)

_SUPPRESSION_DIRECTIVE_RE = re.compile(
    r"#\s*pipelineguard[-:]ignore:?\s*([A-Za-z0-9_-]+)(?:\s*:?\s*([^\n\r#]+))?",
    re.IGNORECASE,
)


class SuppressedFinding(NamedTuple):
    """A finding that was suppressed by an explicit workflow comment."""

    finding: Finding
    reason: str


@dataclass(frozen=True)
class AnalysisResult:
    """Result of analyzing one or more workflow definitions.

    Attributes:
        findings: Active, unsuppressed security findings, sorted stably.
        suppressed: Suppressed findings paired with their justification reasons.
        workflows_analyzed: Count of distinct workflows analyzed during this scan.
    """

    findings: Sequence[Finding] = field(default_factory=tuple)
    suppressed: Sequence[SuppressedFinding] = field(default_factory=tuple)
    workflows_analyzed: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.findings, tuple):
            object.__setattr__(self, "findings", tuple(self.findings))
        if not isinstance(self.suppressed, tuple):
            object.__setattr__(self, "suppressed", tuple(self.suppressed))


def _make_meta_finding(
    rule_id: str,
    file_path: str,
    message: str,
    line: int | None = None,
    evidence: dict[str, Any] | None = None,
) -> Finding:
    """Helper to create parser/scanner/detector meta findings (PG-WF-900 / 901)."""
    return Finding(
        rule_id=rule_id,
        file=file_path,
        line=line,
        column=None,
        job_id=None,
        step_name=None,
        snippet="",
        message=message,
        confidence=CONFIDENCE_HIGH,
        evidence=evidence or {},
    )


def _find_snippet_matches(lines: Sequence[str], snippet: str) -> list[int]:
    """Find line indices that contain the first line of snippet."""
    if not snippet:
        return []
    first_snip_line = snippet.strip().splitlines()[0] if snippet.strip() else ""
    if len(first_snip_line) < 4:
        return []
    return [idx for idx, line_text in enumerate(lines) if first_snip_line in line_text]


def _collect_candidate_indices(
    lines: Sequence[str],
    line_number: int | None,
    snippet: str = "",
) -> list[int]:
    """Collect candidate line indices that may contain suppression comments."""
    candidate_indices: list[int] = []

    def _add_candidates(target_idx: int) -> None:
        if 0 <= target_idx < len(lines) and target_idx not in candidate_indices:
            candidate_indices.append(target_idx)
        # Check contiguous preceding comment lines
        idx = target_idx - 1
        while idx >= 0:
            line_text = lines[idx].strip()
            if line_text.startswith("#"):
                if idx not in candidate_indices:
                    candidate_indices.append(idx)
                idx -= 1
            else:
                if (
                    idx == target_idx - 1
                    and "#" in line_text
                    and idx not in candidate_indices
                ):
                    candidate_indices.append(idx)
                break

    if line_number is not None:
        _add_candidates(line_number - 1)

    for idx in _find_snippet_matches(lines, snippet):
        _add_candidates(idx)

    return candidate_indices


def check_suppression(
    lines: list[str],
    line_number: int | None,
    rule_id: str,
    snippet: str = "",
) -> tuple[bool, str | None]:
    """Check if a finding at line_number is suppressed for the given rule_id.

    Looks on the same line and on immediately preceding comment lines.
    A suppression reason is mandatory.

    Returns:
        (matched, reason)
        - (False, None): No directive found for this rule.
        - (True, reason): Valid suppression directive with non-empty reason.
        - (True, None): Directive found but reason was empty or missing (rejected).
    """
    if not lines:
        return False, None

    candidate_indices = _collect_candidate_indices(lines, line_number, snippet)
    found_directive = False
    target_rule = rule_id.upper()

    for c_idx in candidate_indices:
        if c_idx < 0 or c_idx >= len(lines):
            continue
        line_str = lines[c_idx]
        for match in _SUPPRESSION_DIRECTIVE_RE.finditer(line_str):
            matched_rule = match.group(1).upper()
            if matched_rule == target_rule:
                found_directive = True
                raw_reason = match.group(2)
                reason = raw_reason.lstrip(": ").strip() if raw_reason else None
                if reason:
                    return True, reason

    if found_directive:
        return True, None

    return False, None


def _handle_parse_failure(parse_result: ParseResult) -> AnalysisResult:
    """Generate PG-WF-900 finding for failed workflow parsing."""
    error_msg = parse_result.error or "Workflow parse error"
    file_path = parse_result.path or (
        parse_result.workflow.path if parse_result.workflow else None
    )
    if not file_path:
        m = re.search(r"in\s+([^\s:(]+)", error_msg)
        file_path = m.group(1) if m else "<unknown>"
    line_num: int | None = None
    line_match = re.search(r"\(line (\d+)\)", error_msg)
    if line_match:
        try:
            line_num = int(line_match.group(1))
        except ValueError:
            line_num = None

    return AnalysisResult(
        findings=(
            _make_meta_finding(
                rule_id="PG-WF-900",
                file_path=file_path,
                line=line_num,
                message=error_msg,
                evidence={"error": error_msg},
            ),
        ),
        suppressed=(),
        workflows_analyzed=1,
    )


def _run_detectors(parse_result: ParseResult, file_path: str) -> list[Finding]:
    """Execute all registered detectors with crash isolation."""
    all_findings: list[Finding] = []
    for detector in ALL_DETECTORS:
        try:
            detected = detector(parse_result)
            all_findings.extend(detected)
        except Exception as exc:  # noqa: BLE001 - crash isolation requirement
            detector_name = getattr(detector, "__name__", "unknown_detector")
            logger.warning(
                "Detector %s raised unexpected exception: %s",
                detector_name,
                exc,
            )
            all_findings.append(
                _make_meta_finding(
                    rule_id="PG-WF-901",
                    file_path=file_path,
                    message=f"Internal detector error in {detector_name}: {type(exc).__name__}",
                    evidence={"detector": detector_name, "exception_type": type(exc).__name__},
                )
            )
    return all_findings


def _filter_and_dedup_findings(
    findings: list[Finding],
    config: Config,
) -> list[Finding]:
    """Filter findings by enabled status, domain allowlist, and fingerprint deduplication."""
    filtered: list[Finding] = []
    for f in findings:
        if not config.is_rule_enabled(f.rule_id):
            continue
        if (
            f.rule_id in ("PG-WF-012", "PG-WF-013", "PG-WF-014")
            and config.domain_allowlist
            and any(domain in f.snippet or domain in f.message for domain in config.domain_allowlist)
        ):
            continue
        filtered.append(f)

    seen_fingerprints: set[str] = set()
    deduped: list[Finding] = []
    for f in filtered:
        fp = f.fingerprint()
        if fp not in seen_fingerprints:
            seen_fingerprints.add(fp)
            deduped.append(f)
    return deduped


def _apply_suppressions(
    deduped_findings: list[Finding],
    parse_result: ParseResult,
    file_path: str,
) -> tuple[list[Finding], list[SuppressedFinding]]:
    """Partition findings into active and suppressed based on workflow comments."""
    raw_text = parse_result.raw_text
    if raw_text is None:
        try:
            p = Path(file_path)
            if p.is_file():
                raw_text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            raw_text = None

    has_directive = bool(
        raw_text
        and (
            "pipelineguard-ignore" in raw_text.lower()
            or "pipelineguard:ignore" in raw_text.lower()
        )
    )

    if not has_directive or not deduped_findings:
        return list(deduped_findings), []

    lines = raw_text.splitlines() if raw_text is not None else []
    active_findings: list[Finding] = []
    suppressed_findings: list[SuppressedFinding] = []

    for f in deduped_findings:
        matched, reason = check_suppression(lines, f.line, f.rule_id, snippet=f.snippet)
        if matched and reason:
            suppressed_findings.append(SuppressedFinding(finding=f, reason=reason))
        else:
            active_findings.append(f)

    return active_findings, suppressed_findings


def analyze_workflow(
    parse_result: ParseResult,
    config: Config | None = None,
) -> AnalysisResult:
    """Analyze a single parsed workflow with all enabled detectors.

    Catches individual detector exceptions and converts them to PG-WF-901 findings
    without interrupting the scan. If workflow parsing failed, yields a PG-WF-900 finding.

    Args:
        parse_result: The parsed workflow representation.
        config: Analysis configuration; defaults to standard secure configuration.

    Returns:
        An :class:`AnalysisResult` with deduplicated, stably sorted findings and suppressions.
    """
    cfg = config or Config()

    if not parse_result.ok:
        return _handle_parse_failure(parse_result)

    if parse_result.workflow is None:
        return AnalysisResult(workflows_analyzed=1)

    file_path = parse_result.workflow.path
    all_findings = _run_detectors(parse_result, file_path)
    deduped_findings = _filter_and_dedup_findings(all_findings, cfg)
    active, suppressed = _apply_suppressions(deduped_findings, parse_result, file_path)

    active.sort(key=lambda f: (f.sort_key(), f.fingerprint()))
    suppressed.sort(key=lambda s: (s.finding.sort_key(), s.finding.fingerprint()))

    return AnalysisResult(
        findings=tuple(active),
        suppressed=tuple(suppressed),
        workflows_analyzed=1,
    )


def _is_symlink_escaping(entry: Path, root: Path) -> bool:
    """Return True if entry is a symlink pointing outside root."""
    if not entry.is_symlink():
        return False
    try:
        resolved = entry.resolve()
        resolved_root = root.resolve()
        return not resolved.is_relative_to(resolved_root)
    except (ValueError, OSError):
        return True


def _scan_directory(
    scan_target: Path,
    root_for_item: Path,
    cfg: Config,
) -> list[Path]:
    """Recursively discover workflow files in a directory."""
    discovered: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(scan_target, followlinks=False):
        dirnames[:] = [
            d
            for d in sorted(dirnames)
            if not _is_symlink_escaping(Path(dirpath) / d, root_for_item)
        ]

        for fn in sorted(filenames):
            if not fn.endswith((".yml", ".yaml")):
                continue
            file_p = Path(dirpath) / fn
            if _is_symlink_escaping(file_p, root_for_item):
                continue
            if cfg.path_excludes:
                str_path = str(file_p)
                if any(
                    file_p.match(pat) or fnmatch.fnmatch(str_path, pat)
                    for pat in cfg.path_excludes
                ):
                    continue
            discovered.append(file_p)
    return discovered


def _discover_workflow_files(
    paths_list: Sequence[Path],
    scan_root: Path | None,
    default_root: Path,
    cfg: Config,
) -> list[Path]:
    """Discover all workflow files within provided paths, enforcing symlink and exclusion rules."""
    files_to_scan: list[Path] = []
    for input_path in paths_list:
        resolved_input = input_path.resolve()
        root_for_item = default_root if scan_root is not None else (
            resolved_input if resolved_input.is_dir() else resolved_input.parent
        )

        if resolved_input.is_file():
            if not _is_symlink_escaping(input_path, root_for_item):
                files_to_scan.append(input_path)
            continue

        if not resolved_input.is_dir():
            continue

        workflows_dir = resolved_input / ".github" / "workflows"
        scan_target = workflows_dir if workflows_dir.is_dir() else resolved_input
        files_to_scan.extend(_scan_directory(scan_target, root_for_item, cfg))

    return files_to_scan


def _scan_single_file(
    file_path: Path,
    cfg: Config,
) -> tuple[list[Finding], list[SuppressedFinding], bool]:
    """Scan and analyze a single workflow file, returning (findings, suppressed, analyzed_flag)."""
    str_file = str(file_path)
    try:
        stat_res = file_path.stat()
    except OSError as exc:
        return [
            _make_meta_finding(
                "PG-WF-900",
                str_file,
                f"Failed to access workflow file '{str_file}': {exc}",
                evidence={"path": str_file},
            )
        ], [], False

    if stat_res.st_size > cfg.max_file_size:
        return [
            _make_meta_finding(
                "PG-WF-900",
                str_file,
                (
                    f"Workflow file '{str_file}' size ({stat_res.st_size} bytes) "
                    f"exceeds maximum allowed limit of {cfg.max_file_size} bytes"
                ),
                evidence={"size": stat_res.st_size, "limit": cfg.max_file_size},
            )
        ], [], False

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        return [
            _make_meta_finding(
                "PG-WF-900",
                str_file,
                f"Workflow file '{str_file}' is not valid UTF-8: {exc}",
                evidence={"path": str_file},
            )
        ], [], False
    except OSError as exc:
        return [
            _make_meta_finding(
                "PG-WF-900",
                str_file,
                f"Failed to read workflow file '{str_file}': {exc}",
                evidence={"path": str_file},
            )
        ], [], False

    parsed = parse_workflow_text(content, path=str_file)
    result = analyze_workflow(parsed, config=cfg)
    return list(result.findings), list(result.suppressed), True


def analyze_paths(
    paths: Sequence[str | Path] | str | Path,
    config: Config | None = None,
    scan_root: Path | None = None,
) -> AnalysisResult:
    """Recursively scan and analyze GitHub Actions workflow files.

    Safely resolves files against scan root, rejects symlinks escaping root,
    enforces file count and size limits, flags non-UTF-8 files with PG-WF-900,
    and returns aggregated, deduplicated results.

    Args:
        paths: File path, directory path, or sequence of paths to scan.
        config: Optional configuration overrides and limits.
        scan_root: Optional directory boundary for symlink escaping checks.

    Returns:
        An :class:`AnalysisResult` with all findings across scanned workflows.
    """
    cfg = config or Config()

    if isinstance(paths, (str, Path)):
        paths_list = [Path(paths)]
    else:
        paths_list = [Path(p) for p in paths]

    default_root = scan_root or (paths_list[0].resolve() if paths_list else Path.cwd().resolve())
    if default_root.is_file():
        default_root = default_root.parent

    files_to_scan = _discover_workflow_files(paths_list, scan_root, default_root, cfg)
    all_findings: list[Finding] = []

    # Enforce max file count
    if len(files_to_scan) > cfg.max_file_count:
        all_findings.append(
            _make_meta_finding(
                rule_id="PG-WF-900",
                file_path=str(default_root),
                message=(
                    f"Workflow file count ({len(files_to_scan)}) exceeds maximum "
                    f"limit of {cfg.max_file_count} files"
                ),
                evidence={"limit": cfg.max_file_count, "found": len(files_to_scan)},
            )
        )
        files_to_scan = files_to_scan[: cfg.max_file_count]

    all_suppressed: list[SuppressedFinding] = []
    workflows_analyzed = 0

    for file_p in files_to_scan:
        file_findings, file_suppressed, analyzed = _scan_single_file(file_p, cfg)
        all_findings.extend(file_findings)
        all_suppressed.extend(file_suppressed)
        if analyzed:
            workflows_analyzed += 1

    seen_fps: set[str] = set()
    deduped_findings: list[Finding] = []
    for f in all_findings:
        fp = f.fingerprint()
        if fp not in seen_fps:
            seen_fps.add(fp)
            deduped_findings.append(f)

    deduped_findings.sort(key=lambda f: (f.sort_key(), f.fingerprint()))
    all_suppressed.sort(key=lambda s: (s.finding.sort_key(), s.finding.fingerprint()))

    return AnalysisResult(
        findings=tuple(deduped_findings),
        suppressed=tuple(all_suppressed),
        workflows_analyzed=workflows_analyzed,
    )
