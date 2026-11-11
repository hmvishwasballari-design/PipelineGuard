# PipelineGuard — Workflow Security (Member 1)

Static security analyzer and policy gate for GitHub Actions workflow definitions.

Detects script injections, excessive permissions, dangerous shell commands, suspicious network access, persistence/modification patterns, and supply-chain vulnerabilities in CI/CD workflows and composite actions.

---

## Architecture and Components

| Module | Description |
|---|---|
| `models.py` | Parsed workflow representations (`Workflow`, `Job`, `Step`, `Expression`, `ParseResult`). |
| `parser.py` | Strict line-capturing YAML loader built on `yaml.SafeLoader` with denial-of-service protection against alias bombs, deep nesting, and node exhaustion. Preserves trigger keyword `on:`. |
| `rules.py` | Centralized immutable rule registry (`REGISTRY`), defining metadata, severity, remediation, and CWE identifiers for rules `PG-WF-001` through `PG-WF-023` plus system rules `PG-WF-900` / `901`. |
| `detectors/` | Specialized modular detectors: `injection.py`, `permissions.py`, `commands.py`, `network.py`, `modification.py`, `supply_chain.py`. |
| `analyzer.py` | Analysis orchestrator with detector crash isolation, fingerprint deduplication, suppression parsing (`# pipelineguard-ignore: <RULE_ID> <REASON>`), and safe path discovery. |
| `config.py` | Strict configuration parser and validator supporting precedence hierarchy (`defaults < file < env < CLI`), rule toggles, severity/action overrides, path excludes, and domain allowlists. |
| `risk.py` | Pure deterministic risk scoring formula calculating an integer score (0–100) and letter grade (A–F) based on severity weights, detector confidence, and trigger exposure multipliers. |
| `events.py` | Converter transforming findings into standardized PipelineGuard security events adhering to `pipelineguard-event.schema.json` (draft 2020-12). |
| `reporter.py` | Multi-format reporting engine: ANSI-sanitized text, structured JSON, and official OASIS SARIF 2.1.0 JSON with exit code computation (`ExitCode`). |
| `api.py` | High-level programmatic API re-exported at package root `security.workflow`. |
| `__main__.py` | CLI entry point (`scan` subcommand, `--format`, `--config`, `--fail-on`, `--output`, `--baseline`, `--write-baseline`, `--repository`). |
| `constants.py` | Single source of truth for tool versions, schema URIs, weights, thresholds, and exit codes. |
| `limits.py` | Frozen resource limits enforcing maximum file counts, file sizes, YAML depth, aliases, and node counts. |

---

## Integration Contract for Member 2 & Member 3

Member 2 (Secret Scanning) and Member 3 (Policy Enforcement) integrate via the public programmatic API and common security event schema.

### 1. Python API Import

```python
from security.workflow import (
    analyze_path,
    analyze_text,
    to_events,
    calculate_risk,
    load_config,
    Finding,
    Rule,
    Severity,
    Action,
    ExitCode,
    REGISTRY,
    lookup,
)
```

### 2. Event Schema Contract

Events emitted by `to_events(result, repository="owner/repo")` strictly conform to `security/workflow/schemas/pipelineguard-event.schema.json`:

```json
{
  "schema_version": "1.0.0",
  "event_type": "workflow_finding",
  "source": "workflow-security",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "repository": "owner/repo",
  "file": ".github/workflows/ci.yml",
  "line": 42,
  "rule": "PG-WF-001",
  "action": "BLOCK" | "WARN",
  "status": "active" | "suppressed" | "baselined",
  "fingerprint": "64-character-sha256-hex-digest",
  "timestamp": "2026-11-11T10:00:00Z"
}
```

*Note: `timestamp` is optional and omitted by default to ensure scan determinism.*

### 3. Exit Code Contract

Processes exit with strongly-typed `ExitCode(IntEnum)` codes:
- `ExitCode.SUCCESS` (0): Clean scan or findings allowed by baseline/threshold.
- `ExitCode.BLOCK` (1): Action: `BLOCK` finding detected and above threshold.
- `ExitCode.WARN` (2): Action: `WARN` findings detected (when `--fail-on warn`).
- `ExitCode.ERROR` (3): Usage, configuration, parser, or runtime execution error.

---

## Rule Catalog (PG-WF-001..023)

| Rule ID | Severity | Action | CWE | Description |
|---|---|---|---|---|
| `PG-WF-001` | CRITICAL | BLOCK | CWE-78 | Script injection via untrusted context in `run:` step. |
| `PG-WF-002` | CRITICAL | BLOCK | CWE-94 | Script injection in `actions/github-script` script input. |
| `PG-WF-003` | HIGH | BLOCK | CWE-78 | Untrusted context written to `GITHUB_ENV`, `GITHUB_OUTPUT`, or `GITHUB_PATH`. |
| `PG-WF-004` | MEDIUM | WARN | CWE-272 | Missing top-level `permissions:` block (defaults to write-all). |
| `PG-WF-005` | HIGH | BLOCK | CWE-272 | Overly broad permissions (`write-all` or top-level write scope). |
| `PG-WF-006` | CRITICAL | BLOCK | CWE-829 | Pwn-request: `pull_request_target` trigger checking out PR head ref. |
| `PG-WF-007` | HIGH | WARN | CWE-272 | `secrets: inherit` passing all secrets to called reusable workflow. |
| `PG-WF-008` | HIGH | BLOCK | CWE-494 | Dangerous download piping to shell (`curl \| bash`, `wget \| sh`). |
| `PG-WF-009` | HIGH | BLOCK | CWE-116 | Base64-decoded payload piped directly to shell interpreter. |
| `PG-WF-010` | HIGH | BLOCK | CWE-78 | `eval` of variable or command substitution in `run:` step. |
| `PG-WF-011` | CRITICAL | BLOCK | CWE-78 | Reverse-shell pattern detected in `run:` step. |
| `PG-WF-012` | MEDIUM | WARN | CWE-829 | Download from raw IP address (bypassing DNS controls). |
| `PG-WF-013` | HIGH | BLOCK | CWE-200 | Communication with known data exfiltration or C2 service. |
| `PG-WF-014` | LOW | WARN | CWE-319 | Plain HTTP (non-TLS) download vulnerable to MITM. |
| `PG-WF-015` | MEDIUM | WARN | CWE-295 | `curl -k` / `--insecure` disabling TLS certificate verification. |
| `PG-WF-016` | HIGH | BLOCK | CWE-829 | Workflow step writes to `.github/workflows/` (persistence vector). |
| `PG-WF-017` | MEDIUM | WARN | CWE-829 | `git push` or `git commit` using `GITHUB_TOKEN` in `run:` step. |
| `PG-WF-018` | MEDIUM | WARN | CWE-829 | Cron `schedule:` trigger providing repeated persistence mechanism. |
| `PG-WF-019` | HIGH | WARN | CWE-829 | Action or reusable workflow not pinned to 40-char commit SHA. |
| `PG-WF-020` | LOW | WARN | CWE-312 | `actions/checkout` without `persist-credentials: false`. |
| `PG-WF-021` | HIGH | BLOCK | CWE-312 | Secret value echoed in `run:` step (leaked into logs). |
| `PG-WF-022` | MEDIUM | WARN | CWE-494 | `chmod +x` on downloaded file before integrity verification. |
| `PG-WF-023` | CRITICAL | BLOCK | CWE-829 | Cryptominer or runner-abuse tool invoked in `run:` step. |
| `PG-WF-900` | HIGH | BLOCK | CWE-20 | Workflow parse error, invalid UTF-8, or resource limit exceeded. |
| `PG-WF-901` | MEDIUM | WARN | CWE-703 | Internal detector execution error (isolated finding). |

---

## Configuration Precedence

Configuration settings are resolved following the strict precedence:
$$\text{Defaults} < \text{Configuration File} < \text{Environment Variables} < \text{CLI Flags}$$

1. **Defaults**: Built-in constants in `constants.py` and `limits.py`.
2. **File**: `pipelineguard.yml`, `.pipelineguard.yml`, or `--config <PATH>`.
3. **Environment Variables**:
   - `PIPELINEGUARD_CONFIG`: Path to configuration YAML.
   - `PIPELINEGUARD_FAIL_ON`: Exit threshold (`block`, `warn`, `never`).
   - `PIPELINEGUARD_MAX_FILE_COUNT`: Scanner file count limit.
   - `PIPELINEGUARD_MAX_FILE_SIZE`: File size limit in bytes.
   - `PIPELINEGUARD_REPOSITORY`: Default repository name.
4. **CLI Flags**: Explicit command-line arguments (`--fail-on`, `--repository`).
