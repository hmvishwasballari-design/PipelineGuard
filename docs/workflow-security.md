# PipelineGuard Workflow Security (Member 1)

This document specifies the architecture, integration contract, and detection capabilities of the Workflow Security engine (`security/workflow/`).

---

## 1. Role in PipelineGuard Suite

Member 1 provides deterministic, offline static analysis of GitHub Actions workflows, reusable workflows, and composite actions. It produces standardized security findings and common security events consumed by:
- **Member 2 (Secret Scanner)**: Cross-references secrets found in workflow files with detected workflow vulnerabilities (e.g. `PG-WF-021` secret echoes or `PG-WF-007` secrets inheritance).
- **Member 3 (Policy Enforcement)**: Evaluates organizational security policies against workflow risk grades, severities, and compliance baselines.

---

## 2. Integration Interfaces

### Python Public API
Import all models, rules, and analysis functions directly from `security.workflow`:

```python
import security.workflow as sw

# File and directory scanning
result: sw.AnalysisResult = sw.analyze_path(".github/workflows")

# In-memory text scanning
result = sw.analyze_text(workflow_yaml_string, filename="ci.yml")

# Deterministic risk evaluation
risk: sw.RiskScore = sw.calculate_risk(result.findings)
# risk.score (0-100), risk.grade ("A"-"F")

# Conversion to common PipelineGuard events
events: list[dict] = sw.to_events(result, repository="org/repo")
```

### Common Event Schema Specification
All events emitted by `to_events()` comply with `security/workflow/schemas/pipelineguard-event.schema.json`:
- `schema_version`: `"1.0.0"`
- `event_type`: `"workflow_finding"`
- `source`: `"workflow-security"`
- `severity`: `"CRITICAL"` | `"HIGH"` | `"MEDIUM"` | `"LOW"` | `"INFO"`
- `repository`: Non-empty string formatted as `owner/repo` or `repo-name`
- `file`: Path to workflow file
- `line`: 1-based integer line number or `null`
- `rule`: String matching pattern `^PG-WF-\d{3}$`
- `action`: `"BLOCK"` | `"WARN"`
- `status`: `"active"` | `"suppressed"` | `"baselined"`
- `fingerprint`: 64-character lowercase SHA-256 hex digest
- `timestamp`: Optional ISO 8601 string

---

## 3. Exit Code Standards

The workflow analyzer exits with strongly-typed status codes (`ExitCode(IntEnum)`):
- `0`: Scan clean or findings exempted by baseline/threshold.
- `1`: Blocking finding detected (`Action.BLOCK` under `--fail-on block`).
- `2`: Warning finding detected (`Action.WARN` under `--fail-on warn`).
- `3`: Configuration error, usage syntax error, or unhandled runtime failure.

---

## 4. Reporting Formats

- **SARIF 2.1.0**: Validated against OASIS SARIF 2.1.0 schema for native GitHub Code Scanning upload (`pipelineguard.sarif`).
- **JSON**: Machine-readable output with summary metrics, per-workflow risk grades, findings, and suppressions.
- **Text**: Human-readable console output sanitized against ANSI, OSC, and bidi terminal injection attacks.
