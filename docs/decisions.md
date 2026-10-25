# PipelineGuard Architecture and Production-Readiness Decisions

This document records conservative, secure architectural decisions made during the production-readiness audit of `security/workflow/` (Member 1 module).

---

## Decision 1: Single Source of Truth for Constants and Limits (Phase 1)
- **Context**: Duplicated string literals, magic numbers, schema versions, and exit codes were scattered across `reporter.py`, `risk.py`, `events.py`, `config.py`, and test suites.
- **Decision**:
  - Centralized all tool metadata, schema URLs, exit codes, and severity mappings into `security/workflow/constants.py`.
  - Centralized all parsing budgets, buffer capacities, and resource thresholds into frozen dataclass/constants in `security/workflow/limits.py`.
  - Package version is determined via `importlib.metadata.version("pipelineguard")` with safe fallback `"1.0.0"`.
- **Security Rationale**: Eliminates configuration drift, prevents version mismatch in emitted SARIF/event artifacts, and prevents inconsistent exit code signaling in automated CI gates.

## Decision 2: Strongly-Typed Exit Codes via IntEnum (Phase 1)
- **Context**: Exit codes 0, 1, 2, 3 were treated as bare magic integer literals throughout CLI, reporter, and tests.
- **Decision**: Defined `ExitCode(IntEnum)` with `SUCCESS = 0`, `BLOCK = 1`, `WARN = 2`, `ERROR = 3`.
- **Security Rationale**: Provides compile-time typing and explicit semantics for CI gate policy while retaining integer equality for process exit protocols.

## Decision 3: Ratio-Based Performance Benchmarks over Absolute Timing (Phase 1)
- **Context**: Scaling and performance benchmark assertions previously checked hardcoded wall-clock thresholds (`t <= 30.0s`), which could flake on throttled or shared CI runners.
- **Decision**: Formulated the benchmark assertion primarily on the ratio of large-batch (1,000 workflows) to small-batch (500 workflows) execution time (`scaling_ratio <= 3.0x`), proving linear algorithmic complexity without runner environment sensitivity.
- **Security Rationale**: Guarantees protection against algorithmic degradation (e.g., quadratic scaling) while preventing non-deterministic build failures on constrained runners.

## Decision 4: CLI Error Sanitization and Optional Tracebacks (Phase 1 & Phase 3)
- **Context**: Security tools should never leak raw internal stack traces or untrusted filesystem paths by default, but developers require debugging capability during development.
- **Decision**: Default unexpected error path catches general exceptions, sanitizes the message against control characters, and exits with `ExitCode.ERROR` (3). An explicit `--debug` CLI flag was introduced to emit full tracebacks only when requested by an operator.
- **Security Rationale**: Fail-closed defense against terminal injection and stack trace leakage in automated pipeline logs.

## Decision 5: Cyclomatic Complexity Decomposition and PEP 561 Typing Marker (Phase 2)
- **Context**: Several complex functions in `analyzer.py`, `config.py`, `reporter.py`, and detectors (`commands.py`, `injection.py`, `permissions.py`) had cyclomatic complexity exceeding 10 and lacked explicit `__all__` boundaries or PEP 561 marker files.
- **Decision**:
  - Decomposed all complex functions into cohesive helper sub-routines, ensuring every function in the package has cyclomatic complexity <= 10.
  - Added explicit `__all__` declarations across all public and internal detector modules to define clear API boundaries.
  - Added PEP 561 marker files (`security/py.typed` and `security/workflow/py.typed`) to enable downstream strict type checking.
  - Standardized meta-finding creation (rules PG-WF-900 and 901) and detector crash logging using non-formatting logger invocations.
- **Security Rationale**: Low complexity minimizes hidden logic flaws and bypass vulnerabilities; strict type checking prevents type confusion attacks and unexpected runtime exceptions.
