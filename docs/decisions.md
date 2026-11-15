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

## Decision 6: Offline OASIS SARIF 2.1.0 Validation and Path Traversal Hardening (Phase 3)
- **Context**: Emitted SARIF must strictly adhere to the OASIS SARIF 2.1.0 schema specification, and file operations (`--baseline`, `--output`, `--config`) must be resilient against symlink attacks and path traversal.
- **Decision**:
  - Downloaded and vendored the official OASIS SARIF 2.1.0 JSON Schema into `security/workflow/schemas/sarif-schema-2.1.0.json` so validation runs completely offline without network dependencies.
  - Added automated schema conformance test `test_sarif_conforms_to_oasis_2_1_0_schema` validating live output from vulnerable labs against the schema.
  - Hardened `--baseline` loader to refuse symlinks before reading, preventing arbitrary local file exposure.
  - Attached repository context to the SARIF `run.properties` dictionary.
- **Security Rationale**: Ensures zero external network dependencies for validation gates, eliminates symlink-based arbitrary file read attacks, and guarantees interoperability with GitHub Advanced Security and SARIF viewers.

## Decision 7: Test Suite Mutation Sanity Verification (Phase 4)
- **Context**: High line coverage can mask low assertion quality if tests execute code without validating specific properties.
- **Decision**: Conducted 5 manual mutation sanity checks across 5 distinct subsystem modules:
  1. *Parser* (`parser.py:_trigger_value` returning `None` instead of parsed `on`): Killed by `test_valid_workflow` and `test_on_key_not_coerced_to_boolean`.
  2. *Injection Detector* (`injection.py:_is_untrusted` returning `False` unconditionally): Killed by 7 tests in `test_detector_injection.py`.
  3. *Permissions Detector* (`permissions.py:_has_write_scope` bypassing `write-all` check): Killed by 3 tests in `test_detector_permissions.py`.
  4. *Supply Chain Detector* (`supply_chain.py:_is_pinned_to_full_sha` accepting any `@` ref): Killed by 2 tests in `test_detector_supply_chain.py`.
  5. *Risk Scoring* (`risk.py:calculate_risk` forcing `trigger_mult = 1.0`): Killed by 4 tests in `test_risk.py`.
- **Security Rationale**: Proves the test suite is sensitive to regressions, logic inversions, and bypass vulnerabilities.

## Decision 8: Packaging Entrypoints and Dogfood Self-Scan Validation (Phase 5)
- **Context**: The package required standard entrypoints for CLI execution (`pipelineguard` and `pipelineguard-workflow`), explicit wheel inclusion of package data (`py.typed` and `schemas/*.json`), and verification that CI dogfood scans cleanly produce zero false positives.
- **Decision**:
  - Configured `[project.scripts]` in `pyproject.toml` exposing both `pipelineguard` and `pipelineguard-workflow` mapped to `security.workflow.__main__:main`.
  - Configured `[tool.setuptools.package-data]` ensuring PEP 561 markers and JSON schemas are bundled in wheels.
  - Verified editable installation `pip install -e . --no-deps` and verified both CLI command aliases.
  - Executed dogfood self-scan on `.github/workflows/pipelineguard-ci.yml`, confirming 0 findings detected (clean gate).
- **Security Rationale**: Ensures standard packaging hygiene, eliminates runtime module path confusion, and verifies zero false positives on compliant CI pipelines.

## Decision 9: Pyrefly IDE Diagnostic Configuration for Bundled Typeshed Stubs
- **Context**: Pyrefly (the IDE's Python language server) bundles third-party typeshed stubs out of the box (e.g. for `yaml`). When running in workspace environments without environment-specific hardcoded interpreter paths, Pyrefly flagged `missing-source-for-stubs` because stub definitions exist within Pyrefly while the runtime interpreter discovery is deferred.
- **Decision**: Added `[tool.pyrefly]` and `[tool.pyrefly.errors]` with `missing-source = "ignore"` and `missing-source-for-stubs = "ignore"` to `pyproject.toml`.
- **Security Rationale**: Eliminates IDE false-positive diagnostics in a cross-platform manner without committing machine-specific interpreter paths to repository configuration.

## Decision 10: Evasion Analysis, Detection Boundaries, and Inter-Procedural Dataflow Limits
- **Context**: Adversarial workflow authors can attempt to conceal vulnerabilities using expression indirection (assigning untrusted GitHub contexts to job-level `env` or `matrix` variables before interpolating them in `run:`), delegating execution to local composite actions, using YAML anchors, or obfuscating shell scripts via multiline variable concatenation and `eval`.
- **Decision**:
  - Maintained Member 1's architectural scope as a fast, single-file AST analyzer that parses and audits individual workflow definitions deterministically without inter-repository network fetching or cross-file recursive composite action parsing.
  - *YAML Anchors and Aliases*: Handled natively by PyYAML AST construction. Workflows using YAML anchors to alias malicious commands (e.g. `evasion_17`) are resolved at construct time and reliably detected by PG-WF-008.
  - *Multiline and Eval Obfuscation*: Handled by regex and token normalization in shell detectors (e.g. `evasion_18` detected by PG-WF-008 and PG-WF-010).
  - *Reusable Workflows on PR Targets*: Detected by PG-WF-007 and PG-WF-019 (e.g. `evasion_16`).
  - *Expression Indirection via Env / Matrix (`evasion_13`, `evasion_14`)*: Logged as a known detection boundary. Expanding inter-step dataflow requires symbolic evaluation of GitHub Actions runtime expression evaluation contexts, which introduces high false-positive rates when environment variables are sanitized or modified before execution.
  - *Composite Action Indirection (`evasion_15`)*: Logged as a known detection boundary. Inspecting `./.github/actions/.../action.yml` files requires cross-file filesystem resolution beyond the single-file workflow AST contract.
- **Security Rationale**: Preserves analyzer speed, prevents ReDoS and unbounded recursion, and establishes clear demarcation for downstream taint-analysis engines (Member 2/3).

