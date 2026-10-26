# HermesVault Reliability Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement task-by-task.

**Goal:** Prevent unsafe credential removal and make plugin failures diagnosable.
**Architecture:** Parse migration YAML with a strict SafeLoader; validate plugin-equivalent custody before removal. Reuse source fetch diagnostics from the CLI.
**Tech Stack:** Python, pytest, PyYAML, existing FloorVault and Hermes interfaces.
**Spec:** docs/superpowers/specs/2026-10-25-hermesvault-reliability-design.md

## Global Constraints
- Python >=3.10; preserve plugin FloorVault >=0.2.1,<0.3 compatibility.
- No real credentials, native custody, or user profile changes in tests.
- Do not change host startup failure policy or introduce backup/custody features.

## Review Focus
- Duplicate YAML keys, scalar blocks, disabled sources and wrong nesting cannot authorize removal.
- Profile .env bootstrap keys can differ from the importing shell's keys.
- Invalid identifiers and arbitrary exception messages must not disclose input values.
- Diagnostics must not create a vault at a mistyped directory.
- Existing environment precedence and protected bootstrap variables must be visible.

### Task 1: Migration validation
Files: src/floorvault/hermes_config.py (new), src/floorvault/agent_cli.py, tests/test_agent_cli.py, pyproject.toml, uv.lock.
- [ ] Add regression cases for malformed/ambiguous/disabled YAML, store/key mismatch, quoted/flow mappings and valid removal.
- [ ] Run targeted tests and confirm failures; implement parsing and runtime-equivalent key validation; preserve .env on failures.
- [ ] Run migration tests and update dependency lock.

### Task 2: Plugin diagnostics and CLI validation
Files: plugins/hermesvault/source.py, plugins/hermesvault/cli.py, tests/test_hermes_plugin.py.
- [ ] Add failing tests for doctor success/failure/shadowing/missing store, malformed configuration and CLI validation/redaction.
- [ ] Implement doctor using fetch, validate config and reference inputs, quote YAML safely, redact operational exceptions.
- [ ] Run plugin tests and host conformance.

### Task 3: Documentation and PR
Files: plugins/hermesvault/README.md, docs/USAGE.md.
- [ ] Document diagnostics, stricter migration, optional dependency and remaining runtime limits.
- [ ] Run relevant tests, full suite, lint/format and build; obtain independent review and fix material findings.
- [ ] Commit, push a dedicated branch and create a draft PR with evidence and limitations.
