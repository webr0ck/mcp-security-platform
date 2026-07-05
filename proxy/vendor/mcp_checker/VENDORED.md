# Vendored: mcp_checker

Source: ~/code/mcp_checker @ 6ad051a5cd8cd409fa5560e175ac5ecc60ae3770 (2026-07-05)
Research context: ~/code/mcp-security-research (uses this checker as its audit engine)

Static MCP security assessment engine (27 checks: malicious code patterns,
tool poisoning, credential theft, attack patterns per-OS, SSRF, crypto
stealers, semgrep SAST with 79 MCP-specific rules).

Only the files needed by the static (no-Docker) checks are vendored:
mcp_checker.py, checks_research.py, and policies/{policy.yaml, semgrep.yml,
policy.rego, tool_schema_validator.py, prompt_schema_validator.py,
check_cve_gate.sh, run_checks.sh}.

Invoked by app/services/submission_scanner.py as a subprocess.
To update: re-copy from the source repo and bump the commit hash above.
