"""
injection_patterns.py — Canonical prompt-injection phrase list.

This is the SINGLE SOURCE OF TRUTH for injection detection phrases.
All three enforcement points consume this list:
  1. response_filter.py  — pattern 1 regex + pattern 2 (disregard) phrase list
  2. policies/rego/data.json — mirrored as mcp.injection_phrases (read by authz.rego)
  3. policies/rego/tool_risk.rego — description_prompt_injection + param_description_injection

SYNC REQUIREMENT: Any change to INJECTION_PHRASES MUST be reflected in
policies/rego/data.json under data.mcp.injection_phrases.
The test proxy/tests/unit/test_injection_patterns.py:test_python_list_and_data_json_list_are_identical
enforces this in CI.

Derivation (Task 1.4, DET-F2):
  Union of:
    - response_filter.py:33-47 pattern phrases (as matched substrings)
    - tool_risk.rego:36-47 injection_phrases list
    - authz.rego:255-260 inline regex literals
  Plus net-new patterns:
    - "system:"          — SYSTEM: prompt marker (used in many jailbreak templates)
    - "persona override" — explicit persona replacement
    - "<!--"             — HTML comment injection (hides instructions from rendering)
    - "[inst]"           — Llama/Mistral instruction token marker
    - "new identity"     — identity replacement variant
    - "forget your"      — prior-context erasure
    - "as an ai"         — role override variant (in addition to "act as")
    - "pretend you are"  — persona override via roleplay framing
    - "roleplay as"      — explicit roleplay persona attack
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# INJECTION_PHRASES — lowercase strings used for case-insensitive substring
# matching across all three enforcement points.
#
# Order matters: the list is mirrored verbatim into data.json; keep
# alphabetically sorted within each semantic group so diffs are minimal.
# ---------------------------------------------------------------------------
INJECTION_PHRASES: list[str] = [
    # --- Role / instruction override (original set, all three sources) ---
    "act as",
    "disregard",
    "do not follow",
    "forget your",
    "ignore all prior",
    "ignore previous",
    "jailbreak",
    "override instructions",
    "you are now",

    # --- Persona / identity replacement ---
    "as an ai",
    "new identity",
    "persona override",
    "pretend you are",
    "roleplay as",
    "your new role is",
    "your persona is",
    "your role is",

    # --- Instruction markers (LLM template tokens) ---
    "[inst]",
    "### instructions:",
    "### system:",
    "system:",

    # --- Hidden instruction injection ---
    "<!--",
    "<instructions>",
    "<prompt>",
    "<system>",

    # --- Exfiltration / lateral movement ---
    "base64",
    "call the exfiltrate",
    "call the send",
    "call the upload",
]
