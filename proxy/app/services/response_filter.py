"""
response_filter.py — Tool response content security filter.

Screens MCP tool responses for indirect prompt injection patterns before
returning them to the LLM client. Any response matching a pattern is:
  1. Logged as a TOOL_INVOCATION audit event with outcome='error'
  2. Replaced with a sanitised error response
  3. Never forwarded to the caller verbatim

This is the integration-layer control for OWASP LLM01 indirect injection
(CROSS-001). Perimeter controls (nginx, WAF) cannot intercept tool responses.

Current status: blocking by default (MCP-003). Matching responses are audited
and replaced with a sanitised error. Set RESPONSE_FILTER_BLOCK=false to fall
back to detection-only (log + audit, allow through).
"""
from __future__ import annotations

import re
import logging
import os
from dataclasses import dataclass

log = logging.getLogger(__name__)

# Blocking mode — when True, matching responses are replaced with an error.
# When False (default), matching responses are logged and allowed through.
BLOCK_ON_MATCH = os.environ.get("RESPONSE_FILTER_BLOCK", "true").lower() == "true"

# ── Injection pattern library ─────────────────────────────────────────────────
# These patterns detect common indirect prompt injection payloads embedded in
# tool responses. Extend this list as new patterns are observed.
_PATTERNS: list[re.Pattern[str]] = [
    # Role override instructions
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:an?\s+)?(?:new\s+)?(?:ai|assistant|gpt|claude)", re.IGNORECASE),
    re.compile(r"disregard\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)", re.IGNORECASE),
    # Exfiltration via function calls
    re.compile(r"call\s+(?:the\s+)?(?:send|post|upload|exfiltrate)\w*\s+(?:function|tool|api)", re.IGNORECASE),
    re.compile(r"base64\s*(?:encode|decode)\s*(?:and\s+)?send", re.IGNORECASE),
    # Rug pull / privilege escalation
    re.compile(r"your\s+(?:new\s+)?(?:role|persona|identity)\s+is", re.IGNORECASE),
    re.compile(r"act\s+as\s+(?:an?\s+)?(?:admin|root|superuser|privileged)", re.IGNORECASE),
    # Hidden instruction markers
    re.compile(r"<\s*(?:system|instructions?|prompt)\s*>", re.IGNORECASE),
    re.compile(r"\[INST\]|\[\/INST\]|###\s*(?:System|Instructions?):", re.IGNORECASE),
]


@dataclass
class FilterResult:
    matched: bool
    pattern_index: int | None
    matched_text: str | None


def screen_response(content: str, tool_name: str, client_id: str) -> FilterResult:
    """
    Screen a tool response for indirect prompt injection patterns.

    Returns a FilterResult indicating whether a match was found.
    Callers are responsible for audit logging and blocking based on the result.
    """
    for i, pattern in enumerate(_PATTERNS):
        m = pattern.search(content)
        if m:
            log.warning(
                "response_filter: injection pattern detected",
                extra={
                    "tool_name": tool_name,
                    "client_id": client_id,
                    "pattern_index": i,
                    "matched_text": m.group(0)[:100],
                    "block_mode": BLOCK_ON_MATCH,
                },
            )
            return FilterResult(matched=True, pattern_index=i, matched_text=m.group(0)[:100])
    return FilterResult(matched=False, pattern_index=None, matched_text=None)


INJECTION_DETECTED_RESPONSE = {
    "error": "tool_response_filtered",
    "detail": "Tool response was blocked by the content security filter. "
              "This may indicate an indirect prompt injection attempt. "
              "The event has been logged for review.",
}
