"""
MCP Security Platform — Root Logger Redacting Filter (INV-002)

Applies token/JWT redaction to every log record that reaches any handler on
the root logger, covering the entire Loki-shipped log surface — not just the
structured audit stream.

INV-002: Logs must never contain raw credentials, tokens, or PII.
The audit middleware handles payload-level redaction via mcp_audit_logger.
This filter handles incidental leakage in exception messages, httpx error
strings, upstream response bodies logged at DEBUG, etc.

Usage (applied in main.py startup):
    from app.core.log_filter import RedactingFilter
    logging.getLogger().addFilter(RedactingFilter())
    logging.getLogger("app").addFilter(RedactingFilter())
"""
from __future__ import annotations

import logging
import re

# ─── Patterns ─────────────────────────────────────────────────────────────────
# These are intentionally conservative: only redact strings that have a clear
# token-shaped prefix so that normal log messages (paths, IDs, UUIDs) are never
# corrupted.  The mcp_audit_logger.redaction module handles the full 10-category
# set on structured audit fields; this filter catches incidental leakage in the
# Python logging stream.

# Bearer tokens and Authorization header values:
#   "Bearer eyJxxx..."  "Authorization: Bearer abc123..."
#   "token = abc123..."  "token: abc123..."  "token=abc123..."
_TOKEN_PATTERN = re.compile(
    r'(Bearer\s+|token["\s:=]+|api[_.\-]?key["\s:=]+)([A-Za-z0-9\-_.~+/]{20,})',
    re.IGNORECASE,
)

# Raw JWT tokens: three base64url segments separated by dots
# eyJ<header>.eyJ<payload>.<signature>
_JWT_PATTERN = re.compile(
    r'eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.~+/=]+'
)


def _redact_message(msg: str) -> str:
    """Apply token and JWT redaction patterns to a log message string."""
    msg = _TOKEN_PATTERN.sub(r'\1[REDACTED:token]', msg)
    msg = _JWT_PATTERN.sub('[REDACTED:jwt]', msg)
    return msg


class RedactingFilter(logging.Filter):
    """
    logging.Filter that scrubs token-shaped strings from every log record.

    Applied to the root logger and the proxy app logger in main.py so that
    INV-002 holds for the entire Loki-shipped log surface, not just audit events.

    Only str-typed record.msg is modified. Structured extra fields are not
    touched here (they are handled by mcp_audit_logger.redaction on the audit
    path).  Returning True always ensures no records are dropped; this filter
    only mutates, never filters.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = _redact_message(record.msg)
        # Also scrub pre-formatted args if they were already merged into getMessage
        # by a handler that calls record.getMessage() early.  Redacting args tuple
        # elements here prevents a second leakage path when handlers use %s formatting.
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: _redact_message(v) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    _redact_message(v) if isinstance(v, str) else v
                    for v in record.args
                )
        return True
