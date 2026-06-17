"""Admin config-change audit events, recorded through the HMAC-signed audit chain."""
from __future__ import annotations

import json
import logging
from uuid import uuid4

from app.services.invocation import _emit_audit_event

logger = logging.getLogger(__name__)


async def emit_admin_config_event(
    actor: str,
    action: str,
    client_id: str,
    details: dict,
    outcome: str = "allow",
) -> None:
    """Record an admin config-change event in the tamper-evident audit chain.

    action examples: 'set_limits' | 'reset_limits' | 'anomaly_disabled' | 'reset_rate_limited'
    details carries old->new / target context (serialised as deny_reasons entries).

    The event is recorded via _emit_audit_event so it flows through the same
    HMAC-signed audit chain as tool-invocation events. tool_id=None selects
    INTERNAL_TOOL_INVOCATION (no tool_id FK required). anomaly_score=0.0 satisfies
    the audit_events CHECK (anomaly_score BETWEEN 0 AND 1). outcome must be
    'allow' or 'deny' (DB CHECK); this function defaults to 'allow' and callers
    pass 'deny' for protection-disabling or rate-limited events.

    Failures are caught and logged — a config-change audit failure must not block
    the admin operation itself (the operation is already committed when this fires).
    """
    try:
        await _emit_audit_event(
            tool_id=None,
            tool_name=f"admin.{action}",
            tool_version=None,
            client_id=actor,
            outcome=outcome,
            deny_reasons=[f"target_client={client_id}"]
            + [f"{k}={json.dumps(v, default=str)}" for k, v in details.items()],
            request_id=str(uuid4()),
            latency_ms=0,
            anomaly_score=0.0,
            opa_decision_id=f"adm_{uuid4().hex[:16]}",
            is_testing=False,
        )
    except Exception as exc:
        logger.error(
            "admin config audit emit failed action=%s client=%s: %s",
            action,
            client_id,
            exc,
        )
