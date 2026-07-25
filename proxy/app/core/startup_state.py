"""
Startup subsystem state, so degraded background services are visible.

`lifespan` in main.py starts eight optional subsystems (Registry refresh, OPA data
sync, rescan scheduler, scan evaluator, build evaluator, trust labeler, trust
observer, credential broker). Every one is wrapped in `except Exception:
logger.warning(...)` so a failure degrades the platform instead of crash-looping it
— which is the right call for availability, but it meant the failure existed ONLY as
a line in stdout.

"OPA data sync initialization failed — grants will not be synced" as a WARNING on a
booting fail-closed platform is the wrong severity and the wrong channel: `/health`
answered "ok" while authorization data silently stopped reconciling.

This module is the missing channel. It records what each subsystem did at startup so
`/health` can report it. It deliberately does NOT change whether the process starts —
fail-graceful startup is intentional; invisible fail-graceful startup is not.

State is process-local and set once during lifespan. No locking: writes happen in the
single-threaded startup path before the server accepts traffic, reads are dict copies.
"""
from __future__ import annotations

from typing import Literal

Status = Literal["ok", "degraded", "disabled"]

# name -> {"status": Status, "detail": str, "required": bool}
_STATE: dict[str, dict] = {}


def record(name: str, status: Status, detail: str = "", *, required: bool = False) -> None:
    """Record a subsystem's startup outcome.

    required=True means a degraded state should surface as an overall "degraded"
    platform status. Use it for subsystems whose absence changes enforcement or
    authorization data — not for optional features that are simply switched off.
    """
    _STATE[name] = {"status": status, "detail": detail, "required": required}


def snapshot() -> dict[str, dict]:
    return {k: dict(v) for k, v in _STATE.items()}


def degraded_required() -> list[str]:
    """Names of required subsystems that are not ok — the ones worth alerting on."""
    return sorted(
        n for n, v in _STATE.items()
        if v.get("required") and v.get("status") != "ok"
    )


def reset() -> None:
    """Test helper — clears recorded state."""
    _STATE.clear()
