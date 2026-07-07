#!/usr/bin/env python3
"""
Synthetic end-to-end probe (CR-17 / WP-D1).

login -> low-risk tool invoke -> audit-emission check. The exact three-step
health signal CR-17's implementation sketch asks for: a real credential
(Keycloak password grant, same path a real user takes), a real invocation
through the full gateway/OPA/entitlement/dispatcher chain (echo-sa's
`whoami` — the same low-risk, already-provisioned tool the AT1 auth matrix
uses), and a real DB check that the invocation left an audit trail (INV-001:
"no invocation without an audit record" — the probe fails if this doesn't
hold, not just if the invoke itself failed).

Usage:
    python3 lab/scripts/synthetic_probe.py

Exit code 0 = probe green. Exit code 1 = probe red (prints which step
failed and why). Intended for a periodic health-check cron/CI job, or a
manual run when triaging an incident (see docs/runbooks/incident-triage.md).

Reuses the acceptance suite's own token/invoke helpers rather than
reimplementing OIDC + MCP-envelope parsing a second time.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests" / "acceptance"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from conftest import call_upstream_tool, db_query  # noqa: E402
from functional_test import _get_user_token  # noqa: E402


def _step(name: str, fn) -> None:
    print(f"[probe] {name} ... ", end="", flush=True)
    try:
        result = fn()
    except Exception as exc:
        print(f"FAILED: {exc}")
        raise
    print("ok")
    return result


def main() -> int:
    started_at = time.time()

    # Step 1: login (real Keycloak password grant — the same path a real
    # user's browser/CLI takes, not a pre-minted test fixture token).
    try:
        alice_password = subprocess.run(
            ["grep", "^DEX_ALICE_PASSWORD=", str(Path(__file__).resolve().parents[2] / ".env.lab")],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip().split("=", 1)[-1] or "labpassword"
    except Exception:
        alice_password = "labpassword"

    token = _step("login (Keycloak password grant, alice@corp)", lambda: _get_user_token("alice", alice_password))

    # Step 2: low-risk invoke. echo-sa/whoami is the same fixture AT1's
    # service_account-mode test uses — already entitled, already provisioned,
    # deliberately not a write/destructive action. loopback=True: 'whoami'
    # trips the gateway WAF's CRS 932260 Unix-RCE wordlist (a documented
    # false positive, see test_at1_auth_matrix.py) — every proxy-side gate
    # (auth, entitlement, OPA, credential injection) is still exercised via
    # the container-loopback path.
    probe_started_at = time.time()
    result = _step(
        "low-risk invoke (echo-sa.whoami)",
        lambda: call_upstream_tool(token, "echo-sa", "whoami", {}, loopback=True),
    )
    if not result.get("has_credential"):
        print(f"[probe] FAILED: invoke succeeded but has_credential=False: {result}")
        return 1

    # Step 3: audit-emission check (INV-001). Poll briefly — audit writes are
    # synchronous per INV-001, but leave a small window for DB commit
    # visibility under load rather than a single point-in-time query.
    def _check_audit() -> bool:
        deadline = time.time() + 10
        while time.time() < deadline:
            count = db_query(
                "SELECT COUNT(*) FROM audit_events "
                "WHERE client_id = 'alice@corp' AND tool_name = 'echo-sa' "
                f"AND event_type = 'TOOL_INVOCATION' AND event_ts >= to_timestamp({probe_started_at})"
            )
            if count.strip() not in ("", "0"):
                return True
            time.sleep(1)
        return False

    audited = _step("audit-emission check (INV-001, audit_events)", _check_audit)
    if not audited:
        print("[probe] FAILED: invocation succeeded but no matching audit_events row was found within 10s")
        return 1

    print(f"[probe] GREEN — login -> invoke -> audit all confirmed in {time.time() - started_at:.1f}s")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"[probe] RED — {exc}")
        sys.exit(1)
