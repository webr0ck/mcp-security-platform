"""[TAMPER] INV-012 / F-002: OPA must refuse an unsigned or tampered bundle;
proxy must return 503 (INV-004) when OPA cannot load policy.

Gate check (test_default_compose_requires_verification_key):
  Verifies that docker-compose.yml and any other non-dev compose tiers that run
  OPA all pass --verification-key in the OPA command.

  HISTORICAL NOTE: Before Task 1.1 this test would have FAILED because
  docker-compose.yml used an unsigned read-only directory mount (no
  --verification-key). The test was intentionally designed to fail against the
  old configuration — that failure was the proof that the old default was
  insecure. After Task 1.1 the test passes because docker-compose.yml now ships
  with --verification-key and mounts bundle.tar.gz.

Integration tamper test (test_tampered_bundle_rejected):
  Requires the compose_opa_signed fixture (see conftest.py) which:
    1. Builds a fresh signed bundle.
    2. Flips one byte in bundle.tar.gz to simulate tampering.
    3. Restarts the OPA container.
    4. Waits for the container to attempt startup.
  OPA must refuse to load the tampered bundle, making policy unavailable.
  The proxy must then return 503 (INV-004: fail-closed when OPA is unreachable).
"""

import subprocess
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Structural gate: all production/staging compose files must enforce signing
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent.parent


def test_default_compose_requires_verification_key() -> None:
    """F-002 / INV-012: check_signed_default.sh must pass after Task 1.1.

    This script checks that every non-dev compose tier that runs OPA has
    --verification-key in its command block.  Before Task 1.1 docker-compose.yml
    lacked this flag and the script would have exited non-zero.
    """
    gate_script = REPO_ROOT / "scripts" / "check_signed_default.sh"
    assert gate_script.exists(), f"Gate script not found: {gate_script}"

    result = subprocess.run(
        ["bash", str(gate_script)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        # STRUCTURAL_CHECK_ONLY=1: run only the compose-file grep (no key guard,
        # no podman OPA load). The functional check is covered by the integration
        # fixture test_tampered_bundle_rejected and by test_signed_bundle.sh.
        env={**__import__("os").environ, "STRUCTURAL_CHECK_ONLY": "1"},
    )
    assert result.returncode == 0, (
        f"check_signed_default.sh failed.\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
    assert "PASS" in result.stdout, (
        f"Expected 'PASS' in script output, got:\n{result.stdout}"
    )


def test_docker_compose_yml_has_verification_key() -> None:
    """Direct assertion: docker-compose.yml OPA service contains --verification-key."""
    compose_path = REPO_ROOT / "docker-compose.yml"
    content = compose_path.read_text()

    # Find the opa service block
    opa_start = content.find("\n  opa:")
    assert opa_start != -1, "opa: service not found in docker-compose.yml"

    # Find the next top-level service after opa (2-space indent service header)
    # so we only inspect the opa block, not subsequent services.
    opa_block_start = opa_start + 1
    next_service = content.find("\n  ", opa_block_start + 4)
    # Walk forward to find a top-level service (line that starts with "  <word>:")
    import re
    match = re.search(r"\n  \w[\w-]*:", content[opa_block_start:])
    if match:
        opa_block = content[opa_block_start : opa_block_start + match.start()]
    else:
        opa_block = content[opa_block_start:]

    assert "--verification-key" in opa_block, (
        "docker-compose.yml OPA service is missing --verification-key. "
        "Signed bundles must be the default (INV-012)."
    )
    assert "bundle.tar.gz" in opa_block, (
        "docker-compose.yml OPA service must mount bundle.tar.gz, not the raw Rego directory."
    )


def test_dev_compose_does_not_have_verification_key() -> None:
    """Sanity check: docker-compose.dev.yml OPA override uses unsigned dir mount.

    INV-012 permits unsigned bundles in ENVIRONMENT=development. The dev
    override must NOT include --verification-key as an active YAML value
    (which would break the watch mode workflow). This test ensures the dev
    and prod defaults remain correctly separated.

    Note: comments in the YAML may reference --verification-key as a warning
    ("DO NOT add --verification-key here") — those are filtered out so only
    active YAML values are checked.
    """
    import re

    dev_compose_path = REPO_ROOT / "docker-compose.dev.yml"
    content = dev_compose_path.read_text()

    opa_start = content.find("\n  opa:")
    assert opa_start != -1, "opa: override not found in docker-compose.dev.yml"

    opa_block_start = opa_start + 1
    match = re.search(r"\n  \w[\w-]*:", content[opa_block_start:])
    if match:
        opa_block = content[opa_block_start : opa_block_start + match.start()]
    else:
        opa_block = content[opa_block_start:]

    # Strip comment lines before checking for the flag — comments may reference
    # the flag as a "do not add" warning; those must not trigger a false failure.
    non_comment_lines = [
        line for line in opa_block.splitlines() if not line.lstrip().startswith("#")
    ]
    non_comment_block = "\n".join(non_comment_lines)

    assert "--verification-key" not in non_comment_block, (
        "docker-compose.dev.yml OPA override must NOT include --verification-key "
        "as an active YAML value. "
        "Development is the only environment permitted to run unsigned bundles (INV-012)."
    )
    assert "--watch" in opa_block, (
        "docker-compose.dev.yml OPA override should enable --watch for hot-reload."
    )


def test_opa_signed_overlay_deleted() -> None:
    """docker-compose.opa-signed.yml must no longer exist.

    It has been absorbed into the default docker-compose.yml (Task 1.1).
    If this file still exists it means the overlay and the default are out of
    sync and operators may be confused about which one to use.
    """
    overlay = REPO_ROOT / "docker-compose.opa-signed.yml"
    assert not overlay.exists(), (
        "docker-compose.opa-signed.yml still exists. "
        "It should have been deleted when signed bundles became the default. "
        "Remove the file or revert the default compose change."
    )


# ---------------------------------------------------------------------------
# Integration: tampered bundle must be rejected (proxy returns 503)
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_tampered_bundle_rejected(compose_opa_signed: object) -> None:  # type: ignore[type-arg]
    """INV-012 + INV-004: OPA rejects a tampered bundle; proxy fail-closes to 503.

    The compose_opa_signed fixture (defined in conftest.py) is responsible for:
      1. Building a fresh signed bundle via sign_policy_bundle.sh.
      2. Flipping one byte in policies/bundle.tar.gz to simulate tampering.
      3. Restarting the OPA container with the tampered bundle.
      4. Waiting for the container to attempt and fail startup.

    The fixture exposes:
      - compose_opa_signed.proxy_url   — base URL of the running proxy
      - compose_opa_signed.tool_id     — a seeded tool ID to invoke
      - compose_opa_signed.agent_headers — auth headers for an agent client
      - compose_opa_signed.ca_bundle   — path to the step-ca root cert

    Expected behaviour:
      - OPA refuses to load the tampered bundle and does not serve policy.
      - The proxy's OPA client receives a connection error or non-200 on every
        policy query.
      - INV-004 mandates that the proxy returns HTTP 503 with OPA_UNAVAILABLE,
        never 200 (allow-through) or 403 (silently applying a stale cached
        decision).
    """
    import httpx  # local import so the unit tests don't require httpx installed

    fixture = compose_opa_signed  # type: ignore[assignment]
    resp = httpx.post(
        f"{fixture.proxy_url}/api/v1/tools/{fixture.tool_id}/invoke",
        json={"params": {}},
        headers=fixture.agent_headers,
        verify=fixture.ca_bundle,  # step-ca root; NEVER verify=False
    )
    assert resp.status_code == 503, (
        f"Expected 503 (INV-004 fail-closed) when OPA has a tampered bundle, "
        f"got {resp.status_code}. Body: {resp.text}"
    )
