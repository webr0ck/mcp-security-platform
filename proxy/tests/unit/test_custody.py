"""
Tests for proxy/app/services/custody.py

Validates the ZK-at-rest guarantee:
  - wrap/unwrap roundtrip succeeds with live session
  - storage-only attacker (different session_secret) cannot unwrap
  - typed-principal isolation (wrong principal_id → decrypt fails)
  - CustodyRef repr never contains plaintext or session_secret
  - session zeroing raises CustodySessionExpiredError
  - server nonce variation produces different ciphertext (no static IVs)
"""
import pytest
import asyncio
from app.services.custody import (
    CustodyRef, SessionSUKCustodian, CustodySessionExpiredError, HSMAgentCustodian
)

PRINCIPAL = "human:keycloak:alice"
SERVER_ID = "srv_001"
SECRET = b"super-secret-api-key"
SESSION_SECRET = b"live-session-ikm-32byteslong!!!!!"


@pytest.mark.asyncio
async def test_session_suk_wrap_unwrap_roundtrip():
    custodian = SessionSUKCustodian(SESSION_SECRET)
    ref = await custodian.wrap(PRINCIPAL, SERVER_ID, SECRET)
    result = await custodian.unwrap(PRINCIPAL, SERVER_ID, ref)
    assert result == SECRET


@pytest.mark.asyncio
async def test_storage_only_attacker_cannot_unwrap():
    """Core at-rest guarantee: different session_secret → cannot decrypt."""
    custodian = SessionSUKCustodian(SESSION_SECRET)
    ref = await custodian.wrap(PRINCIPAL, SERVER_ID, SECRET)

    attacker = SessionSUKCustodian(b"attacker-has-different-session!!")
    with pytest.raises(Exception):   # InvalidTag from AESGCM or ValueError
        await attacker.unwrap(PRINCIPAL, SERVER_ID, ref)


@pytest.mark.asyncio
async def test_typed_principal_isolation_blocks_cross_principal_unwrap():
    """agent: principal cannot unwrap a ref wrapped for human: principal."""
    custodian = SessionSUKCustodian(SESSION_SECRET)
    ref = await custodian.wrap(PRINCIPAL, SERVER_ID, SECRET)

    with pytest.raises(Exception):
        await custodian.unwrap("agent:step-ca:bot-cert", SERVER_ID, ref)


@pytest.mark.asyncio
async def test_wrong_server_id_cannot_unwrap():
    """Wrong server_id changes HKDF info → decrypt fails."""
    custodian = SessionSUKCustodian(SESSION_SECRET)
    ref = await custodian.wrap(PRINCIPAL, SERVER_ID, SECRET)

    with pytest.raises(Exception):
        await custodian.unwrap(PRINCIPAL, "srv_OTHER", ref)


@pytest.mark.asyncio
async def test_custody_ref_repr_contains_no_plaintext():
    custodian = SessionSUKCustodian(SESSION_SECRET)
    ref = await custodian.wrap(PRINCIPAL, SERVER_ID, SECRET)

    ref_repr = repr(ref)
    assert SECRET.decode() not in ref_repr
    assert SESSION_SECRET.decode(errors='replace') not in ref_repr


@pytest.mark.asyncio
async def test_custody_ref_str_does_not_leak_ciphertext():
    """str() / repr() must not expose ciphertext_b64 — only metadata."""
    custodian = SessionSUKCustodian(SESSION_SECRET)
    ref = await custodian.wrap(PRINCIPAL, SERVER_ID, SECRET)

    safe = repr(ref)
    assert "ciphertext_b64" not in safe
    assert "nonce_b64" not in safe


@pytest.mark.asyncio
async def test_session_zeroing_raises_on_subsequent_operations():
    custodian = SessionSUKCustodian(SESSION_SECRET)
    ref = await custodian.wrap(PRINCIPAL, SERVER_ID, SECRET)

    custodian.zero_session_secret()

    with pytest.raises(CustodySessionExpiredError):
        await custodian.unwrap(PRINCIPAL, SERVER_ID, ref)


@pytest.mark.asyncio
async def test_wrap_after_zeroing_raises():
    custodian = SessionSUKCustodian(SESSION_SECRET)
    custodian.zero_session_secret()

    with pytest.raises(CustodySessionExpiredError):
        await custodian.wrap(PRINCIPAL, SERVER_ID, SECRET)


@pytest.mark.asyncio
async def test_server_nonce_variation_produces_unique_ciphertexts():
    """Two wraps of the same plaintext must produce different ciphertexts (no static nonces)."""
    custodian = SessionSUKCustodian(SESSION_SECRET)
    ref1 = await custodian.wrap(PRINCIPAL, SERVER_ID, SECRET)
    ref2 = await custodian.wrap(PRINCIPAL, SERVER_ID, SECRET)

    assert ref1.ciphertext_b64 != ref2.ciphertext_b64
    assert ref1.nonce_b64 != ref2.nonce_b64


def test_hsm_agent_custodian_raises_not_implemented():
    stub = HSMAgentCustodian(vault_client=None, key_name="agent-key")

    with pytest.raises(NotImplementedError):
        asyncio.run(stub.wrap(PRINCIPAL, SERVER_ID, SECRET))
