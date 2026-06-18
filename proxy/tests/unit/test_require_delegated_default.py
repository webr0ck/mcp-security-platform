# proxy/tests/unit/test_require_delegated_default.py
"""S-1 (PRD-0002): delegated tools deny when no user identity is available."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.credential_broker.dispatcher import dispatch_credential_injection, CredentialInjectionError


@pytest.mark.asyncio
async def test_entra_user_token_denied_when_no_client_id():
    """S-1: entra_user_token with empty client_id must raise CredentialInjectionError."""
    tool = {
        "tool_id": "m365-mail",
        "injection_mode": "entra_user_token",
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
        "service_name": "m365",
    }
    # Patch broker_instance to a non-None mock (via the lazy-import module path)
    # so the broker-not-initialized guard is satisfied first, and the S-1 guard
    # (empty client_id) is the one that fires.
    mock_broker = MagicMock()
    with patch("app.services.invocation.broker_instance", mock_broker, create=True):
        with pytest.raises(CredentialInjectionError, match="S-1"):
            await dispatch_credential_injection(tool, client_id="", user_kc_token=None)
