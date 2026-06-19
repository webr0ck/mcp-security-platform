# proxy/tests/unit/test_lab_tickets_jwt.py
"""
Validates the token-checking logic used by lab-tickets/server.py.
We copy the validation function inline here so we can test it without
spinning up the FastMCP server or reaching a live KC JWKS endpoint.
"""
import jwt, time, pytest
from cryptography.hazmat.primitives.asymmetric import rsa

EXPECTED_AUDIENCE = "lab-tickets"
EXPECTED_AZP = "mcp-proxy"

def validate_lab_tickets_token(token: str, public_key) -> dict:
    """Validate a KC-issued exchanged token for the lab-tickets resource server."""
    try:
        claims = jwt.decode(
            token, public_key, algorithms=["RS256"],
            audience=EXPECTED_AUDIENCE, options={"verify_aud": True},
        )
    except jwt.PyJWTError as exc:
        raise ValueError(f"JWT validation failed: {exc}") from exc
    azp = claims.get("azp")
    if azp != EXPECTED_AZP:
        raise ValueError(f"azp {azp!r} != expected actor {EXPECTED_AZP!r}")
    return claims

@pytest.fixture
def keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def _mint(key, **overrides):
    base = {"sub": "alice", "aud": "lab-tickets", "azp": "mcp-proxy",
            "iss": "http://kc/realms/mcp", "exp": time.time() + 300}
    base.update(overrides)
    return jwt.encode(base, key, algorithm="RS256")

def test_valid_exchanged_token_accepted(keypair):
    tok = _mint(keypair)
    claims = validate_lab_tickets_token(tok, keypair.public_key())
    assert claims["sub"] == "alice"
    assert claims["azp"] == "mcp-proxy"

def test_wrong_aud_rejected(keypair):
    tok = _mint(keypair, aud="grafana")
    with pytest.raises(ValueError, match="JWT validation failed"):
        validate_lab_tickets_token(tok, keypair.public_key())

def test_missing_azp_rejected(keypair):
    # Cannot use _mint() here: .update({"azp": None}) sets azp=None, not omits the key.
    base = {"sub": "alice", "aud": "lab-tickets", "iss": "http://kc/realms/mcp",
            "exp": time.time() + 300}
    tok = jwt.encode(base, keypair, algorithm="RS256")
    with pytest.raises(ValueError, match="azp"):
        validate_lab_tickets_token(tok, keypair.public_key())

def test_wrong_azp_rejected(keypair):
    tok = _mint(keypair, azp="malicious-client")
    with pytest.raises(ValueError, match="azp"):
        validate_lab_tickets_token(tok, keypair.public_key())

def test_expired_token_rejected(keypair):
    tok = _mint(keypair, exp=time.time() - 1)
    with pytest.raises(ValueError, match="JWT validation failed"):
        validate_lab_tickets_token(tok, keypair.public_key())
