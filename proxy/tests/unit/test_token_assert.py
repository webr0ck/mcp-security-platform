# proxy/tests/unit/test_token_assert.py
import jwt, time, pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from app.credential_broker.token_assert import assert_exchanged_token, ExchangedTokenError

@pytest.fixture
def keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def _mint(key, **claims):
    base = {
        "sub": "alice",
        "aud": "lab-tickets",
        "iss": "http://kc/realms/mcp",
        "exp": time.time() + 300,
        "azp": "mcp-proxy",   # KC 24 uses azp, not act
    }
    base.update(claims)
    return jwt.encode(base, key, algorithm="RS256")

def test_valid_token_passes(keypair):
    tok = _mint(keypair)
    assert_exchanged_token(tok, expected_sub="alice", expected_aud="lab-tickets",
                           public_key=keypair.public_key())  # no raise

def test_sub_mismatch_rejected(keypair):
    tok = _mint(keypair, sub="bob")
    with pytest.raises(ExchangedTokenError, match="sub"):
        assert_exchanged_token(tok, expected_sub="alice", expected_aud="lab-tickets",
                               public_key=keypair.public_key())

def test_aud_mismatch_rejected(keypair):
    tok = _mint(keypair, aud="grafana")
    with pytest.raises(ExchangedTokenError, match="aud"):
        assert_exchanged_token(tok, expected_sub="alice", expected_aud="lab-tickets",
                               public_key=keypair.public_key())

def test_bad_signature_rejected(keypair):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tok = _mint(other)
    with pytest.raises(ExchangedTokenError, match="signature"):
        assert_exchanged_token(tok, expected_sub="alice", expected_aud="lab-tickets",
                               public_key=keypair.public_key())

def test_azp_wrong_actor_rejected(keypair):
    tok = _mint(keypair, azp="attacker")
    with pytest.raises(ExchangedTokenError, match="azp"):
        assert_exchanged_token(tok, expected_sub="alice", expected_aud="lab-tickets",
                               public_key=keypair.public_key())

def test_azp_absent_rejected(keypair):
    # Token with no azp claim at all must be rejected (KC 24 always sets it; missing = tampered).
    # Cannot use _mint() here: base.update({"azp": None}) sets azp=None rather than omitting
    # the claim; the check would still pass but would not be testing the "absent" code path.
    base = {"sub": "alice", "aud": "lab-tickets", "iss": "http://kc/realms/mcp",
            "exp": time.time() + 300}  # no azp key
    tok = jwt.encode(base, keypair, algorithm="RS256")
    with pytest.raises(ExchangedTokenError, match="azp"):
        assert_exchanged_token(tok, expected_sub="alice", expected_aud="lab-tickets",
                               public_key=keypair.public_key())
