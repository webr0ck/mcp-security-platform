"""S-5 (PRD-0002): verify a token-exchanged JWT before trusting any claim.

Closes the RFC 8693 confused-deputy: the broker must not inject an exchanged
token without proving (a) signature, (b) sub==caller, (c) aud==expected,
(d) azp == mcp-proxy (KC 24 uses azp for delegation evidence, not act). Run on EVERY
injection including Redis cache hits (the cache stores no pre-computed claims).
"""
from __future__ import annotations

import jwt

EXPECTED_ACTOR = "mcp-proxy"


class ExchangedTokenError(Exception):
    """Raised when an exchanged token fails any S-5 assertion."""


def assert_exchanged_token(token: str, *, expected_sub: str, expected_aud: str, public_key) -> None:
    try:
        claims = jwt.decode(
            token, public_key, algorithms=["RS256"],
            audience=expected_aud, options={"verify_aud": True},
        )
    except jwt.InvalidSignatureError as exc:
        raise ExchangedTokenError(f"exchanged token signature invalid: {exc}") from exc
    except jwt.InvalidAudienceError as exc:
        raise ExchangedTokenError(f"exchanged token aud != {expected_aud}: {exc}") from exc
    except jwt.PyJWTError as exc:
        raise ExchangedTokenError(f"exchanged token invalid: {exc}") from exc

    if claims.get("sub") != expected_sub:
        raise ExchangedTokenError(
            f"exchanged token sub {claims.get('sub')!r} != caller {expected_sub!r}"
        )

    # KC 24 sets azp=mcp-proxy on the exchanged token (RFC 8693 §4.4 act is optional).
    # Verify azp is present and matches the expected actor.
    azp = claims.get("azp")
    if azp != EXPECTED_ACTOR:
        raise ExchangedTokenError(f"exchanged token azp != {EXPECTED_ACTOR}: {azp!r}")
