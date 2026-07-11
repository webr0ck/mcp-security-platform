# 10 — Portal sign-out doesn't actually log the browser out

- **Status:** INVESTIGATION ONLY — root cause not yet confirmed, no fix applied.
- **Date:** 2026-07-11
- **Reported by:** user, live on `https://100.119.138.35:8443/portal` — "signout doesn't work".

## Symptom

Clicking "Sign out" in the portal (`portalSignOut()` in `proxy/app/routers/portal.py`) does not
actually end the session — the user remains logged in / the old session keeps getting used.

## What's confirmed working (ruled out)

- The backend logout endpoint (`POST /api/v1/auth/oidc/logout`, `oidc_browser.py::oidc_logout`) **is
  being called and does succeed server-side.** Live nginx + proxy logs for two real logout attempts
  (06:07:34 and 06:07:44 UTC) both show:
  - nginx: `"POST /api/v1/auth/oidc/logout HTTP/2.0" 200 25 ...` (200 OK, referer
    `/portal/admin/profile`, real Chrome UA — a genuine user click, not a test).
  - proxy: `UPDATE oidc_sessions SET revoked_at = $1 WHERE session_jwt_jti = $2` actually executes.
  - So DB-side session revocation is NOT the bug — it works.
- Cookie **domain** attribute mismatch between `set_cookie` and `delete_cookie` was my first
  hypothesis (set_cookie passes `domain=settings.SESSION_COOKIE_DOMAIN if != "localhost" else
  None`, `delete_cookie` passes no domain at all) — but checked the live config:
  `SESSION_COOKIE_DOMAIN='localhost'`, which resolves to `domain=None` on the `set_cookie` call too.
  **Domain matches (both None) in this environment** — ruled out as the cause here, though it would
  still be a latent bug in any deployment where `SESSION_COOKIE_DOMAIN` is set to a real value
  (e.g. production), since `delete_cookie()` at oidc_browser.py:742 does not pass a `domain=` at all.

## The actual smoking gun

After the 200 logout response, **the same browser keeps sending the same old `mcp_session` cookie on
subsequent requests** — proxy logs show repeated `SELECT revoked_at FROM oidc_sessions WHERE
session_jwt_jti = $1` checks for the *same* jti continuing after the logout call completed. This
means the cookie was never actually cleared client-side, even though the server-side revocation
worked. `response.delete_cookie(settings.SESSION_COOKIE_NAME)` (oidc_browser.py:742) passes **no**
`secure`, `samesite`, `httponly`, or `path` arguments, unlike the original `set_cookie` call at
oidc_browser.py:673-680 (`httponly=True, secure=settings.SESSION_COOKIE_SECURE, samesite="lax"`,
plus the domain logic above). Whether this attribute mismatch is enough on its own to make Chrome
silently ignore the deletion (browsers generally only require name+domain+path to match for
deletion, not secure/samesite/httponly — so this alone may not fully explain it, but it's a real
inconsistency worth fixing regardless) is not yet confirmed.

## A second, likely-more-important finding

Direct curl test of the endpoint with an **invalid** cookie value (`Cookie: mcp_session=bogus`)
returned **401 Unauthorized** with a `WWW-Authenticate: Bearer realm="mcp-proxy",
resource_metadata=...` challenge header — meaning **the platform's own `AuthMiddleware`
(`proxy/app/middleware/auth.py::AuthMiddleware.dispatch`) gates `/api/v1/auth/oidc/logout` and
rejects the request before it ever reaches `oidc_logout()`'s handler code.** The handler itself is
clearly written to tolerate a missing/invalid/expired token gracefully (falls through to "Logged
out" regardless) — but the middleware in front of it doesn't extend that same tolerance. This is
architecturally backwards for a logout endpoint specifically: a client with an already-expired,
already-revoked, or slightly malformed session should still be able to hit logout and get a clean
"you're logged out" response + cookie-clear, not a 401. Worth checking whether `/api/v1/auth/oidc/
logout` should be added to whatever allowlist exempts `/oauth/`, `/.well-known/`, `/auth/enroll`,
`/auth/callback` from this middleware (see `AuthMiddleware.dispatch`, the early-return path at line
191 — `if <path matches allowlist>: return await call_next(request)`).

This does NOT fully explain the observed symptom by itself (both real logout attempts got 200, not
401 — meaning AuthMiddleware DID let the request through when the cookie was still validly-signed
and not-yet-revoked at request time), but it's a related, real gap: **any retry of logout after the
first one succeeds will now 401 instead of idempotently succeeding**, since the session is revoked
after the first call. That could itself explain part of the user-visible confusion if the frontend
or a second tab retries logout.

## Not yet done (next steps for whoever picks this up)

1. Was in progress: craft a legitimately HS256-signed test session JWT (using
   `oidc_browser.py::_issue_session_jwt`'s exact payload shape + `settings.PROXY_SECRET_KEY`) with a
   matching `oidc_sessions` DB row (`revoked_at IS NULL`), then curl `/api/v1/auth/oidc/logout` with
   that **valid** cookie and inspect the actual `Set-Cookie` response header byte-for-byte. This is
   the decisive test that was interrupted — it will show definitively whether `delete_cookie()`
   itself emits a working clear-cookie header, or whether something between the route handler and
   the client (e.g. `AuthMiddleware.dispatch` reconstructing the response, a proxy/nginx layer, or a
   different middleware) is stripping `Set-Cookie` on the way out.
2. If the Set-Cookie header IS present and correct in that test, the bug is purely front-end/browser
   (e.g. `portalSignOut()`'s `.finally()` navigating before the Set-Cookie is actually applied by the
   browser, though this would be unusual — `fetch()` completion implies headers were already
   processed) — re-examine `portal.py`'s `portalSignOut()` JS for a race or wrong assumption.
3. If the header is missing/malformed, check `AuthMiddleware.dispatch` for how it wraps
   `call_next()`'s response (a common Starlette middleware bug: reconstructing a `Response` object
   from the downstream one without preserving `Set-Cookie`).
4. Regardless of root cause, still worth doing as a cleanup: make `delete_cookie()` at
   oidc_browser.py:742 pass the same `domain`/`secure`/`samesite`/`path` as the original `set_cookie`
   call, and decide whether `/api/v1/auth/oidc/logout` should be exempted from `AuthMiddleware`'s
   strict-auth gate so an already-invalid/expired/revoked session can still hit logout cleanly.
