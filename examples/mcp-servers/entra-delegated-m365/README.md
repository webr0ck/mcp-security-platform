# Example: `entra_user_token` (delegated) with app-only fallback

The most complex example — supports both modes in one server, switching on whether a real
per-user delegated token was actually injected for this specific call:

- **Delegated** (`entra_user_token`): the caller consented via the real interactive
  `/auth/enroll/m365` flow; the server acts as that specific human, and `/me`-style Graph calls
  resolve to them.
- **App-only fallback** (`entra_client_credentials`): no delegated token was injected — the server
  would act as the application itself, reading a fixed `M365_USER` mailbox instead of the caller.

Read `REQUIRE_DELEGATED` and `_is_delegated()` in `server.py` before copying this pattern — the
default (`REQUIRE_DELEGATED=true`) **refuses** the silent fallback, because silently switching from
"acting as the user" to "acting as the application" is a real security footgun (a caller could
believe they're reading their own mailbox when the server is actually reading someone else's fixed
mailbox). Only disable `REQUIRE_DELEGATED` if app-only really is the intended, reviewed behavior.

See the [examples index](../README.md) for the full pattern comparison table.

```bash
podman build -t example-m365 .
podman run -d -p 8000:8000 example-m365
```
