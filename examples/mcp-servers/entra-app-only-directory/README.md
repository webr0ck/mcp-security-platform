# Example: `entra_client_credentials` injection mode (app-only Microsoft Graph)

Read the big comment at the top of `server.py` before copying this pattern — it's the most
commonly misread injection mode on this platform.

**The platform does the entire OAuth client_credentials token exchange itself** and hands your
server a ready-to-use Graph access token as a normal `Authorization: Bearer <token>` header. Your
server never receives a client secret and never talks to `login.microsoftonline.com` directly —
just read the injected Authorization header and forward it to Graph as-is (see `_get_app_token()`).

Required Graph **application** permissions on the app registration (admin consent needed):
`User.Read.All`, `Group.Read.All`, `Application.Read.All` (adjust to whichever Graph endpoints
your own server actually calls).

See the [examples index](../README.md) for the full pattern comparison table, and note the
`stateless_http=True` requirement called out there — without it, this exact server silently
receives an empty Authorization header inside its tool functions even though the broker did
inject one correctly.

```bash
podman build -t example-entra-directory .
podman run -d -p 8000:8000 example-entra-directory
```

Submitting a server with this injection mode via `submit_mcp_server` requires also passing
`upstream_idp_type='entra'`, `upstream_idp_issuer='https://login.microsoftonline.com/<tenant>/v2.0'`,
and `upstream_idp_client_id=<your client id>` in the same call — this cannot be added after
submission.
