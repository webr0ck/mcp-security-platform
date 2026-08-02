# ui/ — portal acceptance suite

This directory holds the **Playwright acceptance suite** for the platform's live UI.

The live UI is the **server-rendered portal** at `proxy/app/routers/portal.py`
(HTML + htmx), served at `/portal`.

## There is no React app here any more

A React/Vite SPA lived in `ui/src` until 2026-07-25. It was deleted because it was
**never deployed**:

- no service in `docker-compose.yml`, `podman-compose.lab.yml` or any `compose.*.yml`
- no `location` block in `gateway/nginx/conf.d/mcp-proxy.conf`
- no CI job built it (`.github/workflows/ci.yml` builds only the proxy and
  compliance-checker images)

It had grown into a parallel implementation of screens the portal already served —
servers, submissions, limits, wizard — so every UI decision was being made twice and
shipped zero-to-once. Its own e2e suite (`e2e/portal.spec.ts`) tested that dead app
against mocks and is gone with it.

If you want a SPA, start from the portal's actual API surface and wire it into compose
and nginx in the same change — otherwise it will drift out of existence again.

## Running the suite

    make -f Makefile.lab lab-up          # the suite needs a live lab
    cd ui && npm ci && npm run acceptance

or `make ui-acceptance` from the repo root. Config: `playwright.portal.config.ts`
(targets the portal over TLS; override the host with `PORTAL_BASE_URL`).
