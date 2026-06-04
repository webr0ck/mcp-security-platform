# MCP Security Platform — UI

Standalone React + TypeScript + Vite frontend. **Zero external UI library dependency** — every component is hand-rolled with CSS custom properties, making it trivial to retheme or port to any stack.

## Structure

```
ui/
├── src/
│   ├── design/
│   │   ├── tokens.css      ← Edit this to retheme the entire UI
│   │   └── global.css      ← Base resets + shared patterns
│   ├── types/index.ts      ← All shared TypeScript types
│   ├── services/api.ts     ← API client — one place to swap backends
│   └── components/
│       ├── common/         ← Badge, Button, Card (reusable primitives)
│       ├── layout/         ← AppShell, Sidebar
│       ├── Dashboard/      ← SecurityDashboard (audit stream + detections)
│       ├── AdminPanel/     ← OIDC config + server registry + credentials
│       ├── Portal/         ← Tool catalog + role-based access
│       └── Wizard/         ← 4-step installation wizard
```

## Quick start

```bash
cd ui
npm install
npm run dev        # → http://localhost:3100
npm run build      # → dist/
```

The dev server proxies `/api/*` to `https://localhost` (the engine tier). Configure via `VITE_API_URL` env var.

## Customising

**Retheme:** edit `src/design/tokens.css` — all colours, fonts, spacing, and border radii are CSS custom properties. No JavaScript changes needed.

**Swap backend:** `src/services/api.ts` is the only file that knows about the API. All components use mock data while the API is unavailable; wire up real calls by replacing the `MOCK_*` constants with `api.*` function calls.

**Add a view:** add an entry to `NAV_ITEMS` in `Sidebar.tsx`, add a `case` in `App.tsx`, and create your component folder.

## API assumptions

The UI talks to the MCP Security Platform proxy (`https://localhost`) via:
- `GET /health` — service health
- `GET /api/v1/audit` — audit events
- `GET/POST /api/v1/admin/servers` — server registry
- `GET/PUT /api/v1/auth/oidc/config` — OIDC configuration

All endpoints require a valid session (Bearer token or API key). In dev, set `VITE_API_URL=https://localhost` and ensure the engine tier is running.
