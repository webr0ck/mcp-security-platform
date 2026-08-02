import { readFileSync } from 'node:fs'

import { defineConfig, devices } from '@playwright/test'

// Portal acceptance tests — targets the SSR proxy portal (port 8443 / 8000),
// NOT the React UI at port 3100.
//
// Prerequisites:
//   make -f Makefile.lab lab-up
//   npx playwright test --config ui/playwright.portal.config.ts
//
// Credentials from .env.lab:
//   alice  / CudvCD5L3WzmmktMEVmWvRkLqFlI  (admin + agent roles)
//   bob    / e25JOYuj7xTqQEZP58EIXOlXf54e  (agent role)
//   carol  / labpassword                    (auditor role)

// Must match the Keycloak client's registered redirect_uri / this lab's PUBLIC_URL
// (see lab/keycloak/realm-mcp.json) — login cookies are scoped to that host, and
// while page.goto() navigations get redirected there transparently, ctx.request()
// API calls do not, so a mismatched default here silently 401s every API-based
// acceptance test without ever exercising a redirect to fix it up.
// Resolve the base URL from .env.lab's PROXY_BASE_URL at runtime.
//
// It MUST match what the server thinks it is: login cookies are scoped to that host,
// and the proxy builds its OAuth redirect_uri from PROXY_BASE_URL
// (app.core.public_url::derive_public_base_url), not from however the test connected.
// A mismatch silently 401s every ctx.request() call in this suite — page.goto() gets
// redirected transparently and hides the problem.
//
// Read at runtime rather than hardcoded because PROXY_BASE_URL is a real LAN/Tailscale
// address and must never be committed. Falls back to loopback when .env.lab is absent
// (fresh clone, CI) so the config still loads; override with PORTAL_BASE_URL.
function proxyBaseFromEnvLab(): string | null {
  try {
    const envPath = new URL('../.env.lab', import.meta.url)
    for (const line of readFileSync(envPath, 'utf8').split('\n')) {
      const m = line.match(/^\s*PROXY_BASE_URL\s*=\s*(.+?)\s*$/)
      if (m) return m[1].replace(/^["']|["']$/g, '') || null
    }
  } catch { /* .env.lab absent — fall through */ }
  return null
}

const BASE = process.env.PORTAL_BASE_URL ?? proxyBaseFromEnvLab() ?? 'https://127.0.0.1:8443'

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/portal-acceptance.spec.ts',
  fullyParallel: false,
  retries: 1,
  timeout: 60_000,          // per-test; beforeAll uses test.setTimeout() internally
  use: {
    baseURL: BASE,
    headless: true,
    ignoreHTTPSErrors: true,      // mkcert self-signed cert — applies to browser + request contexts
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
