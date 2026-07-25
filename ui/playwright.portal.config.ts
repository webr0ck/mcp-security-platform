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
// Never hardcode a real LAN/Tailscale address here — it lands in git. Point at the
// loopback the lab always exposes; override with PORTAL_BASE_URL to test over the
// network (that value must match .env.lab's PROXY_BASE_URL, since the server builds
// its OAuth redirect_uri from that, not from however the test reached it).
const BASE = process.env.PORTAL_BASE_URL ?? 'https://127.0.0.1:8443'

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
