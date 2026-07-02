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

const BASE = process.env.PORTAL_BASE_URL ?? 'https://100.119.138.35:8443'

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
