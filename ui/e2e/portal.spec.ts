import { test, expect, Page } from '@playwright/test'

// These tests run against the live lab stack (proxy + postgres + keycloak).
// Start the lab before running: make -f Makefile.lab lab-up
// Then: npx playwright test
//
// Happy-path tests (catalog visibility, toggle) also have a mock-server mode
// activated by setting PLAYWRIGHT_MOCK=1. In mock mode, Playwright route
// intercepts replace all /api/v1/profiles/* calls so the suite runs in CI
// without live infrastructure. (issue #5)

const MOCK = process.env.PLAYWRIGHT_MOCK === '1'

async function loginAs(page: Page, role: 'viewer' | 'editor' | 'analyst' | 'admin') {
  // Navigate to the UI and simulate login via Keycloak PKCE.
  // In lab: alice=editor, bob=viewer, carol=analyst, admin=admin.
  const creds: Record<string, [string, string]> = {
    viewer: ['bob', 'labpassword'],
    editor: ['alice', 'labpassword'],
    analyst: ['carol', 'labpassword'],
    admin: ['admin', 'labpassword'],
  }
  const [user, pass] = creds[role]
  await page.goto('/')
  // Click the login button / trigger OIDC redirect
  await page.getByRole('button', { name: /sign in/i }).click()
  await page.waitForURL(/keycloak.*auth/)
  await page.fill('#username', user)
  await page.fill('#password', pass)
  await page.getByRole('button', { name: /sign in/i }).click()
  await page.waitForURL('http://localhost:5173/**')
}

// ── Mock helpers (CI / no live stack) ────────────────────────────────────────

const MOCK_MCPS = [
  { server_name: 'poc-echo-server', display_name: 'Echo Server', description: 'Echo server for testing', status: 'active', enabled_for_account: false },
  { server_name: 'poc-notes-server', display_name: 'Notes Server', description: 'Notes server', status: 'active', enabled_for_account: true },
]

const MOCK_PROFILE = {
  principal: 'alice',
  mcps: [
    {
      server_name: 'poc-notes-server',
      description: 'Notes server',
      enabled: true,
      functions: [
        { name: 'create_note', description: 'Create a note', enabled: true },
        { name: 'list_notes', description: 'List notes', enabled: false },
      ],
    },
  ],
}

async function setupMocks(page: Page) {
  if (!MOCK) return
  await page.route('/api/v1/profiles/available-mcps', route =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(MOCK_MCPS) })
  )
  // Issue #9 + #13: getProfile now calls /me — intercept /me instead of
  // the old /<principal> path so the mock stays in sync with the fix.
  await page.route('/api/v1/profiles/me', async route => {
    const req = route.request()
    if (req.method() === 'GET') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(MOCK_PROFILE) })
    }
    return route.continue()
  })
  await page.route('/api/v1/profiles/**', async route => {
    const req = route.request()
    const url = req.url()
    // POST mutations (enable/disable) — acknowledge success
    if (url.includes('/enable') || url.includes('/disable')) {
      return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' })
    }
    return route.continue()
  })
}

// In mock mode, skip Keycloak flow and go straight to the portal page
async function navigateToPortal(page: Page, role: 'viewer' | 'editor' | 'analyst' | 'admin') {
  if (MOCK) {
    await page.goto('/')
  } else {
    await loginAs(page, role)
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test.describe('UserPortal — MCP management', () => {
  test('viewer can see the MCP catalog', async ({ page }) => {
    await setupMocks(page)
    await navigateToPortal(page, 'viewer')
    if (!MOCK) await page.getByRole('link', { name: /portal|catalog/i }).click()

    // Issue #11: use data-testid attributes so selector drift causes explicit
    // failures instead of silently passing against stale DOM.
    await expect(page.locator('[data-testid="portal-title"]')).toContainText(/catalog/i)
    await expect(page.locator('[data-testid="server-card"]').first()).toBeVisible()

    // Issue #1: server cards must show human-readable names, not raw slugs.
    // display_name "Echo Server" from the mock should be visible.
    const firstCardName = page.locator('[data-testid="server-card-name"]').first()
    await expect(firstCardName).not.toContainText('poc-')
  })

  test('editor can enable and disable an MCP', async ({ page }) => {
    await setupMocks(page)
    await navigateToPortal(page, 'editor')
    if (!MOCK) await page.getByRole('link', { name: /portal|catalog/i }).click()

    // Issue #11: use data-testid + data-server attribute for reliable card selection
    const echoCard = page.locator('[data-testid="server-card"][data-server="poc-echo-server"]').first()
    await expect(echoCard).toBeVisible()

    // Issue #12: use data-testid="toggle-btn" so we always hit the real button
    const toggle = echoCard.locator('[data-testid="toggle-btn"]').last()
    const initialLabel = await toggle.getAttribute('aria-label')

    // Toggle it
    await toggle.click()
    if (!MOCK) {
      await page.waitForResponse(r => r.url().includes('/api/v1/profiles') && r.status() < 400)
    }

    // State must have changed
    const newLabel = await toggle.getAttribute('aria-label')
    expect(newLabel).not.toBe(initialLabel)

    // Toggle back
    await toggle.click()
    if (!MOCK) {
      await page.waitForResponse(r => r.url().includes('/api/v1/profiles') && r.status() < 400)
    }
  })

  test('editor can expand server and toggle individual tools', async ({ page }) => {
    await setupMocks(page)
    await navigateToPortal(page, 'editor')
    if (!MOCK) await page.getByRole('link', { name: /portal|catalog/i }).click()

    // Issue #11: data-testid for reliable card selection
    const notesCard = page.locator('[data-testid="server-card"][data-server="poc-notes-server"]').first()

    // Issue #12: expand button is always rendered (issue #2 fix); use data-testid
    // and assert unconditionally rather than guarding with isVisible().
    const expandBtn = notesCard.locator('[data-testid="server-card-expand"]')
    await expect(expandBtn).toBeVisible()
    await expandBtn.click()

    // Function rows must now be visible
    await expect(notesCard.locator('[data-testid="fn-row"]').first()).toBeVisible()

    // Toggle a function
    const firstFnToggle = notesCard.locator('[data-testid="fn-row"] [data-testid="toggle-btn"]').first()
    await firstFnToggle.click()
    if (!MOCK) {
      await page.waitForResponse(r => r.url().includes('functions') && r.status() < 400)
    }
  })

  // Issue #10: test 4 now calls setupMocks + navigateToPortal before the route
  // override so authentication is always established first. This removes the
  // order-dependency and prevents the unauthenticated-user race condition.
  test('error state shown when API fails', async ({ page }) => {
    await setupMocks(page)
    await navigateToPortal(page, 'editor')

    // Override the available-mcps route AFTER authentication so the error is
    // triggered on the authenticated load, not on an unauth redirect.
    await page.route('/api/v1/profiles/available-mcps', route =>
      route.fulfill({ status: 503, body: 'Service unavailable' })
    )
    // Reload the page so the new route intercept fires
    await page.reload()

    if (!MOCK) await page.getByRole('link', { name: /portal|catalog/i }).click()

    // Issue #11: use data-testid for reliable error-state selection
    await expect(page.locator('[data-testid="portal-error"]')).toBeVisible({ timeout: 5000 })
  })
})
