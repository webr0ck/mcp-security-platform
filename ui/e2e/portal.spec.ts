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
  await page.waitForURL('http://localhost:3100/**')
}

// ── Mock helpers (CI / no live stack) ────────────────────────────────────────

const MOCK_MCPS = [
  { server_name: 'poc-echo-server', display_name: 'Echo Server', description: 'Echo server for testing', status: 'active', enabled_for_account: false },
  { server_name: 'poc-notes-server', display_name: 'Notes Server', description: 'Notes server', status: 'active', enabled_for_account: true },
]

// Issue #12/#13: per-role mock profiles so role-gated UI features and
// privilege-isolation regressions are caught in mock/CI mode.
// Viewer (bob) has read-only access and only sees one pre-enabled server.
const MOCK_PROFILE_VIEWER = {
  principal: 'bob',
  mcps: [
    {
      server_name: 'poc-notes-server',
      description: 'Notes server',
      enabled: true,
      functions: [
        { name: 'list_notes', description: 'List notes', enabled: true },
      ],
    },
  ],
}

// Editor (alice) has full access and can enable/disable servers and functions.
const MOCK_PROFILE_EDITOR = {
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

// Convenience alias used where the test doesn't care about role-specific data.
const MOCK_PROFILE = MOCK_PROFILE_EDITOR

// Issue #12/#13: accept a role so each test gets role-appropriate profile data.
// Defaults to 'editor' (alice) to keep existing tests unchanged.
async function setupMocks(page: Page, role: 'viewer' | 'editor' | 'analyst' | 'admin' = 'editor') {
  if (!MOCK) return
  // Mock auth/me so AuthContext resolves as authenticated (avoids ECONNREFUSED log spam)
  const mockUser = role === 'viewer' ? 'bob' : role === 'analyst' ? 'carol' : role === 'admin' ? 'admin' : 'alice'
  await page.route('/api/v1/auth/me', route =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ client_id: mockUser, roles: [role] }) })
  )
  await page.route('/api/v1/profiles/available-mcps', route =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(MOCK_MCPS) })
  )
  // Issue #9 + #13: getProfile calls /me — intercept /me and return the
  // role-appropriate profile so role-gated UI features are exercised in mock mode.
  const profileForRole = role === 'viewer' ? MOCK_PROFILE_VIEWER : MOCK_PROFILE_EDITOR
  await page.route('/api/v1/profiles/me', async route => {
    const req = route.request()
    if (req.method() === 'GET') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(profileForRole) })
    }
    return route.continue()
  })
  // Issue #14: the catch-all must only match mutation paths (enable/disable).
  // Any unmatched sub-path now fails loudly with 501 so a forgotten mock is
  // immediately visible rather than silently hitting the live stack.
  await page.route('/api/v1/profiles/**', async route => {
    const req = route.request()
    const url = req.url()
    // POST mutations (enable/disable) — acknowledge success
    if (url.includes('/enable') || url.includes('/disable')) {
      return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' })
    }
    // Fail loudly for any unmatched path so missing mocks are caught in CI
    return route.fulfill({
      status: 501,
      contentType: 'application/json',
      body: JSON.stringify({ error: `Mock not implemented for ${req.method()} ${url}` }),
    })
  })
}

// Navigate to the portal view. In mock mode, skip Keycloak and click the nav button directly.
async function navigateToPortal(page: Page, role: 'viewer' | 'editor' | 'analyst' | 'admin') {
  if (MOCK) {
    await page.goto('/')
    // The app starts on the dashboard view — click Portal nav button to switch
    await page.getByRole('button', { name: /portal/i }).click()
    // Wait for portal to mount and load
    await page.waitForSelector('[data-testid="portal-title"]', { timeout: 8000 })
  } else {
    await loginAs(page, role)
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test.describe('UserPortal — MCP management', () => {
  test('viewer can see the MCP catalog', async ({ page }) => {
    // Issue #13: pass 'viewer' so the mock returns viewer-appropriate profile data
    await setupMocks(page, 'viewer')
    await navigateToPortal(page, 'viewer')
    // Portal navigation handled by navigateToPortal (both mock and live modes)

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
    await setupMocks(page, 'editor')
    await navigateToPortal(page, 'editor')
    // Portal navigation handled by navigateToPortal (both mock and live modes)

    // Issue #11: use data-testid + data-server attribute for reliable card selection
    const echoCard = page.locator('[data-testid="server-card"][data-server="poc-echo-server"]').first()
    await expect(echoCard).toBeVisible()

    // Issue #9: the toggle now requires a confirmation step.
    // First click shows Confirm/Cancel; second click (Confirm) commits the change.
    const toggleWrapper = echoCard.locator('[data-testid="toggle-wrapper"]').last()
    const initialPressed = await echoCard.locator('[data-testid="toggle-btn"]').last().getAttribute('aria-pressed')

    // First click — should show confirm bar
    await echoCard.locator('[data-testid="toggle-btn"]').last().click()
    await expect(echoCard.locator('[data-testid="confirm-bar"]')).toBeVisible()

    // Confirm the change
    await echoCard.locator('[data-testid="confirm-yes"]').click()
    if (!MOCK) {
      await page.waitForResponse(r => r.url().includes('/api/v1/profiles') && r.status() < 400)
    }

    // State must have changed (toggle re-rendered after reload)
    const newToggle = echoCard.locator('[data-testid="toggle-btn"]').last()
    const newPressed = await newToggle.getAttribute('aria-pressed')
    expect(newPressed).not.toBe(initialPressed)

    // Toggle back: click → confirm
    await newToggle.click()
    await echoCard.locator('[data-testid="confirm-yes"]').click()
    if (!MOCK) {
      await page.waitForResponse(r => r.url().includes('/api/v1/profiles') && r.status() < 400)
    }
  })

  test('editor can expand server and toggle individual tools', async ({ page }) => {
    await setupMocks(page, 'editor')
    await navigateToPortal(page, 'editor')
    // Portal navigation handled by navigateToPortal (both mock and live modes)

    // Issue #11: data-testid for reliable card selection
    const notesCard = page.locator('[data-testid="server-card"][data-server="poc-notes-server"]').first()

    // Issue #12: expand button is rendered for enabled servers; use data-testid
    // and assert unconditionally rather than guarding with isVisible().
    const expandBtn = notesCard.locator('[data-testid="server-card-expand"]')
    await expect(expandBtn).toBeVisible()
    await expandBtn.click()

    // Function rows must now be visible
    await expect(notesCard.locator('[data-testid="fn-row"]').first()).toBeVisible()

    // Issue #9: function toggle also requires confirmation — click then confirm
    const firstFnToggle = notesCard.locator('[data-testid="fn-row"] [data-testid="toggle-btn"]').first()
    await firstFnToggle.click()
    // Confirm bar should appear in that fn-row
    await expect(notesCard.locator('[data-testid="fn-row"] [data-testid="confirm-bar"]').first()).toBeVisible()
    await notesCard.locator('[data-testid="fn-row"] [data-testid="confirm-yes"]').first().click()
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

    // Portal navigation handled by navigateToPortal (both mock and live modes)

    // Issue #11: use data-testid for reliable error-state selection
    await expect(page.locator('[data-testid="portal-error"]')).toBeVisible({ timeout: 5000 })
  })
})
