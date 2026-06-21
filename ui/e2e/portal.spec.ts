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
  // NOTE: Playwright processes routes LIFO (last registered = first matched).
  // Register broad/catch-all routes FIRST so specific routes registered LAST win.

  // Catch-all for mutations (enable/disable) — registered FIRST (matched last)
  await page.route('/api/v1/profiles/**', async route => {
    const req = route.request()
    const url = req.url()
    // POST mutations (enable/disable) — acknowledge success
    if (url.includes('/enable') || url.includes('/disable')) {
      return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' })
    }
    // Fall through to more specific route handlers (route.continue() would hit the live stack)
    // For any unmatched path, return 501 so missing mocks are caught in CI
    return route.fulfill({
      status: 501,
      contentType: 'application/json',
      body: JSON.stringify({ error: `Mock not implemented for ${req.method()} ${url}` }),
    })
  })

  // Specific routes — registered LAST (matched first, override catch-all above)

  // getProfile calls /me — intercept /me and return role-appropriate profile
  const profileForRole = role === 'viewer' ? MOCK_PROFILE_VIEWER : MOCK_PROFILE_EDITOR
  await page.route('/api/v1/profiles/me', async route => {
    const req = route.request()
    if (req.method() === 'GET') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(profileForRole) })
    }
    return route.continue()
  })

  await page.route('/api/v1/profiles/available-mcps', route =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(MOCK_MCPS) })
  )

  // Mock auth/me so AuthContext resolves as authenticated (avoids ECONNREFUSED log spam)
  const mockUser = role === 'viewer' ? 'bob' : role === 'analyst' ? 'carol' : role === 'admin' ? 'admin' : 'alice'
  await page.route('/api/v1/auth/me', route =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ client_id: mockUser, roles: [role] }) })
  )
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

    // Viewers see a read-only badge and NO toggle buttons (role gating)
    await expect(page.locator('[data-testid="readonly-badge"]')).toBeVisible()
    await expect(page.locator('[data-testid="toggle-btn"]')).toHaveCount(0)
  })

  test('editor can enable and disable an MCP', async ({ page }) => {
    // Stateful mock: track enabled servers so profile reload reflects toggle actions.
    // Initially echo is NOT in the profile; notes IS enabled.
    const enabledServers = new Set<string>(['poc-notes-server'])

    // setupMocks registers base handlers. We register additional handlers AFTER
    // so they take precedence (Playwright LIFO: last registered = first matched).
    await setupMocks(page, 'editor')

    if (MOCK) {
      // Stateful /profiles/me: registered AFTER setupMocks → matched FIRST (LIFO wins).
      // Overrides the static handler from setupMocks for this test only.
      await page.route('/api/v1/profiles/me', async route => {
        if (route.request().method() === 'GET') {
          const profile = {
            principal: 'alice',
            mcps: [
              { server_name: 'poc-echo-server', description: 'Echo server', enabled: enabledServers.has('poc-echo-server'), functions: [] },
              ...MOCK_PROFILE_EDITOR.mcps.filter(m => m.server_name !== 'poc-echo-server'),
            ],
          }
          return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(profile) })
        }
        return route.continue()
      })

      // Track enable/disable mutations. Use specific URL patterns (not **) to avoid
      // accidentally intercepting unrelated requests. These are registered LAST so
      // they are matched FIRST (LIFO), ahead of setupMocks' catch-all.
      await page.route('/api/v1/profiles/me/mcps/*/enable', async route => {
        const url = route.request().url()
        const m = url.match(/\/mcps\/([^/]+)\/enable$/)
        if (m) enabledServers.add(decodeURIComponent(m[1]))
        return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' })
      })
      await page.route('/api/v1/profiles/me/mcps/*/disable', async route => {
        const url = route.request().url()
        const m = url.match(/\/mcps\/([^/]+)\/disable$/)
        if (m) enabledServers.delete(decodeURIComponent(m[1]))
        return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' })
      })
    }

    await navigateToPortal(page, 'editor')

    // Issue #11: use data-testid + data-server attribute for reliable card selection
    const echoCard = page.locator('[data-testid="server-card"][data-server="poc-echo-server"]').first()
    await expect(echoCard).toBeVisible()

    // Issue #9: the toggle now requires a confirmation step.
    const initialPressed = await echoCard.locator('[data-testid="toggle-btn"]').last().getAttribute('aria-pressed')

    // First click — should show confirm bar
    await echoCard.locator('[data-testid="toggle-btn"]').last().click()
    await expect(echoCard.locator('[data-testid="confirm-bar"]')).toBeVisible()

    // Confirm the change (enable echo-server)
    await echoCard.locator('[data-testid="confirm-yes"]').click()
    if (!MOCK) {
      await page.waitForResponse(r => r.url().includes('/api/v1/profiles') && r.status() < 400)
    }
    // Wait for portal to reload and re-render
    await page.waitForTimeout(300)

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
    // Register the error route BEFORE setupMocks so the catch-all in setupMocks is
    // registered later and available-mcps specific route below is registered LAST
    // (LIFO means last registered = first matched, so error route wins).
    // We register error route at the end to ensure it's matched first.
    await setupMocks(page)
    await navigateToPortal(page, 'editor')

    // Override available-mcps with 503 AFTER navigation so the portal loaded successfully first.
    // Since this is registered LAST it is matched FIRST (Playwright LIFO), triggering an error
    // only on the NEXT request (e.g., when we navigate to portal after reload).
    await page.route('/api/v1/profiles/available-mcps', route =>
      route.fulfill({ status: 503, body: 'Service unavailable' })
    )

    // Navigate away and back to the portal to trigger a fresh load with the error route active
    await page.getByRole('button', { name: /security/i }).click()
    await page.getByRole('button', { name: /portal/i }).click()

    // Issue #11: use data-testid for reliable error-state selection
    await expect(page.locator('[data-testid="portal-error"]')).toBeVisible({ timeout: 5000 })
  })
})
