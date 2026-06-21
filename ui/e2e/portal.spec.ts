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
  { server_name: 'poc-echo-server', description: 'Echo server for testing', status: 'active', enabled_for_account: false },
  { server_name: 'poc-notes-server', description: 'Notes server', status: 'active', enabled_for_account: true },
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
  await page.route('/api/v1/profiles/**', async route => {
    const req = route.request()
    const url = req.url()
    if (req.method() === 'GET') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(MOCK_PROFILE) })
    }
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
    await expect(page.locator('.portal__title')).toContainText(/catalog/i)
    // Fix issue #1: toHaveCount() takes a number, not an object.
    // Use count() + toBeGreaterThan or first().toBeVisible() instead.
    await expect(page.locator('.server-card').first()).toBeVisible()
  })

  test('editor can enable and disable an MCP', async ({ page }) => {
    await setupMocks(page)
    await navigateToPortal(page, 'editor')
    if (!MOCK) await page.getByRole('link', { name: /portal|catalog/i }).click()

    // Find the echo server card and get its toggle state
    const echoCard = page.locator('.server-card', { hasText: 'poc-echo-server' }).first()
    await expect(echoCard).toBeVisible()

    const toggle = echoCard.locator('button[aria-label]').last()
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

    const notesCard = page.locator('.server-card', { hasText: 'poc-notes-server' }).first()
    const expandBtn = notesCard.locator('.server-card__expand')
    if (await expandBtn.isVisible()) {
      await expandBtn.click()
      // Fix issue #1: toHaveCount() takes a number, not an object.
      // Use first().toBeVisible() or count() + toBeGreaterThan() instead.
      await expect(notesCard.locator('.fn-row').first()).toBeVisible()
      // Toggle a function
      const firstFnToggle = notesCard.locator('.fn-row button[aria-label]').first()
      await firstFnToggle.click()
      if (!MOCK) {
        await page.waitForResponse(r => r.url().includes('functions') && r.status() < 400)
      }
    }
  })

  test('error state shown when API fails', async ({ page }) => {
    await navigateToPortal(page, 'editor')
    // Mock API failure (works in both mock and live modes)
    await page.route('/api/v1/profiles/available-mcps', route =>
      route.fulfill({ status: 503, body: 'Service unavailable' })
    )
    if (!MOCK) await page.getByRole('link', { name: /portal|catalog/i }).click()
    await expect(page.locator('.portal__error')).toBeVisible({ timeout: 5000 })
  })
})
