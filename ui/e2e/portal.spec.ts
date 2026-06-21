import { test, expect, Page } from '@playwright/test'

// These tests run against the live lab stack (proxy + postgres + keycloak).
// Start the lab before running: make -f Makefile.lab lab-up
// Then: npx playwright test

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

test.describe('UserPortal — MCP management', () => {
  test('viewer can see the MCP catalog', async ({ page }) => {
    await loginAs(page, 'viewer')
    await page.getByRole('link', { name: /portal|catalog/i }).click()
    await expect(page.locator('.portal__title')).toContainText('MCP Catalog')
    await expect(page.locator('.server-card')).toHaveCount({ min: 1 })
  })

  test('editor can enable and disable an MCP', async ({ page }) => {
    await loginAs(page, 'editor')
    await page.getByRole('link', { name: /portal|catalog/i }).click()

    // Find the echo server card and get its toggle state
    const echoCard = page.locator('.server-card', { hasText: 'poc-echo-server' }).first()
    await expect(echoCard).toBeVisible()

    const toggle = echoCard.locator('button[aria-label]').last()
    const initialLabel = await toggle.getAttribute('aria-label')

    // Toggle it
    await toggle.click()
    await page.waitForResponse(r => r.url().includes('/api/v1/profiles') && r.status() < 400)

    // State must have changed
    const newLabel = await toggle.getAttribute('aria-label')
    expect(newLabel).not.toBe(initialLabel)

    // Toggle back
    await toggle.click()
    await page.waitForResponse(r => r.url().includes('/api/v1/profiles') && r.status() < 400)
  })

  test('editor can expand server and toggle individual tools', async ({ page }) => {
    await loginAs(page, 'editor')
    await page.getByRole('link', { name: /portal|catalog/i }).click()

    const notesCard = page.locator('.server-card', { hasText: 'poc-notes-server' }).first()
    const expandBtn = notesCard.locator('.server-card__expand')
    if (await expandBtn.isVisible()) {
      await expandBtn.click()
      await expect(notesCard.locator('.fn-row')).toHaveCount({ min: 1 })
      // Toggle a function
      const firstFnToggle = notesCard.locator('.fn-row button[aria-label]').first()
      await firstFnToggle.click()
      await page.waitForResponse(r => r.url().includes('functions') && r.status() < 400)
    }
  })

  test('error state shown when API fails', async ({ page }) => {
    await loginAs(page, 'editor')
    // Mock API failure
    await page.route('/api/v1/profiles/available-mcps', route =>
      route.fulfill({ status: 503, body: 'Service unavailable' })
    )
    await page.getByRole('link', { name: /portal|catalog/i }).click()
    await expect(page.locator('.portal__error')).toBeVisible({ timeout: 5000 })
  })
})
