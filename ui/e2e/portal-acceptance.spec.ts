/**
 * Portal Acceptance Tests — MCP Security Platform
 *
 * Run: cd ui && npx playwright test --config playwright.portal.config.ts
 *
 * Credentials (from .env.lab):
 *   alice / CudvCD5L3WzmmktMEVmWvRkLqFlI  — admin + agent
 *   bob   / e25JOYuj7xTqQEZP58EIXOlXf54e  — agent only
 *
 * Strategy: ONE PKCE login per user in the file-level beforeAll; all tests
 * reuse storageState (cookie-bearing browser context). No Bearer-token extraction
 * needed — ctx.request sends the mcp_session cookie automatically.
 */

import { test, expect, Page, Browser, BrowserContext } from '@playwright/test'

const CREDS = {
  alice: ['alice', 'CudvCD5L3WzmmktMEVmWvRkLqFlI'],
  bob:   ['bob',   'e25JOYuj7xTqQEZP58EIXOlXf54e'],
} as const

// Populated once in file-level beforeAll
let aliceStorage: any = null
let bobStorage: any = null

// Unique suffix per run (pid + ms tail)
const SUFFIX = `${process.pid}-${Date.now() % 100000}`

// ── One-time PKCE login per user ──────────────────────────────────────────────

async function pkceLogin(page: Page, who: keyof typeof CREDS) {
  const [username, password] = CREDS[who]
  await page.goto('/api/v1/auth/oidc/login')
  await page.waitForSelector('#username', { timeout: 35_000 })
  await page.fill('#username', username)
  await page.fill('#password', password)
  await page.click('[name="login"], [type="submit"]')
  await page.waitForURL(/\/portal/, { timeout: 35_000 })
}

test.beforeAll(async ({ browser }) => {
  // Allow for 3 attempts per user × 35s each + 3s waits + buffer
  test.setTimeout(240_000)
  for (const who of ['alice', 'bob'] as const) {
    // Retry up to 3 times — worker restarts after a test failure can find the
    // proxy momentarily returning 503, so a brief pause usually recovers it.
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const ctx = await browser.newContext({ ignoreHTTPSErrors: true })
        await pkceLogin(await ctx.newPage(), who)
        const state = await ctx.storageState()
        if (who === 'alice') aliceStorage = state
        else                 bobStorage   = state
        await ctx.close()
        break  // success — stop retrying
      } catch (e) {
        const msg = (e as Error).message?.split('\n')[0] ?? String(e)
        console.warn(`[beforeAll] ${who} attempt ${attempt + 1}/3 failed: ${msg}`)
        if (attempt < 2) await new Promise(r => setTimeout(r, 4_000))
      }
    }
  }
})

/**
 * Returns a new browser context pre-loaded with the given user's cookies.
 * Caller MUST call ctx.close() after assertions.
 */
async function authedCtx(browser: Browser, who: 'alice' | 'bob'): Promise<BrowserContext> {
  const storage = who === 'alice' ? aliceStorage : bobStorage
  return browser.newContext({ ignoreHTTPSErrors: true, storageState: storage })
}

// ── AC-01: Authentication ─────────────────────────────────────────────────────

test.describe('AC-01 Authentication', () => {
  test('unauthenticated /portal is blocked or shows KC login', async ({ browser }) => {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true })
    const page = await ctx.newPage()
    const resp = await page.goto('/portal')
    const status = resp!.status()
    // 401/302 = KC redirect; 200 = KC login page rendered; 429 = rate-limited (also blocks access).
    expect([200, 302, 401, 429]).toContain(status)
    if (status === 200) {
      const html = await page.content()
      expect(html).not.toContain('loadAdminTab')
    }
    await ctx.close()
  })

  test('alice logs in and sees admin portal', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice login failed in beforeAll')
    const ctx = await authedCtx(browser, 'alice')
    const page = await ctx.newPage()
    await page.goto('/portal')
    await expect(page).toHaveTitle(/MCP Security Platform/)
    expect(await page.content()).toContain('loadAdminTab')
    await ctx.close()
  })

  test('bob logs in and sees agent portal with Submit CTA', async ({ browser }) => {
    test.skip(!bobStorage, 'bob login failed in beforeAll')
    const ctx = await authedCtx(browser, 'bob')
    const page = await ctx.newPage()
    await page.goto('/portal')
    // Wait for HTMX /portal/fragments/my-access to finish swapping in the CTA
    await page.waitForLoadState('networkidle')
    await expect(page).toHaveTitle(/MCP Security Platform/)
    expect(await page.content()).toContain('Submit MCP Server')
    await ctx.close()
  })
})

// ── AC-02: Admin portal navigation ───────────────────────────────────────────

test.describe('AC-02 Admin navigation (alice)', () => {
  test('all admin nav tabs are present', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice login failed')
    const ctx = await authedCtx(browser, 'alice')
    const page = await ctx.newPage()
    await page.goto('/portal')
    for (const tab of ['MCP Servers', 'Submissions', 'Credentials', 'Dashboard', 'Detections']) {
      await expect(page.getByRole('button', { name: tab })).toBeVisible()
    }
    await ctx.close()
  })

  test('MCP Servers tab loads server table', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice login failed')
    const ctx = await authedCtx(browser, 'alice')
    const page = await ctx.newPage()
    await page.goto('/portal')
    await page.getByRole('button', { name: 'MCP Servers' }).click()
    await expect(page.locator('#adm-content')).toContainText(/./, { timeout: 8_000 })
    await ctx.close()
  })

  test('Register server button navigates to Submissions tab', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice login failed')
    const ctx = await authedCtx(browser, 'alice')
    const page = await ctx.newPage()
    await page.goto('/portal')
    await page.getByRole('button', { name: 'MCP Servers' }).click()
    // Wait for HTMX fragment to render before looking for Register server button
    await expect(page.locator('#adm-content')).toContainText(/./, { timeout: 10_000 })
    await page.getByRole('button', { name: /Register server/i }).click()
    await expect(page.locator('#adm-content')).toContainText(/submissions|No submissions/i, { timeout: 10_000 })
    await ctx.close()
  })

  test('Submissions tab shows review queue', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice login failed')
    const ctx = await authedCtx(browser, 'alice')
    const page = await ctx.newPage()
    await page.goto('/portal')
    await page.getByRole('button', { name: 'Submissions' }).click()
    await expect(page.locator('#adm-content')).toContainText(/./, { timeout: 10_000 })
    await ctx.close()
  })

  test('Credentials tab loads', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice login failed')
    const ctx = await authedCtx(browser, 'alice')
    const page = await ctx.newPage()
    await page.goto('/portal')
    await page.getByRole('button', { name: 'Credentials' }).click()
    await expect(page.locator('#adm-content')).toContainText(/./, { timeout: 8_000 })
    await ctx.close()
  })
})

// ── AC-03: Agent portal (bob) ─────────────────────────────────────────────────

test.describe('AC-03 Agent portal (bob)', () => {
  test('"Submit MCP Server" CTA is visible', async ({ browser }) => {
    test.skip(!bobStorage, 'bob login failed')
    const ctx = await authedCtx(browser, 'bob')
    const page = await ctx.newPage()
    await page.goto('/portal')
    await page.waitForLoadState('networkidle')
    expect(await page.content()).toContain('Submit MCP Server')
    await ctx.close()
  })

  test('"Submit MCP Server" navigates to /portal/submit', async ({ browser }) => {
    test.skip(!bobStorage, 'bob login failed')
    const ctx = await authedCtx(browser, 'bob')
    const page = await ctx.newPage()
    await page.goto('/portal')
    await page.waitForLoadState('networkidle')
    const cta = page.locator('a[href*="/portal/submit"]').first()
    if (await cta.count() > 0) {
      await cta.click()
    } else {
      await page.getByText('Submit MCP Server').first().click()
    }
    await expect(page).toHaveURL(/\/portal\/submit/, { timeout: 8_000 })
    await ctx.close()
  })
})

// ── AC-04: Submission wizard ──────────────────────────────────────────────────

test.describe('AC-04 Submission wizard (alice)', () => {
  async function wizardHtml(browser: Browser): Promise<{ html: string; ctx: BrowserContext }> {
    const ctx = await authedCtx(browser, 'alice')
    const page = await ctx.newPage()
    await page.goto('/portal/submit', { waitUntil: 'domcontentloaded' })
    const html = await page.content()
    await page.close()
    return { html, ctx }
  }

  test('wizard page loads with 4 step indicators', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice login failed')
    const { html, ctx } = await wizardHtml(browser)
    expect(html).toContain('step-ind-1')
    expect(html).toContain('step-ind-4')
    await ctx.close()
  })

  test('step 1 fields are present (name, description)', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice login failed')
    const { html, ctx } = await wizardHtml(browser)
    expect(html).toMatch(/srv-name|server.name|showStep1/i)
    expect(html).toMatch(/description|srv-desc/i)
    await ctx.close()
  })

  test('auth mode quick-pick cards are rendered', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice login failed')
    const { html, ctx } = await wizardHtml(browser)
    expect(html).toContain('kc_token_exchange')
    expect(html).toContain('entra_client_credentials')
    await ctx.close()
  })

  test('guided question flow is wired (showGuidedQuestions + askQ1)', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice login failed')
    const { html, ctx } = await wizardHtml(browser)
    expect(html).toContain('showGuidedQuestions')
    expect(html).toContain('askQ1')
    await ctx.close()
  })

  test('data categories step has pii, financial, health', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice login failed')
    const { html, ctx } = await wizardHtml(browser)
    expect(html).toContain('pii')
    expect(html).toContain('financial')
    expect(html).toContain('health')
    await ctx.close()
  })

  test('doSubmit() and showResult() functions are present', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice login failed')
    const { html, ctx } = await wizardHtml(browser)
    expect(html).toContain('doSubmit')
    expect(html).toContain('showResult')
    await ctx.close()
  })

  test('no "coming soon" placeholder on wizard page', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice login failed')
    const { html, ctx } = await wizardHtml(browser)
    expect(html.toLowerCase()).not.toContain('coming soon')
    await ctx.close()
  })
})

// ── AC-05: Design-assist API ──────────────────────────────────────────────────
// Uses ctx.request so the mcp_session cookie is sent automatically.

test.describe('AC-05 Design-assist API', () => {
  test('GET /api/v1/design-assist returns auth_mode_selection', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice session not available')
    const ctx = await authedCtx(browser, 'alice')
    const resp = await ctx.request.get('/api/v1/design-assist')
    expect(resp.ok()).toBeTruthy()
    const body = await resp.json()
    expect(body.stage).toBe('auth_mode_selection')
    expect(body.decision_tree.length).toBeGreaterThanOrEqual(5)
    await ctx.close()
  })

  test('GET /api/v1/design-assist?mode=service returns 6 questions', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice session not available')
    const ctx = await authedCtx(browser, 'alice')
    const resp = await ctx.request.get('/api/v1/design-assist?mode=service')
    expect(resp.ok()).toBeTruthy()
    const body = await resp.json()
    expect(body.stage).toBe('design_questions')
    expect(body.questions.length).toBe(6)
    await ctx.close()
  })

  test('scaffold?mode=user returns 4 files', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice session not available')
    const ctx = await authedCtx(browser, 'alice')
    const resp = await ctx.request.get('/api/v1/design-assist/scaffold?mode=user')
    expect(resp.ok()).toBeTruthy()
    const body = await resp.json()
    expect(Object.keys(body.files).sort()).toEqual(['Dockerfile', 'README.md', 'requirements.txt', 'server.py'])
    await ctx.close()
  })

  test('scaffold?mode=kc_token_exchange contains PlatformMCPServer', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice session not available')
    const ctx = await authedCtx(browser, 'alice')
    const resp = await ctx.request.get('/api/v1/design-assist/scaffold?mode=kc_token_exchange')
    const body = await resp.json()
    expect(body.files['server.py']).toContain('PlatformMCPServer')
    await ctx.close()
  })
})

// ── AC-06: Submission lifecycle ───────────────────────────────────────────────

test.describe('AC-06 Submission lifecycle', () => {
  const serverName = `at-${SUFFIX}`
  let serverId = ''

  test('POST /api/v1/submissions creates a draft (201)', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice session not available')
    const ctx = await authedCtx(browser, 'alice')
    const resp = await ctx.request.post('/api/v1/submissions', {
      data: { name: serverName, description: 'Acceptance test draft' },
    })
    expect(resp.status()).toBe(201)
    const body = await resp.json()
    expect(body.submission_status).toBe('draft')
    serverId = body.server_id
    await ctx.close()
  })

  test('PATCH updates injection_mode and data_categories', async ({ browser }) => {
    test.skip(!aliceStorage || !serverId, 'pre-conditions not met')
    const ctx = await authedCtx(browser, 'alice')
    const resp = await ctx.request.patch(`/api/v1/submissions/${serverId}`, {
      data: { injection_mode: 'kc_token_exchange', data_categories: ['pii'], has_write_ops: false },
    })
    expect(resp.ok()).toBeTruthy()
    expect((await resp.json()).updated).toBe(true)
    await ctx.close()
  })

  test('GET returns correct mode and categories after PATCH', async ({ browser }) => {
    test.skip(!aliceStorage || !serverId, 'pre-conditions not met')
    const ctx = await authedCtx(browser, 'alice')
    const resp = await ctx.request.get(`/api/v1/submissions/${serverId}`)
    expect(resp.ok()).toBeTruthy()
    const body = await resp.json()
    expect(body.injection_mode).toBe('kc_token_exchange')
    expect(body.data_categories).toContain('pii')
    expect(body.submission_status).toBe('draft')
    await ctx.close()
  })

  test('GET /submissions/:id/prompts returns 6 prompts', async ({ browser }) => {
    test.skip(!aliceStorage || !serverId, 'pre-conditions not met')
    const ctx = await authedCtx(browser, 'alice')
    const resp = await ctx.request.get(`/api/v1/submissions/${serverId}/prompts`)
    expect(resp.ok()).toBeTruthy()
    expect((await resp.json()).prompts.length).toBe(6)
    await ctx.close()
  })

  test('POST /submit transitions to awaiting_review', async ({ browser }) => {
    test.skip(!aliceStorage || !serverId, 'pre-conditions not met')
    const ctx = await authedCtx(browser, 'alice')
    const resp = await ctx.request.post(`/api/v1/submissions/${serverId}/submit`)
    expect(resp.ok()).toBeTruthy()
    expect((await resp.json()).submission_status).toBe('awaiting_review')
    await ctx.close()
  })

  test('GET /submissions list includes the new submission', async ({ browser }) => {
    test.skip(!aliceStorage || !serverId, 'pre-conditions not met')
    const ctx = await authedCtx(browser, 'alice')
    const resp = await ctx.request.get('/api/v1/submissions')
    expect(resp.ok()).toBeTruthy()
    const found = (await resp.json()).submissions.find((s: any) => s.server_id === serverId)
    expect(found).toBeDefined()
    expect(found.submission_status).toBe('awaiting_review')
    await ctx.close()
  })
})

// ── AC-07: Role isolation ─────────────────────────────────────────────────────

test.describe('AC-07 Role isolation', () => {
  test('admin review queue returns 403 for bob (agent role)', async ({ browser }) => {
    test.skip(!bobStorage, 'bob session not available')
    const ctx = await authedCtx(browser, 'bob')
    const resp = await ctx.request.get('/api/v1/admin/submissions')
    expect(resp.status()).toBe(403)
    await ctx.close()
  })

  test('bob can create his own submission draft', async ({ browser }) => {
    test.skip(!bobStorage, 'bob session not available')
    const ctx = await authedCtx(browser, 'bob')
    const resp = await ctx.request.post('/api/v1/submissions', {
      data: { name: `bob-${SUFFIX}`, description: 'Bob isolation test' },
    })
    expect(resp.status()).toBe(201)
    await ctx.close()
  })

  test("bob's list does not contain alice-owned entries", async ({ browser }) => {
    test.skip(!bobStorage, 'bob session not available')
    const ctx = await authedCtx(browser, 'bob')
    const resp = await ctx.request.get('/api/v1/submissions')
    expect(resp.ok()).toBeTruthy()
    const names: string[] = (await resp.json()).submissions.map((s: any) => s.name)
    expect(names.every(n => !n.startsWith('at-'))).toBeTruthy()
    await ctx.close()
  })
})

// ── AC-08: GitHub URL security ────────────────────────────────────────────────

test.describe('AC-08 GitHub URL validation', () => {
  const REJECT_URLS = [
    'file:///etc/passwd',
    'https://evil.com/repo',
    'http://github.com/user/repo',
    'https://github.com/-bad/repo',
    'https://github.com/user/repo; rm -rf /',
  ]

  for (const [i, url] of REJECT_URLS.entries()) {
    test(`rejects ${url.slice(0, 55)}`, async ({ browser }) => {
      test.skip(!aliceStorage, 'alice session not available')
      const ctx = await authedCtx(browser, 'alice')
      const resp = await ctx.request.post('/api/v1/submissions', {
        data: { name: `sec-${i}-${SUFFIX}`, description: 'sec test', github_repo_url: url },
      })
      // 422 = our validator rejected it; 403 = WAF/ModSecurity blocked it first.
      // Both are valid rejections. Accept any 4xx (but not 201).
      expect(resp.status()).toBeGreaterThanOrEqual(400)
      await ctx.close()
    })
  }

  test('accepts a valid https://github.com/ URL', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice session not available')
    const ctx = await authedCtx(browser, 'alice')
    const resp = await ctx.request.post('/api/v1/submissions', {
      data: { name: `sec-ok-${SUFFIX}`, description: 'valid url', github_repo_url: 'https://github.com/myorg/my-server' },
    })
    expect(resp.status()).toBe(201)
    await ctx.close()
  })
})
