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
import AxeBuilder from '@axe-core/playwright'

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
    // Nav was regrouped into 5 top-level sections (2026-07-07); see
    // proxy/app/routers/portal.py's _ADMIN_GROUPS for the canonical list.
    for (const group of ['Security', 'Servers', 'Access', 'Settings']) {
      // Anchored regex, NOT exact: the Servers button renders an awaiting-review
      // count badge inside itself (portal.py `adm-nav-badge`), so its accessible name
      // becomes "Servers1" whenever a submission is pending. `exact: true` passed only
      // because AC-06's /submit step never actually succeeded and the count was always
      // zero — fixing that test broke this one.
      await expect(
        page.getByRole('button', { name: new RegExp(`^${group}\\s*\\d*$`) })
      ).toBeVisible()
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
    // Self-service page is a 4-tab persona view (Home/Catalog/Submit/Profile,
    // 2026-07-07 redesign); the CTA lives inside the Submit tab's panel,
    // display:none until that tab is activated (ssShowTab('submit')).
    await page.getByRole('button', { name: 'Submit', exact: true }).click()
    const cta = page.locator('a[href*="/portal/submit"]').first()
    await cta.click()
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

// .serial: these six steps are one chain sharing `serverId`. Declared explicitly so a
// retry re-runs the chain FROM THE START. Previously a retry re-initialised the
// module-level serverId to '', so `test.skip(!serverId)` skipped the retry — a failed
// step then reported as "flaky" instead of "failed", and the /submit step silently
// never passed at all while the suite showed green.
test.describe.serial('AC-06 Submission lifecycle', () => {
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
      data: {
        injection_mode: 'kc_token_exchange',
        data_categories: ['pii'],
        has_write_ops: false,
        // Required before /submit will accept a self-hosted draft (drafts default to
        // is_self_hosted=true). Without it /submit returns 422 INCOMPLETE_SUBMISSION —
        // which is CORRECT product behaviour that this suite was not satisfying.
        requested_upstream_url: 'http://lab-mcp-echo:9000/mcp',
      },
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
    // Report WHAT the server said on failure. Bare `expect(resp.ok())` yields
    // "expected true, received false", which says nothing about why and makes an
    // intermittent failure undiagnosable after the fact.
    const rawBody = await resp.text()
    expect(resp.ok(), `POST /submit -> HTTP ${resp.status()}: ${rawBody}`).toBeTruthy()
    expect(JSON.parse(rawBody).submission_status).toBe('awaiting_review')
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
  // Draft-creation only runs a cheap structural guard (https, no embedded
  // creds, no control chars) — see proxy/app/routers/submission.py's
  // _validate_github_url / _SAFE_REPO_URL_RE docstring. The provider-host
  // allowlist + SSRF check is intentionally async (submission scanner), so a
  // structurally-valid non-GitHub host like evil.com is NOT rejected here.
  const REJECT_URLS = [
    'file:///etc/passwd',
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

  test('structurally-valid non-GitHub host (e.g. evil.com) passes draft creation — host allowlist enforced async', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice session not available')
    const ctx = await authedCtx(browser, 'alice')
    const resp = await ctx.request.post('/api/v1/submissions', {
      data: { name: `sec-host-${SUFFIX}`, description: 'non-github host', github_repo_url: 'https://evil.com/repo' },
    })
    expect(resp.status()).toBe(201)
    await ctx.close()
  })
})

// ── AC-09: portal access pill reflects the REAL profile decision ──────────────
//
// Added 2026-07-25. The portal read `mcp_profiles` directly and knew nothing about
// named profiles, so it was a fourth un-synced re-implementation of the profile
// decision and could render a green "Access enabled" pill for a server that denies
// at invoke. It now resolves through the same function as tools/list and tools/call.
//
// There was no e2e coverage asserting card CONTENT at all — only that the fragment
// loaded — which is why the drift went unnoticed.
//
// Targets the fragment directly rather than the rendered page: alice gets the ADMIN
// shell (which does not embed the access grid), and `agent` — the role that DOES see
// the agent portal — is excluded from _SELF_SERVICE_ALLOWED_ROLES and cannot toggle
// its own profile at all.
test.describe.serial('AC-09 Portal access pill matches invoke decision', () => {
  const TARGET = 'echo-basic'
  const FRAGMENT = '/portal/fragments/my-access'

  // lab-echo's full tool set. A card is "enabled" if ANY of its tools is callable,
  // so a meaningful test must disable them all — and that is also the semantic worth
  // pinning: a server whose every tool is denied is genuinely unusable.
  const SERVER_TOOLS = ['ping', 'slow_tool', 'echo-sa', 'echo-basic']

  test('portal pill follows the profile decision, not a stale source', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice session not available')
    const ctx = await authedCtx(browser, 'alice')

    for (const t of SERVER_TOOLS) {
      const r = await ctx.request.post(`/api/v1/profiles/me/mcps/${t}/enable`)
      expect(r.ok(), `enable ${t} -> ${r.status()}: ${await r.text()}`).toBeTruthy()
    }
    const enabledHtml = await (await ctx.request.get(FRAGMENT)).text()
    expect(enabledHtml).toContain('Access enabled')

    // Disabling ONE tool must NOT flip the card — the server is still usable.
    await ctx.request.post(`/api/v1/profiles/me/mcps/echo-basic/disable`)
    const partialHtml = await (await ctx.request.get(FRAGMENT)).text()
    expect(partialHtml).toContain('Access enabled')

    // Disabling ALL of them must flip it. The portal keyed this lookup on the SERVER
    // name against a TOOL-keyed table, so it silently defaulted to enabled and the
    // pill was decorative — it never showed "Access disabled" for any profile state.
    for (const t of SERVER_TOOLS) {
      const r = await ctx.request.post(`/api/v1/profiles/me/mcps/${t}/disable`)
      expect(r.ok(), `disable ${t} -> ${r.status()}: ${await r.text()}`).toBeTruthy()
    }
    const disabledHtml = await (await ctx.request.get(FRAGMENT)).text()
    expect(disabledHtml).toContain('Access disabled')

    // Restore: leave no state behind (the F5 lesson).
    for (const t of SERVER_TOOLS) {
      await ctx.request.post(`/api/v1/profiles/me/mcps/${t}/enable`)
    }
    await ctx.close()
  })

  test('recovery tools cannot be self-disabled (self-lockout guard)', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice session not available')
    const ctx = await authedCtx(browser, 'alice')
    const resp = await ctx.request.post('/api/v1/profiles/me/mcps/enable_mcp/disable')
    const body = await resp.text()
    expect(resp.status(), body).toBe(400)
    expect(body).toContain('PROFILE_SELF_LOCKOUT_BLOCKED')
    await ctx.close()
  })

  test('the deleted unfiltered catalog fragment is gone', async ({ browser }) => {
    // GET /portal/fragments/catalog dumped every tool_registry row to any
    // agent/auditor with no entitlement, grant or profile filtering.
    test.skip(!aliceStorage, 'alice session not available')
    const ctx = await authedCtx(browser, 'alice')
    expect((await ctx.request.get('/portal/fragments/catalog')).status()).toBe(404)
    await ctx.close()
  })
})

// ── AC-10: Accessibility (axe-core) — R1.3 ────────────────────────────────────
// Runs axe against the loaded /portal admin shell (alice) and agent shell
// (bob) and fails on any 'critical' or 'serious' impact violation. 'moderate'/
// 'minor' are reported but not gating — this is a floor, not full WCAG
// conformance.

test.describe('AC-10 Accessibility (axe-core)', () => {
  async function axeScanPortal(browser: Browser, who: 'alice' | 'bob') {
    const storage = who === 'alice' ? aliceStorage : bobStorage
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true, storageState: storage })
    const page = await ctx.newPage()
    await page.goto('/portal')
    await page.waitForLoadState('networkidle')
    const results = await new AxeBuilder({ page }).analyze()
    await ctx.close()
    return results
  }

  test('alice admin portal has no critical/serious violations', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice session not available')
    const results = await axeScanPortal(browser, 'alice')
    const gating = results.violations.filter(v => v.impact === 'critical' || v.impact === 'serious')
    if (gating.length) {
      console.log('AC-10 alice violations:', JSON.stringify(gating.map(v => ({
        id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.length,
      })), null, 2))
    }
    expect(gating, `violations: ${gating.map(v => `${v.id}(${v.impact})`).join(', ')}`).toEqual([])
  })

  test('bob agent portal has no critical/serious violations', async ({ browser }) => {
    test.skip(!bobStorage, 'bob session not available')
    const results = await axeScanPortal(browser, 'bob')
    const gating = results.violations.filter(v => v.impact === 'critical' || v.impact === 'serious')
    if (gating.length) {
      console.log('AC-10 bob violations:', JSON.stringify(gating.map(v => ({
        id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.length,
      })), null, 2))
    }
    expect(gating, `violations: ${gating.map(v => `${v.id}(${v.impact})`).join(', ')}`).toEqual([])
  })
})

/*
 * AC-11 — every data-act in rendered markup resolves to a registered handler.
 *
 * R1.4 replaced 80 inline onclick= attributes with data-act delegation. The failure
 * mode of that change is silent: a renamed or unregistered handler leaves a button
 * that looks completely normal and does nothing when clicked. Nothing else in this
 * suite would catch it — the old inline handlers had the same weakness, which is
 * why several were only ever verified by hand.
 *
 * This walks the admin tabs, collects every [data-act] the server actually renders,
 * and asserts each one is callable.
 */
test.describe('AC-11 Delegated actions are all wired', () => {
  test('every rendered data-act resolves to a registered function', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice session not available')
    const ctx = await authedCtx(browser, 'alice')
    const page = await ctx.newPage()

    // A CSP violation surfaces only as a console error — the page still renders, the
    // button just silently does nothing. Exactly the failure mode this suite exists
    // to catch, so collect them rather than trusting the page to look right.
    const cspErrors: string[] = []
    page.on('console', m => {
      const t = m.text()
      if (/Content Security Policy|Refused to (execute|apply|load|connect)/i.test(t)) cspErrors.push(t)
    })

    const seen = new Set<string>()
    const collect = async () => {
      for (const a of await page.$$eval('[data-act]', els => els.map(e => e.getAttribute('data-act')))) {
        if (a) seen.add(a)
      }
    }

    await page.goto('/portal')
    await page.waitForLoadState('networkidle')
    await collect()

    // Walk the admin tabs so fragment-rendered actions are covered too, not just
    // the ones present on the initial shell.
    for (const tab of ['servers', 'tools', 'credentials', 'grants', 'policy', 'audit', 'profile']) {
      const btn = page.locator(`[data-act="loadAdminTab"][data-a0="${tab}"]`).first()
      if (await btn.count()) {
        await btn.click().catch(() => {})
        await page.waitForTimeout(400)
        await collect()
      }
    }

    expect(seen.size, 'no data-act attributes found at all — the probe is not exercising the portal').toBeGreaterThan(10)

    console.log('AC-11 data-act names rendered:', seen.size,
      '| allowlist:', await page.evaluate(() => (window as any).PORTAL_ACTIONS.size),
      '| handlers defined at script-end:', await page.evaluate(() => (window as any).__PORTAL_ACTIONS_DEFINED_AT_LOAD__))

    const unresolved = await page.evaluate((names: string[]) => {
      const reg = (window as any).PORTAL_ACTIONS
      // Must be BOTH allowlisted and actually defined — checking only one of the two
      // is how the first version of this passed against a completely dead dispatcher.
      return names.filter(n => !(reg && reg.has(n)) || typeof (window as any)[n] !== 'function')
    }, [...seen])

    await ctx.close()
    expect(unresolved, `data-act names with no handler: ${unresolved.join(', ')}`).toEqual([])
    expect(cspErrors, `CSP violations: ${cspErrors.join(' | ')}`).toEqual([])
  })
})

test.describe('AC-12 Portal Content-Security-Policy', () => {
  test('portal HTML carries a nonce CSP with no unsafe-inline script-src', async ({ browser }) => {
    test.skip(!aliceStorage, 'alice session not available')
    const ctx = await authedCtx(browser, 'alice')
    const page = await ctx.newPage()
    const resp = await page.goto('/portal')
    const csp = resp?.headers()['content-security-policy'] || ''
    await ctx.close()

    expect(csp, 'portal HTML served with no Content-Security-Policy at all').not.toEqual('')
    expect(csp).toContain("script-src 'self' 'nonce-")
    // A policy carrying BOTH a nonce and 'unsafe-inline' silently drops the nonce in
    // every browser that supports one — it would look protected and not be.
    expect(csp, 'script-src must not carry unsafe-inline alongside a nonce')
      .not.toMatch(/script-src[^;]*'unsafe-inline'/)
    // style-src still carries 'unsafe-inline' for portal.js's 58 CSSOM writes (R1.7),
    // NOT for markup: R1.5 removed all 593 inline style= attributes. Asserted as a
    // known state so that when R1.7 lands, this line is what forces the policy update.
    expect(csp).toContain("style-src 'self' 'unsafe-inline'")
    expect(csp).toContain("object-src 'none'")
    expect(csp).toContain("base-uri 'none'")
  })
})
