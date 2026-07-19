// ─── API Service Layer ────────────────────────────────────────────────────────
// All communication with the MCP Security Platform proxy goes through here.

// Base URL is the proxy; the UI is served from the same origin in production.
// In dev (vite proxy), requests to /api/* are forwarded to the proxy.
const BASE = import.meta.env.VITE_API_BASE ?? ''

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
    this.name = 'ApiError'
  }
}

// ─── Single unified fetch primitive ──────────────────────────────────────────
// All API helpers (legacy request() and new profiles api) share this
// implementation so credentials, error handling, and headers stay consistent.
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...init?.headers,
    },
  })
  if (!res.ok) {
    const body = await res.text().catch(() => res.statusText)
    throw new ApiError(res.status, body)
  }
  if (res.status === 204) return undefined as T
  const ct = res.headers.get('content-type') ?? ''
  return ct.includes('json') ? res.json() : (res.text() as unknown as T)
}

// ── Health ────────────────────────────────────────────────────────────────────
export const health = {
  get: () => request<{ status: string; services: Record<string, string> }>('/health'),
}

// ── Auth session (Keycloak browser login flow — proxy/app/routers/oidc_browser.py) ─
// NOTE: the session/logout routes live under /api/v1/auth/oidc/*, not /api/v1/auth/me
// (that path doesn't exist server-side — proxy/app/routers/auth.py is a stub with no
// routes; oidc_browser.py is where the real implementation lives).
export interface SessionInfo {
  subject: string
  client_id: string
  roles: string[]
  auth_method: string
  expires_at: number
}

export const auth = {
  session: () => request<SessionInfo>('/api/v1/auth/oidc/session'),
  logout: () => request<{ message: string }>('/api/v1/auth/oidc/logout', { method: 'POST' }),
  loginUrl: (redirectAfter: string = '/') =>
    `/api/v1/auth/oidc/login?redirect=${encodeURIComponent(redirectAfter)}`,
}

// ── Audit events ──────────────────────────────────────────────────────────────
export const audit = {
  list: (params?: { limit?: number; outcome?: string; client_id?: string }) => {
    const q = new URLSearchParams(params as Record<string, string>).toString()
    return request<{ events: import('@/types').AuditEvent[]; total: number }>(
      `/api/v1/audit${q ? `?${q}` : ''}`
    )
  },
}

// ── Servers ───────────────────────────────────────────────────────────────────
export const servers = {
  list: () => request<{ servers: import('@/types').MCPServer[] }>('/api/v1/admin/servers')
    .then(r => r.servers),
  // D3 dual-control: approval requires a single-use consent token minted by
  // requestConsent() below — POST /api/v1/admin/servers/{id}/approve 422s on
  // an empty body (H-04, 2026-07-11 audit).
  requestConsent: (id: string) =>
    request<{ consent_token: string; jti: string; expires_in_seconds: number }>(
      `/api/v1/servers/${id}/consent`, { method: 'POST', body: JSON.stringify({ action: 'approve' }) }
    ),
  approve: (id: string, consentToken: string) =>
    request(`/api/v1/admin/servers/${id}/approve`, {
      method: 'POST',
      body: JSON.stringify({ consent_token: consentToken }),
    }),
  suspend: (id: string) => request(`/api/v1/admin/servers/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ status: 'suspended' }),
  }),
  // WS-A (docs/spec/11-server-lifecycle-and-hardening-batch.md): edit the
  // fields the backend already allowlists in _PATCH_ALLOWED
  // (server_registry.py) — name/upstream_url/service_name/trust_tier.
  update: (id: string, body: { name?: string; upstream_url?: string; service_name?: string; trust_tier?: number }) =>
    request<{ server_id: string; updated: string[] }>(`/api/v1/admin/servers/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),
  // Lifecycle ops — forwarded by proxy routers/admin_ops.py to the isolated
  // ops-agent (no container runtime socket in the proxy itself). Gated on
  // debug_mode=true server-side; the UI-side gate below is UX only.
  restart: (id: string) =>
    request<{ status?: string } | undefined>(`/api/v1/admin/servers/${id}/restart`, { method: 'POST' }),
  rebuild: (id: string) =>
    request<{ status?: string } | undefined>(`/api/v1/admin/servers/${id}/rebuild`, { method: 'POST' }),
  logs: (id: string, tail = 200) =>
    request<{ logs: string }>(`/api/v1/admin/servers/${id}/logs?tail=${tail}`),
}

// ── OIDC configuration ────────────────────────────────────────────────────────
export const oidc = {
  get:  () => request<import('@/types').OIDCConfig>('/api/v1/auth/oidc/config'),
  save: (cfg: import('@/types').OIDCConfig) =>
    request('/api/v1/auth/oidc/config', { method: 'PUT', body: JSON.stringify(cfg) }),
  test: () => request<{ ok: boolean; detail: string }>('/api/v1/auth/oidc/test'),
}

// ── Request limits ────────────────────────────────────────────────────────────
export const limits = {
  list: () => request<{ limits: import('@/types').LimitRow[]; count: number }>('/api/v1/admin/limits'),
  get: (id: string) => request<import('@/types').LimitRow>(`/api/v1/admin/limits/${encodeURIComponent(id)}`),
  put: (id: string, body: { rate_limit: number | null; anomaly_sensitivity: 'normal' | 'lenient' | 'off' }) =>
    request(`/api/v1/admin/limits/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(body) }),
  reset: (id: string, target: 'rate' | 'anomaly' | 'both') =>
    request(`/api/v1/admin/limits/${encodeURIComponent(id)}/reset`, { method: 'POST', body: JSON.stringify({ target }) }),
}

// ── Policy ────────────────────────────────────────────────────────────────────
export const policy = {
  eval: (input: Record<string, unknown>) =>
    request<{ allow: boolean; deny: string[] }>('/api/v1/policy/eval', {
      method: 'POST',
      body: JSON.stringify(input),
    }),
}

export { ApiError }

// ─── Profiles API ─────────────────────────────────────────────────────────────
// Live MCP/tool management for non-technical stakeholders.

export interface McpFunction {
  name: string
  description: string
  enabled: boolean
}

export interface McpEntry {
  server_name: string
  description: string
  enabled: boolean
  functions: McpFunction[]
}

export interface Profile {
  principal: string
  mcps: McpEntry[]
}

const VALID_MCP_STATUSES = ['active', 'quarantined', 'pending'] as const
export type McpStatus = typeof VALID_MCP_STATUSES[number]

export interface AvailableMcp {
  server_name: string
  /** Human-readable display name — falls back to server_name if absent */
  display_name?: string
  description: string
  // status is validated against the allowlist before use in class names
  status: McpStatus | string
  enabled_for_account: boolean
}

// Validate status against allowlist before interpolating into CSS class names
export function safeMcpStatus(status: string): McpStatus {
  return (VALID_MCP_STATUSES as readonly string[]).includes(status)
    ? (status as McpStatus)
    : 'pending'
}

// NOTE (SECURITY / issue #9 + #13): getProfile now calls the /me alias so the
// backend derives the principal from the session cookie — the caller-supplied
// string is no longer interpolated into the URL and is accepted but ignored.
// This eliminates the IDOR on the profile read path and removes the
// prototype-pollution / XSS lateral-movement vector that existed when
// principal was caller-controlled.
export const api = {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  getProfile: (_principal: string) =>
    request<Profile>('/api/v1/profiles/me'),

  listAvailableMcps: () =>
    request<AvailableMcp[]>('/api/v1/profiles/available-mcps'),

  // Mutations: no principal parameter — backend infers identity from session cookie.
  enableMcp: (serverName: string) =>
    request<void>(`/api/v1/profiles/me/mcps/${encodeURIComponent(serverName)}/enable`, { method: 'POST' }),

  disableMcp: (serverName: string) =>
    request<void>(`/api/v1/profiles/me/mcps/${encodeURIComponent(serverName)}/disable`, { method: 'POST' }),

  enableFunction: (serverName: string, fnName: string) =>
    request<void>(`/api/v1/profiles/me/mcps/${encodeURIComponent(serverName)}/functions/${encodeURIComponent(fnName)}/enable`, { method: 'POST' }),

  disableFunction: (serverName: string, fnName: string) =>
    request<void>(`/api/v1/profiles/me/mcps/${encodeURIComponent(serverName)}/functions/${encodeURIComponent(fnName)}/disable`, { method: 'POST' }),
}

// ── MCP Server Submissions ────────────────────────────────────────────────────
// Field names match the actual API (submission.py + V044 DB schema).

export interface Submission {
  server_id: string
  name: string
  github_repo_url: string | null
  description: string | null
  injection_mode: string | null
  data_categories: string[] | null
  has_write_ops: boolean | null
  submission_status: string
  scan_status: string | null
  scan_report: Array<Record<string, unknown>> | null
  review_notes: string | null
  owner_sub?: string
  reviewed_by?: string | null
  reviewed_at?: string | null
  created_at: string
  updated_at: string | null
  upstream_url?: string | null
  requested_upstream_url?: string | null
  service_name?: string | null
  upstream_idp_type?: string | null
  upstream_idp_config?: Record<string, unknown> | null
}

export interface DesignPrompt { id: string; prompt: string }
export interface DesignPromptsResponse {
  server_id: string
  injection_mode: string
  prompts: DesignPrompt[]
}

export const submissions = {
  create: (body: { name: string; github_repo_url?: string; description?: string; self_host?: boolean }) =>
    request<{ server_id: string; submission_status: string }>(
      '/api/v1/submissions', { method: 'POST', body: JSON.stringify(body) }
    ),

  update: (id: string, body: {
    github_repo_url?: string; description?: string
    injection_mode?: string; data_categories?: string[]; has_write_ops?: boolean
    requested_upstream_url?: string
  }) =>
    request<{ server_id: string; updated: boolean }>(
      `/api/v1/submissions/${id}`, { method: 'PATCH', body: JSON.stringify(body) }
    ),

  submit: (id: string) =>
    request<{ server_id: string; submission_status: string }>(
      `/api/v1/submissions/${id}/submit`, { method: 'POST' }
    ),

  list: () =>
    request<{ submissions: Submission[] }>('/api/v1/submissions'),

  get: (id: string) =>
    request<Submission>(`/api/v1/submissions/${id}`),

  prompts: (id: string) =>
    request<DesignPromptsResponse>(`/api/v1/submissions/${id}/prompts`),
}

export const adminSubmissions = {
  list: () =>
    request<{ submissions: Submission[] }>('/api/v1/admin/submissions'),

  approve: (id: string, notes?: string) =>
    request<{ server_id: string; submission_status: string }>(
      `/api/v1/admin/submissions/${id}/approve`, { method: 'POST', body: JSON.stringify({ notes }) }
    ),

  reject: (id: string, notes?: string) =>
    request<{ server_id: string; submission_status: string }>(
      `/api/v1/admin/submissions/${id}/reject`, { method: 'POST', body: JSON.stringify({ notes }) }
    ),

  requestChanges: (id: string, notes?: string) =>
    request<{ server_id: string; submission_status: string }>(
      `/api/v1/admin/submissions/${id}/request-changes`, { method: 'POST', body: JSON.stringify({ notes }) }
    ),
}

// ── Credential store (proxy/app/routers/admin_credentials.py) ────────────────────
// NOTE: these routes intentionally live at /admin/credentials/*, not /api/v1/*
// (admin_credentials.router carries no prefix override in main.py) — this is the
// same backend that originally served the htmx admin page at GET /admin/credentials;
// this JSON API (GET .../api, PUT/DELETE .../{tool_id}) is the same surface that
// page already used, just consumed from the React UI instead.
//
// Static secrets uploaded here (api_key, basic_auth, entra_client_secret,
// service_account_jwt, oauth2_refresh) are AES-256-GCM encrypted at rest
// (credential_broker/approaches/approach_a.py) and injected by the proxy at
// invocation time. Keycloak-brokered modes (service_account, kc_token_exchange /
// oauth_user_token, entra_user_token) mint tokens live at call time via
// credential_broker/keycloak_client.py — they don't consume an uploaded secret
// through this form. See services/auth_modes.py (backend) for the canonical mode
// catalog INJECTION_MODE_LABELS below is kept in sync with.

export interface CredentialTool {
  tool_id: string
  name: string
  version: string
  status: string
  injection_mode: string
  service_name: string | null
  inject_header: string | null
  inject_prefix: string | null
  kc_client_id: string | null
  kc_token_audience: string | null
  entra_tenant_id: string | null
  entra_client_id: string | null
  entra_scope: string | null
  has_service_credential: boolean
}

export interface CredentialUploadBody {
  secret: string
  credential_type: string
  owner_type: 'service' | 'user'
  user_sub?: string
  username?: string
  description?: string
}

export const CREDENTIAL_TYPES = [
  { value: 'api_key', label: 'API key' },
  { value: 'oauth2_refresh', label: 'OAuth2 refresh token' },
  { value: 'entra_client_secret', label: 'Microsoft Entra client secret' },
  { value: 'service_account_jwt', label: 'Service-account JWT' },
  { value: 'basic_auth', label: 'Basic auth (username + password)' },
] as const

export const credentials = {
  list: () => request<{ tools: CredentialTool[]; count: number }>('/admin/credentials/api'),

  upload: (toolId: string, body: CredentialUploadBody) =>
    request<{ message: string; tool_id: string; service: string; owner_type: string }>(
      `/admin/credentials/${encodeURIComponent(toolId)}`,
      { method: 'PUT', body: JSON.stringify(body) }
    ),

  revoke: (toolId: string, ownerType: 'service' | 'user', userSub?: string) => {
    const q = new URLSearchParams({
      owner_type: ownerType,
      ...(userSub ? { user_sub: userSub } : {}),
    }).toString()
    return request<{ message: string; tool_id: string }>(
      `/admin/credentials/${encodeURIComponent(toolId)}?${q}`,
      { method: 'DELETE' }
    )
  },
}
