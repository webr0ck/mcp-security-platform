// ─── API Service Layer ────────────────────────────────────────────────────────
// All communication with the MCP Security Platform proxy goes through here.

// Base URL is the proxy; the UI is served from the same origin in production.
// In dev (vite proxy), requests to /api/* are forwarded to the proxy.
const BASE = import.meta.env.VITE_API_BASE ?? ''

// Legacy base URL alias (used by older code paths)
const BASE_URL = BASE

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
  const res = await fetch(`${BASE_URL}${path}`, {
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
  list: () => request<import('@/types').MCPServer[]>('/api/v1/admin/servers'),
  approve: (id: string) => request(`/api/v1/admin/servers/${id}/approve`, { method: 'POST' }),
  suspend: (id: string) => request(`/api/v1/admin/servers/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ status: 'suspended' }),
  }),
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

// NOTE (SECURITY): Principal is intentionally removed from mutation URL paths
// (issue #18). The backend must derive the principal from the session
// server-side. The client-supplied username is used only for GET profile reads
// and should be replaced with a server-side self-alias ('/api/v1/profiles/me')
// once the backend supports it.
export const api = {
  getProfile: (principal: string) =>
    request<Profile>(`/api/v1/profiles/${encodeURIComponent(principal)}`),

  listAvailableMcps: () =>
    request<AvailableMcp[]>('/api/v1/profiles/available-mcps'),

  // Mutations: no principal in path — backend infers identity from session.
  enableMcp: (_principal: string, serverName: string) =>
    request<void>(`/api/v1/profiles/me/mcps/${encodeURIComponent(serverName)}/enable`, { method: 'POST' }),

  disableMcp: (_principal: string, serverName: string) =>
    request<void>(`/api/v1/profiles/me/mcps/${encodeURIComponent(serverName)}/disable`, { method: 'POST' }),

  enableFunction: (_principal: string, serverName: string, fnName: string) =>
    request<void>(`/api/v1/profiles/me/mcps/${encodeURIComponent(serverName)}/functions/${encodeURIComponent(fnName)}/enable`, { method: 'POST' }),

  disableFunction: (_principal: string, serverName: string, fnName: string) =>
    request<void>(`/api/v1/profiles/me/mcps/${encodeURIComponent(serverName)}/functions/${encodeURIComponent(fnName)}/disable`, { method: 'POST' }),
}
