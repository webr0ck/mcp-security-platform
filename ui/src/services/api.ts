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
  return res.json()
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

export interface AvailableMcp {
  server_name: string
  description: string
  status: string  // 'active' | 'quarantined' | 'pending'
  enabled_for_account: boolean
}

async function _req(method: string, path: string, body?: unknown): Promise<unknown> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    credentials: 'include',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`${method} ${path} → ${res.status}: ${text}`)
  }
  const ct = res.headers.get('content-type') ?? ''
  return ct.includes('json') ? res.json() : res.text()
}

export const api = {
  getProfile: (principal: string) =>
    _req('GET', `/api/v1/profiles/${encodeURIComponent(principal)}`) as Promise<Profile>,

  listAvailableMcps: () =>
    _req('GET', '/api/v1/profiles/available-mcps') as Promise<AvailableMcp[]>,

  enableMcp: (principal: string, serverName: string) =>
    _req('POST', `/api/v1/profiles/${encodeURIComponent(principal)}/mcps/${encodeURIComponent(serverName)}/enable`) as Promise<void>,

  disableMcp: (principal: string, serverName: string) =>
    _req('POST', `/api/v1/profiles/${encodeURIComponent(principal)}/mcps/${encodeURIComponent(serverName)}/disable`) as Promise<void>,

  enableFunction: (principal: string, serverName: string, fnName: string) =>
    _req('POST', `/api/v1/profiles/${encodeURIComponent(principal)}/mcps/${encodeURIComponent(serverName)}/functions/${encodeURIComponent(fnName)}/enable`) as Promise<void>,

  disableFunction: (principal: string, serverName: string, fnName: string) =>
    _req('POST', `/api/v1/profiles/${encodeURIComponent(principal)}/mcps/${encodeURIComponent(serverName)}/functions/${encodeURIComponent(fnName)}/disable`) as Promise<void>,
}
