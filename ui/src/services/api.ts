// ─── API Service Layer ────────────────────────────────────────────────────────
// All communication with the MCP Security Platform proxy goes through here.
// Configure BASE_URL via the VITE_API_URL environment variable.

const BASE_URL = import.meta.env.VITE_API_URL ?? ''

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
    this.name = 'ApiError'
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
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
