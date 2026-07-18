// ─── Core domain types ────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Role = 'admin' | 'analyst' | 'editor' | 'viewer' | 'agent' | 'auditor'
export type AuditOutcome = 'allow' | 'deny' | 'error'
export type ServerStatus = 'approved' | 'pending' | 'suspended'
export type TierName = 'engine' | 'standard' | 'poc'

export interface AuditEvent {
  event_id: string
  event_type: string
  timestamp: string
  client_id: string
  tool_name: string
  tool_id: string
  outcome: AuditOutcome
  anomaly_score: number | null
  latency_ms: number | null
  sha256_hash: string
}

export interface MCPServer {
  server_id: string
  name: string
  upstream_url: string
  status: ServerStatus
  owner_sub: string
  injection_mode: string
  service_name: string | null
  created_at: string
  approved_at: string | null
  // Optional: only present when the backend list SELECT includes these
  // columns (server_registry.py:list_servers currently does not — see
  // docs/spec/15-profile-naming-and-credential-ui.md). Treat missing/undefined
  // as "unknown" and fail closed (hide debug-gated actions) rather than
  // assuming false.
  debug_mode?: boolean
  // SEP-1913 rank (0=untrustedPublic .. 4=system) — see taint_floor.py.
  trust_tier?: number
}

export interface RoleAssignment {
  assignment_id: string
  client_id: string
  role: Role
  granted_by: string
  expires_at: string | null
  created_at: string
}

export interface HealthStatus {
  service: string
  status: 'healthy' | 'degraded' | 'down'
  latency_ms?: number
  detail?: string
}

export interface DetectionFiring {
  rule_id: string
  title: string
  severity: Severity
  client_id: string
  tool_name: string
  fired_at: string
  count: number
}

export interface OIDCConfig {
  enabled: boolean
  issuer_url: string
  client_id: string
  // client_secret: API returns '***' when a secret is already set.
  // Browser should never receive or display the real value.
  // Send the real value only when the user explicitly enters a new one.
  client_secret: string
  audience: string
  role_claim_path: string
  redirect_uri: string
}

export interface WizardStep {
  id: number
  title: string
  description: string
}

export interface LimitRow {
  client_id: string
  rate: { count: number; limit: number; is_override: boolean }
  anomaly: {
    window_calls?: number
    score?: number
    cutoff: number
    sensitivity: 'normal' | 'lenient' | 'off'
  }
  blocked_by?: 'none' | 'rate' | 'anomaly' | 'both'
  updated_by?: string | null
  updated_at?: string | null
}
