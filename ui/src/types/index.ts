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
  created_at: string
  approved_at: string | null
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
