import { useState } from 'react'
import { Badge } from '../common/Badge'
import { Card, StatCard } from '../common/Card'
import type { AuditEvent, DetectionFiring, Severity } from '@/types'
import './SecurityDashboard.css'

// ── Mock data — replace with API calls from services/api.ts ──────────────────
const MOCK_EVENTS: AuditEvent[] = [
  { event_id: 'a1', event_type: 'TOOL_INVOCATION', timestamp: new Date(Date.now()-12000).toISOString(), client_id: 'alice', tool_name: 'ping', tool_id: 'e1', outcome: 'allow', anomaly_score: 0.08, latency_ms: 42, sha256_hash: 'abc123' },
  { event_id: 'a2', event_type: 'TOOL_INVOCATION', timestamp: new Date(Date.now()-28000).toISOString(), client_id: 'bob', tool_name: 'notes_write', tool_id: 'e2', outcome: 'deny', anomaly_score: 0.91, latency_ms: 11, sha256_hash: 'def456' },
  { event_id: 'a3', event_type: 'TOOL_INVOCATION', timestamp: new Date(Date.now()-55000).toISOString(), client_id: 'carol', tool_name: 'search', tool_id: 'e3', outcome: 'allow', anomaly_score: 0.21, latency_ms: 130, sha256_hash: 'ghi789' },
  { event_id: 'a4', event_type: 'CREDENTIAL_UPLOADED', timestamp: new Date(Date.now()-180000).toISOString(), client_id: 'admin', tool_name: '', tool_id: '', outcome: 'allow', anomaly_score: null, latency_ms: null, sha256_hash: 'jkl012' },
  { event_id: 'a5', event_type: 'TOOL_INVOCATION', timestamp: new Date(Date.now()-240000).toISOString(), client_id: 'svc-agent', tool_name: 'get_email', tool_id: 'e5', outcome: 'allow', anomaly_score: 0.05, latency_ms: 77, sha256_hash: 'mno345' },
  { event_id: 'a6', event_type: 'TOOL_INVOCATION', timestamp: new Date(Date.now()-310000).toISOString(), client_id: 'alice@corp', tool_name: 'list_files', tool_id: 'e6', outcome: 'deny', anomaly_score: 0.74, latency_ms: 8, sha256_hash: 'pqr678' },
]

const MOCK_DETECTIONS: DetectionFiring[] = [
  { rule_id: 'mcp-0002', title: 'Policy Probe — Repeated Denial Burst', severity: 'high', client_id: 'alice@corp', tool_name: 'list_files', fired_at: new Date(Date.now()-310000).toISOString(), count: 7 },
  { rule_id: 'mcp-0003', title: 'High Anomaly Score on Tool Invocation', severity: 'high', client_id: 'bob', tool_name: 'notes_write', fired_at: new Date(Date.now()-28000).toISOString(), count: 1 },
  { rule_id: 'mcp-0004', title: 'Credential Change Event', severity: 'medium', client_id: 'admin', tool_name: '—', fired_at: new Date(Date.now()-180000).toISOString(), count: 1 },
]

function relativeTime(iso: string) {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`
  return `${Math.floor(diff/3600)}h ago`
}

function AnomalyBar({ score }: { score: number | null }) {
  if (score === null) return <span className="text-muted">—</span>
  const pct = Math.round(score * 100)
  const cls = score > 0.85 ? 'high' : score > 0.5 ? 'med' : 'low'
  return (
    <div className="anomaly-bar" title={`${pct}%`}>
      <div className={`anomaly-bar__fill anomaly-bar__fill--${cls}`} style={{ width: `${pct}%` }} />
      <span className="anomaly-bar__label">{pct}</span>
    </div>
  )
}

export function SecurityDashboard() {
  const [filter, setFilter] = useState<'all' | 'allow' | 'deny'>('all')
  const filtered = MOCK_EVENTS.filter(e => filter === 'all' || e.outcome === filter)

  return (
    <div className="dashboard animate-in">
      {/* Header */}
      <header className="dashboard__header">
        <div>
          <h1 className="dashboard__title font-display">Security Dashboard</h1>
          <p className="dashboard__subtitle">Real-time audit stream and threat detection</p>
        </div>
        <div className="dashboard__header-actions">
          <span className="live-indicator">
            <span className="live-indicator__dot" />
            Live
          </span>
        </div>
      </header>

      {/* Stats row */}
      <div className="dashboard__stats">
        <StatCard label="Events (24h)" value="1,247" delta="+12% vs yesterday" accent />
        <StatCard label="Policy Denials" value="34" />
        <StatCard label="Detections Fired" value="3" />
        <StatCard label="Avg Anomaly" value="0.18" />
      </div>

      {/* Detection firings */}
      <Card padded={false}>
        <div className="section-header">
          <h2 className="section-title">Active Detections</h2>
          <Badge label={`${MOCK_DETECTIONS.length} active`} variant="high" dot pulse />
        </div>
        <div className="detection-list">
          {MOCK_DETECTIONS.map(d => (
            <DetectionRow key={d.rule_id} d={d} />
          ))}
        </div>
      </Card>

      {/* Audit stream */}
      <Card padded={false}>
        <div className="section-header">
          <h2 className="section-title">Audit Stream</h2>
          <div className="filter-tabs">
            {(['all','allow','deny'] as const).map(f => (
              <button
                key={f}
                className={`filter-tab ${filter === f ? 'filter-tab--active' : ''}`}
                onClick={() => setFilter(f)}
              >
                {f}
              </button>
            ))}
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Client</th>
              <th>Event</th>
              <th>Tool</th>
              <th>Outcome</th>
              <th>Anomaly</th>
              <th>Latency</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(ev => (
              <tr key={ev.event_id}>
                <td><code className="mono-sm">{relativeTime(ev.timestamp)}</code></td>
                <td><code className="mono-sm client-id">{ev.client_id}</code></td>
                <td><span className="event-type">{ev.event_type}</span></td>
                <td>{ev.tool_name || <span className="text-muted">—</span>}</td>
                <td>
                  <Badge
                    label={ev.outcome}
                    variant={ev.outcome === 'allow' ? 'low' : ev.outcome === 'deny' ? 'critical' : 'medium'}
                    dot
                  />
                </td>
                <td><AnomalyBar score={ev.anomaly_score} /></td>
                <td>
                  {ev.latency_ms !== null
                    ? <code className="mono-sm">{ev.latency_ms}ms</code>
                    : <span className="text-muted">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  )
}

function DetectionRow({ d }: { d: DetectionFiring }) {
  return (
    <div className="detection-row">
      <div className="detection-row__sev">
        <Badge label={d.severity} variant={d.severity as Severity} />
      </div>
      <div className="detection-row__body">
        <p className="detection-row__title">{d.title}</p>
        <p className="detection-row__meta">
          <code className="mono-sm">{d.rule_id}</code>
          <span>·</span>
          <code className="mono-sm client-id">{d.client_id}</code>
          {d.tool_name !== '—' && <><span>·</span><span>{d.tool_name}</span></>}
        </p>
      </div>
      <div className="detection-row__right">
        {d.count > 1 && <Badge label={`×${d.count}`} variant="neutral" />}
        <span className="detection-row__time">{relativeTime(d.fired_at)}</span>
      </div>
    </div>
  )
}
