import { useState, useEffect, useRef } from 'react'
import { Button } from '../common/Button'
import { Card } from '../common/Card'
import { limits as limitsApi } from '@/services/api'
import type { LimitRow } from '@/types'

export function LimitsPanel() {
  const [rows, setRows] = useState<LimitRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<Record<string, boolean>>({})

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await limitsApi.list()
      setRows(data.limits)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load limits')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const setBusyKey = (key: string, val: boolean) =>
    setBusy(prev => ({ ...prev, [key]: val }))

  const save = async (row: LimitRow, rateLimit: number | null, sensitivity: 'normal' | 'lenient' | 'off') => {
    const key = `save-${row.client_id}`
    setBusyKey(key, true)
    try {
      await limitsApi.put(row.client_id, { rate_limit: rateLimit, anomaly_sensitivity: sensitivity })
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to save limits for ${row.client_id}`)
    } finally {
      setBusyKey(key, false)
    }
  }

  const reset = async (id: string, target: 'rate' | 'anomaly' | 'both') => {
    const key = `reset-${id}-${target}`
    setBusyKey(key, true)
    try {
      await limitsApi.reset(id, target)
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to reset ${target} for ${id}`)
    } finally {
      setBusyKey(key, false)
    }
  }

  return (
    <div className="limits-panel">
      {error && (
        <div className="pending-banner" style={{ borderColor: 'rgba(239,68,68,0.25)', background: 'var(--danger-dim)', color: 'var(--danger)' }}>
          <span>!</span>
          <span>{error}</span>
        </div>
      )}

      <Card padded={false}>
        <div className="section-header">
          <h2 className="section-title">Request Limits</h2>
          <Button variant="ghost" size="sm" onClick={load} disabled={loading}>
            {loading ? 'Loading…' : 'Refresh'}
          </Button>
        </div>

        {loading && rows.length === 0 ? (
          <div style={{ padding: 'var(--sp-8)', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
            Loading…
          </div>
        ) : rows.length === 0 ? (
          <div style={{ padding: 'var(--sp-8)', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
            No clients with custom limits.
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Client ID</th>
                <th>Rate (used / limit)</th>
                <th>Anomaly window</th>
                <th>Sensitivity</th>
                <th>Blocked by</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(row => (
                <LimitRowItem
                  key={row.client_id}
                  row={row}
                  busy={busy}
                  onSave={save}
                  onReset={reset}
                />
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  )
}

function LimitRowItem({
  row,
  busy,
  onSave,
  onReset,
}: {
  row: LimitRow
  busy: Record<string, boolean>
  onSave: (row: LimitRow, rateLimit: number | null, sensitivity: 'normal' | 'lenient' | 'off') => void
  onReset: (id: string, target: 'rate' | 'anomaly' | 'both') => void
}) {
  const rateLimitRef = useRef<HTMLInputElement>(null)
  const isSaving = busy[`save-${row.client_id}`]
  const isResettingBoth = busy[`reset-${row.client_id}-both`]
  const isResettingRate = busy[`reset-${row.client_id}-rate`]
  const isResettingAnomaly = busy[`reset-${row.client_id}-anomaly`]
  const anyBusy = isSaving || isResettingBoth || isResettingRate || isResettingAnomaly

  const isBlocked = row.blocked_by && row.blocked_by !== 'none'
  const isExempt = row.anomaly.sensitivity === 'off'

  const handleRateBlur = () => {
    const el = rateLimitRef.current
    if (!el) return
    const raw = el.value.trim()
    const val = raw === '' ? null : parseInt(raw, 10)
    if (val !== null && (isNaN(val) || val < 0)) return
    // preserve current sensitivity
    onSave(row, val, row.anomaly.sensitivity)
  }

  const handleSensitivityChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const sensitivity = e.target.value as 'normal' | 'lenient' | 'off'
    // preserve current rate override (null if not overridden)
    const rateLimit = row.rate.is_override ? row.rate.limit : null
    onSave(row, rateLimit, sensitivity)
  }

  return (
    <tr style={isBlocked ? { background: 'rgba(239,68,68,0.04)' } : undefined}>
      <td>
        <code className="mono-sm">{row.client_id}</code>
        {isBlocked && (
          <span style={{ marginLeft: 6, fontSize: 11, color: 'var(--danger)', fontWeight: 600 }}>
            BLOCKED
          </span>
        )}
      </td>
      <td>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>{row.rate.count} /</span>
          <input
            ref={rateLimitRef}
            type="number"
            defaultValue={row.rate.limit}
            min={0}
            onBlur={handleRateBlur}
            disabled={anyBusy}
            style={{
              width: 64,
              padding: '2px 6px',
              fontSize: 12,
              fontFamily: 'var(--font-mono)',
              background: 'var(--bg-elevated)',
              border: '1px solid var(--border-base)',
              borderRadius: 'var(--r-sm)',
              color: row.rate.is_override ? 'var(--accent)' : 'var(--text-primary)',
            }}
          />
          {row.rate.is_override && (
            <span style={{ fontSize: 10, color: 'var(--accent)' }}>override</span>
          )}
        </div>
      </td>
      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>
        {row.anomaly.window_calls != null ? `${row.anomaly.window_calls} calls` : '—'}
      </td>
      <td>
        <select
          value={row.anomaly.sensitivity}
          onChange={handleSensitivityChange}
          disabled={anyBusy}
          style={{
            fontSize: 12,
            padding: '2px 6px',
            background: 'var(--bg-elevated)',
            border: '1px solid var(--border-base)',
            borderRadius: 'var(--r-sm)',
            color: isExempt ? 'var(--warning)' : 'var(--text-primary)',
          }}
        >
          <option value="normal">Normal</option>
          <option value="lenient">Lenient</option>
          <option value="off">Off (exempt)</option>
        </select>
        {isExempt && <span style={{ marginLeft: 4, fontSize: 11 }}>⚠</span>}
      </td>
      <td>
        {row.blocked_by && row.blocked_by !== 'none' ? (
          <span style={{ fontSize: 12, color: 'var(--danger)', fontWeight: 500 }}>
            {row.blocked_by}
          </span>
        ) : (
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>—</span>
        )}
      </td>
      <td>
        <div className="row-actions">
          {isBlocked && (
            <Button
              size="sm"
              variant="danger"
              onClick={() => onReset(row.client_id, 'both')}
              disabled={anyBusy}
              loading={isResettingBoth}
            >
              Unblock
            </Button>
          )}
          <Button
            size="sm"
            variant="ghost"
            onClick={() => onReset(row.client_id, 'rate')}
            disabled={anyBusy}
            loading={isResettingRate}
          >
            Reset rate
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => onReset(row.client_id, 'anomaly')}
            disabled={anyBusy}
            loading={isResettingAnomaly}
          >
            Reset anomaly
          </Button>
        </div>
      </td>
    </tr>
  )
}
