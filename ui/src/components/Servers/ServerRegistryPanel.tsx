import { useEffect, useState } from 'react'
import { Button } from '../common/Button'
import { Badge } from '../common/Badge'
import { Card } from '../common/Card'
import { servers as serversApi, ApiError } from '@/services/api'
import type { MCPServer } from '@/types'
import '../AdminPanel/AdminPanel.css'

// H-04 (2026-07-11 audit): the generic message hid which action actually
// failed (approve vs. suspend vs. list). Surface the real backend detail
// where we have one, falling back to a generic message only when we don't.
function friendlyError(action: string, e: unknown): string {
  console.error('[ServerRegistryPanel]', e)
  if (e instanceof ApiError) return `${action} failed: ${e.message || e.status}`
  return `${action} failed. Please try again.`
}

interface PendingConsent { token: string; expiresAt: number }

export function ServerRegistryPanel() {
  const [servers, setServers] = useState<MCPServer[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [busyId, setBusyId] = useState<string | null>(null)
  // D3 dual-control: a consent token minted via "Request approval" must be
  // handed to Approve before the backend will accept the approval.
  const [consents, setConsents] = useState<Record<string, PendingConsent>>({})

  async function load() {
    setLoading(true); setError('')
    try {
      setServers(await serversApi.list())
    } catch (e) { setError(friendlyError('Load servers', e)) }
    finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  async function requestApproval(id: string) {
    setBusyId(id)
    try {
      const { consent_token, expires_in_seconds } = await serversApi.requestConsent(id)
      setConsents(c => ({ ...c, [id]: { token: consent_token, expiresAt: Date.now() + expires_in_seconds * 1000 } }))
    } catch (e) { setError(friendlyError('Request approval', e)) }
    finally { setBusyId(null) }
  }

  async function approve(id: string) {
    const consent = consents[id]
    if (!consent) return
    setBusyId(id)
    try {
      await serversApi.approve(id, consent.token)
      setConsents(c => { const next = { ...c }; delete next[id]; return next })
      await load()
    }
    catch (e) { setError(friendlyError('Approve', e)) }
    finally { setBusyId(null) }
  }

  async function suspend(id: string) {
    setBusyId(id)
    try { await serversApi.suspend(id); await load() }
    catch (e) { setError(friendlyError('Suspend', e)) }
    finally { setBusyId(null) }
  }

  const pending = servers.filter(s => s.status === 'pending')

  return (
    <div className="server-registry animate-in">
      {pending.length > 0 && (
        <div className="pending-banner">
          <span>⚠</span>
          <span><strong>{pending.length}</strong> server{pending.length > 1 ? 's' : ''} awaiting approval</span>
        </div>
      )}
      <Card padded={false}>
        <div className="section-header">
          <h2 className="section-title">Registered Servers</h2>
          <Button variant="primary" size="sm" onClick={load} disabled={loading}>↺ Refresh</Button>
        </div>
        {error && <p className="review__error" role="alert" style={{ padding: '0 var(--sp-4)' }}>{error}</p>}
        {loading && <p style={{ padding: 'var(--sp-4)' }}>Loading…</p>}
        {!loading && servers.length === 0 && !error && (
          <p style={{ padding: 'var(--sp-4)' }}>No servers registered yet.</p>
        )}
        {!loading && servers.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Upstream URL</th>
                <th>Injection</th>
                <th>Credential</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {servers.map(s => (
                <tr key={s.server_id}>
                  <td><code className="mono-sm">{s.name}</code></td>
                  <td><code className="mono-sm">{s.upstream_url}</code></td>
                  <td><Badge label={s.injection_mode} variant="neutral" /></td>
                  <td>{s.service_name ? <code className="mono-sm">{s.service_name}</code> : '—'}</td>
                  <td>
                    <Badge
                      label={s.status}
                      variant={s.status === 'approved' ? 'low' : s.status === 'pending' ? 'medium' : 'critical'}
                      dot
                    />
                  </td>
                  <td>
                    <div className="row-actions">
                      {s.status === 'pending' && !consents[s.server_id] && (
                        <Button size="sm" variant="primary" onClick={() => requestApproval(s.server_id)} disabled={busyId === s.server_id}>
                          Request approval
                        </Button>
                      )}
                      {s.status === 'pending' && consents[s.server_id] && (
                        <>
                          <span className="mono-sm" title="Single-use consent token — expires in 15 minutes">
                            Consent ready
                          </span>
                          <Button size="sm" variant="primary" onClick={() => approve(s.server_id)} disabled={busyId === s.server_id}>
                            Approve
                          </Button>
                        </>
                      )}
                      {s.status === 'approved' && (
                        <Button size="sm" variant="danger" onClick={() => suspend(s.server_id)} disabled={busyId === s.server_id}>
                          Suspend
                        </Button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  )
}
