import { useEffect, useState } from 'react'
import { Button } from '../common/Button'
import { Badge } from '../common/Badge'
import { Card } from '../common/Card'
import { Modal } from '../common/Modal'
import { servers as serversApi, ApiError } from '@/services/api'
import type { MCPServer } from '@/types'
import '../AdminPanel/AdminPanel.css'

// SEP-1913 rank labels — mirrors taint_floor.py's docstring table exactly
// (0=untrustedPublic .. 4=system); keep in sync if that ranking changes.
const TRUST_TIER_LABELS: Record<number, string> = {
  0: '0 — untrustedPublic',
  1: '1 — trustedPublic',
  2: '2 — internal',
  3: '3 — user',
  4: '4 — system',
}

// H-04 (2026-07-11 audit): the generic message hid which action actually
// failed (approve vs. suspend vs. list). Surface the real backend detail
// where we have one, falling back to a generic message only when we don't.
function friendlyError(action: string, e: unknown): string {
  console.error('[ServerRegistryPanel]', e)
  if (e instanceof ApiError) return `${action} failed: ${e.message || e.status}`
  return `${action} failed. Please try again.`
}

interface PendingConsent { token: string; expiresAt: number }

interface EditFormState { upstream_url: string; service_name: string; trust_tier: string }

export function ServerRegistryPanel() {
  const [servers, setServers] = useState<MCPServer[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [busyId, setBusyId] = useState<string | null>(null)
  // D3 dual-control: a consent token minted via "Request approval" must be
  // handed to Approve before the backend will accept the approval.
  const [consents, setConsents] = useState<Record<string, PendingConsent>>({})

  // WS-A: edit modal
  const [editing, setEditing] = useState<MCPServer | null>(null)
  const [editForm, setEditForm] = useState<EditFormState>({ upstream_url: '', service_name: '', trust_tier: '' })
  const [editError, setEditError] = useState('')

  // WS-A: rebuild recreates the container — require an explicit confirm click
  // (same pattern as CredentialsPanel's revoke confirm).
  const [rebuildConfirmId, setRebuildConfirmId] = useState<string | null>(null)

  // WS-A: view-logs modal
  const [logsFor, setLogsFor] = useState<MCPServer | null>(null)
  const [logsText, setLogsText] = useState('')
  const [logsLoading, setLogsLoading] = useState(false)
  const [logsError, setLogsError] = useState('')

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

  function openEdit(s: MCPServer) {
    setEditing(s)
    setEditError('')
    setEditForm({
      upstream_url: s.upstream_url,
      service_name: s.service_name ?? '',
      trust_tier: s.trust_tier != null ? String(s.trust_tier) : '',
    })
  }

  async function saveEdit() {
    if (!editing) return
    setEditError('')
    if (!editForm.upstream_url.trim()) { setEditError('Upstream URL is required.'); return }
    const body: { upstream_url?: string; service_name?: string; trust_tier?: number } = {
      upstream_url: editForm.upstream_url.trim(),
      service_name: editForm.service_name.trim() || undefined,
    }
    if (editForm.trust_tier !== '') {
      const tier = Number(editForm.trust_tier)
      if (!Number.isInteger(tier) || tier < 0 || tier > 4) { setEditError('Trust tier must be 0-4.'); return }
      body.trust_tier = tier
    }
    setBusyId(editing.server_id)
    try {
      await serversApi.update(editing.server_id, body)
      setEditing(null)
      await load()
    } catch (e) { setEditError(friendlyError('Save server', e)) }
    finally { setBusyId(null) }
  }

  async function restart(id: string) {
    setBusyId(id)
    try { await serversApi.restart(id) }
    catch (e) { setError(friendlyError('Restart', e)) }
    finally { setBusyId(null) }
  }

  async function rebuild(id: string) {
    if (rebuildConfirmId !== id) { setRebuildConfirmId(id); return }
    setRebuildConfirmId(null)
    setBusyId(id)
    try { await serversApi.rebuild(id) }
    catch (e) { setError(friendlyError('Rebuild', e)) }
    finally { setBusyId(null) }
  }

  async function openLogs(s: MCPServer) {
    setLogsFor(s)
    setLogsText('')
    setLogsError('')
    setLogsLoading(true)
    try {
      const { logs } = await serversApi.logs(s.server_id, 200)
      setLogsText(logs)
    } catch (e) { setLogsError(friendlyError('Load logs', e)) }
    finally { setLogsLoading(false) }
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
                      <Button size="sm" variant="secondary" onClick={() => openEdit(s)} disabled={busyId === s.server_id}>
                        Edit
                      </Button>
                      {s.status === 'approved' && (
                        <>
                          <Button size="sm" variant="secondary" onClick={() => restart(s.server_id)} disabled={busyId === s.server_id}>
                            Restart
                          </Button>
                          {rebuildConfirmId === s.server_id ? (
                            <>
                              <span className="mono-sm">Recreates the container — confirm?</span>
                              <Button size="sm" variant="danger" onClick={() => rebuild(s.server_id)} disabled={busyId === s.server_id}>Confirm rebuild</Button>
                              <Button size="sm" variant="ghost" onClick={() => setRebuildConfirmId(null)} disabled={busyId === s.server_id}>Cancel</Button>
                            </>
                          ) : (
                            <Button size="sm" variant="secondary" onClick={() => rebuild(s.server_id)} disabled={busyId === s.server_id}>
                              Rebuild
                            </Button>
                          )}
                        </>
                      )}
                      {s.debug_mode === true && (
                        <Button size="sm" variant="secondary" onClick={() => openLogs(s)} disabled={busyId === s.server_id}>
                          View logs
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

      {editing && (
        <Modal
          title={`Edit ${editing.name}`}
          onClose={() => setEditing(null)}
          footer={
            <>
              <Button variant="ghost" onClick={() => setEditing(null)} disabled={busyId === editing.server_id}>Cancel</Button>
              <Button variant="primary" loading={busyId === editing.server_id} onClick={saveEdit}>Save</Button>
            </>
          }
        >
          {editError && <p className="form-error" role="alert">{editError}</p>}
          <div className="form-grid">
            <div className="form-field form-field--wide">
              <label htmlFor="edit-upstream-url">Upstream URL <span className="required">*</span></label>
              <input
                id="edit-upstream-url"
                value={editForm.upstream_url}
                onChange={e => setEditForm(f => ({ ...f, upstream_url: e.target.value }))}
                placeholder="https://…"
              />
            </div>
            <div className="form-field form-field--wide">
              <label htmlFor="edit-service-name">Service name</label>
              <input
                id="edit-service-name"
                value={editForm.service_name}
                onChange={e => setEditForm(f => ({ ...f, service_name: e.target.value }))}
                placeholder="e.g. gitea"
              />
            </div>
            <div className="form-field form-field--wide">
              <label htmlFor="edit-trust-tier">Trust tier</label>
              <select
                id="edit-trust-tier"
                value={editForm.trust_tier}
                onChange={e => setEditForm(f => ({ ...f, trust_tier: e.target.value }))}
              >
                <option value="">Unchanged</option>
                {Object.entries(TRUST_TIER_LABELS).map(([v, label]) => (
                  <option key={v} value={v}>{label}</option>
                ))}
              </select>
              <p className="form-hint">Raising this affects the taint floor for future callers (SEP-1913) — only promote a server once it's actually been vetted.</p>
            </div>
          </div>
        </Modal>
      )}

      {logsFor && (
        <Modal title={`Logs — ${logsFor.name}`} onClose={() => setLogsFor(null)}>
          {logsLoading && <p>Loading…</p>}
          {logsError && <p className="form-error" role="alert">{logsError}</p>}
          {!logsLoading && !logsError && <pre className="modal-logs">{logsText || '(no output)'}</pre>}
        </Modal>
      )}
    </div>
  )
}
