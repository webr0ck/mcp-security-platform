import { useState, useEffect } from 'react'
import { Button } from '../common/Button'
import { Badge } from '../common/Badge'
import { Card } from '../common/Card'
import { credentials as credentialsApi, ApiError, CREDENTIAL_TYPES, type CredentialTool } from '@/services/api'
import '../AdminPanel/AdminPanel.css'

// Labels mirror proxy/app/services/auth_modes.py::AUTH_MODES — the backend's
// single source of truth for mode names/labels. Kept here as a small static
// map (matching the pattern SubmitServerWizard.tsx already uses for
// AUTH_MODES) since there's no JSON endpoint exposing that catalog yet.
const INJECTION_MODE_LABELS: Record<string, string> = {
  none: 'No credential injection',
  service: 'Shared service credential',
  basic_auth: 'Basic auth',
  user: 'Per-user identity',
  service_account: 'Keycloak service account',
  kc_token_exchange: 'Same-IdP token exchange',
  oauth_user_token: 'Same-IdP token exchange',
  entra_client_credentials: 'Microsoft Entra app-only',
  entra_user_token: 'Microsoft Entra delegated',
  external_oauth_client_credentials: 'External OAuth, app-only',
  external_oauth_user_token: 'External OAuth, per-user',
  passthrough: 'Passthrough (admin-only)',
}

// Modes that mint tokens live from Keycloak/Entra at invocation time
// (credential_broker/dispatcher.py + keycloak_client.py) rather than reading
// a secret uploaded through this form.
const BROKERED_MODES = new Set(['service_account', 'kc_token_exchange', 'oauth_user_token', 'entra_user_token'])

function friendlyError(action: string, e: unknown): string {
  console.error('[CredentialsPanel]', e)
  if (e instanceof ApiError) return `${action} failed: ${e.message || e.status}`
  return `${action} failed. Please try again.`
}

interface FormState {
  credentialType: string
  ownerType: 'service' | 'user'
  userSub: string
  username: string
  secret: string
  description: string
}

const EMPTY_FORM: FormState = {
  credentialType: 'api_key', ownerType: 'service', userSub: '', username: '', secret: '', description: '',
}

export function CredentialsPanel() {
  const [tools, setTools] = useState<CredentialTool[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [form, setForm] = useState<FormState>(EMPTY_FORM)
  const [busyId, setBusyId] = useState<string | null>(null)
  const [revokeConfirmId, setRevokeConfirmId] = useState<string | null>(null)

  async function load() {
    setLoading(true); setError('')
    try {
      const { tools } = await credentialsApi.list()
      setTools(tools)
    } catch (e) { setError(friendlyError('Load credential status', e)) }
    finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  function toggleForm(toolId: string) {
    setExpanded(expanded === toolId ? null : toolId)
    setForm(EMPTY_FORM)
    setError('')
  }

  async function save(tool: CredentialTool) {
    setError('')
    if (!form.secret.trim()) { setError('Secret value is required.'); return }
    if (form.ownerType === 'user' && !form.userSub.trim()) { setError('A user is required for a per-user credential.'); return }
    if (form.credentialType === 'basic_auth' && !form.username.trim()) { setError('Username is required for basic auth.'); return }

    setBusyId(tool.tool_id)
    try {
      await credentialsApi.upload(tool.tool_id, {
        secret: form.secret.trim(),
        credential_type: form.credentialType,
        owner_type: form.ownerType,
        user_sub: form.ownerType === 'user' ? form.userSub.trim() : undefined,
        username: form.credentialType === 'basic_auth' ? form.username.trim() : undefined,
        description: form.description.trim() || undefined,
      })
      setExpanded(null)
      setForm(EMPTY_FORM)
      await load()
    } catch (e) { setError(friendlyError('Save credential', e)) }
    finally { setBusyId(null) }
  }

  async function revoke(tool: CredentialTool) {
    if (revokeConfirmId !== tool.tool_id) { setRevokeConfirmId(tool.tool_id); return }
    setRevokeConfirmId(null)
    setBusyId(tool.tool_id)
    try {
      await credentialsApi.revoke(tool.tool_id, 'service')
      await load()
    } catch (e) { setError(friendlyError('Revoke credential', e)) }
    finally { setBusyId(null) }
  }

  return (
    <div className="cred-panel animate-in">
      <Card>
        <h3 className="form-section-title">Credential Store</h3>
        <p className="form-section-desc" style={{ marginBottom: 'var(--sp-6)' }}>
          Static secrets (API keys, basic auth, Entra client secrets) are AES-256-GCM encrypted at rest and
          injected by the proxy at invocation time — the raw secret is never shown again after upload.
          Keycloak-brokered modes (service account, same-IdP token exchange) mint tokens live at call time
          and don't take an uploaded secret here.
        </p>

        {error && <p className="form-error" role="alert">{error}</p>}
        {loading && <p style={{ padding: 'var(--sp-4) 0' }}>Loading…</p>}

        {!loading && tools.length === 0 && !error && (
          <div className="cred-empty">
            <div className="cred-empty__icon">🔐</div>
            <p>No MCP servers registered yet.</p>
            <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              Register a server from the Servers tab first, then attach its credential here.
            </p>
          </div>
        )}

        {!loading && tools.length > 0 && (
          <div className="cred-tool-list">
            {tools.map(tool => {
              const isExpanded = expanded === tool.tool_id
              const isBrokered = BROKERED_MODES.has(tool.injection_mode)
              const isBusy = busyId === tool.tool_id
              return (
                <div key={tool.tool_id} className="cred-tool">
                  <div className="cred-tool__row">
                    <div className="cred-tool__info">
                      <span className="cred-tool__name">{tool.name}</span>
                      <code className="mono-sm" style={{ color: 'var(--text-muted)' }}>v{tool.version}</code>
                      <Badge label={INJECTION_MODE_LABELS[tool.injection_mode] ?? tool.injection_mode} variant="neutral" />
                      {tool.has_service_credential
                        ? <Badge label="Credential stored" variant="low" dot />
                        : <Badge label="No credential" variant="medium" dot />}
                    </div>
                    <div className="row-actions">
                      {tool.has_service_credential && (
                        revokeConfirmId === tool.tool_id ? (
                          <>
                            <span className="mono-sm">Revoke this credential?</span>
                            <Button size="sm" variant="danger" onClick={() => revoke(tool)} disabled={isBusy}>Confirm</Button>
                            <Button size="sm" variant="ghost" onClick={() => setRevokeConfirmId(null)} disabled={isBusy}>Cancel</Button>
                          </>
                        ) : (
                          <Button size="sm" variant="danger" onClick={() => revoke(tool)} disabled={isBusy}>Revoke</Button>
                        )
                      )}
                      <Button size="sm" variant={isExpanded ? 'secondary' : 'primary'} onClick={() => toggleForm(tool.tool_id)}>
                        {isExpanded ? 'Close' : 'Manage credential'}
                      </Button>
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="cred-tool__form">
                      {isBrokered && (
                        <p className="form-hint" style={{ marginBottom: 'var(--sp-3)' }}>
                          This tool is set to <strong>{INJECTION_MODE_LABELS[tool.injection_mode] ?? tool.injection_mode}</strong> —
                          Keycloak issues tokens for it at call time. You only need to upload a secret here if this tool
                          also needs a separate stored credential; it won't override the brokered flow.
                        </p>
                      )}
                      <div className="form-grid">
                        <div className="form-field">
                          <label htmlFor={`cred-type-${tool.tool_id}`}>Credential type</label>
                          <select
                            id={`cred-type-${tool.tool_id}`}
                            value={form.credentialType}
                            onChange={e => setForm(f => ({ ...f, credentialType: e.target.value }))}
                          >
                            {CREDENTIAL_TYPES.map(c => <option key={c.value} value={c.value}>{c.label}</option>)}
                          </select>
                        </div>
                        <div className="form-field">
                          <label id={`cred-owner-label-${tool.tool_id}`}>Owner</label>
                          <div className="cred-tool__owner-choice" role="radiogroup" aria-labelledby={`cred-owner-label-${tool.tool_id}`}>
                            <label className="cred-tool__owner-option">
                              <input
                                type="radio"
                                name={`owner-${tool.tool_id}`}
                                checked={form.ownerType === 'service'}
                                onChange={() => setForm(f => ({ ...f, ownerType: 'service' }))}
                              />
                              Service account — shared for all callers
                            </label>
                            <label className="cred-tool__owner-option">
                              <input
                                type="radio"
                                name={`owner-${tool.tool_id}`}
                                checked={form.ownerType === 'user'}
                                onChange={() => setForm(f => ({ ...f, ownerType: 'user' }))}
                              />
                              Specific user
                            </label>
                          </div>
                        </div>
                        {form.ownerType === 'user' && (
                          <div className="form-field">
                            <label htmlFor={`cred-user-${tool.tool_id}`}>User <span className="required">*</span></label>
                            <input
                              id={`cred-user-${tool.tool_id}`}
                              value={form.userSub}
                              onChange={e => setForm(f => ({ ...f, userSub: e.target.value }))}
                              placeholder="user's subject or email"
                            />
                          </div>
                        )}
                        {form.credentialType === 'basic_auth' && (
                          <div className="form-field">
                            <label htmlFor={`cred-username-${tool.tool_id}`}>Username <span className="required">*</span></label>
                            <input
                              id={`cred-username-${tool.tool_id}`}
                              value={form.username}
                              onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                              placeholder="service-account username"
                            />
                          </div>
                        )}
                        <div className="form-field form-field--wide">
                          <label htmlFor={`cred-secret-${tool.tool_id}`}>Secret <span className="required">*</span></label>
                          <input
                            id={`cred-secret-${tool.tool_id}`}
                            type="password"
                            value={form.secret}
                            onChange={e => setForm(f => ({ ...f, secret: e.target.value }))}
                            placeholder="Paste secret — never shown again after saving"
                            autoComplete="new-password"
                          />
                        </div>
                        <div className="form-field form-field--wide">
                          <label htmlFor={`cred-desc-${tool.tool_id}`}>Description</label>
                          <input
                            id={`cred-desc-${tool.tool_id}`}
                            value={form.description}
                            onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                            placeholder="e.g. rotated 2026-07-18"
                          />
                        </div>
                      </div>
                      <div className="form-actions">
                        <Button variant="primary" loading={isBusy} onClick={() => save(tool)}>Save credential</Button>
                        <Button variant="ghost" onClick={() => toggleForm(tool.tool_id)} disabled={isBusy}>Cancel</Button>
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </Card>
    </div>
  )
}
