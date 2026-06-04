import { useState } from 'react'
import { Button } from '../common/Button'
import { Badge } from '../common/Badge'
import { Card } from '../common/Card'
import type { OIDCConfig, MCPServer } from '@/types'
import './AdminPanel.css'

const MOCK_SERVERS: MCPServer[] = [
  { server_id: 's1', name: 'poc-echo-server', upstream_url: 'http://mcp-echo:8000', status: 'approved', owner_sub: 'poc-seeder', injection_mode: 'none', created_at: '2026-06-04T10:00:00Z', approved_at: '2026-06-04T10:01:00Z' },
  { server_id: 's2', name: 'poc-notes-server', upstream_url: 'http://mcp-notes:8000', status: 'approved', owner_sub: 'poc-seeder', injection_mode: 'user', created_at: '2026-06-04T10:00:00Z', approved_at: '2026-06-04T10:01:00Z' },
  { server_id: 's3', name: 'poc-search-server', upstream_url: 'http://mcp-search:8000', status: 'approved', owner_sub: 'poc-seeder', injection_mode: 'service', created_at: '2026-06-04T10:00:00Z', approved_at: '2026-06-04T10:01:00Z' },
  { server_id: 's4', name: 'corp-jira-mcp', upstream_url: 'http://jira-mcp:8080', status: 'pending', owner_sub: 'bob@corp', injection_mode: 'none', created_at: '2026-06-04T14:30:00Z', approved_at: null },
]

const DEFAULT_OIDC: OIDCConfig = {
  enabled: false, issuer_url: '', client_id: '', client_secret: '***',
  audience: '', role_claim_path: 'roles', redirect_uri: '',
}

type Tab = 'oidc' | 'servers' | 'credentials'

export function AdminPanel() {
  const [tab, setTab] = useState<Tab>('oidc')
  const [oidc, setOidc] = useState<OIDCConfig>(DEFAULT_OIDC)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)

  const handleSave = async () => {
    setSaving(true)
    await new Promise(r => setTimeout(r, 800))
    setSaving(false)
    setSaved(true)
    setTimeout(() => setSaved(false), 3000)
  }

  return (
    <div className="admin animate-in">
      <header className="admin__header">
        <div>
          <h1 className="admin__title font-display">Administration</h1>
          <p className="admin__subtitle">Identity, server registry, and credential management</p>
        </div>
        <Badge label="LAN Only" variant="info" dot />
      </header>

      <div className="admin__tabs">
        {(['oidc','servers','credentials'] as Tab[]).map(t => (
          <button
            key={t}
            className={`admin__tab ${tab === t ? 'admin__tab--active' : ''}`}
            onClick={() => setTab(t)}
          >
            {t === 'oidc' ? 'Identity (OIDC)' : t === 'servers' ? 'MCP Servers' : 'Credentials'}
          </button>
        ))}
      </div>

      {tab === 'oidc' && (
        <OIDCForm oidc={oidc} onChange={setOidc} onSave={handleSave} saving={saving} saved={saved} />
      )}
      {tab === 'servers' && <ServerRegistry servers={MOCK_SERVERS} />}
      {tab === 'credentials' && <CredentialsPanel />}
    </div>
  )
}

function OIDCForm({ oidc, onChange, onSave, saving, saved }: {
  oidc: OIDCConfig
  onChange: (c: OIDCConfig) => void
  onSave: () => void
  saving: boolean
  saved: boolean
}) {
  const set = (k: keyof OIDCConfig) => (e: React.ChangeEvent<HTMLInputElement>) =>
    onChange({ ...oidc, [k]: e.target.value })

  return (
    <div className="oidc-form">
      <Card>
        <div className="oidc-form__toggle">
          <div>
            <h3 className="form-section-title">Identity Provider</h3>
            <p className="form-section-desc">Connect any OAuth2/OIDC-compatible IdP — Keycloak, Okta, Auth0, Entra.</p>
          </div>
          <label className="toggle" aria-label="Enable OIDC">
            <input type="checkbox" checked={oidc.enabled} onChange={e => onChange({ ...oidc, enabled: e.target.checked })} />
            <span className="toggle__track"><span className="toggle__thumb" /></span>
          </label>
        </div>

        {oidc.enabled && (
          <div className="form-grid" style={{ animationDelay: '0ms' }}>
            <div className="form-field form-field--wide">
              <label>Issuer URL <span className="required">*</span></label>
              <input type="url" value={oidc.issuer_url} onChange={set('issuer_url')} placeholder="https://your-idp.example.com/realms/mcp" />
              <span className="form-hint">The OIDC discovery endpoint base URL</span>
            </div>
            <div className="form-field">
              <label>Client ID <span className="required">*</span></label>
              <input value={oidc.client_id} onChange={set('client_id')} placeholder="mcp-security-platform" />
            </div>
            <div className="form-field">
              <label>Client Secret <span className="required">*</span></label>
              <input
                type="password"
                value={oidc.client_secret === '***' ? '' : oidc.client_secret}
                onChange={set('client_secret')}
                placeholder="Enter new secret to update (leave blank to keep current)"
                autoComplete="new-password"
              />
              {oidc.client_secret === '***' && (
                <span className="form-hint" style={{ color: 'var(--success)' }}>✓ Secret configured (stored server-side)</span>
              )}
            </div>
            <div className="form-field">
              <label>Audience</label>
              <input value={oidc.audience} onChange={set('audience')} placeholder="mcp-security-platform" />
            </div>
            <div className="form-field">
              <label>Role Claim Path</label>
              <input value={oidc.role_claim_path} onChange={set('role_claim_path')} placeholder="roles" />
              <span className="form-hint">JWT claim containing the user's roles (e.g. <code>roles</code> or <code>realm_access.roles</code>)</span>
            </div>
            <div className="form-field form-field--wide">
              <label>Redirect URI</label>
              <input type="url" value={oidc.redirect_uri} onChange={set('redirect_uri')} placeholder="https://your-host/api/v1/auth/oidc/callback" />
            </div>
          </div>
        )}

        <div className="form-actions">
          <Button variant="primary" loading={saving} onClick={onSave} disabled={!oidc.enabled}>
            {saved ? '✓ Saved' : 'Save Configuration'}
          </Button>
          {oidc.enabled && (
            <Button variant="ghost">Test Connection</Button>
          )}
        </div>
      </Card>
    </div>
  )
}

function ServerRegistry({ servers }: { servers: MCPServer[] }) {
  const pending = servers.filter(s => s.status === 'pending')
  return (
    <div className="server-registry">
      {pending.length > 0 && (
        <div className="pending-banner">
          <span>⚠</span>
          <span><strong>{pending.length}</strong> server{pending.length > 1 ? 's' : ''} awaiting approval</span>
        </div>
      )}
      <Card padded={false}>
        <div className="section-header">
          <h2 className="section-title">Registered Servers</h2>
          <Button variant="primary" size="sm">+ Register</Button>
        </div>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Upstream URL</th>
              <th>Injection</th>
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
                <td>
                  <Badge
                    label={s.status}
                    variant={s.status === 'approved' ? 'success' : s.status === 'pending' ? 'medium' : 'critical'}
                    dot
                  />
                </td>
                <td>
                  <div className="row-actions">
                    {s.status === 'pending' && <Button size="sm" variant="primary">Approve</Button>}
                    <Button size="sm" variant="ghost">Edit</Button>
                    {s.status === 'approved' && <Button size="sm" variant="danger">Suspend</Button>}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  )
}

function CredentialsPanel() {
  return (
    <Card>
      <h3 className="form-section-title">Credential Store</h3>
      <p className="form-section-desc" style={{ marginBottom: 'var(--sp-6)' }}>
        Service credentials are AES-256-GCM encrypted at rest and injected by the proxy at invocation time. The raw secret is never visible after upload.
      </p>
      <div className="cred-empty">
        <div className="cred-empty__icon">🔐</div>
        <p>No credentials stored</p>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>Upload credentials per MCP server from the server registry</p>
        <Button variant="secondary" size="sm" style={{ marginTop: 'var(--sp-4)' }}>Upload Credential</Button>
      </div>
    </Card>
  )
}
