import { useState } from 'react'
import { Button } from '../common/Button'
import { Card } from '../common/Card'
import { oidc as oidcApi } from '@/services/api'
import type { OIDCConfig } from '@/types'
import '../AdminPanel/AdminPanel.css'

const DEFAULT_OIDC: OIDCConfig = {
  enabled: false, issuer_url: '', client_id: '', client_secret: '***',
  audience: '', role_claim_path: 'roles', redirect_uri: '',
}

export function IdentitySettings() {
  const [oidc, setOidc] = useState<OIDCConfig>(DEFAULT_OIDC)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)

  const handleSave = async () => {
    setSaving(true)
    try {
      await oidcApi.save(oidc)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (err) {
      // Show error state — don't expose raw error to UI
      console.error('OIDC save failed:', err)
      // Could add an error state here; for now fall through
    } finally {
      setSaving(false)
    }
  }

  const set = (k: keyof OIDCConfig) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setOidc({ ...oidc, [k]: e.target.value })

  return (
    <div className="oidc-form animate-in">
      <Card>
        <div className="oidc-form__toggle">
          <div>
            <h3 className="form-section-title">Identity Provider</h3>
            <p className="form-section-desc">Connect any OAuth2/OIDC-compatible IdP — Keycloak, Okta, Auth0, Entra.</p>
          </div>
          <label className="toggle" aria-label="Enable OIDC">
            <input type="checkbox" checked={oidc.enabled} onChange={e => setOidc({ ...oidc, enabled: e.target.checked })} />
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
          <Button variant="primary" loading={saving} onClick={handleSave} disabled={!oidc.enabled}>
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
