import { Button } from '../common/Button'
import { Card } from '../common/Card'
import '../AdminPanel/AdminPanel.css'

export function CredentialsPanel() {
  return (
    <Card className="animate-in">
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
