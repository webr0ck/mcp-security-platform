import { useState } from 'react'
import { Button } from '../common/Button'
import type { TierName } from '@/types'
import './InstallWizard.css'

const TIERS: { id: TierName; label: string; tagline: string; features: string[]; compose: string }[] = [
  {
    id: 'engine',
    label: 'Engine',
    tagline: 'Minimal install — bring your own IDP',
    features: [
      'Gateway (nginx + ModSec)',
      'Security proxy + OPA policy',
      'PostgreSQL + Redis + Vault',
      'mTLS via step-ca',
      'Plug in any OIDC provider',
      'LAN-only admin panel',
    ],
    compose: 'compose.engine.yml',
  },
  {
    id: 'standard',
    label: 'Standard',
    tagline: 'Engine + Keycloak + Grafana',
    features: [
      'Everything in Engine',
      'Keycloak (no users by default)',
      'Grafana + Loki + Promtail',
      'Keycloak SSO for Grafana',
      'Role groups pre-configured',
      'One init script for all secrets',
    ],
    compose: 'compose.standard.yml',
  },
  {
    id: 'poc',
    label: 'Full POC',
    tagline: 'Standard + Wazuh + demo users',
    features: [
      'Everything in Standard',
      'Wazuh SIEM (manager + dashboard)',
      '3 demo MCP servers',
      'alice / bob / carol demo users',
      'Sigma detection rules wired',
      'Full E2E demo in one command',
    ],
    compose: 'compose.poc.yml',
  },
]

const STEPS = ['Choose tier', 'Configure secrets', 'Review', 'Deploy']

const SECRET_FIELDS: { key: string; label: string; hint: string; generated?: boolean }[] = [
  { key: 'DB_PASSWORD', label: 'Database password', hint: 'PostgreSQL app user password', generated: true },
  { key: 'REDIS_PASSWORD', label: 'Redis password', hint: 'Redis requirepass value', generated: true },
  { key: 'VAULT_TOKEN', label: 'Vault token', hint: 'Root token for dev mode (change for production)', generated: true },
  { key: 'PROXY_SECRET_KEY', label: 'Proxy secret key', hint: '32-byte hex — used for session signing', generated: true },
]

function generateSecret(len = 32) {
  return Array.from(crypto.getRandomValues(new Uint8Array(len)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('').slice(0, len)
}

export function InstallWizard() {
  const [step, setStep] = useState(0)
  const [tier, setTier] = useState<TierName>('standard')
  const [secrets, setSecrets] = useState<Record<string, string>>(() =>
    Object.fromEntries(SECRET_FIELDS.map(f => [f.key, '']))
  )
  const [deploying, setDeploying] = useState(false)
  const [deployed, setDeployed] = useState(false)

  const selectedTier = TIERS.find(t => t.id === tier)!

  const generateAll = () => {
    setSecrets(Object.fromEntries(
      SECRET_FIELDS.map(f => [f.key, f.generated ? generateSecret() : secrets[f.key]])
    ))
  }

  const handleDeploy = async () => {
    setDeploying(true)
    await new Promise(r => setTimeout(r, 1800))
    setDeploying(false)
    setDeployed(true)
  }

  const envContent = Object.entries(secrets)
    .map(([k, v]) => `${k}=${v}`)
    .join('\n')

  return (
    <div className="wizard animate-in">
      <header className="wizard__header">
        <h1 className="wizard__title font-display">Setup Wizard</h1>
        <p className="wizard__subtitle">Deploy the MCP Security Platform in minutes</p>
      </header>

      {/* Progress bar */}
      <div className="wizard__steps" role="list">
        {STEPS.map((s, i) => (
          <div key={s} role="listitem" className={`wizard__step ${i === step ? 'wizard__step--active' : ''} ${i < step ? 'wizard__step--done' : ''}`}>
            <div className="wizard__step-circle">
              {i < step ? '✓' : i + 1}
            </div>
            <span className="wizard__step-label">{s}</span>
            {i < STEPS.length - 1 && <div className="wizard__step-line" />}
          </div>
        ))}
      </div>

      {/* Step content */}
      <div className="wizard__content">
        {step === 0 && (
          <div className="tier-select">
            <h2 className="wizard__section-title">Select deployment tier</h2>
            <div className="tier-grid">
              {TIERS.map(t => (
                <button
                  key={t.id}
                  className={`tier-card ${tier === t.id ? 'tier-card--selected' : ''}`}
                  onClick={() => setTier(t.id)}
                >
                  <div className="tier-card__header">
                    <span className="tier-card__name">{t.label}</span>
                    {t.id === 'standard' && <span className="tier-card__recommended">Recommended</span>}
                  </div>
                  <p className="tier-card__tagline">{t.tagline}</p>
                  <ul className="tier-card__features">
                    {t.features.map(f => (
                      <li key={f}><span>✓</span> {f}</li>
                    ))}
                  </ul>
                  <code className="tier-card__cmd">docker compose -f {t.compose} up -d</code>
                </button>
              ))}
            </div>
          </div>
        )}

        {step === 1 && (
          <div className="secrets-step">
            <div className="secrets-step__header">
              <h2 className="wizard__section-title">Configure secrets</h2>
              <Button size="sm" variant="secondary" onClick={generateAll}>⟳ Generate all</Button>
            </div>
            <p className="wizard__hint">
              These values will be written to <code>.env</code> in your project root.
              Or run <code>bash scripts/init-{tier}.sh</code> to auto-generate.
            </p>
            <div className="secrets-grid">
              {SECRET_FIELDS.map(f => (
                <div key={f.key} className="secrets-grid__field">
                  <label>{f.label}</label>
                  <div className="secrets-grid__input-row">
                    <input
                      type="text"
                      value={secrets[f.key]}
                      onChange={e => setSecrets(s => ({ ...s, [f.key]: e.target.value }))}
                      placeholder={f.generated ? 'Generate or enter a secure value' : 'Enter value'}
                      className="mono-input"
                    />
                    {f.generated && (
                      <button
                        className="gen-btn"
                        onClick={() => setSecrets(s => ({ ...s, [f.key]: generateSecret() }))}
                        title="Generate"
                      >⟳</button>
                    )}
                  </div>
                  <span className="form-hint">{f.hint}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="review-step">
            <h2 className="wizard__section-title">Review configuration</h2>
            <div className="review-grid">
              <div className="review-box">
                <p className="review-box__label">Deployment tier</p>
                <p className="review-box__value">{selectedTier.label}</p>
                <p className="review-box__sub">{selectedTier.tagline}</p>
              </div>
              <div className="review-box">
                <p className="review-box__label">Compose command</p>
                <code className="review-box__code">docker compose -f {selectedTier.compose} up -d</code>
              </div>
            </div>
            <div className="env-preview">
              <div className="env-preview__header">
                <span>.env preview</span>
                <button className="copy-btn" onClick={() => navigator.clipboard.writeText(envContent)}>
                  Copy
                </button>
              </div>
              <pre className="env-preview__content">{envContent}</pre>
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="deploy-step">
            {!deployed ? (
              <>
                <div className="deploy-step__icon">⬡</div>
                <h2 className="wizard__section-title">Ready to deploy</h2>
                <p className="wizard__hint">
                  This will write your <code>.env</code> file and start the stack.
                  The admin panel will be available at{' '}
                  <code>https://localhost/admin</code> (LAN only) once healthy.
                </p>
                <div className="deploy-step__actions">
                  <Button variant="primary" size="lg" loading={deploying} onClick={handleDeploy}>
                    {deploying ? 'Starting stack…' : 'Deploy now'}
                  </Button>
                  <Button variant="ghost" size="lg">Download .env only</Button>
                </div>
              </>
            ) : (
              <div className="deploy-done">
                <div className="deploy-done__check">✓</div>
                <h2 className="wizard__section-title">Stack started</h2>
                <p className="wizard__hint">Services are initialising. Check status with:</p>
                <code className="deploy-done__cmd">
                  docker compose -f {selectedTier.compose} ps
                </code>
                <div className="deploy-done__links">
                  <a href="https://localhost/admin" className="deploy-done__link">Admin panel →</a>
                  {(tier === 'standard' || tier === 'poc') && (
                    <a href="http://localhost:3000" className="deploy-done__link">Grafana →</a>
                  )}
                  {tier === 'poc' && (
                    <a href="http://localhost:5601" className="deploy-done__link">Wazuh →</a>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Navigation */}
      <div className="wizard__nav">
        <Button variant="ghost" disabled={step === 0} onClick={() => setStep(s => s - 1)}>
          ← Back
        </Button>
        {step < STEPS.length - 1 && (
          <Button variant="primary" onClick={() => setStep(s => s + 1)}>
            {step === STEPS.length - 2 ? 'Review' : 'Continue'} →
          </Button>
        )}
      </div>
    </div>
  )
}
