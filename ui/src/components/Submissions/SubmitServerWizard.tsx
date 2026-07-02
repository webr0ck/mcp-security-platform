import { useState, useEffect } from 'react'
import { submissions, type DesignPromptsResponse } from '@/services/api'
import './SubmitServerWizard.css'

// Values must match _VALID_MODES in submission.py
const AUTH_MODES = [
  { value: 'none',                     label: 'No authentication — publicly accessible' },
  { value: 'service',                  label: 'Service account (static API key / secret)' },
  { value: 'oauth_user_token',         label: 'OAuth — forward user token to upstream' },
  { value: 'kc_token_exchange',        label: 'OAuth — Keycloak token exchange' },
  { value: 'entra_client_credentials', label: 'Azure Entra — client credentials (app identity)' },
  { value: 'entra_user_token',         label: 'Azure Entra — delegated user token' },
]

// Values must match _VALID_CATEGORIES in submission.py
const DATA_CATEGORIES = [
  { value: 'public',          label: 'Public information' },
  { value: 'internal_docs',   label: 'Internal documents' },
  { value: 'source_code',     label: 'Source code / repositories' },
  { value: 'email_calendar',  label: 'Email / calendar' },
  { value: 'pii',             label: 'Personal data (PII)' },
  { value: 'health',          label: 'Health / medical data' },
  { value: 'financial',       label: 'Financial data' },
  { value: 'infrastructure',  label: 'Infrastructure / system config' },
]

const STATUS_LABELS: Record<string, string> = {
  draft:                 'Draft — not submitted yet',
  scan_pending:          'Queued for code scan…',
  scan_running:          'Scanning code…',
  scan_blocked:          'Scan found issues — review required',
  awaiting_review:       'Awaiting security review',
  changes_requested:     'Changes requested by reviewer',
  approved_pending_url:  'Approved — provide running server URL',
  approved:              'Approved and live',
  rejected:              'Rejected',
}

type Step = 'url' | 'details' | 'review' | 'submitted'

function friendlyError(e: unknown): string {
  const s = String(e)
  if (s.includes('422')) return 'Some fields are invalid — check the highlighted fields and try again.'
  if (s.includes('401') || s.includes('403')) return 'Not authorised. Try signing out and back in.'
  if (s.includes('409')) return 'A server with this name already exists.'
  console.error('[SubmitServerWizard]', e)
  return 'Something went wrong. Please try again.'
}

export function SubmitServerWizard() {
  const [step, setStep]   = useState<Step>('url')
  const [serverId, setServerId] = useState('')
  const [submissionStatus, setSubmissionStatus] = useState('draft')
  const [prompts, setPrompts] = useState<DesignPromptsResponse | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy]   = useState(false)

  // Step 1 fields
  const [name, setName]         = useState('')
  const [githubUrl, setGithubUrl] = useState('')

  // Step 2 fields
  const [description, setDescription]     = useState('')
  const [injectionMode, setInjectionMode] = useState('')
  const [dataCategories, setDataCategories] = useState<string[]>([])
  const [hasWriteOps, setHasWriteOps]     = useState<boolean | null>(null)

  // Load prompts once we have a serverId + injectionMode saved
  useEffect(() => {
    if (!serverId) return
    submissions.prompts(serverId).then(setPrompts).catch(() => {/* prompts are advisory */})
  }, [serverId])

  async function createDraft() {
    setError('')
    setBusy(true)
    try {
      const res = await submissions.create({
        name: name.trim(),
        github_repo_url: githubUrl.trim() || undefined,
      })
      setServerId(res.server_id)
      setSubmissionStatus(res.submission_status)
      setStep('details')
    } catch (e) { setError(friendlyError(e)) }
    finally { setBusy(false) }
  }

  async function saveDetails() {
    if (!serverId) return
    setError('')
    setBusy(true)
    try {
      await submissions.update(serverId, {
        github_repo_url:  githubUrl.trim() || undefined,
        description:      description.trim() || undefined,
        injection_mode:   injectionMode || undefined,
        data_categories:  dataCategories.length ? dataCategories : undefined,
        has_write_ops:    hasWriteOps ?? undefined,
      })
      setStep('review')
    } catch (e) { setError(friendlyError(e)) }
    finally { setBusy(false) }
  }

  async function submitForReview() {
    if (!serverId) return
    setError('')
    setBusy(true)
    try {
      const res = await submissions.submit(serverId)
      setSubmissionStatus(res.submission_status)
      setStep('submitted')
    } catch (e) { setError(friendlyError(e)) }
    finally { setBusy(false) }
  }

  function toggleCategory(v: string) {
    setDataCategories(prev =>
      prev.includes(v) ? prev.filter(c => c !== v) : [...prev, v]
    )
  }

  function reset() {
    setStep('url'); setServerId(''); setSubmissionStatus('draft'); setPrompts(null)
    setName(''); setGithubUrl(''); setDescription('')
    setInjectionMode(''); setDataCategories([]); setHasWriteOps(null); setError('')
  }

  const stepOrder: Step[] = ['url', 'details', 'review', 'submitted']
  const stepLabels: Record<Step, string> = {
    url: '1. GitHub URL', details: '2. Configuration', review: '3. Review', submitted: 'Submitted',
  }
  const currentIdx = stepOrder.indexOf(step)

  return (
    <div className="wizard">
      {/* Step progress */}
      <div className="wizard__steps" aria-label="Wizard progress">
        {stepOrder.slice(0, -1).map((s, i) => (
          <div key={s} className={`wizard__step ${i < currentIdx ? 'wizard__step--done' : ''} ${i === currentIdx ? 'wizard__step--active' : ''}`}>
            <span className="wizard__step-num">{i < currentIdx ? '✓' : i + 1}</span>
            <span className="wizard__step-label">{stepLabels[s]}</span>
            {i < stepOrder.length - 2 && <span className="wizard__step-sep" aria-hidden>›</span>}
          </div>
        ))}
      </div>

      {error && (
        <div className="wizard__error" role="alert">
          {error}<button onClick={() => setError('')}>✕</button>
        </div>
      )}

      {/* ── Step 1: GitHub URL ───────────────────────────────────────────────── */}
      {step === 'url' && (
        <section className="wizard__panel">
          <h2 className="wizard__title">Request a new AI tool server</h2>
          <p className="wizard__desc">
            Point us to the GitHub repository for the MCP server you'd like to add.
            Our security team will automatically scan the code and review the configuration before it goes live.
          </p>

          <label className="wizard__label">
            Server identifier <span aria-hidden className="wizard__required">*</span>
            <input
              className="wizard__input"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="e.g. company-docs-search"
              aria-describedby="name-hint"
            />
            <span id="name-hint" className="wizard__hint">
              Lowercase letters, numbers, hyphens — no spaces. This is the ID your team uses in Claude Code (<code>server-name</code>).
            </span>
          </label>

          <label className="wizard__label">
            GitHub repository URL
            <input
              className="wizard__input"
              value={githubUrl}
              onChange={e => setGithubUrl(e.target.value)}
              placeholder="https://github.com/your-org/your-mcp-server"
              type="url"
              aria-describedby="url-hint"
            />
            <span id="url-hint" className="wizard__hint">
              Must be a <strong>public</strong> GitHub HTTPS URL.
              Our scanner clones and audits it automatically.
              No repository yet? Leave this blank — we'll generate a starter template.
            </span>
          </label>

          <div className="wizard__info-box">
            <h3 className="wizard__info-title">What to look for in the repository</h3>
            <ul className="wizard__info-list">
              <li>A <code>server.py</code> or <code>index.ts</code> with MCP <code>@tool</code> definitions</li>
              <li>A <code>README.md</code> describing what the server does and what data it accesses</li>
              <li>Authentication requirements — API keys, OAuth scopes, service accounts</li>
              <li>Data sensitivity — does it touch PII, internal docs, financial or health data?</li>
              <li>Network access — which external services does it call, and does it write data?</li>
            </ul>
          </div>

          <button
            className="wizard__btn wizard__btn--primary"
            onClick={createDraft}
            disabled={busy || !name.trim()}
          >
            {busy ? 'Creating…' : 'Continue →'}
          </button>
        </section>
      )}

      {/* ── Step 2: Configuration ────────────────────────────────────────────── */}
      {step === 'details' && (
        <section className="wizard__panel">
          <h2 className="wizard__title">Configure <em>{name}</em></h2>

          {/* AI-generated prompts for this mode */}
          {prompts && prompts.prompts.length > 0 && (
            <div className="wizard__prompts">
              <p className="wizard__prompts-intro">
                Answer these questions to help the security team review your submission.
                Use them as a guide while filling in the fields below.
              </p>
              {prompts.prompts.map((p, i) => (
                <details key={p.id} className="wizard__prompt-item" open={i === 0}>
                  <summary className="wizard__prompt-title">{p.id.replace(/_/g, ' ')}</summary>
                  <p className="wizard__prompt-text">{p.prompt}</p>
                </details>
              ))}
            </div>
          )}

          <label className="wizard__label">
            Description <span aria-hidden className="wizard__required">*</span>
            <textarea
              className="wizard__input wizard__input--textarea"
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="What does this server do? What problem does it solve? What data does it access?"
              rows={4}
            />
            <span className="wizard__hint">
              Tip: imagine a security auditor asks "why does this tool need access to [X]?" — write that answer here.
            </span>
          </label>

          <fieldset className="wizard__fieldset">
            <legend className="wizard__legend">Authentication method <span aria-hidden className="wizard__required">*</span></legend>
            <p className="wizard__hint wizard__hint--top">How does the server authenticate to the upstream service it calls?</p>
            {AUTH_MODES.map(m => (
              <label key={m.value} className="wizard__radio">
                <input type="radio" name="injection_mode" value={m.value}
                  checked={injectionMode === m.value} onChange={() => setInjectionMode(m.value)} />
                {m.label}
              </label>
            ))}
          </fieldset>

          <fieldset className="wizard__fieldset">
            <legend className="wizard__legend">Data categories this server accesses</legend>
            <p className="wizard__hint wizard__hint--top">Select all that apply. When in doubt, include the category.</p>
            <div className="wizard__checkboxes">
              {DATA_CATEGORIES.map(c => (
                <label key={c.value} className="wizard__checkbox">
                  <input type="checkbox" value={c.value}
                    checked={dataCategories.includes(c.value)} onChange={() => toggleCategory(c.value)} />
                  {c.label}
                </label>
              ))}
            </div>
          </fieldset>

          <fieldset className="wizard__fieldset">
            <legend className="wizard__legend">Does this server write or modify data? <span aria-hidden className="wizard__required">*</span></legend>
            <p className="wizard__hint wizard__hint--top">
              "Write" means any create, update, delete, send, or execute operation on the upstream service.
              Read-only servers are easier to approve.
            </p>
            <label className="wizard__radio">
              <input type="radio" name="has_write_ops" checked={hasWriteOps === false} onChange={() => setHasWriteOps(false)} />
              Read only — no side effects on the upstream service
            </label>
            <label className="wizard__radio">
              <input type="radio" name="has_write_ops" checked={hasWriteOps === true} onChange={() => setHasWriteOps(true)} />
              Read + write — can create, update, delete, send, or execute
            </label>
          </fieldset>

          <div className="wizard__actions">
            <button className="wizard__btn" onClick={() => setStep('url')} disabled={busy}>← Back</button>
            <button
              className="wizard__btn wizard__btn--primary"
              onClick={saveDetails}
              disabled={busy || !description.trim() || !injectionMode || hasWriteOps === null}
            >
              {busy ? 'Saving…' : 'Review submission →'}
            </button>
          </div>
        </section>
      )}

      {/* ── Step 3: Review ──────────────────────────────────────────────────── */}
      {step === 'review' && (
        <section className="wizard__panel">
          <h2 className="wizard__title">Review before submitting</h2>
          <p className="wizard__desc">
            Once submitted, the security team will scan your repository and review the configuration.
            You'll be notified when the review is complete.
          </p>

          <dl className="wizard__summary">
            <dt>Server name</dt><dd><code>{name}</code></dd>
            {githubUrl && <>
              <dt>Repository</dt>
              <dd><a href={githubUrl} target="_blank" rel="noopener noreferrer">{githubUrl}</a></dd>
            </>}
            <dt>Description</dt><dd>{description}</dd>
            <dt>Authentication</dt><dd>{AUTH_MODES.find(m => m.value === injectionMode)?.label ?? injectionMode}</dd>
            <dt>Data accessed</dt>
            <dd>{dataCategories.map(c => DATA_CATEGORIES.find(d => d.value === c)?.label ?? c).join(', ') || '—'}</dd>
            <dt>Writes data?</dt><dd>{hasWriteOps ? 'Yes — read + write' : 'No — read only'}</dd>
          </dl>

          <div className="wizard__actions">
            <button className="wizard__btn" onClick={() => setStep('details')} disabled={busy}>← Edit</button>
            <button className="wizard__btn wizard__btn--primary" onClick={submitForReview} disabled={busy}>
              {busy ? 'Submitting…' : 'Submit for security review'}
            </button>
          </div>
        </section>
      )}

      {/* ── Step 4: Submitted ───────────────────────────────────────────────── */}
      {step === 'submitted' && (
        <section className="wizard__panel wizard__panel--success">
          <div className="wizard__success-icon" aria-hidden>✓</div>
          <h2 className="wizard__title">Submission received</h2>
          <p className="wizard__desc"><strong>{name}</strong> has been submitted for security review.</p>

          <div className="wizard__status-card">
            <span className="wizard__status-label">Status</span>
            <span className={`wizard__status-value wizard__status--${submissionStatus}`}>
              {STATUS_LABELS[submissionStatus] ?? submissionStatus}
            </span>
          </div>

          <div className="wizard__info-box">
            <h3 className="wizard__info-title">What happens next</h3>
            <ol className="wizard__info-list wizard__info-list--ordered">
              <li>Our scanner clones the repository and runs automated security checks</li>
              <li>A Security Auditor reviews the scan results, code, and your configuration answers</li>
              <li>You'll be notified when the review is complete (approved, rejected, or changes requested)</li>
              <li>Once approved, provide the running server URL so tools can be registered</li>
            </ol>
          </div>

          <button className="wizard__btn wizard__btn--primary" onClick={reset}>Submit another</button>
        </section>
      )}
    </div>
  )
}
