import { useState, useEffect } from 'react'
import { adminSubmissions, type Submission } from '@/services/api'
import './SubmissionReview.css'

const AUTH_LABELS: Record<string, string> = {
  none:                     'No authentication',
  service:                  'Service account (static key)',
  oauth_user_token:         'OAuth — user token passthrough',
  kc_token_exchange:        'OAuth — Keycloak token exchange',
  entra_client_credentials: 'Azure Entra — client credentials',
  entra_user_token:         'Azure Entra — delegated user token',
  service_account:          'Service account',
  passthrough:              'Passthrough',
}

const DATA_LABELS: Record<string, string> = {
  public:         'Public information',
  internal_docs:  'Internal documents',
  source_code:    'Source code / repositories',
  email_calendar: 'Email / calendar',
  pii:            'Personal data (PII)',
  health:         'Health / medical data',
  financial:      'Financial data',
  infrastructure: 'Infrastructure / system config',
}

const STATUS_LABELS: Record<string, string> = {
  draft:                'Draft',
  scan_pending:         'Queued for scan',
  scan_running:         'Scanning',
  scan_blocked:         'Scan blocked',
  awaiting_review:      'Awaiting review',
  changes_requested:    'Changes requested',
  approved_pending_url: 'Approved — pending URL',
  approved:             'Approved',
  rejected:             'Rejected',
}

function friendlyError(e: unknown): string {
  console.error('[SubmissionReview]', e)
  return 'Action failed. Please try again.'
}

type ScanFinding = { severity?: string; rule?: string; message?: string; file?: string; line?: number }

function ScanReport({ report }: { report: Array<Record<string, unknown>> | null }) {
  if (!report) return <p className="review__no-data">No scan results yet.</p>
  if (report.length === 0) return <p className="review__scan-clean">✓ No issues found by automated scan.</p>

  const findings = report as unknown as ScanFinding[]
  const counts: Record<string, number> = {}
  findings.forEach(f => { const s = (f.severity ?? 'info').toLowerCase(); counts[s] = (counts[s] ?? 0) + 1 })

  return (
    <div className="review__scan">
      <div className="review__scan-summary">
        {Object.entries(counts).map(([k, v]) => (
          <span key={k} className={`review__scan-badge review__scan-badge--${k}`}>{k}: {v}</span>
        ))}
      </div>
      <table className="review__scan-table">
        <thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th></tr></thead>
        <tbody>
          {findings.map((f, i) => {
            const sev = (f.severity ?? 'info').toLowerCase()
            return (
              <tr key={i} className={`review__scan-row review__scan-row--${sev}`}>
                <td><span className={`review__sev review__sev--${sev}`}>{f.severity ?? 'info'}</span></td>
                <td><code className="review__code">{f.rule ?? '—'}</code></td>
                <td>{f.file && <code className="review__code">{f.file}{f.line ? `:${f.line}` : ''}</code>}</td>
                <td>{f.message}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function DetailCard({ sub }: { sub: Submission }) {
  return (
    <div className="review__detail">
      <h3 className="review__section-title">Configuration</h3>
      <dl className="review__dl">
        <dt>Server name</dt><dd><code>{sub.name}</code></dd>
        <dt>Auth method</dt><dd>{AUTH_LABELS[sub.injection_mode ?? ''] ?? sub.injection_mode ?? '—'}</dd>
        <dt>Writes data?</dt>
        <dd>{sub.has_write_ops === null ? '—' : sub.has_write_ops ? 'Yes — read + write' : 'No — read only'}</dd>
        <dt>Data categories</dt>
        <dd>
          {(sub.data_categories ?? []).length
            ? (sub.data_categories ?? []).map(c => (
                <span key={c} className="review__tag">{DATA_LABELS[c] ?? c}</span>
              ))
            : '—'}
        </dd>
        <dt>Submitter</dt><dd><code>{sub.owner_sub ?? '—'}</code></dd>
        {sub.reviewed_by && <><dt>Reviewed by</dt><dd><code>{sub.reviewed_by}</code></dd></>}
        {sub.reviewed_at && <><dt>Reviewed at</dt><dd>{new Date(sub.reviewed_at).toLocaleString()}</dd></>}
        <dt>Updated</dt><dd>{sub.updated_at ? new Date(sub.updated_at).toLocaleString() : '—'}</dd>
      </dl>

      <h3 className="review__section-title">Backend &amp; credentials</h3>
      <dl className="review__dl">
        <dt>{sub.upstream_url ? 'Backend URL (live)' : 'Backend URL (requested)'}</dt>
        <dd>
          {sub.upstream_url
            ? <code>{sub.upstream_url}</code>
            : sub.requested_upstream_url
              ? <code>{sub.requested_upstream_url}</code>
              : sub.github_repo_url
                ? <span className="review__no-data">Not stated — check the description before approving</span>
                : 'No backend yet — no-code scaffold submission'}
        </dd>
        {sub.service_name && <><dt>Credential / service name</dt><dd><code>{sub.service_name}</code></dd></>}
        {sub.upstream_idp_type && <><dt>Upstream identity provider</dt><dd>{sub.upstream_idp_type}</dd></>}
        {sub.upstream_idp_config && (
          <>
            <dt>Requested IdP config</dt>
            <dd><pre className="review__idp-config">{JSON.stringify(sub.upstream_idp_config, null, 2)}</pre></dd>
          </>
        )}
      </dl>

      {sub.description && (
        <>
          <h3 className="review__section-title">Description</h3>
          <p className="review__description">{sub.description}</p>
        </>
      )}

      {sub.review_notes && (
        <>
          <h3 className="review__section-title">Previous review notes</h3>
          <p className="review__description">{sub.review_notes}</p>
        </>
      )}

      {sub.github_repo_url && (
        <>
          <h3 className="review__section-title">Source code</h3>
          <div className="review__github">
            <a href={sub.github_repo_url} target="_blank" rel="noopener noreferrer" className="review__github-link">
              <span aria-hidden>⎇</span> {sub.github_repo_url}
            </a>
            <a href={`${sub.github_repo_url}/tree/main`} target="_blank" rel="noopener noreferrer"
              className="review__github-link review__github-link--small">
              Browse code ↗
            </a>
          </div>
        </>
      )}

      <h3 className="review__section-title">Automated scan results</h3>
      <ScanReport report={sub.scan_report} />
    </div>
  )
}

export function SubmissionReview() {
  const [subs, setSubs]         = useState<Submission[]>([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState('')
  const [selected, setSelected] = useState<Submission | null>(null)
  const [note, setNote]         = useState('')
  const [busy, setBusy]         = useState(false)
  const [actionMsg, setActionMsg] = useState('')

  async function load() {
    setLoading(true); setError('')
    try {
      const res = await adminSubmissions.list()
      setSubs(res.submissions)
    } catch (e) { setError(friendlyError(e)) }
    finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  async function act(action: 'approve' | 'reject' | 'request-changes') {
    if (!selected) return
    setBusy(true); setActionMsg('')
    try {
      if (action === 'approve')          await adminSubmissions.approve(selected.server_id, note)
      else if (action === 'reject')      await adminSubmissions.reject(selected.server_id, note)
      else                               await adminSubmissions.requestChanges(selected.server_id, note)
      setNote('')
      setActionMsg('Decision recorded.')
      await load()
      // refresh selected with updated data
      setSubs(prev => {
        const updated = prev.find(s => s.server_id === selected.server_id)
        if (updated) setSelected(updated)
        return prev
      })
    } catch (e) { setActionMsg(friendlyError(e)) }
    finally { setBusy(false) }
  }

  const reviewable = selected &&
    ['awaiting_review', 'scan_blocked', 'changes_requested'].includes(selected.submission_status)

  return (
    <div className="review">
      <div className="review__list-panel">
        <div className="review__list-header">
          <h2 className="review__list-title">MCP Server Requests</h2>
          <button className="review__refresh" onClick={load} disabled={loading} aria-label="Refresh">↺</button>
        </div>

        {error && <p className="review__error" role="alert">{error}</p>}
        {loading && <p className="review__loading">Loading…</p>}
        {!loading && subs.length === 0 && <p className="review__empty">No submissions in the queue.</p>}

        <ul className="review__list">
          {subs.map(s => (
            <li key={s.server_id}>
              <button
                className={`review__item ${selected?.server_id === s.server_id ? 'review__item--active' : ''}`}
                onClick={() => { setSelected(s); setNote(''); setActionMsg('') }}
              >
                <div className="review__item-name">{s.name}</div>
                <div className="review__item-meta">
                  <span className={`review__status review__status--${s.submission_status}`}>
                    {STATUS_LABELS[s.submission_status] ?? s.submission_status}
                  </span>
                  <span className="review__item-date">
                    {s.updated_at
                      ? new Date(s.updated_at).toLocaleDateString()
                      : new Date(s.created_at).toLocaleDateString()}
                  </span>
                </div>
              </button>
            </li>
          ))}
        </ul>
      </div>

      <div className="review__detail-panel">
        {!selected ? (
          <p className="review__placeholder">Select a submission from the list to review.</p>
        ) : (
          <>
            <div className="review__detail-header">
              <div>
                <h2 className="review__detail-title">{selected.name}</h2>
                <span className={`review__status review__status--lg review__status--${selected.submission_status}`}>
                  {STATUS_LABELS[selected.submission_status] ?? selected.submission_status}
                </span>
              </div>
            </div>

            <DetailCard sub={selected} />

            {reviewable && (
              <div className="review__actions">
                <h3 className="review__section-title">Review decision</h3>
                <textarea
                  className="review__note"
                  value={note}
                  onChange={e => setNote(e.target.value)}
                  placeholder="Optional note to the submitter…"
                  rows={3}
                />
                {actionMsg && <p className="review__action-msg">{actionMsg}</p>}
                <div className="review__action-btns">
                  <button className="review__btn review__btn--approve" onClick={() => act('approve')} disabled={busy}>
                    ✓ Approve
                  </button>
                  <button className="review__btn review__btn--changes" onClick={() => act('request-changes')} disabled={busy}>
                    ↩ Request changes
                  </button>
                  <button className="review__btn review__btn--reject" onClick={() => act('reject')} disabled={busy}>
                    ✕ Reject
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
