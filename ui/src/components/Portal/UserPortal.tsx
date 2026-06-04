import { useState } from 'react'
import { Badge } from '../common/Badge'
import { Card } from '../common/Card'
import { Button } from '../common/Button'
import type { Role } from '@/types'
import './UserPortal.css'

// Mock: in production, role comes from the session JWT
const MOCK_ROLE: Role = 'analyst'

interface Tool {
  id: string; name: string; server: string; description: string
  risk_level: 'low' | 'medium' | 'high' | 'critical'
  allowed_roles: Role[]
  last_used?: string
  call_count_7d: number
}

const TOOLS: Tool[] = [
  { id: 't1', name: 'ping', server: 'poc-echo-server', description: 'Liveness check — returns server identity and timestamp', risk_level: 'low', allowed_roles: ['viewer','editor','analyst','admin'], last_used: '2m ago', call_count_7d: 142 },
  { id: 't2', name: 'echo_args', server: 'poc-echo-server', description: 'Reflect back supplied arguments with integrity hash', risk_level: 'low', allowed_roles: ['viewer','editor','analyst','admin'], call_count_7d: 38 },
  { id: 't3', name: 'notes_read', server: 'poc-notes-server', description: 'Read notes for the authenticated user (per-user isolation)', risk_level: 'low', allowed_roles: ['editor','analyst','admin'], last_used: '1h ago', call_count_7d: 77 },
  { id: 't4', name: 'notes_write', server: 'poc-notes-server', description: 'Write or update a note (per-user, keyed by user sub)', risk_level: 'medium', allowed_roles: ['editor','analyst','admin'], call_count_7d: 21 },
  { id: 't5', name: 'notes_delete', server: 'poc-notes-server', description: 'Permanently delete a note', risk_level: 'medium', allowed_roles: ['editor','analyst','admin'], call_count_7d: 3 },
  { id: 't6', name: 'search', server: 'poc-search-server', description: 'Full-text search across the built-in document corpus', risk_level: 'low', allowed_roles: ['analyst','admin'], last_used: '12m ago', call_count_7d: 310 },
  { id: 't7', name: 'fetch_url', server: 'poc-search-server', description: 'Fetch and return contents from an allowlisted URL', risk_level: 'medium', allowed_roles: ['analyst','admin'], call_count_7d: 44 },
  { id: 't8', name: 'summarize', server: 'poc-search-server', description: 'Summarize a document from the search corpus', risk_level: 'low', allowed_roles: ['analyst','admin'], call_count_7d: 89 },
]

const RISK_ORDER = { low: 0, medium: 1, high: 2, critical: 3 }

export function UserPortal() {
  const [query, setQuery] = useState('')
  const [serverFilter, setServerFilter] = useState('all')

  const servers = [...new Set(TOOLS.map(t => t.server))]
  const canUse = (t: Tool) => t.allowed_roles.includes(MOCK_ROLE)

  const filtered = TOOLS
    .filter(t => canUse(t) || true) // show all, grey out inaccessible
    .filter(t => serverFilter === 'all' || t.server === serverFilter)
    .filter(t => !query || t.name.includes(query) || t.description.toLowerCase().includes(query.toLowerCase()))

  return (
    <div className="portal animate-in">
      <header className="portal__header">
        <div>
          <h1 className="portal__title font-display">Tool Catalog</h1>
          <p className="portal__subtitle">Browse and invoke tools according to your role permissions</p>
        </div>
        <div className="portal__role-chip">
          <span className="portal__role-label">Signed in as</span>
          <Badge label={MOCK_ROLE} variant="info" dot />
        </div>
      </header>

      {/* Search + filter */}
      <div className="portal__toolbar">
        <div className="search-box">
          <span className="search-box__icon" aria-hidden>⌕</span>
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Search tools…"
            className="search-box__input"
          />
        </div>
        <div className="portal__filters">
          {['all', ...servers].map(s => (
            <button
              key={s}
              className={`filter-tab ${serverFilter === s ? 'filter-tab--active' : ''}`}
              onClick={() => setServerFilter(s)}
            >
              {s === 'all' ? 'All servers' : s.replace('-server','').replace('poc-','')}
            </button>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div className="portal__stats">
        <span className="portal__stat"><strong>{filtered.filter(canUse).length}</strong> accessible</span>
        <span className="portal__stat-sep">·</span>
        <span className="portal__stat"><strong>{filtered.length}</strong> total</span>
        <span className="portal__stat-sep">·</span>
        <span className="portal__stat text-muted">{filtered.filter(t => !canUse(t)).length} restricted</span>
      </div>

      {/* Tool grid */}
      <div className="tool-grid">
        {filtered.map((tool, i) => (
          <ToolCard key={tool.id} tool={tool} accessible={canUse(tool)} delay={i * 30} />
        ))}
      </div>
    </div>
  )
}

function ToolCard({ tool, accessible, delay }: { tool: Tool; accessible: boolean; delay: number }) {
  const [invoking, setInvoking] = useState(false)
  const [result, setResult] = useState<string | null>(null)

  const invoke = async () => {
    if (!accessible) return
    setInvoking(true)
    await new Promise(r => setTimeout(r, 600))
    setInvoking(false)
    setResult(`{"status":"ok","tool":"${tool.name}","ts":"${new Date().toISOString()}"}`)
    setTimeout(() => setResult(null), 4000)
  }

  return (
    <div
      className={`tool-card ${!accessible ? 'tool-card--locked' : ''}`}
      style={{ animationDelay: `${delay}ms` }}
    >
      <div className="tool-card__header">
        <div className="tool-card__name-row">
          <code className="tool-card__name">{tool.name}</code>
          <Badge label={tool.risk_level} variant={RISK_ORDER[tool.risk_level] >= 2 ? 'high' : 'low'} />
        </div>
        <Badge label={tool.server.replace('-server','').replace('poc-','')} variant="neutral" />
      </div>

      <p className="tool-card__desc">{tool.description}</p>

      <div className="tool-card__meta">
        <span title="7-day calls">↑ {tool.call_count_7d}</span>
        {tool.last_used && <span>used {tool.last_used}</span>}
      </div>

      {result && (
        <div className="tool-card__result">
          <code>{result}</code>
        </div>
      )}

      <div className="tool-card__footer">
        {accessible
          ? <Button size="sm" variant="primary" loading={invoking} onClick={invoke}>Invoke</Button>
          : <span className="tool-card__locked-msg">🔒 Requires {tool.allowed_roles[0]} role</span>
        }
      </div>
    </div>
  )
}
