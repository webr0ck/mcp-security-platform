import { useState, useEffect, useCallback, useId } from 'react'
import { api, type AvailableMcp, type McpEntry, type McpFunction, safeMcpStatus } from '@/services/api'
import { useAuth } from '@/auth/AuthContext'
import './UserPortal.css'

type Status = 'loading' | 'error' | 'ready'

// User-facing copy for HTTP error codes (issue #16 — no raw error strings)
function friendlyError(e: unknown): string {
  const msg = String(e)
  if (msg.includes('401') || msg.includes('403')) return 'You are not authorised to perform this action. Try signing out and back in.'
  if (msg.includes('503') || msg.includes('502')) return 'The service is temporarily unavailable. Please try again in a moment.'
  if (msg.includes('404')) return 'The requested resource was not found.'
  if (msg.includes('Failed to fetch') || msg.includes('NetworkError')) return 'Could not reach the server. Check your network connection.'
  // Log full error for debugging but never surface raw details to the user
  console.error('[UserPortal] API error:', e)
  return 'Something went wrong. Please try again.'
}

function ToggleSwitch({ enabled, loading, onToggle, label }: {
  enabled: boolean; loading: boolean; onToggle: () => void; label: string
}) {
  return (
    <button
      onClick={onToggle}
      disabled={loading}
      // Contextual label includes server/function name (issue #6)
      aria-label={enabled ? `Disable ${label}` : `Enable ${label}`}
      // aria-pressed declares toggle-button state for screen readers (issue #7)
      aria-pressed={enabled}
      // aria-busy signals in-flight request to assistive tech (issue #9)
      aria-busy={loading}
      style={{
        width: 40, height: 22, borderRadius: 11, border: 'none', cursor: loading ? 'wait' : 'pointer',
        background: enabled ? '#00d4ff' : '#2a3a4a', position: 'relative',
        transition: 'background 0.2s', flexShrink: 0,
        // outline:none removed — browser default focus ring restored (issue #8 / WCAG 2.4.7)
      }}
    >
      <span style={{
        position: 'absolute', top: 3, left: enabled ? 20 : 3,
        width: 16, height: 16, borderRadius: 8, background: '#fff',
        transition: 'left 0.2s',
      }} />
    </button>
  )
}

export function UserPortal() {
  const auth = useAuth()
  const principal = auth.username ?? 'me'

  const [status, setStatus] = useState<Status>('loading')
  const [mcps, setMcps] = useState<AvailableMcp[]>([])
  const [profile, setProfile] = useState<McpEntry[]>([])
  const [toggling, setToggling] = useState<Set<string>>(new Set())
  const [query, setQuery] = useState('')
  const [expandedMcp, setExpandedMcp] = useState<string | null>(null)
  const [error, setError] = useState('')
  // Unique ID for aria-live region (issue #10)
  const liveRegionId = useId()

  const load = useCallback(async () => {
    setError('')
    try {
      setStatus('loading')
      const [availList, prof] = await Promise.all([
        api.listAvailableMcps(),
        api.getProfile(principal),
      ])
      setMcps(availList)
      setProfile(prof.mcps)
      setStatus('ready')
    } catch (e) {
      setError(friendlyError(e))
      setStatus('error')
    }
  }, [principal])

  useEffect(() => { load() }, [load])

  const profileMap = Object.fromEntries(profile.map(m => [m.server_name, m]))

  const getEnabledForServer = (serverName: string) =>
    profileMap[serverName]?.enabled ?? false

  // Toggle only retries the specific failed operation, not a full reload (issue #17)
  const toggle = async (serverName: string, currentEnabled: boolean) => {
    const key = `mcp:${serverName}`
    setToggling(prev => new Set(prev).add(key))
    setError('')
    try {
      if (currentEnabled) {
        await api.disableMcp(principal, serverName)
      } else {
        await api.enableMcp(principal, serverName)
      }
      // Refresh only after success to keep UI consistent
      await load()
    } catch (e) {
      setError(friendlyError(e))
    } finally {
      setToggling(prev => { const s = new Set(prev); s.delete(key); return s })
    }
  }

  const toggleFn = async (serverName: string, fnName: string, currentEnabled: boolean) => {
    const key = `fn:${serverName}:${fnName}`
    setToggling(prev => new Set(prev).add(key))
    setError('')
    try {
      if (currentEnabled) {
        await api.disableFunction(principal, serverName, fnName)
      } else {
        await api.enableFunction(principal, serverName, fnName)
      }
      await load()
    } catch (e) {
      setError(friendlyError(e))
    } finally {
      setToggling(prev => { const s = new Set(prev); s.delete(key); return s })
    }
  }

  const filtered = mcps.filter(m =>
    !query || m.server_name.includes(query) ||
    (m.description ?? '').toLowerCase().includes(query.toLowerCase())
  )

  // Loading state — static div with no aria-live needed here since the
  // aria-live region below will announce transitions (issue #10)
  if (status === 'loading') return (
    <div className="portal">
      <div className="portal__loading" role="status" aria-live="polite">
        Loading your tool catalog…
      </div>
    </div>
  )

  // Error state: unconditional render when status='error', independent of
  // whether the error string is truthy (issue #3)
  if (status === 'error') return (
    <div className="portal">
      {/* aria-live region for screen reader announcements (issue #10) */}
      <div id={liveRegionId} aria-live="polite" aria-atomic="true" className="sr-only" />
      <div className="portal__error" role="alert">
        {error || 'An unexpected error occurred.'}
        <div className="portal__error-actions">
          <button onClick={() => { setError(''); load() }}>Retry</button>
          <button onClick={() => { setError(''); setStatus('ready') }}>Dismiss</button>
        </div>
      </div>
    </div>
  )

  return (
    <div className="portal animate-in">
      {/* aria-live region for screen reader announcements (issue #10) */}
      <div id={liveRegionId} aria-live="polite" aria-atomic="true" className="sr-only" />

      <header className="portal__header">
        <div>
          {/* Title with tooltip explaining MCP concept (issue #12) */}
          <h1 className="portal__title font-display">
            AI Tool Catalog
            <span
              className="portal__title-hint"
              title="MCP (Model Context Protocol) servers provide tools and data sources that your AI assistant can use. Enabling a server grants the AI access to its capabilities."
              aria-label="What is this? MCP servers provide tools your AI assistant can use. Enabling one grants access to its capabilities."
            >
              {' '}ⓘ
            </span>
          </h1>
          <p className="portal__subtitle">
            Enable or disable AI tools and data sources for your profile.
            Changes take effect immediately and control what your AI assistant can access.
          </p>
        </div>
        <div className="portal__role-chip">
          <span className="portal__role-label">Signed in as</span>
          <span className="portal__role-value">{auth.role ?? 'unknown'}</span>
        </div>
      </header>

      {/* Inline error banner (shown alongside ready content, e.g. toggle errors) */}
      {error && (
        <div className="portal__error" role="alert">
          {error}
          <div className="portal__error-actions">
            <button onClick={() => { setError(''); load() }}>Retry</button>
            <button onClick={() => setError('')}>Dismiss</button>
          </div>
        </div>
      )}

      <div className="portal__toolbar">
        <input
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="Search AI tools…"
          className="search-box__input"
          aria-label="Search AI tools"
        />
        <span className="portal__count">{filtered.length} server{filtered.length !== 1 ? 's' : ''}</span>
      </div>

      <div className="portal__server-list">
        {/* Empty state — no silent blank area (issue #15) */}
        {filtered.length === 0 && (
          <div className="portal__empty" role="status">
            {query
              ? `No tools match "${query}". Try a different search term.`
              : 'No AI tools are available for your account. Contact your administrator.'}
          </div>
        )}

        {filtered.map(mcp => {
          const enabled = getEnabledForServer(mcp.server_name)
          const togKey = `mcp:${mcp.server_name}`
          const profileEntry = profileMap[mcp.server_name]
          const isExpanded = expandedMcp === mcp.server_name
          // Validate status against allowlist before CSS interpolation (issue #22)
          const safeStatus = safeMcpStatus(mcp.status)

          return (
            <div key={mcp.server_name} className={`server-card ${enabled ? 'server-card--enabled' : ''}`}>
              <div className="server-card__header">
                <div className="server-card__info">
                  <div className="server-card__name">{mcp.server_name}</div>
                  <div className="server-card__desc">{mcp.description}</div>
                  <div className="server-card__status">
                    {/* aria-hidden on decorative dot; status text provides the accessible label.
                        Shape prefix differentiates states for color-blind users (issue #11). */}
                    <span
                      className={`status-dot status-dot--${safeStatus}`}
                      aria-hidden="true"
                    />
                    <span className="status-dot__label">
                      {safeStatus === 'active' && '● '}
                      {safeStatus === 'quarantined' && '■ '}
                      {safeStatus === 'pending' && '◐ '}
                      {safeStatus}
                    </span>
                  </div>
                </div>
                <div className="server-card__controls">
                  {profileEntry && profileEntry.functions.length > 0 && (
                    <button
                      className="server-card__expand"
                      onClick={() => setExpandedMcp(isExpanded ? null : mcp.server_name)}
                      aria-expanded={isExpanded}
                      aria-controls={`fn-list-${mcp.server_name}`}
                    >
                      {isExpanded ? '▲' : '▼'} Tools ({profileEntry.functions.length})
                    </button>
                  )}
                  <ToggleSwitch
                    enabled={enabled}
                    loading={toggling.has(togKey)}
                    onToggle={() => toggle(mcp.server_name, enabled)}
                    label={mcp.server_name}
                  />
                </div>
              </div>

              {isExpanded && profileEntry && (
                <div
                  id={`fn-list-${mcp.server_name}`}
                  className="server-card__functions"
                >
                  {profileEntry.functions.map((fn: McpFunction) => {
                    const fnKey = `fn:${mcp.server_name}:${fn.name}`
                    // Plain-language label: prefer description, fall back to name (issue #13)
                    const displayLabel = fn.description && fn.description !== fn.name
                      ? fn.description
                      : fn.name
                    return (
                      <div key={fn.name} className="fn-row">
                        <div className="fn-row__info">
                          {/* Show plain-language description prominently; raw name as secondary */}
                          <span className="fn-row__label">{displayLabel}</span>
                          {fn.description !== fn.name && (
                            <code className="fn-row__name">{fn.name}</code>
                          )}
                        </div>
                        <ToggleSwitch
                          enabled={fn.enabled}
                          loading={toggling.has(fnKey)}
                          onToggle={() => toggleFn(mcp.server_name, fn.name, fn.enabled)}
                          label={`${fn.description || fn.name} in ${mcp.server_name}`}
                        />
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
