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

// Issue #1: Convert raw server slug into a readable display name.
// display_name (if the backend provides it) is preferred; otherwise the slug
// is title-cased with hyphens/underscores replaced by spaces.
function toDisplayName(mcp: AvailableMcp): string {
  if (mcp.display_name) return mcp.display_name
  return mcp.server_name
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase())
}

// Issue #4: Map raw internal status codes to plain-language labels that a
// non-technical stakeholder can understand without security jargon.
const STATUS_LABELS: Record<string, string> = {
  active: 'Available',
  quarantined: 'Suspended — contact your administrator',
  pending: 'Awaiting approval',
}
function friendlyStatus(status: string): string {
  return STATUS_LABELS[status] ?? status
}

function ToggleSwitch({ enabled, loading, onToggle, label }: {
  enabled: boolean; loading: boolean; onToggle: () => void; label: string
}) {
  // Issue #3: Add visible ON/OFF text label so non-technical users understand
  // what the control does and what its current state is, independent of
  // toggle-switch convention familiarity.
  return (
    <div className="toggle-wrapper" data-testid="toggle-wrapper">
      <span className="toggle-wrapper__label" aria-hidden="true">
        {enabled ? 'ON' : 'OFF'}
      </span>
      <button
        onClick={onToggle}
        disabled={loading}
        // Contextual label includes server/function name (issue #6)
        aria-label={enabled ? `Disable ${label}` : `Enable ${label}`}
        // aria-pressed declares toggle-button state for screen readers (issue #7)
        aria-pressed={enabled}
        // aria-busy signals in-flight request to assistive tech (issue #9)
        aria-busy={loading}
        data-testid="toggle-btn"
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
    </div>
  )
}

// Issue #7: Accessible tooltip that is reachable on touch devices.
// Clicking/tapping the ⓘ button toggles a visible popover; keyboard users get
// focus-triggered visibility. This replaces the hover-only `title` attribute.
function InfoTooltip({ text }: { text: string }) {
  const [open, setOpen] = useState(false)
  const id = useId()
  return (
    <span className="info-tooltip" data-testid="info-tooltip">
      <button
        type="button"
        className="info-tooltip__trigger"
        aria-label="About AI tools"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen(v => !v)}
        onBlur={() => setOpen(false)}
      >
        ⓘ
      </button>
      {open && (
        <span id={id} role="tooltip" className="info-tooltip__popover">
          {text}
        </span>
      )}
    </span>
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
  // Issue #8: track whether the last load succeeded so Dismiss can show a
  // meaningful explanation when the server list is empty after a reload failure.
  const [dataStale, setDataStale] = useState(false)
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
      setDataStale(false)
      setStatus('ready')
    } catch (e) {
      setError(friendlyError(e))
      setDataStale(true)
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

  // Issue #5: use consistent term "tool" throughout — placeholder, counter, and
  // empty states all say "tool" (never mixing "server" and "tool" in the same view).
  const filtered = mcps.filter(m =>
    !query || m.server_name.toLowerCase().includes(query.toLowerCase()) ||
    toDisplayName(m).toLowerCase().includes(query.toLowerCase()) ||
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
      <div className="portal__error" role="alert" data-testid="portal-error">
        {error || 'An unexpected error occurred.'}
        <div className="portal__error-actions">
          <button onClick={() => { setError(''); load() }}>Retry</button>
          {/* Issue #8: Dismiss moves to 'ready' but shows a notice when data is
              stale so the user is not left with a blank list and no explanation. */}
          <button onClick={() => { setError(''); setStatus('ready') }}>
            {dataStale ? 'Show last loaded data' : 'Dismiss'}
          </button>
        </div>
        {dataStale && (
          <p className="portal__error-stale-notice">
            The tool list below may be out of date. Use Retry to reload.
          </p>
        )}
      </div>
    </div>
  )

  return (
    <div className="portal animate-in">
      {/* aria-live region for screen reader announcements (issue #10) */}
      <div id={liveRegionId} aria-live="polite" aria-atomic="true" className="sr-only" />

      <header className="portal__header">
        <div>
          {/* Issue #7: ⓘ is now a clickable/tappable popover, not hover-only */}
          <h1 className="portal__title font-display" data-testid="portal-title">
            AI Tool Catalog
            <InfoTooltip text="MCP (Model Context Protocol) servers provide tools and data sources that your AI assistant can use. Enabling a tool grants the AI access to its capabilities." />
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
        <div className="portal__error" role="alert" data-testid="portal-error">
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
          // Issue #5: placeholder and counter both use "tool" — no mixing of terminology
          placeholder="Search AI tools…"
          className="search-box__input"
          aria-label="Search AI tools"
          data-testid="search-input"
        />
        {/* Issue #5: counter says "tool / tools" to match the search placeholder */}
        <span className="portal__count" data-testid="tool-count">
          {filtered.length} {filtered.length !== 1 ? 'tools' : 'tool'}
        </span>
      </div>

      <div className="portal__server-list" data-testid="server-list">
        {/* Issue #6: Empty state includes a mailto CTA so the user can reach the
            administrator instead of seeing a dead-end message. */}
        {filtered.length === 0 && (
          <div className="portal__empty" role="status" data-testid="empty-state">
            {query
              ? `No tools match "${query}". Try a different search term.`
              : (
                <>
                  No AI tools are available for your account.{' '}
                  <a
                    href="mailto:admin@example.com?subject=MCP%20Tool%20Access%20Request"
                    className="portal__empty-cta"
                  >
                    Contact your administrator
                  </a>{' '}
                  to request access.
                </>
              )}
          </div>
        )}

        {filtered.map(mcp => {
          const enabled = getEnabledForServer(mcp.server_name)
          const togKey = `mcp:${mcp.server_name}`
          const profileEntry = profileMap[mcp.server_name]
          const isExpanded = expandedMcp === mcp.server_name
          // Validate status against allowlist before CSS interpolation (issue #22)
          const safeStatus = safeMcpStatus(mcp.status)
          // Issue #1: use human-readable display name instead of raw slug
          const displayName = toDisplayName(mcp)

          // Issue #2: always render an expand button for discovery, even when
          // the server is not yet in the user's profile (never enabled before).
          // If the profile entry exists, show the real function list; otherwise
          // show a placeholder explaining that functions become visible after
          // the tool is enabled.
          const hasProfileFunctions = profileEntry && profileEntry.functions.length > 0
          const canExpand = hasProfileFunctions || !profileEntry  // show button for unknowns too

          return (
            <div
              key={mcp.server_name}
              className={`server-card ${enabled ? 'server-card--enabled' : ''}`}
              data-testid="server-card"
              data-server={mcp.server_name}
            >
              <div className="server-card__header">
                <div className="server-card__info">
                  {/* Issue #1: display human-readable name; show slug as secondary */}
                  <div className="server-card__name" data-testid="server-card-name">
                    {displayName}
                  </div>
                  {displayName !== mcp.server_name && (
                    <code className="server-card__slug">{mcp.server_name}</code>
                  )}
                  <div className="server-card__desc">{mcp.description}</div>
                  <div className="server-card__status">
                    {/* aria-hidden on decorative dot; status text provides the accessible label.
                        Shape prefix differentiates states for color-blind users (issue #11). */}
                    <span
                      className={`status-dot status-dot--${safeStatus}`}
                      aria-hidden="true"
                    />
                    {/* Issue #4: plain-language status instead of raw jargon */}
                    <span className="status-dot__label">
                      {friendlyStatus(safeStatus)}
                    </span>
                  </div>
                </div>
                <div className="server-card__controls">
                  {/* Issue #2: always render expand button so new users can
                      discover what a tool offers before enabling it. */}
                  {canExpand && (
                    <button
                      className="server-card__expand"
                      data-testid="server-card-expand"
                      onClick={() => setExpandedMcp(isExpanded ? null : mcp.server_name)}
                      aria-expanded={isExpanded}
                      aria-controls={`fn-list-${mcp.server_name}`}
                    >
                      {isExpanded ? '▲' : '▼'} Tools
                      {hasProfileFunctions ? ` (${profileEntry.functions.length})` : ''}
                    </button>
                  )}
                  <ToggleSwitch
                    enabled={enabled}
                    loading={toggling.has(togKey)}
                    onToggle={() => toggle(mcp.server_name, enabled)}
                    label={displayName}
                  />
                </div>
              </div>

              {isExpanded && (
                <div
                  id={`fn-list-${mcp.server_name}`}
                  className="server-card__functions"
                  data-testid="fn-list"
                >
                  {/* Issue #2: if not yet in profile, explain what happens on enable */}
                  {!profileEntry && (
                    <p className="server-card__functions-placeholder">
                      Enable this tool to see and manage its individual functions.
                    </p>
                  )}

                  {profileEntry && profileEntry.functions.length === 0 && (
                    <p className="server-card__functions-placeholder">
                      This tool has no individual functions to configure.
                    </p>
                  )}

                  {profileEntry && profileEntry.functions.map((fn: McpFunction) => {
                    const fnKey = `fn:${mcp.server_name}:${fn.name}`
                    // Plain-language label: prefer description, fall back to name (issue #13)
                    const displayLabel = fn.description && fn.description !== fn.name
                      ? fn.description
                      : fn.name
                    return (
                      <div key={fn.name} className="fn-row" data-testid="fn-row">
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
                          label={`${fn.description || fn.name} in ${displayName}`}
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
