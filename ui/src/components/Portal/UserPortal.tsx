import { useState, useEffect, useCallback } from 'react'
import { api, type AvailableMcp, type McpEntry, type McpFunction } from '@/services/api'
import { useAuth } from '@/auth/AuthContext'
import './UserPortal.css'

type Status = 'loading' | 'error' | 'ready'

function ToggleSwitch({ enabled, loading, onToggle }: {
  enabled: boolean; loading: boolean; onToggle: () => void
}) {
  return (
    <button
      onClick={onToggle}
      disabled={loading}
      aria-label={enabled ? 'Disable' : 'Enable'}
      style={{
        width: 40, height: 22, borderRadius: 11, border: 'none', cursor: loading ? 'wait' : 'pointer',
        background: enabled ? '#00d4ff' : '#2a3a4a', position: 'relative',
        transition: 'background 0.2s', outline: 'none', flexShrink: 0,
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

  const load = useCallback(async () => {
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
      setError(String(e))
      setStatus('error')
    }
  }, [principal])

  useEffect(() => { load() }, [load])

  const profileMap = Object.fromEntries(profile.map(m => [m.server_name, m]))

  const getEnabledForServer = (serverName: string) =>
    profileMap[serverName]?.enabled ?? false

  const toggle = async (serverName: string, currentEnabled: boolean) => {
    const key = `mcp:${serverName}`
    setToggling(prev => new Set(prev).add(key))
    try {
      if (currentEnabled) {
        await api.disableMcp(principal, serverName)
      } else {
        await api.enableMcp(principal, serverName)
      }
      await load()
    } catch (e) {
      setError(String(e))
    } finally {
      setToggling(prev => { const s = new Set(prev); s.delete(key); return s })
    }
  }

  const toggleFn = async (serverName: string, fnName: string, currentEnabled: boolean) => {
    const key = `fn:${serverName}:${fnName}`
    setToggling(prev => new Set(prev).add(key))
    try {
      if (currentEnabled) {
        await api.disableFunction(principal, serverName, fnName)
      } else {
        await api.enableFunction(principal, serverName, fnName)
      }
      await load()
    } catch (e) {
      setError(String(e))
    } finally {
      setToggling(prev => { const s = new Set(prev); s.delete(key); return s })
    }
  }

  const filtered = mcps.filter(m =>
    !query || m.server_name.includes(query) ||
    (m.description ?? '').toLowerCase().includes(query.toLowerCase())
  )

  if (status === 'loading') return (
    <div className="portal">
      <div className="portal__loading">Loading your tool catalog…</div>
    </div>
  )

  return (
    <div className="portal animate-in">
      <header className="portal__header">
        <div>
          <h1 className="portal__title font-display">MCP Catalog</h1>
          <p className="portal__subtitle">
            Enable or disable MCP servers and individual tools for your profile.
            Changes take effect immediately.
          </p>
        </div>
        <div className="portal__role-chip">
          <span className="portal__role-label">Signed in as</span>
          <span className="portal__role-value">{auth.role ?? 'unknown'}</span>
        </div>
      </header>

      {error && (
        <div className="portal__error" role="alert">
          {error}
          <button onClick={() => { setError(''); load() }}>Retry</button>
        </div>
      )}

      <div className="portal__toolbar">
        <input
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="Search MCP servers…"
          className="search-box__input"
        />
        <span className="portal__count">{filtered.length} server{filtered.length !== 1 ? 's' : ''}</span>
      </div>

      <div className="portal__server-list">
        {filtered.map(mcp => {
          const enabled = getEnabledForServer(mcp.server_name)
          const togKey = `mcp:${mcp.server_name}`
          const profileEntry = profileMap[mcp.server_name]
          const isExpanded = expandedMcp === mcp.server_name

          return (
            <div key={mcp.server_name} className={`server-card ${enabled ? 'server-card--enabled' : ''}`}>
              <div className="server-card__header">
                <div className="server-card__info">
                  <div className="server-card__name">{mcp.server_name}</div>
                  <div className="server-card__desc">{mcp.description}</div>
                  <div className="server-card__status">
                    <span className={`status-dot status-dot--${mcp.status}`} />
                    {mcp.status}
                  </div>
                </div>
                <div className="server-card__controls">
                  {profileEntry && profileEntry.functions.length > 0 && (
                    <button
                      className="server-card__expand"
                      onClick={() => setExpandedMcp(isExpanded ? null : mcp.server_name)}
                    >
                      {isExpanded ? '▲' : '▼'} Tools ({profileEntry.functions.length})
                    </button>
                  )}
                  <ToggleSwitch
                    enabled={enabled}
                    loading={toggling.has(togKey)}
                    onToggle={() => toggle(mcp.server_name, enabled)}
                  />
                </div>
              </div>

              {isExpanded && profileEntry && (
                <div className="server-card__functions">
                  {profileEntry.functions.map((fn: McpFunction) => {
                    const fnKey = `fn:${mcp.server_name}:${fn.name}`
                    return (
                      <div key={fn.name} className="fn-row">
                        <div className="fn-row__info">
                          <code className="fn-row__name">{fn.name}</code>
                          <span className="fn-row__desc">{fn.description}</span>
                        </div>
                        <ToggleSwitch
                          enabled={fn.enabled}
                          loading={toggling.has(fnKey)}
                          onToggle={() => toggleFn(mcp.server_name, fn.name, fn.enabled)}
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
