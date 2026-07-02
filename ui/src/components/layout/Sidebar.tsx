import type { View } from './AppShell'
import './Sidebar.css'

const NAV_ITEMS: { id: View; label: string; icon: string; badge?: string }[] = [
  { id: 'dashboard', label: 'Security', icon: '⬡' },
  { id: 'portal',    label: 'Portal',   icon: '⊞' },
  { id: 'submit',    label: 'Request',  icon: '＋' },
  { id: 'review',    label: 'Review',   icon: '◉' },
  { id: 'admin',     label: 'Admin',    icon: '⚙' },
  { id: 'wizard',    label: 'Setup',    icon: '◈' },
]

interface Props {
  active: View
  onNav: (v: View) => void
}

export function Sidebar({ active, onNav }: Props) {
  return (
    <aside className="sidebar">
      <div className="sidebar__logo">
        <span className="sidebar__logo-mark">⬡</span>
        <div>
          <p className="sidebar__logo-name">MCP Guard</p>
          <p className="sidebar__logo-version">v0.1.0</p>
        </div>
      </div>

      <nav className="sidebar__nav" aria-label="Main navigation">
        {NAV_ITEMS.map(item => (
          <button
            key={item.id}
            className={`sidebar__item ${active === item.id ? 'sidebar__item--active' : ''}`}
            onClick={() => onNav(item.id)}
            aria-current={active === item.id ? 'page' : undefined}
          >
            <span className="sidebar__item-icon" aria-hidden>{item.icon}</span>
            <span className="sidebar__item-label">{item.label}</span>
            {item.badge && (
              <span className="sidebar__item-badge">{item.badge}</span>
            )}
          </button>
        ))}
      </nav>

      <div className="sidebar__footer">
        <div className="sidebar__health">
          <span className="sidebar__health-dot" />
          <span>All systems nominal</span>
        </div>
      </div>
    </aside>
  )
}
