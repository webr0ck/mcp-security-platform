import type { CSSProperties } from 'react'
import type { MainView } from './AppShell'
import { useAuth } from '@/auth/AuthContext'
import './Sidebar.css'

interface NavItem {
  id: MainView
  label: string
  color: string
}

const NAV_ITEMS: NavItem[] = [
  { id: 'overview', label: 'Overview', color: 'var(--accent)' },
  { id: 'servers',  label: 'Servers',  color: 'var(--success)' },
  { id: 'access',   label: 'Access',   color: 'var(--accent-purple)' },
  { id: 'settings', label: 'Settings', color: 'var(--warning)' },
  { id: 'catalog',  label: 'Catalog',  color: 'var(--accent-pink)' },
]

// Raw API role strings -> readable labels. Kept in sync with UserPortal's
// ROLE_LABELS so the same role reads the same way everywhere in the app.
const ROLE_LABELS: Record<string, string> = {
  admin: 'Administrator',
  admin_user: 'Administrator',
  editor: 'Editor',
  viewer: 'Viewer',
  read_only: 'Viewer',
  analyst: 'Analyst',
  security_auditor: 'Security Auditor',
  auditor: 'Auditor',
}
function friendlyRole(role: string | null): string {
  if (!role) return 'Unknown role'
  return ROLE_LABELS[role.toLowerCase()] ?? role
}

interface Props {
  active: MainView
  onNav: (v: MainView) => void
}

export function Sidebar({ active, onNav }: Props) {
  const auth = useAuth()

  return (
    <aside className="sidebar">
      <div className="sidebar__logo">
        <span className="sidebar__logo-mark">M</span>
        <div>
          <p className="sidebar__logo-name">MCP Security</p>
          <p className="sidebar__logo-version">Console</p>
        </div>
      </div>

      <p className="sidebar__section-label">NAVIGATION</p>
      <nav className="sidebar__nav" aria-label="Main navigation">
        {NAV_ITEMS.map(item => (
          <button
            key={item.id}
            className={`sidebar__item ${active === item.id ? 'sidebar__item--active' : ''}`}
            style={{ '--item-color': item.color } as CSSProperties}
            onClick={() => onNav(item.id)}
            aria-current={active === item.id ? 'page' : undefined}
          >
            <span className="sidebar__item-dot" aria-hidden />
            <span className="sidebar__item-label">{item.label}</span>
          </button>
        ))}
      </nav>

      <div className="sidebar__footer">
        {auth.authenticated && (
          <div className="sidebar__identity">
            <div className="sidebar__identity-info">
              <span className="sidebar__identity-user" title={auth.username ?? undefined}>{auth.username}</span>
              <span className="sidebar__identity-role">{friendlyRole(auth.role)}</span>
            </div>
            <button className="sidebar__signout" onClick={() => auth.logout()} aria-label="Sign out">
              Sign out
            </button>
          </div>
        )}
        <div className="sidebar__health">
          <span className="sidebar__health-dot" />
          <span>All systems nominal</span>
        </div>
      </div>
    </aside>
  )
}
