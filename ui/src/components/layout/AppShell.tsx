import { useState } from 'react'
import { Sidebar } from './Sidebar'
import './AppShell.css'

export type MainView = 'overview' | 'servers' | 'access' | 'settings' | 'catalog'

const SECTION_LABEL: Record<MainView, string> = {
  overview: 'Overview',
  servers: 'Servers',
  access: 'Access',
  settings: 'Settings',
  catalog: 'Catalog',
}

interface Props {
  children: (view: MainView, setView: (v: MainView) => void) => React.ReactNode
}

export function AppShell({ children }: Props) {
  const [view, setView] = useState<MainView>('overview')
  return (
    <div className="app-shell">
      <Sidebar active={view} onNav={setView} />
      <div className="app-shell__col">
        <header className="app-shell__topbar">
          <div className="app-shell__breadcrumb">
            <span>MCP Console</span>
            <span className="app-shell__breadcrumb-sep">/</span>
            <span className="app-shell__breadcrumb-current">{SECTION_LABEL[view]}</span>
          </div>
          <button className="app-shell__quick-action" onClick={() => setView('servers')}>
            + Submit Server
          </button>
        </header>
        <main className="app-shell__main">
          {children(view, setView)}
        </main>
      </div>
    </div>
  )
}
