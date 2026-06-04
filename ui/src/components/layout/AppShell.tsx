import { useState } from 'react'
import { Sidebar } from './Sidebar'
import './AppShell.css'

export type View = 'wizard' | 'admin' | 'dashboard' | 'portal'

interface Props {
  children: (view: View, setView: (v: View) => void) => React.ReactNode
}

export function AppShell({ children }: Props) {
  const [view, setView] = useState<View>('dashboard')
  return (
    <div className="app-shell">
      <Sidebar active={view} onNav={setView} />
      <main className="app-shell__main">
        {children(view, setView)}
      </main>
    </div>
  )
}
