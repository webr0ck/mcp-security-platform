import { AppShell } from './components/layout/AppShell'
import { SecurityDashboard } from './components/Dashboard/SecurityDashboard'
import { LimitsPanel } from './components/AdminPanel/LimitsPanel'
import { UserPortal } from './components/Portal/UserPortal'
import { ServersSection } from './components/Servers/ServersSection'
import { SettingsSection } from './components/Settings/SettingsSection'
import { Unauthorized } from './components/common/Unauthorized'
import { useAuth } from './auth/AuthContext'

export function App() {
  const auth = useAuth()
  const isAdmin = auth.authenticated && auth.role === 'admin'

  return (
    <AppShell>
      {(view) => {
        switch (view) {
          case 'overview': return <SecurityDashboard />
          case 'servers':  return <ServersSection />
          case 'access':   return isAdmin ? <LimitsPanel /> : <Unauthorized />
          case 'settings': return <SettingsSection />
          case 'catalog':  return <UserPortal />
        }
      }}
    </AppShell>
  )
}
