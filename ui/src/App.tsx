import { AppShell } from './components/layout/AppShell'
import { SecurityDashboard } from './components/Dashboard/SecurityDashboard'
import { AdminPanel } from './components/AdminPanel/AdminPanel'
import { UserPortal } from './components/Portal/UserPortal'
import { InstallWizard } from './components/Wizard/InstallWizard'

export function App() {
  return (
    <AppShell>
      {(view) => {
        switch (view) {
          case 'dashboard': return <SecurityDashboard />
          case 'admin':     return <AdminPanel />
          case 'portal':    return <UserPortal />
          case 'wizard':    return <InstallWizard />
        }
      }}
    </AppShell>
  )
}
