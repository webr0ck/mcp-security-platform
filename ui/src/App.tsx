import { AppShell } from './components/layout/AppShell'
import { SecurityDashboard } from './components/Dashboard/SecurityDashboard'
import { AdminPanel } from './components/AdminPanel/AdminPanel'
import { UserPortal } from './components/Portal/UserPortal'
import { InstallWizard } from './components/Wizard/InstallWizard'
import { SubmitServerWizard } from './components/Submissions/SubmitServerWizard'
import { SubmissionReview } from './components/Submissions/SubmissionReview'
import { useAuth } from './auth/AuthContext'

function Unauthorized() {
  return (
    <div style={{ padding: '64px', textAlign: 'center', color: 'var(--text-muted)' }}>
      <p style={{ fontSize: 24, marginBottom: 8 }}>🔒</p>
      <p style={{ fontSize: 16, color: 'var(--text-secondary)' }}>Admin access required</p>
      <p style={{ fontSize: 13, marginTop: 8 }}>Sign in with an account that has the admin role.</p>
    </div>
  )
}

export function App() {
  const auth = useAuth()

  return (
    <AppShell>
      {(view) => {
        if (view === 'admin' && (!auth.authenticated || auth.role !== 'admin')) {
          return <Unauthorized />
        }
        if (view === 'review' && (!auth.authenticated || !['admin', 'security_auditor', 'auditor'].includes(auth.role ?? ''))) {
          return <Unauthorized />
        }
        switch (view) {
          case 'dashboard': return <SecurityDashboard />
          case 'admin':     return <AdminPanel />
          case 'portal':    return <UserPortal />
          case 'wizard':    return <InstallWizard />
          case 'submit':    return <SubmitServerWizard />
          case 'review':    return <SubmissionReview />
        }
      }}
    </AppShell>
  )
}
