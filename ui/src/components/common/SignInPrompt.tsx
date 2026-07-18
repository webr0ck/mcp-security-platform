import { Button } from './Button'
import { useAuth } from '@/auth/AuthContext'

// Shown in place of section content whenever there's no session at all —
// distinct from Unauthorized, which is for an authenticated user missing a
// specific role. Before this existed, an unauthenticated visitor just saw
// each section's API calls fail silently (401/403 in the console) with no
// way to actually sign in from the UI.
export function SignInPrompt() {
  const auth = useAuth()
  return (
    <div style={{ padding: '64px', textAlign: 'center' }}>
      <p style={{ fontSize: 24, marginBottom: 8 }}>🔑</p>
      <p style={{ fontSize: 16, color: 'var(--text-secondary)' }}>Sign-in required</p>
      <p style={{ fontSize: 13, marginTop: 8, color: 'var(--text-muted)' }}>
        Sign in with your organization's identity provider to use the console.
      </p>
      <Button
        variant="primary"
        style={{ marginTop: 'var(--sp-6)' }}
        onClick={() => auth.login()}
      >
        Sign in
      </Button>
    </div>
  )
}
