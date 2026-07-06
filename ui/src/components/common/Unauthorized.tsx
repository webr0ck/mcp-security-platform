export function Unauthorized({ hint = 'Sign in with an account that has the admin role.' }: { hint?: string }) {
  return (
    <div style={{ padding: '64px', textAlign: 'center', color: 'var(--text-muted)' }}>
      <p style={{ fontSize: 24, marginBottom: 8 }}>🔒</p>
      <p style={{ fontSize: 16, color: 'var(--text-secondary)' }}>Admin access required</p>
      <p style={{ fontSize: 13, marginTop: 8 }}>{hint}</p>
    </div>
  )
}
