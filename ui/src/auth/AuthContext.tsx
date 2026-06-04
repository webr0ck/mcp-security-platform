import { createContext, useContext, useState, useEffect, type ReactNode } from 'react'

export type AuthState = {
  authenticated: boolean
  role: string | null
  username: string | null
  loading: boolean
}

const AuthContext = createContext<AuthState>({ authenticated: false, role: null, username: null, loading: true })

export function AuthProvider({ children }: { children: ReactNode }) {
  const [auth, setAuth] = useState<AuthState>({ authenticated: false, role: null, username: null, loading: true })

  useEffect(() => {
    // Check session by calling the health/me endpoint
    fetch('/api/v1/auth/me', { credentials: 'include' })
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data?.client_id) {
          setAuth({ authenticated: true, role: data.roles?.[0] ?? null, username: data.client_id, loading: false })
        } else {
          setAuth({ authenticated: false, role: null, username: null, loading: false })
        }
      })
      .catch(() => setAuth({ authenticated: false, role: null, username: null, loading: false }))
  }, [])

  return <AuthContext.Provider value={auth}>{children}</AuthContext.Provider>
}

export const useAuth = () => useContext(AuthContext)
