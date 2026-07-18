import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react'
import { auth as authApi } from '@/services/api'

export type AuthState = {
  authenticated: boolean
  role: string | null
  username: string | null
  loading: boolean
  // Redirects the browser to the Keycloak login flow (GET /api/v1/auth/oidc/login).
  // Not a fetch — this is a full-page navigation, so there's nothing to await.
  login: (redirectAfter?: string) => void
  // Revokes the session server-side (POST /api/v1/auth/oidc/logout) then clears
  // local state. Best-effort: if the network call fails, local state still
  // clears so the UI doesn't strand the user in a "logged in" view.
  logout: () => Promise<void>
}

const noop = () => {}
const AuthContext = createContext<AuthState>({
  authenticated: false, role: null, username: null, loading: true,
  login: noop, logout: async () => {},
})

type SessionState = { authenticated: boolean; role: string | null; username: string | null; loading: boolean }
const UNAUTHENTICATED: SessionState = { authenticated: false, role: null, username: null, loading: false }

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionState>({ authenticated: false, role: null, username: null, loading: true })

  const checkSession = useCallback(() => {
    // Real "who am I?" endpoint — see services/api.ts's `auth` export for why
    // this isn't /api/v1/auth/me (that path was never implemented server-side).
    authApi.session()
      .then(data => {
        setSession({ authenticated: true, role: data.roles?.[0] ?? null, username: data.client_id, loading: false })
      })
      .catch(() => setSession(UNAUTHENTICATED))
  }, [])

  useEffect(() => { checkSession() }, [checkSession])

  const login = useCallback((redirectAfter: string = window.location.pathname) => {
    window.location.href = authApi.loginUrl(redirectAfter)
  }, [])

  const logout = useCallback(async () => {
    try { await authApi.logout() } catch (e) { console.error('[AuthContext] logout call failed:', e) }
    setSession(UNAUTHENTICATED)
  }, [])

  return <AuthContext.Provider value={{ ...session, login, logout }}>{children}</AuthContext.Provider>
}

export const useAuth = () => useContext(AuthContext)
