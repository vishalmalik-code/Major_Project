import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { authLogin, authLogout, authMe, authRegister } from './api/client.js'

// Session storage: {token, user: {id, username, role, created_at}} in
// sessionStorage -- deliberately NOT localStorage. localStorage is shared
// across every tab/window of the same origin, so a second tab logging in
// (e.g. an admin account in Tab 3) overwrote the SAME key a user's Tab 1 was
// reading, and any reload/remount of Tab 1 (a real F5, or the browser
// discarding a backgrounded tab to save memory -- both routine) would pick
// up the admin's token instead of the user's own. That was the multi-tab
// auth bug: one shared login for the whole browser, not one per tab.
//
// sessionStorage is scoped to the browsing-context (tab) AND origin: a new
// tab -- even to the exact same URL -- starts with its own empty
// sessionStorage, never another open tab's. Tab 1 (user), Tab 2 (no login,
// /attacker), and Tab 3 (admin) each get an independent copy; writes in one
// never touch another. This needed no backend change -- the existing
// sessions table/Bearer-token mechanism (app/db/repository.py's
// SessionRepository) already allows any number of valid tokens to coexist,
// nothing there was ever the bottleneck.
//
// Trade-off, stated plainly: opening /chat in a second tab as the SAME
// account now requires logging in again in that tab too (sessionStorage
// isn't shared even between two tabs of one account). That's the accepted
// cost of genuine per-tab isolation -- seeing one shared login as "more
// convenient" is exactly the assumption that caused this bug.
//
// The frontend route guards below remain pure UX either way -- the actual
// boundary is server-side (app/api/deps.py re-derives role from the token
// on every request, never trusting anything the browser claims).

const KEY = 'llm_firewall_auth'
const AuthContext = createContext(null)

function readStored() {
  try {
    const raw = sessionStorage.getItem(KEY)
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

export function AuthProvider({ children }) {
  const [auth, setAuth] = useState(readStored)
  const [ready, setReady] = useState(false)

  useEffect(() => {
    const stored = readStored()
    if (!stored) {
      setReady(true)
      return
    }
    // Re-validate the stored token once on load (it may have been logged
    // out from another tab, or simply be stale).
    authMe(stored.token)
      .then((user) => setAuth({ token: stored.token, user }))
      .catch(() => {
        sessionStorage.removeItem(KEY)
        setAuth(null)
      })
      .finally(() => setReady(true))
  }, [])

  const login = useCallback(async (username, password) => {
    const res = await authLogin(username, password)
    sessionStorage.setItem(KEY, JSON.stringify(res))
    setAuth(res)
    return res
  }, [])

  const register = useCallback(async (username, password, profile) => {
    const res = await authRegister(username, password, profile)
    sessionStorage.setItem(KEY, JSON.stringify(res))
    setAuth(res)
    return res
  }, [])

  const logout = useCallback(async () => {
    const stored = readStored()
    sessionStorage.removeItem(KEY)
    setAuth(null)
    if (stored) {
      try {
        await authLogout(stored.token)
      } catch {
        // already logged out server-side, or the backend is unreachable --
        // either way the client has already dropped its own token.
      }
    }
  }, [])

  return (
    <AuthContext.Provider value={{ auth, ready, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
