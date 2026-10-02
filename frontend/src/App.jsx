import { Routes, Route, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './AuthContext.jsx'
import Landing from './pages/Landing.jsx'
import LoginPage from './pages/LoginPage.jsx'
import UserChat from './pages/UserChat.jsx'
import AttackConsole from './pages/AttackConsole.jsx'
import AttackerSimulator from './pages/AttackerSimulator.jsx'
import AdminDashboard from './pages/AdminDashboard.jsx'

// Five clearly separated experiences, per the project's security model:
//   /          signed-out front door - Landing; skipped entirely (redirected
//              straight to /chat or /admin) once signed in, see HomeGate
//   /login     account entry - one page, two tabs (User / Admin), but the
//              backend -- never the tab clicked -- decides the real role
//   /chat      normal user  - a simple ChatGPT-like UI with conversation
//              history, no security internals, reachable only when logged
//              in as role='user'
//   /admin     security     - the dashboard, reachable only when logged in
//              as role='admin'; gated server-side independently of this
//              frontend route guard (every /api/admin/* call re-checks)
//   /attacker  simulation   - an attack console; controls the existing
//                             attacker generators, sends every query over
//                             real HTTP through /api/chat, never touches
//                             Ollama or firewall internals directly, and
//                             needs NO login at all -- it represents an
//                             external attacker, not an account holder
//
// /attacker carries no nav link to/from anywhere else in the app, no login
// gate, and is given no more information than an external attacker/client
// would plausibly see (query, response) -- decision/risk/signals are
// admin-only, surfaced only on /admin. Route guards below are a UX
// convenience; the backend enforces the actual boundary independently (see
// app/api/deps.py) regardless of what this file does.
//
// /attack (singular) still exists as an unlinked legacy route from an
// earlier in-process attack API that predates both the standalone
// attacker.py CLI and the /attacker page; reachable by direct URL only.

function Nav() {
  const { pathname } = useLocation()
  const { auth, logout } = useAuth()
  const navigate = useNavigate()

  if (pathname.startsWith('/attacker')) {
    return (
      <nav className="nav">
        <span className="nav__brand">Attacker Console</span>
      </nav>
    )
  }

  // Landing and Login each own their own full-width nav (brand, styled to
  // match that page's theme) -- the shared bar here would just duplicate it
  // under the generic shell styling, and Login is never reached alongside
  // another role's real nav anyway (RequireRole always redirects here first).
  if (pathname === '/' || pathname === '/login') return null

  if (!auth) {
    return (
      <nav className="nav">
        <span className="nav__brand">LLM Firewall</span>
      </nav>
    )
  }

  async function handleLogout() {
    await logout()
    navigate('/login', { replace: true })
  }

  const brand = auth.user.role === 'admin' ? 'SentinelLM' : 'Chat'
  return (
    <nav className="nav">
      <span className="nav__brand">{brand}</span>
      <button className="nav__logout" onClick={handleLogout}>Logout</button>
    </nav>
  )
}

function RequireRole({ role, children }) {
  const { auth, ready } = useAuth()
  const location = useLocation()
  if (!ready) return null
  if (!auth) return <Navigate to="/login" state={{ from: location }} replace />
  if (auth.user.role !== role) {
    return <Navigate to={auth.user.role === 'admin' ? '/admin' : '/chat'} replace />
  }
  return children
}

function HomeGate() {
  const { auth, ready } = useAuth()
  if (!ready) return null
  if (!auth) return <Landing />
  return <Navigate to={auth.user.role === 'admin' ? '/admin' : '/chat'} replace />
}

export default function App() {
  return (
    <AuthProvider>
      <div className="app">
        <Nav />
        <Routes>
          <Route path="/" element={<HomeGate />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/chat" element={<RequireRole role="user"><UserChat /></RequireRole>} />
          <Route path="/attacker" element={<AttackerSimulator />} />
          <Route path="/attack" element={<AttackConsole />} />
          <Route path="/admin" element={<RequireRole role="admin"><AdminDashboard /></RequireRole>} />
        </Routes>
      </div>
    </AuthProvider>
  )
}
