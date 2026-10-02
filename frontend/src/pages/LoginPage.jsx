import { useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../AuthContext.jsx'
import { SparkMark } from '../components/LandingIcons.jsx'
import '../styles/landing.css'
import '../styles/login.css'

// /login -- the one entry point for both normal users and the admin.
//
// The "User login" / "Admin login" tabs below are presentational only: both
// submit to the exact same POST /api/auth/login, and where the app sends you
// afterward is decided from the account's real `role` column in the
// response, not from which tab was open. Picking "Admin login" with a
// normal-user account does not grant admin access -- it logs you in as that
// user and redirects to /chat, same as if you'd used the other tab.
//
// Deliberately absent: any link to /attacker. The attacker console is a
// separate simulation environment, launched directly by URL, never reached
// through this page (see App.jsx's Nav for the same rule).
//
// Signup asks for first/last name + email like a normal product would, but
// POST /api/auth/register still only has one real identifier: `username`
// (see app/schemas/auth.py -- first_name/last_name/email are optional,
// additive profile fields, not new auth concepts). deriveUsername() turns
// the entered email into a valid, unique-enough username locally so the
// person filling this form never has to think about "username" at all.

const RESERVED_LOCAL_PARTS = new Set(['admin', 'root', 'support'])

function deriveUsername(email) {
  const local = (email.split('@')[0] || '').toLowerCase().replace(/[^a-z0-9_.-]/g, '')
  const safe = local.length >= 3 && !RESERVED_LOCAL_PARTS.has(local)
    ? local.slice(0, 28)
    : `user${Math.floor(100 + Math.random() * 900)}`
  return safe
}

function withSuffix(base) {
  const suffix = Math.floor(1000 + Math.random() * 9000)
  return `${base}`.slice(0, 27) + suffix
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export default function LoginPage() {
  const { auth, ready, login, register } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  // The landing page's "Sign up" button links here with { state: { mode:
  // 'signup' } } so it opens straight into account creation instead of
  // login -- everything else about this page (which tab, real role
  // resolution) is unaffected.
  const [tab, setTab] = useState('user') // 'user' | 'admin'
  const [mode, setMode] = useState(location.state?.mode === 'signup' ? 'signup' : 'login')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [email, setEmail] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [roleNotice, setRoleNotice] = useState(null)

  if (ready && auth) {
    return <Navigate to={auth.user.role === 'admin' ? '/admin' : '/chat'} replace />
  }

  async function submit(e) {
    e.preventDefault()
    setError(null)
    setRoleNotice(null)
    setBusy(true)
    try {
      const res = await login(username.trim(), password)

      const actualRole = res.user.role
      const expectedRole = tab === 'admin' ? 'admin' : 'user'
      if (actualRole !== expectedRole) {
        setRoleNotice(
          actualRole === 'admin'
            ? 'This is an admin account — opening SentinelLM.'
            : 'This is a normal user account — opening Chat.'
        )
      }
      navigate(actualRole === 'admin' ? '/admin' : '/chat', { replace: true })
    } catch (err) {
      setError(err.message || 'Something went wrong. Please try again.')
    } finally {
      setBusy(false)
    }
  }

  async function submitSignup(e) {
    e.preventDefault()
    setError(null)
    setRoleNotice(null)

    if (!EMAIL_RE.test(email.trim())) {
      setError('Enter a valid email address.')
      return
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters.')
      return
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match.')
      return
    }

    setBusy(true)
    let candidate = deriveUsername(email.trim())
    const profile = { first_name: firstName.trim(), last_name: lastName.trim(), email: email.trim() }
    try {
      // The derived username collides only if someone else's local-part
      // sanitized to the same string -- retry a couple of times with a
      // random suffix before giving up (the person filling this out never
      // sees "username" or picks one, so this is resolved transparently).
      for (let attempt = 0; ; attempt += 1) {
        try {
          const res = await register(candidate, password, profile)
          navigate(res.user.role === 'admin' ? '/admin' : '/chat', { replace: true })
          return
        } catch (err) {
          if (err.code === 'USERNAME_TAKEN' && attempt < 3) {
            candidate = withSuffix(deriveUsername(email.trim()))
            continue
          }
          throw err
        }
      }
    } catch (err) {
      setError(
        err.code === 'USERNAME_TAKEN'
          ? "That email looks like it's already registered — try logging in instead."
          : err.message || 'Something went wrong. Please try again.'
      )
    } finally {
      setBusy(false)
    }
  }

  function switchTab(next) {
    setTab(next)
    setMode('login')
    setError(null)
    setRoleNotice(null)
  }

  function toSignup() {
    setMode('signup')
    setError(null)
    setRoleNotice(null)
  }

  function toLogin() {
    setMode('login')
    setError(null)
    setRoleNotice(null)
  }

  return (
    <div className="landing login-landing">
      <header className="login-landing__nav">
        <button className="lp-nav__brand" onClick={() => navigate('/')}>
          <SparkMark /><span>QueryFirewall</span>
        </button>
      </header>

      <main className="login-landing__main">
        <div className="login-landing__ambient" aria-hidden="true">
          <span className="lp-ring lp-ring--outer" />
          <span className="lp-ring lp-ring--inner" />
        </div>

        <div className="login-landing__card">
          <span className="lp-eyebrow">{mode === 'signup' ? 'Create account' : 'Account access'}</span>
          <h1 className="login-landing__title">{mode === 'signup' ? 'Welcome.' : 'Welcome back.'}</h1>
          <p className="login-landing__sub">
            {mode === 'signup' ? 'Create your account to start chatting.' : 'Sign in to continue your conversation.'}
          </p>

          {mode === 'login' ? (
            <>
              <div className="login-landing__tabs" role="tablist" aria-label="Login as">
                <button
                  type="button" role="tab" aria-selected={tab === 'user'}
                  className={`login-landing__tab${tab === 'user' ? ' login-landing__tab--active' : ''}`}
                  onClick={() => switchTab('user')}
                >
                  User Login
                </button>
                <button
                  type="button" role="tab" aria-selected={tab === 'admin'}
                  className={`login-landing__tab${tab === 'admin' ? ' login-landing__tab--active' : ''}`}
                  onClick={() => switchTab('admin')}
                >
                  Admin Login
                </button>
              </div>

              <form onSubmit={submit} className="login-landing__form">
                <label>
                  Username
                  <input
                    type="text" value={username} autoFocus
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder={tab === 'admin' ? 'admin username' : 'username'}
                    required
                  />
                </label>
                <label>
                  Password
                  <input
                    type="password" value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="password" required
                  />
                </label>

                {error && <p className="notice error">{error}</p>}
                {roleNotice && <p className="notice">{roleNotice}</p>}

                <button className="lp-btn lp-btn--primary lp-btn--lg" type="submit" disabled={busy}>
                  {busy ? 'Please wait…' : 'Log in'}
                </button>
              </form>

              {tab === 'user' && (
                <p className="login-landing__switch">
                  New here?{' '}
                  <button type="button" className="link-button" onClick={toSignup}>
                    Create an account
                  </button>
                </p>
              )}
            </>
          ) : (
            <>
              <form onSubmit={submitSignup} className="login-landing__form">
                <div className="login-landing__row">
                  <label>
                    First name
                    <input
                      type="text" value={firstName} autoFocus
                      onChange={(e) => setFirstName(e.target.value)}
                      placeholder="Ada" required
                    />
                  </label>
                  <label>
                    Last name
                    <input
                      type="text" value={lastName}
                      onChange={(e) => setLastName(e.target.value)}
                      placeholder="Lovelace" required
                    />
                  </label>
                </div>
                <label>
                  Email
                  <input
                    type="email" value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@example.com" required
                  />
                </label>
                <label>
                  Password
                  <input
                    type="password" value={password} minLength={8}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="At least 8 characters" required
                  />
                </label>
                <label>
                  Confirm password
                  <input
                    type="password" value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Re-enter your password" required
                  />
                </label>

                {error && <p className="notice error">{error}</p>}

                <button className="lp-btn lp-btn--primary lp-btn--lg" type="submit" disabled={busy}>
                  {busy ? 'Please wait…' : 'Create account'}
                </button>
              </form>

              <p className="login-landing__switch">
                Already have an account?{' '}
                <button type="button" className="link-button" onClick={toLogin}>
                  Log in instead
                </button>
              </p>
            </>
          )}
        </div>
      </main>
    </div>
  )
}
