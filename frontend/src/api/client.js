// Thin fetch wrapper. Vite proxies /api to the backend on :8000.
//
// Session tokens (from /api/auth/login) are held in sessionStorage (tab-
// scoped, not shared across tabs -- see AuthContext.jsx) and attached as a
// Bearer token -- to /api/conversations/* for normal users, and to
// /api/admin/* for an admin account. The backend independently re-derives
// role from the token server-side on every call (see app/api/deps.py);
// nothing here is trusted as the actual boundary.

async function handle(resp) {
  if (!resp.ok) {
    let detail
    try {
      detail = await resp.json()
    } catch {
      detail = { error: { message: resp.statusText } }
    }
    const err = new Error(detail?.error?.message || `Request failed (${resp.status})`)
    err.status = resp.status
    err.code = detail?.error?.code
    throw err
  }
  return resp.json()
}

export async function postChat(clientId, query) {
  const resp = await fetch('/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: clientId, query }),
  })
  return handle(resp)
}

export async function getStrategies() {
  const resp = await fetch('/api/attack/strategies')
  return handle(resp)
}

export async function previewAttack(body) {
  const resp = await fetch('/api/attack/preview', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return handle(resp)
}

export async function runAttack(body) {
  const resp = await fetch('/api/attack/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return handle(resp)
}

export async function getRun(runId) {
  const resp = await fetch(`/api/attack/runs/${runId}`)
  return handle(resp)
}

// The attacker console's "is a live /chat conversation available to
// continue?" check (PROMPT section 14). Returns only {available: boolean}
// -- no client_id/conversation_id/username, by design (see
// app/services/target_registry.py).
export async function getAttackerTarget() {
  const resp = await fetch('/api/attacker-console/target')
  return handle(resp)
}

export async function adminGet(path, token) {
  const resp = await fetch(path, { headers: { Authorization: `Bearer ${token}` } })
  return handle(resp)
}

export async function adminPost(path, token, body) {
  const resp = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: body ? JSON.stringify(body) : undefined,
  })
  return handle(resp)
}

// --- auth ---------------------------------------------------------------

export async function authRegister(username, password, profile = {}) {
  const resp = await fetch('/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    // profile (first_name/last_name/email) is optional -- omitting it keeps
    // this call identical to the original two-field signup.
    body: JSON.stringify({ username, password, ...profile }),
  })
  return handle(resp)
}

export async function authLogin(username, password) {
  const resp = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  return handle(resp)
}

export async function authLogout(token) {
  const resp = await fetch('/api/auth/logout', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  })
  return handle(resp)
}

export async function authMe(token) {
  const resp = await fetch('/api/auth/me', { headers: { Authorization: `Bearer ${token}` } })
  return handle(resp)
}

// --- authenticated chat history -------------------------------------------

function authHeaders(token) {
  return { Authorization: `Bearer ${token}` }
}

export async function listConversations(token) {
  const resp = await fetch('/api/conversations', { headers: authHeaders(token) })
  return handle(resp)
}

export async function createConversation(token) {
  const resp = await fetch('/api/conversations', { method: 'POST', headers: authHeaders(token) })
  return handle(resp)
}

export async function getConversation(token, id) {
  const resp = await fetch(`/api/conversations/${id}`, { headers: authHeaders(token) })
  return handle(resp)
}

export async function sendMessage(token, id, query) {
  const resp = await fetch(`/api/conversations/${id}/messages`, {
    method: 'POST',
    headers: { ...authHeaders(token), 'Content-Type': 'application/json' },
    body: JSON.stringify({ query }),
  })
  return handle(resp)
}
