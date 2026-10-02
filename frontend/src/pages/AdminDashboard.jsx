import { useEffect, useRef, useState } from 'react'
import { useAuth } from '../AuthContext.jsx'
import { adminGet, adminPost } from '../api/client.js'
import RiskBadge from '../components/RiskBadge.jsx'
import ActionTag from '../components/ActionTag.jsx'
import SignalTable from '../components/SignalTable.jsx'
import RiskChart from '../components/RiskChart.jsx'

// ADMIN / SECURITY surface, mounted at /admin. Reachable only via a real
// admin-role login (see App.jsx's RequireRole); the backend independently
// re-checks the session's role on every /api/admin/* call regardless of
// this frontend guard (app/api/deps.py:require_admin).
//
// Registered Users (below) is the account-layer view added for this
// restructuring: real login accounts only, prompts visible for security
// observation, model responses never included (the backend's
// /api/admin/users/{id} response has no `response` field to leak). Clients
// is the pre-existing, lower-level view keyed by client_id -- it also
// includes attacker sessions (kind='attacker'), which is how an admin
// watches a live attack (query, risk, decision, signals) in near real time
// while the attacker console itself shows none of that.
//
// Real-time: ONE GET /api/admin/stream SSE connection (subscribed for as
// long as this page is mounted) delivers every firewall decision in the
// system the moment it happens -- see ChatService.handle()'s admin_bus
// publish. The top-level tables (clients, users, query log, security
// events) are patched directly from each event's payload, no HTTP round
// trip. The two drill-down panels (client/user detail) and the KPI tiles
// are refetched, but only when a live event actually concerns them --
// event-triggered, not a fixed-interval poll (the previous 2s
// setInterval(refresh, ...) is gone).

const STATUS_LABEL = { ALLOW: 'LOW', MONITOR: 'MONITOR', THROTTLE: 'THROTTLED', BLOCK: 'BLOCKED' }
const USER_STATUS_COLOR = {
  NORMAL: 'var(--allow)', MONITORED: 'var(--monitor)',
  THROTTLED: 'var(--throttle)', BLOCKED: 'var(--block)',
}
const ACTION_TO_USER_STATUS = {
  ALLOW: 'NORMAL', MONITOR: 'MONITORED', THROTTLE: 'THROTTLED', BLOCK: 'BLOCKED',
}
const QUERY_LOG_CAP = 25
const EVENTS_CAP = 25
const STATS_DEBOUNCE_MS = 800

export default function AdminDashboard() {
  const { auth } = useAuth()
  const token = auth.token

  const [error, setError] = useState(null)
  const [stats, setStats] = useState(null)
  const [users, setUsers] = useState([])
  const [clients, setClients] = useState([])
  const [events, setEvents] = useState([])
  const [queryLog, setQueryLog] = useState([])
  const [evaluation, setEvaluation] = useState(null)

  const [selectedUserId, setSelectedUserId] = useState(null)
  const [userDetail, setUserDetail] = useState(null)

  const [selectedClient, setSelectedClient] = useState(null)
  const [clientDetail, setClientDetail] = useState(null)
  const [selectedQuery, setSelectedQuery] = useState(null)

  // Read inside the SSE handler below, which is set up once per connection
  // (not per render) -- refs avoid it ever closing over a stale selection.
  const selectedClientRef = useRef(null)
  const selectedUserIdRef = useRef(null)
  useEffect(() => { selectedClientRef.current = selectedClient }, [selectedClient])
  useEffect(() => { selectedUserIdRef.current = selectedUserId }, [selectedUserId])
  const statsDebounceRef = useRef(null)
  const readyCountRef = useRef(0)

  async function refresh() {
    // allSettled, not all -- these six panels are independent, so one slow
    // or failing call (a transient DB/network hiccup) shouldn't blank out
    // the five others that succeeded. Each setter only fires for its own
    // fulfilled result; anything already on screen from a previous refresh
    // is left as-is rather than wiped.
    const [s, u, c, e, q, ev] = await Promise.allSettled([
      adminGet('/api/admin/stats', token),
      adminGet('/api/admin/users', token),
      adminGet('/api/admin/clients', token),
      adminGet(`/api/admin/events?limit=${EVENTS_CAP}`, token),
      adminGet(`/api/admin/queries?limit=${QUERY_LOG_CAP}`, token),
      adminGet('/api/admin/evaluation', token),
    ])
    if (s.status === 'fulfilled') setStats(s.value)
    if (u.status === 'fulfilled') setUsers(u.value)
    if (c.status === 'fulfilled') setClients(c.value)
    if (e.status === 'fulfilled') setEvents(e.value)
    if (q.status === 'fulfilled') setQueryLog(q.value)
    if (ev.status === 'fulfilled') setEvaluation(ev.value)

    const failed = [s, u, c, e, q, ev].find((r) => r.status === 'rejected')
    // Clearing on success too: previously a single failed refresh left its
    // error banner on screen forever, even after a later refresh succeeded.
    setError(failed ? failed.reason?.message || 'Some dashboard data failed to load.' : null)
  }

  useEffect(() => {
    refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Fetched once when the admin selects a row; kept live afterward purely
  // by applyLiveQuery's event-triggered refetch below, not a timer.
  useEffect(() => {
    if (!selectedUserId) return
    adminGet(`/api/admin/users/${selectedUserId}`, token)
      .then(setUserDetail)
      .catch((e) => setError(e.message))
  }, [selectedUserId, token])

  useEffect(() => {
    if (!selectedClient) return
    setSelectedQuery(null)
    adminGet(`/api/admin/clients/${selectedClient}`, token)
      .then(setClientDetail)
      .catch((e) => setError(e.message))
  }, [selectedClient, token])

  // The one real-time connection this page needs. `query` events patch
  // clients/users/queryLog/events directly from the payload; the KPI tiles
  // get a debounced refetch (the aggregates -- unique_clients, flagged_users,
  // etc. -- are real SQL rollups, not safe to hand-recompute client-side).
  useEffect(() => {
    const es = new EventSource(`/api/admin/stream?token=${encodeURIComponent(token)}`)

    es.addEventListener('ready', () => {
      readyCountRef.current += 1
      if (readyCountRef.current > 1) {
        // A `ready` after the first one means the connection dropped and
        // EventSource reconnected on its own -- resync everything once,
        // simply, rather than tracking precise missed-event offsets.
        refresh()
      }
    })

    es.addEventListener('query', (e) => applyLiveQuery(JSON.parse(e.data)))

    return () => es.close()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token])

  function scheduleStatsRefetch() {
    if (statsDebounceRef.current) return
    statsDebounceRef.current = setTimeout(() => {
      statsDebounceRef.current = null
      adminGet('/api/admin/stats', token).then(setStats).catch(() => {})
    }, STATS_DEBOUNCE_MS)
  }

  function applyLiveQuery(data) {
    setQueryLog((prev) => {
      if (prev.some((q) => q.id === data.id)) return prev
      return [data, ...prev].slice(0, QUERY_LOG_CAP)
    })

    setClients((prev) => {
      const idx = prev.findIndex((c) => c.client_id === data.client_id)
      if (idx === -1) {
        // A client_id this page hasn't seen yet -- fetch the real row
        // rather than fabricate one from the query payload alone.
        adminGet('/api/admin/clients', token).then(setClients).catch(() => {})
        return prev
      }
      const next = prev.slice()
      const c = next[idx]
      next[idx] = {
        ...c, risk_score: data.risk_after, risk_band: data.risk_band,
        query_count: c.query_count + 1,
        highest_risk: Math.max(c.highest_risk, data.risk_after),
        last_action: data.action, last_seen: data.created_at,
      }
      return next
    })

    setUsers((prev) => {
      const idx = prev.findIndex((u) => u.client_id === data.client_id)
      if (idx === -1) return prev  // an attacker-kind client, not a registered user
      const next = prev.slice()
      const u = next[idx]
      next[idx] = {
        ...u, status: ACTION_TO_USER_STATUS[data.action] || u.status,
        current_risk: data.risk_after,
        highest_risk: Math.max(u.highest_risk, data.risk_after),
        total_queries: u.total_queries + 1,
        blocked_count: data.action === 'BLOCK' ? u.blocked_count + 1 : u.blocked_count,
        last_active_at: data.created_at,
      }
      if (selectedUserIdRef.current === u.id) {
        adminGet(`/api/admin/users/${u.id}`, token).then(setUserDetail).catch(() => {})
      }
      return next
    })

    if (data.security_event) {
      setEvents((prev) => {
        if (prev.some((ev) => ev.id === data.security_event.id)) return prev
        return [{
          id: data.security_event.id, client_id: data.client_id, query_id: data.id,
          severity: data.security_event.severity, event_type: data.security_event.event_type,
          message: data.security_event.message, risk_score: data.risk_after,
          created_at: data.created_at,
        }, ...prev].slice(0, EVENTS_CAP)
      })
    }

    if (selectedClientRef.current === data.client_id) {
      adminGet(`/api/admin/clients/${data.client_id}`, token).then(setClientDetail).catch(() => {})
    }

    scheduleStatsRefetch()
  }

  async function resetClient(id) {
    await adminPost(`/api/admin/clients/${id}/reset`, token)
    refresh()
    if (selectedClient === id) {
      const d = await adminGet(`/api/admin/clients/${id}`, token)
      setClientDetail(d)
    }
  }

  const activeSignals = selectedQuery ? selectedQuery.signals : clientDetail?.latest_signals

  return (
    <main className="page">
      <h2>SentinelLM</h2>
      {error && <p className="notice error">{error}</p>}

      {stats && (
        <>
          <div className="panel stat-grid">
            <Stat label="Total Queries" value={stats.total_queries} />
            <Stat label="Active Clients" value={stats.unique_clients} />
            <Stat label="Monitored Queries" value={stats.by_action.MONITOR} />
            <Stat label="Throttled Queries" value={stats.by_action.THROTTLE} />
            <Stat label="Blocked Queries" value={stats.by_action.BLOCK} />
            <Stat label="Clients at risk" value={stats.clients_at_risk} />
          </div>

          <div className="panel stat-grid">
            <Stat label="Total Users" value={stats.total_users} />
            <Stat label="Active Users" value={stats.active_users} />
            <Stat label="Total Conversations" value={stats.total_conversations} />
            <Stat label="Flagged Users" value={stats.flagged_users} />
            <Stat label="Throttled Users" value={stats.throttled_users} />
            <Stat label="Blocked Users" value={stats.blocked_users} />
            <Stat label="Total Blocked Queries" value={stats.total_blocked_queries} />
            <Stat label="Total Throttled Queries" value={stats.total_throttled_queries} />
            <Stat label="Total Security Events" value={stats.total_security_events} />
          </div>
        </>
      )}

      <div className="panel">
        <h3>Registered Users</h3>
        <p className="muted">Real login accounts. Attacker sessions show up in Clients below.</p>
        <table className="admin-table">
          <thead>
            <tr>
              <th>user</th><th>status</th><th>queries</th><th>risk</th>
              <th>blocked</th><th>conversations</th><th>last active</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} className={selectedUserId === u.id ? 'selected' : ''}>
                <td className="mono link" onClick={() => setSelectedUserId(u.id)}>{u.username}</td>
                <td><UserStatusBadge status={u.status} /></td>
                <td>{u.total_queries}</td>
                <td className="mono">{u.current_risk.toFixed(1)} <span className="muted">(peak {u.highest_risk.toFixed(1)})</span></td>
                <td>{u.blocked_count}</td>
                <td>{u.total_conversations}</td>
                <td className="muted">{new Date(u.last_active_at).toLocaleString()}</td>
              </tr>
            ))}
            {users.length === 0 && (
              <tr><td colSpan={7} className="muted">No registered users yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {userDetail && (
        <div className="panel">
          <h3>User — {userDetail.username}</h3>
          <UserStatusBadge status={userDetail.status} />
          <span className="muted" style={{ marginLeft: '0.75rem' }}>
            {userDetail.total_queries} queries · {userDetail.total_conversations} conversations ·
            {' '}throttled {userDetail.throttled_count}× · blocked {userDetail.blocked_count}×
          </span>
          <p className="muted" style={{ fontSize: '0.85rem' }}>
            first seen {new Date(userDetail.created_at).toLocaleString()} · last active{' '}
            {new Date(userDetail.last_active_at).toLocaleString()} · client{' '}
            <span className="mono">{userDetail.client_id}</span>
          </p>

          <h4>Query history — prompts only (model responses are never shown here)</h4>
          <table className="admin-table">
            <thead>
              <tr><th>#</th><th>prompt</th><th>action</th><th>risk</th><th>time</th></tr>
            </thead>
            <tbody>
              {userDetail.queries.map((q) => (
                <tr key={q.seq}>
                  <td className="mono">{q.seq}</td>
                  <td>{q.text}</td>
                  <td><ActionTag action={q.action} /></td>
                  <td className="mono">{q.risk_score.toFixed(1)}</td>
                  <td className="muted">{new Date(q.created_at).toLocaleTimeString()}</td>
                </tr>
              ))}
              {userDetail.queries.length === 0 && (
                <tr><td colSpan={5} className="muted">No queries yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      <div className="panel">
        <h3>Clients</h3>
        <p className="muted">Every client_id the firewall has seen — registered users AND attacker sessions.</p>
        <table className="admin-table">
          <thead>
            <tr>
              <th>client</th><th>type</th><th>queries</th><th>current risk</th><th>highest risk</th>
              <th>last decision</th><th>status</th><th />
            </tr>
          </thead>
          <tbody>
            {clients.map((c) => (
              <tr key={c.client_id} className={selectedClient === c.client_id ? 'selected' : ''}>
                <td className="mono link" onClick={() => setSelectedClient(c.client_id)}>{c.client_id}</td>
                <td>
                  {c.kind === 'attacker'
                    ? <span className="badge kind-badge kind-badge--attacker">ATTACKER</span>
                    : <span className="badge kind-badge">user</span>}
                </td>
                <td>{c.query_count}</td>
                <td><RiskBadge band={c.risk_band} score={c.risk_score} /></td>
                <td className="mono">{c.highest_risk.toFixed(1)}</td>
                <td>{c.last_action && <ActionTag action={c.last_action} />}</td>
                <td className="mono">{STATUS_LABEL[c.last_action] || 'LOW'}</td>
                <td><button onClick={() => resetClient(c.client_id)}>reset</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {clientDetail && (
        <div className="panel">
          <h3>Client detail — {clientDetail.client_id}</h3>
          <RiskBadge band={clientDetail.risk_band} score={clientDetail.risk_score} />
          <span className="muted" style={{ marginLeft: '0.75rem' }}>
            throttled {clientDetail.throttle_count}× · blocked {clientDetail.block_count}× (lifetime)
          </span>

          <p className="window-note">
            <strong>Query-based window:</strong> showing this client's last{' '}
            {clientDetail.window_size} queries, in the order they arrived — a{' '}
            <strong>query count</strong>, not a time window. Query {clientDetail.window_size + 1}{' '}
            would evict query 1, however long the client waited between them.
          </p>

          <h4>Risk by query number</h4>
          <RiskChart points={clientDetail.risk_trajectory} />

          <h4>Last {clientDetail.window_size} queries (query order)</h4>
          <table className="admin-table">
            <thead>
              <tr><th>#</th><th>query</th><th>action</th><th>risk before → after</th><th>time</th></tr>
            </thead>
            <tbody>
              {clientDetail.window.map((q) => (
                <tr key={q.id} className={selectedQuery?.id === q.id ? 'selected' : ''}>
                  <td className="mono">{q.seq}</td>
                  <td className="link" onClick={() => setSelectedQuery(q)}>
                    {q.text.length > 60 ? q.text.slice(0, 57) + '...' : q.text}
                  </td>
                  <td><ActionTag action={q.action} /></td>
                  <td className="mono">{q.risk_before.toFixed(1)} → {q.risk_after.toFixed(1)}</td>
                  <td className="muted">{new Date(q.created_at).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h4>{selectedQuery ? `Signal breakdown — query #${selectedQuery.seq}` : 'Latest signal breakdown'}</h4>
          <SignalTable signals={activeSignals} />
        </div>
      )}

      <div className="panel">
        <h3>Query log</h3>
        <p className="muted">Most recent queries across all clients.</p>
        <table className="admin-table">
          <thead>
            <tr><th>time</th><th>client</th><th>query</th><th>risk before → after</th><th>decision</th></tr>
          </thead>
          <tbody>
            {queryLog.map((q) => (
              <tr key={q.id}>
                <td className="muted">{new Date(q.created_at).toLocaleTimeString()}</td>
                <td className="mono link" onClick={() => setSelectedClient(q.client_id)}>{q.client_id}</td>
                <td>{q.text.length > 50 ? q.text.slice(0, 47) + '...' : q.text}</td>
                <td className="mono">{q.risk_before.toFixed(1)} → {q.risk_after.toFixed(1)}</td>
                <td><ActionTag action={q.action} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="panel">
        <h3>Recent security events</h3>
        <ul className="event-list">
          {events.map((e) => (
            <li key={e.id}>
              <span className="muted mono event-time">
                {new Date(e.created_at).toLocaleTimeString()}
              </span>
              <span className={`severity severity-${e.severity}`}>{e.severity}</span>
              <span className="mono">{e.client_id}</span>
              {e.risk_score != null && <span className="mono">risk {e.risk_score.toFixed(1)}</span>}
              <span>{e.message}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="panel">
        <h3>Attack evaluation</h3>
        {!evaluation?.available && (
          <p className="muted">
            No evaluation data available yet. Run <code>python evaluate.py</code> in the backend
            to populate this panel with real detection-rate results.
          </p>
        )}
        {evaluation?.available && <EvaluationView evaluation={evaluation} />}
      </div>
    </main>
  )
}

function EvaluationView({ evaluation }) {
  const attackerSessions = evaluation.sessions.filter((s) => s.session_type === 'attacker')
  const byStrategy = {}
  for (const s of attackerSessions) {
    byStrategy[s.label] ??= {}
    byStrategy[s.label][s.mode] = s
  }

  return (
    <>
      <p className="muted">
        Run <span className="mono">{evaluation.run_id}</span> · seed{' '}
        <span className="mono">{evaluation.base_seed}</span> — real results, not simulated.
      </p>

      <table className="admin-table">
        <thead>
          <tr><th>Strategy</th><th>Fast Detection</th><th>Slow Detection</th></tr>
        </thead>
        <tbody>
          {Object.entries(byStrategy).map(([strategy, byMode]) => (
            <tr key={strategy}>
              <td>{strategy}</td>
              <td>{detectionCell(byMode.fast)}</td>
              <td>{detectionCell(byMode.slow)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <table className="admin-table" style={{ marginTop: '1rem' }}>
        <thead>
          <tr>
            <th>Strategy</th><th>Mode</th><th>Detection</th><th>Throttle</th>
            <th>Block</th><th>Avg Risk</th>
          </tr>
        </thead>
        <tbody>
          {attackerSessions.map((s) => (
            <tr key={`${s.label}-${s.mode}`}>
              <td>{s.label}</td>
              <td>{s.mode.toUpperCase()}</td>
              <td>{s.metrics.detected ? `Yes (@${s.metrics.first_detection_query})` : 'No'}</td>
              <td>{s.metrics.throttled > 0 ? 'Yes' : 'No'}</td>
              <td>{s.metrics.blocked > 0 ? 'Yes' : 'No'}</td>
              <td className="mono">{fmt(s.metrics.avg_risk)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}

function detectionCell(session) {
  if (!session) return '—'
  return session.metrics.detected ? `Yes (@${session.metrics.first_detection_query})` : 'No'
}

function fmt(v) {
  return typeof v === 'number' ? v.toFixed(1) : 'n/a'
}

function Stat({ label, value }) {
  return (
    <div className="stat-tile">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}

function UserStatusBadge({ status }) {
  const color = USER_STATUS_COLOR[status] || 'var(--muted)'
  return (
    <span
      className="badge"
      style={{ color, borderColor: color, background: `color-mix(in srgb, ${color} 14%, transparent)` }}
    >
      {status}
    </span>
  )
}
