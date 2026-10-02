import { useEffect, useRef, useState } from 'react'
import { getAttackerTarget, getStrategies } from '../api/client.js'
import '../styles/attacker.css'

// ATTACKER CONSOLE — mounted at /attacker. A control + visualization layer
// only: every query goes out over GET /api/attacker-console/stream, a
// server-sent-events endpoint that itself does nothing but (a) generate
// queries with the existing Python strategy generators and (b) POST each one
// to the real /api/chat, exactly like attacker.py and a real browser do.
// This page never talks to Ollama, never talks to the firewall directly, and
// carries no more information than an external attacker would plausibly see.
//
// That last point is load-bearing, not incidental: the SSE payload itself is
// client-safe (query_number, query, response -- nothing else), so there is
// no decision/risk/signal data available to this component even to
// accidentally render. A blocked query looks identical, on the wire, to any
// other query with no response text. /admin is the only surface that sees
// why.

// UI-facing strategy ids (shared vocabulary with attacker.py's CLI flags) and
// their presentation-only pattern preview -- the actual query text always
// comes from the backend's reusable generators, this is decoration only.
const STRATEGY_PREVIEW = {
  repetition: { short: 'REPETITION', preview: ['Q', 'Q', 'Q', 'Q', 'Q'] },
  minimal_modification: { short: 'MIN. MODIFICATION', preview: ['Q+Δ1', 'Q+Δ2', 'Q+Δ3', 'Q+Δ4'] },
  value_sweep: { short: 'VALUE SWEEP', preview: ['1', '2', '3', '4', '5'] },
  output_constraint: { short: 'OUTPUT CONSTRAINT', preview: ['JSON', 'TABLE', '50w', 'STEPS'] },
  boundary: { short: 'BOUNDARY / EDGE', preview: ['80', '443', '0', '−1', '65535'] },
}
const STRATEGY_ORDER = ['repetition', 'minimal_modification', 'value_sweep', 'output_constraint', 'boundary']
const INTERNAL_TO_ALIAS = {
  exact_repetition: 'repetition', minimal_modification: 'minimal_modification',
  value_sweep: 'value_sweep', constraint_probing: 'output_constraint',
  boundary_probing: 'boundary',
}

const COUNT_PRESETS = [10, 20, 30, 50]

export default function AttackerSimulator() {
  const [strategies, setStrategies] = useState(null)
  const [strategy, setStrategy] = useState('repetition')
  const [mode, setMode] = useState('fast')
  const [count, setCount] = useState(10)
  const [customCount, setCustomCount] = useState('')
  const [topic, setTopic] = useState('')

  const [status, setStatus] = useState('idle') // idle | running | stopped | completed
  const [clientId, setClientId] = useState(null)
  const [total, setTotal] = useState(0)
  const [entries, setEntries] = useState([])
  const [errorMsg, setErrorMsg] = useState(null)
  // Whether a real /chat conversation is currently available to continue --
  // see app/services/target_registry.py. Polled rather than pushed: it's a
  // single boolean checked a few times a minute, not worth a second SSE
  // connection just for this (PROMPT section 5 explicitly allows polling
  // "if it significantly reduces implementation complexity").
  const [targetAvailable, setTargetAvailable] = useState(false)

  const sourceRef = useRef(null)
  const streamEndRef = useRef(null)

  useEffect(() => {
    getStrategies()
      .then((list) => {
        const byAlias = {}
        for (const s of list) {
          const alias = INTERNAL_TO_ALIAS[s.id]
          if (alias) byAlias[alias] = s
        }
        setStrategies(byAlias)
      })
      .catch(() => setStrategies({}))
  }, [])

  useEffect(() => {
    let cancelled = false
    function poll() {
      getAttackerTarget()
        .then((s) => { if (!cancelled) setTargetAvailable(!!s.available) })
        .catch(() => { if (!cancelled) setTargetAvailable(false) })
    }
    poll()
    const id = setInterval(poll, 4000)
    return () => { cancelled = true; clearInterval(id) }
  }, [])

  useEffect(() => () => sourceRef.current?.close(), [])

  useEffect(() => {
    streamEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
  }, [entries.length])

  const activeCount = customCount ? Number(customCount) || 0 : count

  function startAttack() {
    if (status === 'running' || activeCount < 1) return
    setEntries([])
    setErrorMsg(null)
    setClientId(null)
    setTotal(activeCount)
    setStatus('running')

    const params = new URLSearchParams({ strategy, mode, count: String(activeCount) })
    if (topic.trim()) params.set('topic', topic.trim())

    const es = new EventSource(`/api/attacker-console/stream?${params.toString()}`)
    sourceRef.current = es

    es.addEventListener('meta', (e) => {
      const data = JSON.parse(e.data)
      setClientId(data.client_id)
      setTotal(data.total)
    })

    es.addEventListener('query', (e) => {
      setEntries((prev) => [...prev, JSON.parse(e.data)])
    })

    es.addEventListener('done', (e) => {
      const data = JSON.parse(e.data)
      setStatus(data.status === 'stopped' ? 'stopped' : 'completed')
      es.close()
    })

    es.addEventListener('error', (e) => {
      if (e.data) {
        try { setErrorMsg(JSON.parse(e.data).message) } catch { /* ignore */ }
      }
    })

    es.onerror = () => {
      // A network-level drop, not our own explicit stop/completion.
      setStatus((s) => (s === 'running' ? 'stopped' : s))
      es.close()
    }
  }

  function stopAttack() {
    sourceRef.current?.close()
    sourceRef.current = null
    setStatus('stopped')
  }

  return (
    <div className="attacker-console">
      <div className="ac-topline">
        <span className="ac-topline__id">
          ATTACKER CONSOLE &nbsp;/&nbsp; simulation environment &nbsp;/&nbsp;
          target <b>/api/chat</b>
        </span>
        <span className="ac-topline__clock">
          {clientId ? `session ${clientId}` : 'no active session'}
        </span>
      </div>

      <StatusBar
        status={status} strategyLabel={STRATEGY_PREVIEW[strategy]?.short}
        mode={mode} sent={entries.length} total={total}
      />

      <div className="ac-layout">
        <ConfigPanel
          strategies={strategies} strategy={strategy} setStrategy={setStrategy}
          mode={mode} setMode={setMode}
          count={count} setCount={setCount}
          customCount={customCount} setCustomCount={setCustomCount}
          topic={topic} setTopic={setTopic}
          clientId={clientId} status={status}
          onStart={startAttack} onStop={stopAttack}
          activeCount={activeCount}
          targetAvailable={targetAvailable}
        />

        <div className="ac-main">
          <LiveStream entries={entries} status={status} endRef={streamEndRef} errorMsg={errorMsg} />
        </div>
      </div>
    </div>
  )
}

function StatusBar({ status, strategyLabel, mode, sent, total }) {
  return (
    <div className="ac-status">
      <Cell label="Attack Status">
        <span className={`ac-status__value ac-status__value--${status}`}>
          {status === 'running' && <span className="ac-pulse" />}
          {status.toUpperCase()}
        </span>
      </Cell>
      <Cell label="Strategy">
        <span className="ac-status__value">{strategyLabel || '—'}</span>
      </Cell>
      <Cell label="Mode">
        <span className="ac-status__value">{mode.toUpperCase()}</span>
      </Cell>
      <Cell label="Queries Sent">
        <span className="ac-status__value">{sent} / {total || '—'}</span>
      </Cell>
    </div>
  )
}

function Cell({ label, children }) {
  return (
    <div className="ac-status__cell">
      <div className="ac-status__label">{label}</div>
      {children}
    </div>
  )
}

function ConfigPanel({
  strategies, strategy, setStrategy, mode, setMode, count, setCount,
  customCount, setCustomCount, topic, setTopic, clientId, status,
  onStart, onStop, activeCount, targetAvailable,
}) {
  const running = status === 'running'
  const active = strategies?.[strategy]
  const preview = STRATEGY_PREVIEW[strategy]

  return (
    <div className="ac-panel ac-sidebar">
      <div className="ac-panel__body">
        <div className="ac-field">
          <span className="ac-field__label">Attack Pattern</span>
          <div className="ac-strategy-list" role="radiogroup" aria-label="Attack pattern">
            {STRATEGY_ORDER.map((id) => (
              <button
                key={id} type="button" className="ac-strategy"
                role="radio" aria-checked={strategy === id} aria-pressed={strategy === id}
                onClick={() => setStrategy(id)} disabled={running}
              >
                <div className="ac-strategy__name">{strategies?.[id]?.name || STRATEGY_PREVIEW[id].short}</div>
                <div className="ac-strategy__targets">
                  {strategies?.[id]?.targets?.slice(0, 2).join(' · ') || ' '}
                </div>
              </button>
            ))}
          </div>

          {active && (
            <div className="ac-pattern">
              <p className="ac-pattern__desc">{active.description}</p>
              <div className="ac-pattern__preview">
                {preview.preview.map((chip, i) => (
                  <span key={i} style={{ display: 'contents' }}>
                    {i > 0 && <span className="ac-pattern__arrow">&rarr;</span>}
                    <span className="ac-pattern__chip">{chip}</span>
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="ac-field">
          <span className="ac-field__label">Attack Speed</span>
          <div className="ac-mode" role="radiogroup" aria-label="Attack speed">
            <button type="button" className="ac-mode__btn" aria-pressed={mode === 'fast'}
                    onClick={() => setMode('fast')} disabled={running}>
              FAST
              <small>burst · ~0.3s between queries</small>
            </button>
            <button type="button" className="ac-mode__btn" aria-pressed={mode === 'slow'}
                    onClick={() => setMode('slow')} disabled={running}>
              SLOW / HUMAN
              <small>paced · 5–15s, randomized</small>
            </button>
          </div>
        </div>

        <div className="ac-field">
          <span className="ac-field__label">Query Count</span>
          <div className="ac-count">
            {COUNT_PRESETS.map((n) => (
              <button key={n} type="button" className="ac-count__chip"
                      aria-pressed={!customCount && count === n}
                      onClick={() => { setCount(n); setCustomCount('') }} disabled={running}>
                {n}
              </button>
            ))}
            <input
              className="ac-count__custom" type="number" min="1" max="200" placeholder="custom"
              value={customCount} onChange={(e) => setCustomCount(e.target.value)} disabled={running}
            />
          </div>
        </div>

        <div className="ac-field">
          <span className="ac-field__label">Topic Hint (optional)</span>
          <input
            className="ac-input" type="text" placeholder="e.g. jwt, xss, tls"
            value={topic} onChange={(e) => setTopic(e.target.value)} disabled={running}
          />
        </div>

        <div className="ac-field">
          <span className="ac-field__label">Target</span>
          <div className={`ac-target${targetAvailable ? ' ac-target--connected' : ''}`}>
            <span className="ac-target__dot" />
            <div>
              <div className="ac-target__state">
                {targetAvailable ? 'Connected' : 'No active target'}
              </div>
              <div className="ac-target__desc">
                {targetAvailable
                  ? 'An open /chat conversation will be continued.'
                  : 'Open a chat conversation first.'}
              </div>
            </div>
          </div>
        </div>

        <div className="ac-field">
          <span className="ac-field__label">Client ID</span>
          <div className="ac-clientid">
            <span className="ac-clientid__value">{clientId || 'assigned on start'}</span>
          </div>
        </div>

        <div className="ac-actions">
          <button className="ac-btn ac-btn--start" onClick={onStart} disabled={running || activeCount < 1}>
            START ATTACK
          </button>
          <button className="ac-btn ac-btn--stop" onClick={onStop} disabled={!running}>
            STOP ATTACK
          </button>
        </div>
      </div>
    </div>
  )
}

function LiveStream({ entries, status, endRef, errorMsg }) {
  return (
    <div className="ac-panel ac-stream">
      <div className="ac-panel__head">
        <span className="ac-panel__title">Live Query Stream</span>
        <span className="ac-panel__title" style={{ color: 'var(--ac-text-faint)' }}>
          {entries.length} received
        </span>
      </div>
      <div className="ac-stream__body">
        {entries.length === 0 && status !== 'running' && (
          <div className="ac-stream__empty">
            {errorMsg
              ? <>Could not start the attack: <b>{errorMsg}</b></>
              : <>Configure an attack on the left and press <b>START ATTACK</b>.
                  Queries and model responses will appear here in real
                  time.</>}
          </div>
        )}
        {entries.length === 0 && status === 'running' && (
          <div className="ac-stream__empty">Waiting for the first response…</div>
        )}
        {entries.map((e) => <StreamEntry key={e.query_number} entry={e} />)}
        <div ref={endRef} />
      </div>
    </div>
  )
}

function StreamEntry({ entry }) {
  const hasResponse = !!entry.response
  return (
    <div className={`ac-entry${hasResponse ? '' : ' ac-entry--empty'}`}>
      <div className="ac-entry__head">
        <span className="ac-entry__q">QUERY {String(entry.query_number).padStart(2, '0')}</span>
      </div>
      <p className="ac-entry__query">&ldquo;{entry.query}&rdquo;</p>
      {hasResponse ? (
        <div className="ac-entry__response">{entry.response}</div>
      ) : (
        <div className="ac-entry__empty-response">No response from the model.</div>
      )}
    </div>
  )
}
