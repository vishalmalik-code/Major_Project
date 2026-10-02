import { useEffect, useState, useRef } from 'react'
import { getStrategies, previewAttack, runAttack, getRun } from '../api/client.js'
import QueryTimeline from '../components/QueryTimeline.jsx'
import RiskChart from '../components/RiskChart.jsx'

// ATTACK SIMULATOR surface.
//
// Controls: strategy (5) x mode (FAST | SLOW) x count x client_id x seed.
// Preview shows the generated queries BEFORE firing, so the pattern is
// visible as a pattern. Running streams a live timeline via polling.

const POLL_MS = 1500

export default function AttackConsole() {
  const [strategies, setStrategies] = useState([])
  const [strategy, setStrategy] = useState('')
  const [mode, setMode] = useState('FAST')
  const [count, setCount] = useState(10)
  const [seed, setSeed] = useState(42)
  const [clientId, setClientId] = useState('attacker-1')
  const [preview, setPreview] = useState(null)
  const [run, setRun] = useState(null)
  const [error, setError] = useState(null)
  const pollRef = useRef(null)

  useEffect(() => {
    getStrategies().then((s) => {
      setStrategies(s)
      if (s.length) setStrategy(s[0].id)
    }).catch((e) => setError(e.message))
  }, [])

  useEffect(() => () => clearInterval(pollRef.current), [])

  const selected = strategies.find((s) => s.id === strategy)

  async function doPreview() {
    setError(null)
    try {
      const res = await previewAttack({ strategy, count: Number(count), seed: Number(seed) })
      setPreview(res.queries)
    } catch (e) {
      setError(e.message)
    }
  }

  async function doRun() {
    setError(null)
    setRun(null)
    clearInterval(pollRef.current)
    try {
      const started = await runAttack({
        strategy, mode, count: Number(count), client_id: clientId, seed: Number(seed),
      })
      setRun(started)
      pollRef.current = setInterval(async () => {
        try {
          const latest = await getRun(started.run_id)
          setRun(latest)
          if (latest.status === 'finished') clearInterval(pollRef.current)
        } catch (e) {
          clearInterval(pollRef.current)
          setError(e.message)
        }
      }, POLL_MS)
    } catch (e) {
      setError(e.message)
    }
  }

  const chartPoints = run?.timeline?.map((s) => ({ seq: s.seq, risk: s.risk })) || []

  return (
    <main className="page">
      <h2>Attack Simulator</h2>
      {error && <p className="notice error">{error}</p>}

      <div className="panel">
        <div className="form-row">
          <label>
            Strategy
            <select value={strategy} onChange={(e) => { setStrategy(e.target.value); setPreview(null) }}>
              {strategies.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
          </label>
          <label>
            Mode
            <select value={mode} onChange={(e) => setMode(e.target.value)}>
              <option value="FAST">FAST (burst)</option>
              <option value="SLOW">SLOW (human-paced)</option>
            </select>
          </label>
          <label>
            Count
            <input type="number" min={1} max={40} value={count}
                  onChange={(e) => setCount(e.target.value)} />
          </label>
          <label>
            Seed
            <input type="number" value={seed} onChange={(e) => setSeed(e.target.value)} />
          </label>
          <label>
            Client ID
            <input type="text" value={clientId} onChange={(e) => setClientId(e.target.value)} />
          </label>
        </div>
        {selected && <p className="muted">{selected.description} Targets: {selected.targets.join(', ')}.</p>}
        <div className="button-row">
          <button onClick={doPreview}>Preview queries</button>
          <button className="primary" onClick={doRun}>Run attack</button>
        </div>
      </div>

      {preview && (
        <div className="panel">
          <h3>Generated queries</h3>
          <ol>{preview.map((q, i) => <li key={i} className="mono">{q}</li>)}</ol>
        </div>
      )}

      {run && (
        <div className="panel">
          <h3>Run {run.run_id} — {run.status}</h3>
          <p className="muted">
            sent {run.sent}/{run.total} · ALLOW {run.counts.ALLOW || 0} ·
            MONITOR {run.counts.MONITOR || 0} · THROTTLE {run.counts.THROTTLE || 0} ·
            BLOCK {run.counts.BLOCK || 0}
            {run.queries_to_first_block != null &&
              ` · blocked after ${run.queries_to_first_block} queries`}
          </p>
          <RiskChart points={chartPoints} />
          <QueryTimeline steps={run.timeline} />
        </div>
      )}
    </main>
  )
}
