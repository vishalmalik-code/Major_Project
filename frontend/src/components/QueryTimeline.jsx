import ActionTag from './ActionTag.jsx'

// Live attack-run feed: one row per sent query, in order.
export default function QueryTimeline({ steps }) {
  if (!steps || steps.length === 0) {
    return <p className="muted">No queries sent yet.</p>
  }
  return (
    <ol className="timeline">
      {steps.map((s) => (
        <li key={s.seq} className="timeline-row">
          <span className="mono timeline-seq">#{s.seq}</span>
          <ActionTag action={s.action} />
          <span className="mono timeline-risk">risk {s.risk.toFixed(1)}</span>
          <span className="timeline-query">{s.query}</span>
          {s.top_signal && (
            <span className="muted timeline-signal">
              {s.top_signal.name} ({s.top_signal.score.toFixed(2)})
            </span>
          )}
        </li>
      ))}
    </ol>
  )
}
