// The eight signals with score, weight, and evidence sentence -- the
// explainability guarantee, rendered. `signals` is a list of
// {name, score, weight, evidence, details}.
export default function SignalTable({ signals }) {
  if (!signals || signals.length === 0) {
    return <p className="muted">No signal data for this query.</p>
  }
  const sorted = [...signals].sort((a, b) => b.score * b.weight - a.score * a.weight)
  return (
    <table className="signal-table">
      <thead>
        <tr>
          <th>signal</th>
          <th>score</th>
          <th>weight</th>
          <th>evidence</th>
        </tr>
      </thead>
      <tbody>
        {sorted.map((s) => (
          <tr key={s.name}>
            <td className="mono">{s.name}</td>
            <td>
              <div className="score-bar">
                <div className="score-bar-fill" style={{ width: `${s.score * 100}%` }} />
                <span>{s.score.toFixed(2)}</span>
              </div>
            </td>
            <td className="mono">{s.weight.toFixed(1)}</td>
            <td className="evidence">{s.evidence}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
