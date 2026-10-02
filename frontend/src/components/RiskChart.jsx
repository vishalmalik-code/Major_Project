import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ReferenceLine } from 'recharts'

// x-axis is QUERY SEQUENCE, not time -- the chart must reflect the model.
// `points` is a list of {seq, risk}.
export default function RiskChart({ points, width = 480, height = 220 }) {
  if (!points || points.length === 0) {
    return <p className="muted">No risk history yet.</p>
  }
  return (
    <LineChart width={width} height={height} data={points} margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
      <CartesianGrid strokeDasharray="3 3" stroke="#2a2f3a" />
      <XAxis dataKey="seq" stroke="#8b93a1" label={{ value: 'query seq', position: 'insideBottom', offset: -4, fill: '#8b93a1' }} />
      <YAxis domain={[0, 100]} stroke="#8b93a1" />
      <Tooltip contentStyle={{ background: '#171a21', border: '1px solid #2a2f3a' }} labelFormatter={(v) => `query #${v}`} />
      <ReferenceLine y={30} stroke="#d29922" strokeDasharray="4 4" />
      <ReferenceLine y={55} stroke="#db6d28" strokeDasharray="4 4" />
      <ReferenceLine y={80} stroke="#f85149" strokeDasharray="4 4" />
      <Line type="monotone" dataKey="risk" stroke="#58a6ff" strokeWidth={2} dot={{ r: 3 }} isAnimationActive={false} />
    </LineChart>
  )
}
