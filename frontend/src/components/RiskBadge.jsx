const COLORS = {
  LOW: 'var(--allow)',
  MEDIUM: 'var(--monitor)',
  HIGH: 'var(--throttle)',
  CRITICAL: 'var(--block)',
}

export default function RiskBadge({ band, score }) {
  const color = COLORS[band] || 'var(--muted)'
  return (
    <span
      className="badge"
      style={{
        color,
        borderColor: color,
        background: `color-mix(in srgb, ${color} 14%, transparent)`,
      }}
    >
      {band}{typeof score === 'number' ? ` · ${score.toFixed(1)}` : ''}
    </span>
  )
}
