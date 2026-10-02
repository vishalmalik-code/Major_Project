const COLORS = {
  ALLOW: 'var(--allow)',
  MONITOR: 'var(--monitor)',
  THROTTLE: 'var(--throttle)',
  BLOCK: 'var(--block)',
}

export default function ActionTag({ action }) {
  const color = COLORS[action] || 'var(--muted)'
  return (
    <span
      className="badge"
      style={{
        color,
        borderColor: color,
        background: `color-mix(in srgb, ${color} 14%, transparent)`,
      }}
    >
      {action}
    </span>
  )
}
