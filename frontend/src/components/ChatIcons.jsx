// One consistent stroke-based icon system for the /chat page -- 24x24,
// currentColor, 1.75 stroke, round caps/joins. No emoji, no glyph fonts.

const base = {
  width: '1em', height: '1em', viewBox: '0 0 24 24',
  fill: 'none', stroke: 'currentColor', strokeWidth: 1.75,
  strokeLinecap: 'round', strokeLinejoin: 'round',
}

export function ShieldIcon(props) {
  return (
    <svg {...base} {...props}>
      <path d="M12 3.5 5 6.2v5.4c0 4.6 3 7.9 7 9.1 4-1.2 7-4.5 7-9.1V6.2L12 3.5Z" />
      <path d="m9.2 12.2 1.9 1.9 3.7-3.9" />
    </svg>
  )
}

export function MenuIcon(props) {
  return (
    <svg {...base} {...props}>
      <path d="M4 6.5h16" />
      <path d="M4 12h16" />
      <path d="M4 17.5h16" />
    </svg>
  )
}

export function PanelCloseIcon(props) {
  return (
    <svg {...base} {...props}>
      <rect x="3.5" y="4.5" width="17" height="15" rx="3" />
      <path d="M14.5 4.5v15" />
      <path d="m11 9.5-3 2.5 3 2.5" />
    </svg>
  )
}

export function PlusIcon(props) {
  return (
    <svg {...base} {...props}>
      <path d="M12 5v14" />
      <path d="M5 12h14" />
    </svg>
  )
}

export function SendIcon(props) {
  return (
    <svg {...base} {...props}>
      <path d="M4.5 12 19.5 5l-6 15-2.6-6.4L4.5 12Z" />
      <path d="m10.9 13.6 3.4-3.5" />
    </svg>
  )
}

export function BugIcon(props) {
  return (
    <svg {...base} {...props}>
      <path d="M9 8.5V7a3 3 0 0 1 6 0v1.5" />
      <rect x="7.5" y="8.5" width="9" height="10" rx="4.5" />
      <path d="M7.5 12H4M20 12h-3.5M8 17l-2.5 2M16 17l2.5 2M8 9.5 5.5 7.5M16 9.5 18.5 7.5" />
    </svg>
  )
}

export function KeyIcon(props) {
  return (
    <svg {...base} {...props}>
      <circle cx="8" cy="15" r="4" />
      <path d="M10.8 12.2 18 5" />
      <path d="M15.5 7.5 18 5l2.2 2.2" />
    </svg>
  )
}

export function LockIcon(props) {
  return (
    <svg {...base} {...props}>
      <rect x="5" y="10.5" width="14" height="9" rx="2.5" />
      <path d="M8 10.5V7.8a4 4 0 0 1 8 0v2.7" />
    </svg>
  )
}
