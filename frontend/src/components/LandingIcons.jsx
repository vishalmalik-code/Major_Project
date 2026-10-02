// Icon system for the landing page (/) only -- same spec as ChatIcons.jsx
// (24x24, currentColor, 1.75 stroke, round caps/joins) so anything borrowed
// between the two reads as one visual language. Two of the landing page's
// icons (protection, send) are imported directly from ChatIcons.jsx instead
// of being redrawn here -- see Landing.jsx.

const base = {
  width: '1em', height: '1em', viewBox: '0 0 24 24',
  fill: 'none', stroke: 'currentColor', strokeWidth: 1.75,
  strokeLinecap: 'round', strokeLinejoin: 'round',
}

// Brand mark: a four-point spark -- "intelligence" as a point of light,
// not a shield or a terminal prompt. Reused at nav size and footer size.
export function SparkMark(props) {
  return (
    <svg {...base} strokeWidth={1.4} {...props}>
      <path d="M12 3c.6 3.4 2.1 5.9 5.5 6.5-3.4.6-4.9 3.1-5.5 6.5-.6-3.4-2.1-5.9-5.5-6.5C9.9 8.9 11.4 6.4 12 3Z"
        fill="currentColor" stroke="none" opacity="0.92" />
      <path d="M18.5 16.2c.3 1.5.9 2.6 2.4 2.9-1.5.3-2.1 1.4-2.4 2.9-.3-1.5-.9-2.6-2.4-2.9 1.5-.3 2.1-1.4 2.4-2.9Z"
        fill="currentColor" stroke="none" opacity="0.6" />
    </svg>
  )
}

export function MessageIcon(props) {
  return (
    <svg {...base} {...props}>
      <path d="M4 5.5h16v10.5H9l-4 3.5v-3.5H4z" />
      <path d="M8 9.5h8" />
      <path d="M8 12.5h5" />
    </svg>
  )
}

export function BrainIcon(props) {
  return (
    <svg {...base} {...props}>
      <path d="M9.5 4.5a2.5 2.5 0 0 0-2.5 2.5v.3A3 3 0 0 0 5 10v1a3 3 0 0 0 1.4 2.5A3 3 0 0 0 9 18a2.5 2.5 0 0 0 2.5-2.5v-8A2.5 2.5 0 0 0 9.5 4.5Z" />
      <path d="M14.5 4.5a2.5 2.5 0 0 1 2.5 2.5v.3A3 3 0 0 1 19 10v1a3 3 0 0 1-1.4 2.5A3 3 0 0 1 15 18a2.5 2.5 0 0 1-2.5-2.5v-8A2.5 2.5 0 0 1 14.5 4.5Z" />
    </svg>
  )
}

export function BoltIcon(props) {
  return (
    <svg {...base} {...props}>
      <path d="M12.5 3.5 5.5 13h4.8l-.8 7.5 7-9.5h-4.8z" />
    </svg>
  )
}

export function ArrowRightIcon(props) {
  return (
    <svg {...base} {...props}>
      <path d="M4.5 12h15" />
      <path d="m13.5 6 6 6-6 6" />
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

export function CloseIcon(props) {
  return (
    <svg {...base} {...props}>
      <path d="m6 6 12 12" />
      <path d="m18 6-12 12" />
    </svg>
  )
}

// ---- footer contact icons ----

// GitHub mark -- filled, not stroke, same exception SparkMark already makes
// (a brand glyph reads better solid than outlined at footer-link size).
export function GithubIcon(props) {
  return (
    <svg {...base} viewBox="0 0 16 16" fill="currentColor" stroke="none" {...props}>
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z" />
    </svg>
  )
}

export function MailIcon(props) {
  return (
    <svg {...base} {...props}>
      <rect x="3.5" y="5.5" width="17" height="13" rx="2.5" />
      <path d="m4.5 7 7.5 6 7.5-6" />
    </svg>
  )
}

export function SupportIcon(props) {
  return (
    <svg {...base} {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <circle cx="12" cy="12" r="3.5" />
      <path d="m6.2 6.2 3.5 3.5M17.8 6.2l-3.5 3.5M6.2 17.8l3.5-3.5M17.8 17.8l-3.5-3.5" />
    </svg>
  )
}
