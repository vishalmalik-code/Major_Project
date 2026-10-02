// Minimal markdown-to-React renderer for assistant chat responses.
//
// Deliberately not a dependency: it builds React elements directly (never
// dangerouslySetInnerHTML / raw HTML), so there is no XSS surface even
// though the input is untrusted LLM output. Supports the handful of
// constructs a technical Q&A response actually uses -- headings, ordered/
// unordered lists, fenced code blocks, inline code, bold, italic, and
// paragraphs -- not the full CommonMark spec.

function renderInline(text, keyPrefix) {
  const nodes = []
  const re = /`([^`]+)`|\*\*([^*]+)\*\*|\*([^*]+)\*/g
  let lastIndex = 0
  let match
  let key = 0
  while ((match = re.exec(text))) {
    if (match.index > lastIndex) nodes.push(text.slice(lastIndex, match.index))
    if (match[1] !== undefined) {
      nodes.push(<code key={`${keyPrefix}-${key++}`}>{match[1]}</code>)
    } else if (match[2] !== undefined) {
      nodes.push(<strong key={`${keyPrefix}-${key++}`}>{match[2]}</strong>)
    } else if (match[3] !== undefined) {
      nodes.push(<em key={`${keyPrefix}-${key++}`}>{match[3]}</em>)
    }
    lastIndex = re.lastIndex
  }
  if (lastIndex < text.length) nodes.push(text.slice(lastIndex))
  return nodes
}

const FENCE_RE = /^```(\w*)\s*$/
const HEADING_RE = /^(#{1,6})\s+(.*)$/
const ORDERED_RE = /^\s*\d+\.\s+/
const BULLET_RE = /^\s*[-*]\s+/
const BLANK_RE = /^\s*$/

export default function Markdown({ text }) {
  if (!text) return null
  const lines = text.split('\n')
  const blocks = []
  let i = 0
  let key = 0

  while (i < lines.length) {
    const line = lines[i]

    if (BLANK_RE.test(line)) { i++; continue }

    const fence = line.match(FENCE_RE)
    if (fence) {
      const code = []
      i++
      while (i < lines.length && lines[i].trim() !== '```') { code.push(lines[i]); i++ }
      i++ // skip closing fence (or end of text)
      blocks.push(<pre className="md-code" key={`b${key++}`}><code>{code.join('\n')}</code></pre>)
      continue
    }

    const heading = line.match(HEADING_RE)
    if (heading) {
      const level = heading[1].length
      blocks.push(
        <p className={`md-heading md-heading-${level}`} key={`b${key++}`}>
          {renderInline(heading[2], `h${key}`)}
        </p>
      )
      i++
      continue
    }

    if (ORDERED_RE.test(line)) {
      const items = []
      while (i < lines.length && ORDERED_RE.test(lines[i])) {
        items.push(lines[i].replace(ORDERED_RE, ''))
        i++
      }
      blocks.push(
        <ol className="md-list" key={`b${key++}`}>
          {items.map((it, idx) => <li key={idx}>{renderInline(it, `ol${key}-${idx}`)}</li>)}
        </ol>
      )
      continue
    }

    if (BULLET_RE.test(line)) {
      const items = []
      while (i < lines.length && BULLET_RE.test(lines[i])) {
        items.push(lines[i].replace(BULLET_RE, ''))
        i++
      }
      blocks.push(
        <ul className="md-list" key={`b${key++}`}>
          {items.map((it, idx) => <li key={idx}>{renderInline(it, `ul${key}-${idx}`)}</li>)}
        </ul>
      )
      continue
    }

    const para = []
    while (
      i < lines.length && !BLANK_RE.test(lines[i]) && !FENCE_RE.test(lines[i]) &&
      !HEADING_RE.test(lines[i]) && !ORDERED_RE.test(lines[i]) && !BULLET_RE.test(lines[i])
    ) {
      para.push(lines[i])
      i++
    }
    blocks.push(
      <p key={`b${key++}`}>
        {para.map((l, idx) => (
          <span key={idx}>
            {renderInline(l, `p${key}-${idx}`)}
            {idx < para.length - 1 ? <br /> : null}
          </span>
        ))}
      </p>
    )
  }

  return <>{blocks}</>
}
