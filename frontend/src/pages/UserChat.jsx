import { useEffect, useRef, useState } from 'react'
import { useAuth } from '../AuthContext.jsx'
import { createConversation, getConversation, listConversations, sendMessage } from '../api/client.js'
import Markdown from '../components/Markdown.jsx'
import {
  BugIcon, KeyIcon, LockIcon, MenuIcon, PanelCloseIcon, PlusIcon, SendIcon, ShieldIcon,
} from '../components/ChatIcons.jsx'
import '../styles/chat.css'

// NORMAL USER surface -- a simple ChatGPT-like interface, mounted at /chat.
//
// Shows: the user's own prompts, the model's responses, and their own
// conversation history. Deliberately does NOT show: risk scores, firewall
// decisions (ALLOW/MONITOR/THROTTLE/BLOCK), signal names/weights,
// thresholds, other users, or security events -- those live only behind
// /admin, gated server-side. A message the firewall blocked (or that
// otherwise failed to get a response) is shown as a plain "couldn't
// respond" notice, not as a security event -- see api/client.js's
// sendMessage and the backend's ConversationMessage schema, which has no
// action/risk_score/risk_band field to leak in the first place.
//
// Security identity vs. chat history, the core fix behind this page: the
// firewall's client_id comes from the authenticated account (assigned once
// at registration, see backend/app/db/repository.py's UserRepository.create),
// not from a random id cached in this browser's localStorage. Starting a new
// conversation only ever calls POST /api/conversations -- it never touches
// security state, so a fresh conversation is a clean transcript, never a
// firewall reset.

const SUGGESTIONS = [
  {
    icon: BugIcon, title: 'SQL Injection',
    desc: 'How attackers exploit unsanitized queries.',
    query: 'What is SQL injection?',
  },
  {
    icon: KeyIcon, title: 'JWT Authentication',
    desc: 'How tokens verify identity and stay secure.',
    query: 'Explain JWT authentication.',
  },
  {
    icon: LockIcon, title: 'TLS vs SSL',
    desc: 'How the two encrypted transport protocols differ.',
    query: 'What is the difference between TLS and SSL?',
  },
]

const NEAR_BOTTOM_PX = 120
const TEXTAREA_MAX_PX = 152

// Merges one resolved turn (from this tab's own POST response, OR from the
// conversation's live SSE stream -- see the effect below) into the message
// list exactly once, whichever arrives first:
//   - a `seq` already present means the other path already applied this
//     turn; no-op (this is the whole de-duplication story -- item 21 of the
//     PROMPT).
//   - otherwise, if there's still an in-flight optimistic "pending" bubble
//     for this exact query text, resolve it in place (so this tab's own
//     send doesn't show a duplicate bubble if the SSE echo wins the race).
//   - otherwise it's a turn this tab didn't originate locally (the
//     attacker console continuing this conversation) -- append it.
function mergeResolvedTurn(prev, data) {
  if (prev.some((m) => m.seq === data.seq)) return prev
  const role = data.source === 'attacker' ? 'external' : 'user'
  const resolved = { role, text: data.query, response: data.response, seq: data.seq }
  const pendingIdx = prev.findIndex((m) => m.role === 'pending' && m.text === data.query)
  if (pendingIdx !== -1) {
    const next = prev.slice()
    next[pendingIdx] = resolved
    return next
  }
  return [...prev, resolved]
}

export default function UserChat() {
  const { auth } = useAuth()
  const token = auth.token

  const [conversations, setConversations] = useState([])
  const [activeId, setActiveId] = useState(null)
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const [loadingConv, setLoadingConv] = useState(false)
  const [error, setError] = useState(null)
  const [sidebarOpen, setSidebarOpen] = useState(true)

  const logRef = useRef(null)
  const bottomRef = useRef(null)
  const textareaRef = useRef(null)
  const stickToBottomRef = useRef(true)
  const latestConvRequest = useRef(0)
  const sourceRef = useRef(null)

  useEffect(() => {
    refreshConversations()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Only auto-scroll to the newest message if the reader was already near
  // the bottom -- don't yank them away from older content they're reading.
  useEffect(() => {
    const el = logRef.current
    if (!el) return
    function onScroll() {
      const distance = el.scrollHeight - el.scrollTop - el.clientHeight
      stickToBottomRef.current = distance < NEAR_BOTTOM_PX
    }
    el.addEventListener('scroll', onScroll)
    return () => el.removeEventListener('scroll', onScroll)
  }, [])

  useEffect(() => {
    if (stickToBottomRef.current) bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, sending])

  useEffect(() => {
    stickToBottomRef.current = true
  }, [activeId])

  // Real-time companion to loading a conversation: while it's open, any new
  // turn filed under it -- including one the attacker console injects into
  // this SAME conversation (see AttackerSimulator.jsx) -- arrives here the
  // moment it's ready, no refresh or re-fetch needed. The browser's native
  // EventSource auto-reconnects on a dropped connection by itself; replayed
  // events are simply no-ops via mergeResolvedTurn's seq check above.
  useEffect(() => {
    sourceRef.current?.close()
    sourceRef.current = null
    if (!activeId) return undefined

    const es = new EventSource(`/api/conversations/${activeId}/stream?token=${encodeURIComponent(token)}`)
    sourceRef.current = es
    let readyCount = 0

    es.addEventListener('ready', () => {
      readyCount += 1
      if (readyCount > 1) {
        // A `ready` after the first one means this connection dropped and
        // EventSource reconnected on its own -- reload the conversation
        // once to pick up anything sent while disconnected. mergeResolvedTurn
        // isn't involved here on purpose: openConversation replaces the
        // whole list from the backend (the source of truth), so there's
        // nothing to de-duplicate against.
        openConversation(activeId)
      }
    })

    es.addEventListener('message', (e) => {
      const data = JSON.parse(e.data)
      setMessages((prev) => mergeResolvedTurn(prev, data))
    })

    return () => {
      es.close()
      if (sourceRef.current === es) sourceRef.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeId])

  useEffect(() => {
    const ta = textareaRef.current
    if (!ta) return
    ta.style.height = 'auto'
    ta.style.height = `${Math.min(ta.scrollHeight, TEXTAREA_MAX_PX)}px`
  }, [input])

  async function refreshConversations(selectId) {
    try {
      const list = await listConversations(token)
      setConversations(list)
      if (selectId) {
        await openConversation(selectId)
      } else if (!activeId && list.length > 0) {
        await openConversation(list[0].id)
      }
    } catch (err) {
      setError(err.message)
    }
  }

  async function openConversation(id) {
    // Guards against overlapping loads resolving out of order (StrictMode's
    // dev-only double effect invocation fires the mount-time load twice;
    // this also protects a real double-click on two sidebar items in a row)
    // -- only the response to the MOST RECENT request is ever applied.
    const requestId = ++latestConvRequest.current
    setActiveId(id)
    setLoadingConv(true)
    setError(null)
    try {
      const detail = await getConversation(token, id)
      if (latestConvRequest.current !== requestId) return
      setMessages(detail.messages.map((m) => ({
        role: m.source === 'attacker' ? 'external' : 'user',
        text: m.query, response: m.response, seq: m.seq,
      })))
    } catch (err) {
      if (latestConvRequest.current === requestId) setError(err.message)
    } finally {
      if (latestConvRequest.current === requestId) setLoadingConv(false)
    }
  }

  async function startNewConversation() {
    setError(null)
    try {
      const conv = await createConversation(token)
      setConversations((cs) => [conv, ...cs])
      setActiveId(conv.id)
      setMessages([])
    } catch (err) {
      setError(err.message)
    }
  }

  async function send(e) {
    e.preventDefault()
    const query = input.trim()
    if (!query || sending) return

    let conversationId = activeId
    if (!conversationId) {
      try {
        const conv = await createConversation(token)
        setConversations((cs) => [conv, ...cs])
        conversationId = conv.id
        setActiveId(conv.id)
      } catch (err) {
        setError(err.message)
        return
      }
    }

    setInput('')
    setSending(true)
    setError(null)
    setMessages((m) => [...m, { role: 'pending', text: query }])

    try {
      const res = await sendMessage(token, conversationId, query)
      setMessages((m) => mergeResolvedTurn(m, {
        seq: res.seq, query, response: res.response, source: 'user',
      }))
      // Title/order may have changed (first message in a conversation sets
      // its title) -- refresh the sidebar list quietly, keep this
      // conversation selected.
      const list = await listConversations(token)
      setConversations(list)
    } catch {
      // Never surface raw backend/network error text to the chat transcript
      // -- no stack traces, no firewall/db internals, just a plain retry
      // prompt (Part 18).
      setMessages((m) => [
        ...m.slice(0, -1),
        { role: 'user', text: query, response: null, failed: true },
      ])
    } finally {
      setSending(false)
    }
  }

  function onInputKeyDown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send(e)
    }
  }

  const hasMessages = messages.length > 0

  return (
    <div className="chat-shell">
      {sidebarOpen && (
        <div className="chat-sidebar-backdrop" onClick={() => setSidebarOpen(false)} />
      )}
      <aside className={`chat-sidebar${sidebarOpen ? '' : ' chat-sidebar--closed'}`}>
        <div className="chat-sidebar__head">
          <button className="chat-sidebar__new" onClick={startNewConversation}>
            <PlusIcon /> New Chat
          </button>
          <button
            className="chat-sidebar__collapse" onClick={() => setSidebarOpen(false)}
            title="Close history" aria-label="Close history"
          >
            <PanelCloseIcon />
          </button>
        </div>
        <ConversationList
          conversations={conversations} activeId={activeId} onSelect={openConversation}
        />
      </aside>

      <main className="chat-page">
        <div className="chat-topbar">
          {!sidebarOpen && (
            <button
              className="chat-history-fab" onClick={() => setSidebarOpen(true)}
              title="Open history" aria-label="Open history"
            >
              <MenuIcon />
            </button>
          )}
          <p className="muted chat-signed-in">
            Signed in as <span className="mono">{auth.user.username}</span>
          </p>
        </div>

        {error && <p className="notice error" style={{ padding: '0 1.25rem' }}>{error}</p>}

        <div className="chat-log" ref={logRef}>
          {loadingConv && (
            <div className="chat-hero-wrap"><p className="muted">Loading…</p></div>
          )}

          {!loadingConv && !hasMessages && (
            <div className="chat-hero-wrap">
              <div className="chat-hero">
                <div className="chat-hero__icon-wrap"><ShieldIcon /></div>
                <h1 className="chat-hero__greeting">
                  Welcome back, <span className="accent">{auth.user.username}</span>.
                </h1>
                <p className="chat-hero__subtitle">Think. Ask. Explore.</p>
                <div className="chat-cards">
                  {SUGGESTIONS.map((s) => (
                    <button key={s.query} className="chat-card" onClick={() => setInput(s.query)}>
                      <div className="chat-card__icon"><s.icon /></div>
                      <div className="chat-card__title">{s.title}</div>
                      <p className="chat-card__desc">{s.desc}</p>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {!loadingConv && hasMessages && (
            <div className="chat-conversation">
              {messages.map((m, i) => <MessageTurn key={i} turn={m} />)}
              <div ref={bottomRef} />
            </div>
          )}
        </div>

        <div className="chat-input-area">
          <form className="chat-input-row" onSubmit={send}>
            <textarea
              ref={textareaRef}
              rows={1}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={onInputKeyDown}
              placeholder="Ask a question…"
              disabled={sending}
            />
            <span className="chat-badge">Numa</span>
            <button
              type="submit" className="chat-send-btn"
              disabled={sending || !input.trim()}
              aria-label={sending ? 'Sending…' : 'Send'} title={sending ? 'Sending…' : 'Send'}
            >
              <SendIcon />
            </button>
          </form>
          <p className="chat-disclaimer">
            Numa can make mistakes. Verify important security guidance.
          </p>
        </div>
      </main>
    </div>
  )
}

function ConversationList({ conversations, activeId, onSelect }) {
  if (conversations.length === 0) {
    return <p className="muted chat-sidebar__empty">No conversations yet.</p>
  }
  const groups = groupByDate(conversations)
  return (
    <div className="chat-sidebar__list">
      {groups.map(([label, items]) => (
        <div key={label} className="chat-sidebar__group">
          <div className="chat-sidebar__group-label">{label}</div>
          {items.map((c) => (
            <button
              key={c.id}
              className={`chat-sidebar__item${c.id === activeId ? ' chat-sidebar__item--active' : ''}`}
              onClick={() => onSelect(c.id)}
              title={c.title || 'New conversation'}
            >
              {c.title || 'New conversation'}
            </button>
          ))}
        </div>
      ))}
    </div>
  )
}

function groupByDate(conversations) {
  const today = new Date(); today.setHours(0, 0, 0, 0)
  const yesterday = new Date(today); yesterday.setDate(yesterday.getDate() - 1)

  const buckets = new Map()
  for (const c of conversations) {
    const d = new Date(c.updated_at)
    const dayStart = new Date(d); dayStart.setHours(0, 0, 0, 0)
    let label
    if (dayStart.getTime() === today.getTime()) label = 'Today'
    else if (dayStart.getTime() === yesterday.getTime()) label = 'Yesterday'
    else label = dayStart.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
    if (!buckets.has(label)) buckets.set(label, [])
    buckets.get(label).push(c)
  }
  return [...buckets.entries()]
}

function MessageTurn({ turn }) {
  const isPending = turn.role === 'pending'
  const isExternal = turn.role === 'external'
  return (
    <div className="chat-turn">
      {isExternal && <div className="msg-external-label">External request</div>}
      <div className="msg-user"><p>{turn.text}</p></div>

      {isPending ? (
        <div className="msg-assistant msg-assistant--thinking">
          <div className="msg-assistant__label">
            <span className="msg-assistant__avatar"><ShieldIcon /></span> Numa
          </div>
          <p className="msg-assistant__thinking">Thinking…</p>
        </div>
      ) : (
        <div className="msg-assistant">
          <div className="msg-assistant__label">
            <span className="msg-assistant__avatar"><ShieldIcon /></span> Numa
          </div>
          {turn.response ? (
            <Markdown text={turn.response} />
          ) : (
            <p className="msg-assistant__empty">
              {turn.failed
                ? "Sorry, I couldn't get a response from the model. Please try again."
                : 'The assistant could not respond to this message.'}
            </p>
          )}
        </div>
      )}
    </div>
  )
}
