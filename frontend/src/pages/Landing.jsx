import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { SparkMark, MessageIcon, BrainIcon, BoltIcon, ArrowRightIcon, MenuIcon, CloseIcon, GithubIcon, MailIcon, SupportIcon } from '../components/LandingIcons.jsx'
import { ShieldIcon, SendIcon } from '../components/ChatIcons.jsx'
import '../styles/landing.css'

// / -- the signed-out front door (see App.jsx's HomeGate: a signed-in user
// never reaches this file, they're redirected straight to /chat or /admin).
//
// This is a MARKETING page only. It positions QueryFirewall as an AI
// assistant first and a protection layer second -- on purpose, per the
// product brief -- and every one of its calls to action does nothing but
// route into the existing, unmodified auth flow:
//
//   nav "Log in"           -> /login                      (login tab)
//   nav "Get Started"      -> /login  {state:{mode:'signup'}}
//   hero "Start Chatting"  -> /login  {state:{mode:'signup'}}
//   nav/footer "Product" link is a same-page scroll anchor, not a route
//
// Page is intentionally short: hero + one feature grid + footer. No
// "How It Works"/"Security"/showcase/final-CTA sections -- trimmed per
// request so scrolling to the bottom happens fast, not to hide content.
//
// It deliberately carries NO link to /attacker or /admin anywhere (nav,
// footer, or body) -- those stay reachable only by their own direct URLs,
// exactly as before this page existed. Nothing here touches auth, chat,
// firewall, or admin code.
//
// VISUAL SYSTEM: rather than each <section> painting its own flat ivory or
// charcoal background (which reads as unrelated pages stacked together),
// every section only sets `data-tone` and stays transparent -- ONE
// continuous top-to-bottom gradient is measured off the real section
// offsets (useSectionGradient, below) and painted once on the page root, so
// light/dark zones blend into each other instead of cutting hard.

function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(false)
  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    setReduced(mq.matches)
    const onChange = (e) => setReduced(e.matches)
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])
  return reduced
}

function usePointerFine() {
  const [fine, setFine] = useState(false)
  useEffect(() => {
    const mq = window.matchMedia('(hover: hover) and (pointer: fine)')
    setFine(mq.matches)
    const onChange = (e) => setFine(e.matches)
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])
  return fine
}

function useInView(threshold = 0.2) {
  const ref = useRef(null)
  const [inView, setInView] = useState(false)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) { setInView(true); return }
    const obs = new IntersectionObserver(
      (entries) => entries.forEach((e) => { if (e.isIntersecting) { setInView(true); obs.unobserve(e.target) } }),
      { threshold },
    )
    obs.observe(el)
    return () => obs.disconnect()
  }, [threshold])
  return [ref, inView]
}

function Reveal({ children, className = '', delay = 0 }) {
  const [ref, inView] = useInView(0.15)
  return (
    <div
      ref={ref}
      className={`lp-reveal${inView ? ' lp-reveal--visible' : ''}${className ? ` ${className}` : ''}`}
      style={delay ? { transitionDelay: `${delay}ms` } : undefined}
    >
      {children}
    </div>
  )
}

function scrollToId(id) {
  const el = document.getElementById(id)
  if (!el) return
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches
  el.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' })
}

// One continuous background instead of hard per-section color cuts: read
// the real DOM offsets of every `[data-tone]` section and build a single
// linear-gradient (painted on the page root) whose stops blend across a
// small margin at each boundary. Recomputed on resize/content changes via
// ResizeObserver -- no fixed percentages to keep in sync by hand.
function useSectionGradient(rootRef) {
  const [bg, setBg] = useState(null)
  useLayoutEffect(() => {
    const root = rootRef.current
    if (!root) return
    function compute() {
      const sections = Array.from(root.querySelectorAll('[data-tone]'))
      if (!sections.length) return
      const total = root.scrollHeight || 1
      const blend = Math.max(70, Math.min(180, total * 0.025))
      const stops = []
      sections.forEach((sec, i) => {
        const color = sec.dataset.tone === 'dark' ? 'var(--lp-charcoal)' : 'var(--lp-ivory)'
        const top = sec.offsetTop
        const bottom = top + sec.offsetHeight
        const start = i === 0 ? 0 : Math.min(total, top + blend)
        const end = Math.max(start, bottom - blend)
        stops.push(`${color} ${(start / total * 100).toFixed(3)}%`, `${color} ${(end / total * 100).toFixed(3)}%`)
      })
      setBg(`linear-gradient(to bottom, ${stops.join(', ')})`)
    }
    compute()
    const ro = new ResizeObserver(compute)
    ro.observe(root)
    window.addEventListener('resize', compute)
    return () => { ro.disconnect(); window.removeEventListener('resize', compute) }
  }, [rootRef])
  return bg
}

// Tiny, restrained mouse-parallax for the hero visual only -- disabled on
// touch/coarse pointers and under prefers-reduced-motion. Writes --px/--py
// custom properties the CSS reads with a translate3d, so the JS never
// touches layout.
function useParallax(ref, strength = 14) {
  const reduced = usePrefersReducedMotion()
  const fine = usePointerFine()
  useEffect(() => {
    const el = ref.current
    if (!el || reduced || !fine) return
    let raf = null
    function onMove(e) {
      const rect = el.getBoundingClientRect()
      const mx = (e.clientX - rect.left) / rect.width - 0.5
      const my = (e.clientY - rect.top) / rect.height - 0.5
      if (raf) cancelAnimationFrame(raf)
      raf = requestAnimationFrame(() => {
        el.style.setProperty('--px', `${(mx * strength).toFixed(2)}px`)
        el.style.setProperty('--py', `${(my * strength).toFixed(2)}px`)
      })
    }
    function onLeave() {
      el.style.setProperty('--px', '0px')
      el.style.setProperty('--py', '0px')
    }
    el.addEventListener('pointermove', onMove)
    el.addEventListener('pointerleave', onLeave)
    return () => {
      el.removeEventListener('pointermove', onMove)
      el.removeEventListener('pointerleave', onLeave)
      if (raf) cancelAnimationFrame(raf)
    }
  }, [ref, strength, reduced, fine])
}

// Scrollspy: which of the in-page anchor sections is nearest the vertical
// center of the viewport right now -- drives the nav's active-link state.
function useActiveSection(ids) {
  const [active, setActive] = useState(null)
  useEffect(() => {
    const els = ids.map((id) => document.getElementById(id)).filter(Boolean)
    if (!els.length) return
    const obs = new IntersectionObserver(
      (entries) => entries.forEach((e) => { if (e.isIntersecting) setActive(e.target.id) }),
      { rootMargin: '-45% 0px -45% 0px', threshold: 0 },
    )
    els.forEach((el) => obs.observe(el))
    return () => obs.disconnect()
  }, [ids.join('|')])
  return active
}

// ---- signature background: thin gold data-lines with particles drifting
// along them, plus a handful of fixed, slow-breathing "network nodes" so it
// reads as infrastructure rather than sparkle. One static frame under
// prefers-reduced-motion, fewer lines/particles on narrow viewports, paused
// via IntersectionObserver when off-screen. ----

function ParticleField({ density = 'normal' }) {
  const canvasRef = useRef(null)
  const wrapRef = useRef(null)
  const reduced = usePrefersReducedMotion()

  useEffect(() => {
    const canvas = canvasRef.current
    const wrap = wrapRef.current
    if (!canvas || !wrap) return
    const ctx = canvas.getContext('2d')
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    const narrow = window.matchMedia('(max-width: 640px)').matches
    let width = 0, height = 0
    let raf = null
    let visible = true
    let elapsed = 0

    const lineCount = (density === 'dense' ? 6 : 4) - (narrow ? 2 : 0)
    const perLine = (density === 'dense' ? 5 : 4) - (narrow ? 1 : 0)

    const lines = Array.from({ length: Math.max(2, lineCount) }, (_, i) => {
      const y0 = 0.12 + (i / lineCount) * 0.8 + (Math.random() - 0.5) * 0.08
      return {
        cp1: { x: 0.15 + Math.random() * 0.2, y: y0 + (Math.random() - 0.5) * 0.25 },
        cp2: { x: 0.6 + Math.random() * 0.2, y: y0 + (Math.random() - 0.5) * 0.25 },
        y0,
        particles: Array.from({ length: Math.max(2, perLine) }, (_, j) => ({
          t: j / perLine,
          speed: 0.00006 + Math.random() * 0.00005,
        })),
        nodes: [0.22, 0.5, 0.78].map((t) => ({ t, phase: Math.random() * Math.PI * 2 })),
      }
    })

    function pointOnLine(line, t) {
      const p0 = { x: -0.06, y: line.y0 }
      const p3 = { x: 1.06, y: line.y0 }
      const p1 = line.cp1, p2 = line.cp2
      const mt = 1 - t
      const x = mt ** 3 * p0.x + 3 * mt ** 2 * t * p1.x + 3 * mt * t ** 2 * p2.x + t ** 3 * p3.x
      const y = mt ** 3 * p0.y + 3 * mt ** 2 * t * p1.y + 3 * mt * t ** 2 * p2.y + t ** 3 * p3.y
      return { x, y }
    }

    function resize() {
      const rect = wrap.getBoundingClientRect()
      width = rect.width
      height = rect.height
      canvas.width = width * dpr
      canvas.height = height * dpr
      canvas.style.width = `${width}px`
      canvas.style.height = `${height}px`
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }

    function drawFrame(advance) {
      elapsed += advance
      ctx.clearRect(0, 0, width, height)
      lines.forEach((line) => {
        const p0 = { x: -0.06 * width, y: line.y0 * height }
        const p3 = { x: 1.06 * width, y: line.y0 * height }
        const p1 = { x: line.cp1.x * width, y: line.cp1.y * height }
        const p2 = { x: line.cp2.x * width, y: line.cp2.y * height }
        ctx.beginPath()
        ctx.moveTo(p0.x, p0.y)
        ctx.bezierCurveTo(p1.x, p1.y, p2.x, p2.y, p3.x, p3.y)
        ctx.strokeStyle = 'rgba(201, 162, 75, 0.16)'
        ctx.lineWidth = 1
        ctx.stroke()

        line.nodes.forEach((node) => {
          const pt = pointOnLine(line, node.t)
          const alpha = 0.22 + 0.18 * Math.sin(elapsed * 0.0006 + node.phase)
          ctx.beginPath()
          ctx.arc(pt.x, pt.y, 2.4, 0, Math.PI * 2)
          ctx.strokeStyle = `rgba(231, 195, 115, ${alpha})`
          ctx.lineWidth = 1
          ctx.stroke()
        })

        line.particles.forEach((particle) => {
          if (advance) {
            particle.t += particle.speed * advance
            if (particle.t > 1) particle.t -= 1
          }
          const pt = pointOnLine(line, particle.t)
          const glowAlpha = 0.35 + 0.25 * Math.sin(particle.t * Math.PI)
          ctx.beginPath()
          ctx.arc(pt.x, pt.y, 1.6, 0, Math.PI * 2)
          ctx.fillStyle = `rgba(231, 195, 115, ${glowAlpha})`
          ctx.shadowColor = 'rgba(231, 195, 115, 0.55)'
          ctx.shadowBlur = 6
          ctx.fill()
          ctx.shadowBlur = 0
        })
      })
    }

    resize()
    drawFrame(0)

    let lastTs = null
    function tick(ts) {
      if (!visible || reduced) return
      if (lastTs == null) lastTs = ts
      const dt = ts - lastTs
      lastTs = ts
      drawFrame(dt)
      raf = requestAnimationFrame(tick)
    }
    if (!reduced) raf = requestAnimationFrame(tick)

    const ro = new ResizeObserver(() => { resize(); drawFrame(0) })
    ro.observe(wrap)

    const io = new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting
      if (visible && !reduced && raf == null) { lastTs = null; raf = requestAnimationFrame(tick) }
    }, { threshold: 0 })
    io.observe(wrap)

    return () => {
      if (raf) cancelAnimationFrame(raf)
      ro.disconnect()
      io.disconnect()
    }
  }, [density, reduced])

  return (
    <div ref={wrapRef} className="lp-field" aria-hidden="true">
      <canvas ref={canvasRef} />
    </div>
  )
}

// ---- reusable chat mock, with a typing effect on the assistant turn once
// it scrolls into view. Pure UI -- no network calls, no real client_id. ----

function ChatMock({ userText, assistantText, size = 'mini' }) {
  const [ref, inView] = useInView(0.35)
  const reduced = usePrefersReducedMotion()
  const [shown, setShown] = useState(reduced ? assistantText.length : 0)

  useEffect(() => {
    if (!inView) return
    if (reduced) { setShown(assistantText.length); return }
    let i = 0
    const id = setInterval(() => {
      i += 1
      setShown(i)
      if (i >= assistantText.length) clearInterval(id)
    }, 14)
    return () => clearInterval(id)
  }, [inView, assistantText, reduced])

  const done = shown >= assistantText.length

  return (
    <div ref={ref} className={`lp-chat lp-chat--${size}`}>
      <div className="lp-chat__bar">
        <span className="lp-chat__dot" /><span className="lp-chat__dot" /><span className="lp-chat__dot" />
        <span className="lp-chat__bar-label">QueryFirewall</span>
      </div>
      <div className="lp-chat__body">
        <div className="lp-chat__msg lp-chat__msg--user">
          <span className="lp-chat__msg-label">You</span>
          <p>{userText}</p>
        </div>
        <div className="lp-chat__msg lp-chat__msg--assistant">
          <span className="lp-chat__msg-label">QueryFirewall</span>
          <p>{assistantText.slice(0, shown)}{!done && <span className="lp-chat__caret" />}</p>
        </div>
      </div>
      <div className="lp-chat__input">
        <span>Ask anything…</span>
        <span className="lp-chat__send"><SendIcon /></span>
      </div>
    </div>
  )
}

// ---- nav: scroll-progress hairline, active-section indicator, translucent
// blur once the page has scrolled past the hero. ----

function LandingNav({ onGo, onGetStarted, activeId }) {
  const [scrolled, setScrolled] = useState(false)
  const [progress, setProgress] = useState(0)
  const [open, setOpen] = useState(false)

  useEffect(() => {
    let ticking = false
    function onScroll() {
      if (ticking) return
      ticking = true
      requestAnimationFrame(() => {
        setScrolled(window.scrollY > 8)
        const doc = document.documentElement
        const max = doc.scrollHeight - doc.clientHeight
        setProgress(max > 0 ? Math.min(1, Math.max(0, window.scrollY / max)) : 0)
        ticking = false
      })
    }
    window.addEventListener('scroll', onScroll, { passive: true })
    onScroll()
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  function go(id) {
    setOpen(false)
    scrollToId(id)
  }

  const links = [
    { id: 'product', label: 'Product' },
  ]

  return (
    <header className={`lp-nav${scrolled ? ' lp-nav--scrolled' : ''}`}>
      <div className="lp-nav__progress" style={{ transform: `scaleX(${progress})` }} aria-hidden="true" />
      <div className="lp-nav__row">
        <button className="lp-nav__brand" onClick={() => scrollToId('lp-top')}>
          <SparkMark /><span>QueryFirewall</span>
        </button>

        <nav className="lp-nav__links">
          {links.map((l) => (
            <button key={l.id} data-active={activeId === l.id} onClick={() => go(l.id)}>{l.label}</button>
          ))}
        </nav>

        <div className="lp-nav__actions">
          <button className="lp-btn lp-btn--ghost" onClick={() => onGo('/login')}>Log in</button>
          <button className="lp-btn lp-btn--primary" onClick={onGetStarted}>Get Started</button>
        </div>

        <button className="lp-nav__burger" aria-label="Menu" onClick={() => setOpen((o) => !o)}>
          {open ? <CloseIcon /> : <MenuIcon />}
        </button>
      </div>

      {open && (
        <div className="lp-nav__mobile">
          {links.map((l) => (
            <button key={l.id} onClick={() => go(l.id)}>{l.label}</button>
          ))}
          <div className="lp-nav__mobile-actions">
            <button className="lp-btn lp-btn--ghost" onClick={() => onGo('/login')}>Log in</button>
            <button className="lp-btn lp-btn--primary" onClick={onGetStarted}>Get Started</button>
          </div>
        </div>
      )}
    </header>
  )
}

// ---- page ----

const FEATURES = [
  { n: '01', icon: MessageIcon, title: 'Ask Anything', desc: 'Get useful answers, explanations, ideas, and assistance across a wide range of topics.' },
  { n: '02', icon: BrainIcon, title: 'Think With AI', desc: 'Brainstorm, learn, write, summarize, and solve problems through natural conversation.' },
  { n: '03', icon: BoltIcon, title: 'Fast & Focused', desc: 'A clean conversational experience designed to get you to useful answers quickly.' },
  { n: '04', icon: ShieldIcon, title: 'Built With Protection', desc: 'Advanced safeguards work quietly behind the scenes to protect the system from suspicious usage.' },
]

export default function Landing() {
  const navigate = useNavigate()
  const getStarted = () => navigate('/login', { state: { mode: 'signup' } })

  const rootRef = useRef(null)
  const heroVisualRef = useRef(null)
  const bgGradient = useSectionGradient(rootRef)
  const activeId = useActiveSection(['product'])
  useParallax(heroVisualRef, 14)

  return (
    <div className="landing" id="lp-top" ref={rootRef} style={bgGradient ? { backgroundImage: bgGradient } : undefined}>
      <LandingNav onGo={navigate} onGetStarted={getStarted} activeId={activeId} />

      {/* ---- hero ---- */}
      <section className="lp-section lp-hero" data-tone="dark">
        <ParticleField />
        <div className="lp-hero__inner">
          <div className="lp-hero__copy">
            <Reveal><span className="lp-eyebrow">Your AI assistant</span></Reveal>
            <Reveal delay={80}>
              <h1 className="lp-h1">
                Ask anything.<br /><span className="lp-gold-word">Get intelligent</span> answers.
              </h1>
            </Reveal>
            <Reveal delay={160}>
              <p className="lp-lead">
                An intelligent AI assistant built to help you explore ideas, solve problems,
                write, and learn — with a quiet layer of protection working behind every
                conversation.
              </p>
            </Reveal>
            <Reveal delay={240}>
              <div className="lp-cta-row">
                <button className="lp-btn lp-btn--primary lp-btn--lg" onClick={getStarted}>
                  Start Chatting <ArrowRightIcon />
                </button>
                <button className="lp-btn lp-btn--secondary lp-btn--lg" onClick={() => scrollToId('product')}>
                  See What It Can Do
                </button>
              </div>
            </Reveal>
          </div>

          <Reveal delay={200} className="lp-hero__visual" >
            <div ref={heroVisualRef} className="lp-hero__visual-inner">
              <div className="lp-hero__rings" aria-hidden="true">
                <span className="lp-ring lp-ring--outer" />
                <span className="lp-ring lp-ring--inner" />
              </div>
              <ChatMock
                userText="Can you explain quantum computing simply?"
                assistantText="Think of a quantum computer as a machine that uses probability instead of certainty — exploring many answers at once before settling on the right one."
              />
            </div>
          </Reveal>
        </div>
      </section>

      {/* ---- why ---- */}
      <section className="lp-section" data-tone="light" id="product">
        <div className="lp-container">
          <Reveal><h2 className="lp-h2">Everything you need from your AI assistant.</h2></Reveal>

          <div className="lp-features">
            {FEATURES.map((f, i) => (
              <Reveal key={f.title} delay={i * 70} className="lp-feature">
                <span className="lp-feature__n">{f.n}</span>
                <span className="lp-feature__icon"><f.icon /></span>
                <h3>{f.title}</h3>
                <p>{f.desc}</p>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* ---- footer ---- */}
      <footer className="lp-footer">
        <div className="lp-footer__row">
          <div className="lp-footer__brand"><SparkMark /><span>QueryFirewall</span></div>
          <p className="lp-footer__tag">Intelligent conversations, protected by design.</p>
        </div>
        <div className="lp-footer__links">
          <div className="lp-footer__nav">
            <button onClick={() => scrollToId('product')}>Product</button>
            <button onClick={() => navigate('/login')}>Log in</button>
          </div>
          <div className="lp-footer__contact">
            {/* TODO: swap href for the real repo URL once it exists */}
            <a className="lp-footer__btn" href="#" target="_blank" rel="noopener noreferrer">
              <GithubIcon /><span>GitHub</span>
            </a>
            <a className="lp-footer__btn" href="mailto:vishalmalik1458@gmail.com">
              <MailIcon /><span>Email</span>
            </a>
            <a className="lp-footer__btn" href="mailto:vishalmalik1458@gmail.com?subject=QueryFirewall%20Support">
              <SupportIcon /><span>Support</span>
            </a>
          </div>
        </div>
        <p className="lp-footer__fine">QueryFirewall — a local research build.</p>
      </footer>
    </div>
  )
}
