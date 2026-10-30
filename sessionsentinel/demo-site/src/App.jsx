import { useEffect, useState } from 'react'
import { BrowserRouter, Link, NavLink, Navigate, Route, Routes, useNavigate } from 'react-router-dom'
import { api } from './api'
import './App.css'

function deviceId() {
  const saved = localStorage.getItem('device_id')
  if (saved) return saved
  const value = crypto.randomUUID()
  localStorage.setItem('device_id', value)
  return value
}

function PasswordField({ value, onChange }) {
  const [visible, setVisible] = useState(false)
  return <div className="password-field">
    <input type={visible ? 'text' : 'password'} value={value} onChange={onChange} />
    <button type="button" className="password-toggle" onClick={() => setVisible(!visible)} aria-label={visible ? 'Hide password' : 'Show password'}>
      {visible ? 'Hide' : 'Show'}
    </button>
  </div>
}

function Login() {
  const navigate = useNavigate()
  const resetToken = new URLSearchParams(window.location.search).get('token') || ''
  const [email, setEmail] = useState(() => new URLSearchParams(window.location.search).get('email') || 'ali@test.com')
  const [password, setPassword] = useState(() => resetToken ? '' : 'Test@12345')
  const [error, setError] = useState(() => {
    const params = new URLSearchParams(window.location.search)
    if (params.get('verified') === '1') return 'Email verified. Sign in to open your account.'
    if (params.get('reset') === '1') return 'Password reset. Sign in with the new password.'
    return ''
  })
  const [mode, setMode] = useState(resetToken ? 'reset' : 'login')
  const [resetRequested, setResetRequested] = useState(false)
  const [signupPending, setSignupPending] = useState(false)
  const [signupMessage, setSignupMessage] = useState('')

  async function submit(event) {
    event.preventDefault()
    setError('')
    const path = mode === 'signup' ? '/signup' : '/login'
    const response = await api(path, {
      method: 'POST',
      body: JSON.stringify(mode === 'signup'
        ? { email, password }
        : { email, password, device_id: deviceId() }),
    })
    const body = await response.json()
    if (response.status === 429) {
      setError(`Too many attempts. Try again in ${body.detail.retry_after} seconds.`)
      return
    }
    if (!response.ok) {
      setError(body.detail || 'Invalid email or password')
      return
    }
    if (mode === 'signup') {
      setSignupMessage(body.message || 'Check your email for a verification link before signing in.')
      setSignupPending(true)
      return
    }
    localStorage.setItem('token', body.token)
    navigate('/account')
  }

  async function resetPassword(event) {
    event.preventDefault()
    setError('')
    const response = await api(resetToken ? '/reset-password' : '/forgot-password', {
      method: 'POST',
      body: JSON.stringify(resetToken
        ? { token: resetToken, new_password: password }
        : { email }),
    })
    const body = await response.json()
    if (!response.ok) {
      setError(body.detail || 'Could not process password reset')
      return
    }
    if (!resetToken) {
      setResetRequested(true)
      setError(body.message)
      return
    }
    setMode('login')
    setError('Password reset. Sign in with the new password.')
    navigate('/?reset=1', { replace: true })
  }

  const resetMode = mode === 'reset'
  return <div className="auth-layout">
    <aside className="auth-aside">
      <Link className="auth-brand" to="/"><span className="brand-mark">S</span><span>Session<span>Sentinel</span></span></Link>
      <div className="auth-aside-copy"><span className="auth-kicker"><i /> PERSONAL SECURITY CENTER</span><h2>Know what’s happening with your account.</h2><p>Review sign-ins, keep an eye on active sessions, and respond quickly when activity feels unfamiliar.</p><div className="auth-proof"><span className="proof-icon">✓</span><span><strong>Security activity, made clear</strong><small>Stay informed. Stay in control.</small></span></div></div>
      <span className="auth-aside-foot">SESSION SENTINEL <i /> ACCOUNT PROTECTION</span>
    </aside>
    <main className="auth-main"><section className="auth-card">
      <div className="auth-mobile-brand"><span className="brand-mark">S</span> SessionSentinel</div>
      <p className="eyebrow">{resetMode ? 'ACCOUNT RECOVERY' : mode === 'signup' ? 'GET STARTED' : 'SECURE SIGN IN'}</p>
      <h1>{resetMode ? 'Reset your password' : mode === 'signup' ? 'Create your account' : 'Welcome back'}</h1>
      <p className="auth-description">{signupPending ? 'Your account is waiting for email verification.' : resetMode ? resetToken ? 'Choose a new password using your secure reset link.' : resetRequested ? 'Check your email for a secure password reset link.' : 'We’ll email you a secure link to reset your password.' : mode === 'signup' ? 'Create an account to keep your sign-in activity in one place.' : 'Sign in to review your account and security activity.'}</p>
      {signupPending ? <div className="signup-verification-prompt" role="status"><p className="auth-message success">{signupMessage}</p><p>Open the verification email sent to <strong>{email}</strong> and click its link. You cannot sign in until the email is verified. After verification, you’ll return here to sign in.</p><button type="button" className="auth-text-button" onClick={() => { setSignupPending(false); setMode('login'); setError('') }}>Back to sign in</button></div> : <>
      <form onSubmit={resetMode ? resetPassword : submit}>
        {(!resetMode || (!resetToken && !resetRequested)) && <label>Email address<input type="email" autoComplete="email" placeholder="you@example.com" value={email} onChange={(event) => setEmail(event.target.value)} required /></label>}
        {(!resetMode || resetToken) && <label>{resetMode ? 'New password' : 'Password'}<PasswordField value={password} onChange={(event) => setPassword(event.target.value)} /></label>}
        {!resetMode && mode === 'login' && <div className="auth-form-row"><label className="remember-label"><input type="checkbox" /> Remember this device</label><button type="button" className="auth-text-button" onClick={() => { setError(''); setResetRequested(false); setPassword(''); setMode('reset') }}>Forgot password?</button></div>}
        {!resetMode || resetToken || !resetRequested ? <button className="auth-submit" type="submit">{resetMode ? resetToken ? 'Save new password' : 'Send reset link' : mode === 'signup' ? 'Create account' : 'Sign in securely'}<span>→</span></button> : null}
      </form>
      {error && <p className={`auth-message ${error.startsWith('Account created') || error.startsWith('Password reset') || error.startsWith('If the account exists') ? 'success' : 'error'}`} role="alert">{error}</p>}
      {!resetMode && mode === 'login' && <><div className="auth-divider"><span>DEMO ACCESS</span></div><div className="demo-credentials"><strong>Seeded user account</strong><span>ali@test.com <i>·</i> Test@12345</span></div><p className="auth-switch">New to SessionSentinel? <button type="button" className="auth-text-button" onClick={() => { setError(''); setMode('signup') }}>Create an account</button></p></>}
      {!resetMode && mode === 'signup' && <p className="auth-switch">Already have an account? <button type="button" className="auth-text-button" onClick={() => { setError(''); setMode('login') }}>Sign in</button></p>}
      {resetMode && <p className="auth-switch"><button type="button" className="auth-text-button" onClick={() => { setError(''); setMode('login'); setResetRequested(false); navigate('/') }}>← Back to sign in</button></p>}
      </>}
    </section></main>
  </div>
}

function EmailAction({ action }) {
  const navigate = useNavigate()
  const [message, setMessage] = useState(() => new URLSearchParams(window.location.search).get('token') ? 'Processing link...' : 'This link is missing its security token.')
  useEffect(() => {
    const token = new URLSearchParams(window.location.search).get('token')
    window.history.replaceState({}, document.title, window.location.pathname)
    if (!token) return
    api(action, {
      method: 'POST',
      body: JSON.stringify({ token }),
    }).then(async (response) => {
      const body = await response.json()
      if (!response.ok) throw new Error(body.detail || 'This link is invalid or expired.')
      if (action === '/verify-email') {
        navigate(`/?verified=1&email=${encodeURIComponent(body.email || '')}`, { replace: true })
        return
      }
      setMessage(action === '/verify-device'
        ? 'Device verified. You can now sign in.'
        : action === '/verify-device'
          ? 'Device verified. You can now sign in.'
          : 'The sign-in session has been cancelled.')
    }).catch((reason) => setMessage(reason.message))
  }, [action, navigate])
  return <main className="auth-page"><section className="auth-card auth-action-card"><span className="brand-mark">S</span><p className="eyebrow">SECURITY CHECK</p><h1>SessionSentinel</h1><p className="muted">{message}</p><Link className="button" to="/">Continue to sign in <span>→</span></Link></section></main>
}

function Layout({ children }) {
  const navigate = useNavigate()
  async function logout() {
    await api('/logout', { method: 'POST' })
    localStorage.removeItem('token')
    navigate('/')
  }
  return <div className="shell">
    <header className="site-header"><Link className="site-brand" to="/account"><span className="brand-mark">S</span><span>Session<span>Sentinel</span></span></Link><nav className="site-nav" aria-label="Account navigation"><NavLink to="/account">Account</NavLink><NavLink to="/security">My Security</NavLink><button className="link-button" onClick={logout}>Log out</button></nav></header>
    {children}
  </div>
}

function Account() {
  const [user, setUser] = useState(null)
  useEffect(() => { api('/me').then((response) => response.json()).then(setUser) }, [])
  return <Layout><main className="page-main"><div className="page-heading"><p className="eyebrow">ACCOUNT OVERVIEW</p><h1>Welcome back</h1><p className="muted">Your account security, at a glance.</p></div><section className="panel account-summary"><div className="account-avatar">{user?.email?.[0]?.toUpperCase() || 'S'}</div><div className="account-summary-copy"><span className="eyebrow">SIGNED IN AS</span>{user ? <strong>{user.email}</strong> : <span className="muted">Loading account…</span>}<span className="account-status"><i /> Account protected</span></div></section><section className="panel account-cta"><div><p className="eyebrow">SECURITY CENTER</p><h2>Review your recent account activity</h2><p className="muted">Check sign-ins and sessions connected to your account.</p></div><Link className="button" to="/security">Open security center <span>→</span></Link></section></main></Layout>
}

function Security() {
  const [activity, setActivity] = useState([])
  const [sessions, setSessions] = useState([])
  const [error, setError] = useState('')
  useEffect(() => {
    Promise.all([api('/me/activity'), api('/me/sessions')])
      .then(async ([activityResponse, sessionsResponse]) => {
        if (!activityResponse.ok || !sessionsResponse.ok) throw new Error('Could not load security data')
        setActivity(await activityResponse.json())
        setSessions(await sessionsResponse.json())
      })
      .catch((reason) => setError(reason.message))
  }, [])
  return <Layout><main className="page-main"><div className="page-heading"><p className="eyebrow">ACCOUNT PROTECTION</p><h1>My security</h1><p className="muted">Manage your sessions and review recent account activity.</p></div>{error && <p className="status-message error">{error}</p>}
    <section className="panel"><div className="section-heading"><div><p className="eyebrow">CONNECTED DEVICES</p><h2>Active sessions</h2></div><span className="item-count">{sessions.length} {sessions.length === 1 ? 'session' : 'sessions'}</span></div>{sessions.length === 0 ? <p className="empty-state">No active sessions.</p> : <ul className="session-list">{sessions.map((session) => <li key={session.id}><div className="session-device"><span className="device-icon">⌘</span><div><strong>{session.device_id}</strong><span>{new Date(session.created_at).toLocaleString()}</span></div></div>{session.current && <span className="current-badge"><i /> Current device</span>}</li>)}</ul>}</section>
    <section className="panel"><div className="section-heading"><div><p className="eyebrow">SIGN-IN HISTORY</p><h2>Recent activity</h2></div><span className="item-count">Latest events</span></div>{activity.length === 0 ? <p className="empty-state">No recent activity.</p> : <ul className="activity-list">{activity.map((event) => <li key={event.id} className={event.type === 'new_device' ? 'new-device' : ''}><span className={`event-icon ${event.type === 'new_device' ? 'event-warning' : ''}`}>{event.type === 'new_device' ? '!' : '↗'}</span><div className="event-copy"><strong>{event.type.replaceAll('_', ' ')}</strong><span>{new Date(event.created_at).toLocaleString()}</span></div>{event.type === 'new_device' && <span className="review-badge">Review</span>}</li>)}</ul>}</section>
  </main></Layout>
}

function ProtectedRoutes() {
  if (!localStorage.getItem('token')) return <Navigate to="/" replace />
  return <Routes><Route path="/account" element={<Account />} /><Route path="/security" element={<Security />} /><Route path="*" element={<Navigate to="/account" replace />} /></Routes>
}

export default function App() {
  return <BrowserRouter><Routes>
    <Route path="/" element={<Login />} />
    <Route path="/reset-password" element={<Login />} />
    <Route path="/verify-email" element={<EmailAction action="/verify-email" />} />
    <Route path="/verify-device" element={<EmailAction action="/verify-device" />} />
    <Route path="/cancel-session" element={<EmailAction action="/cancel-session" />} />
    <Route path="*" element={<ProtectedRoutes />} />
  </Routes></BrowserRouter>
}
