import { useEffect, useState } from 'react'
import { BrowserRouter, Link, Navigate, Route, Routes, useNavigate } from 'react-router-dom'
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
  const [email, setEmail] = useState('ali@test.com')
  const [password, setPassword] = useState('Test@12345')
  const [error, setError] = useState('')
  const [mode, setMode] = useState('login')

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
      setError('Account created. Check your email to verify it before signing in.')
      setMode('login')
      return
    }
    localStorage.setItem('token', body.token)
    navigate('/account')
  }

  async function resetPassword(event) {
    event.preventDefault()
    setError('')
    const response = await api('/reset-password', {
      method: 'POST',
      body: JSON.stringify({ email, new_password: password }),
    })
    if (!response.ok) {
      const body = await response.json()
      setError(body.detail || 'Could not reset password')
      return
    }
    setMode('login')
    setError('Password reset. Sign in with the new password.')
  }

  const resetMode = mode === 'reset'
  return <main className="auth-card">
    <h1>SessionSentinel</h1>
    <p>Secure account access for the demo site.</p>
    <form onSubmit={resetMode ? resetPassword : submit}>
      <label>Email<input value={email} onChange={(event) => setEmail(event.target.value)} /></label>
      <label>Password<PasswordField value={password} onChange={(event) => setPassword(event.target.value)} /></label>
      <button type="submit">{resetMode ? 'Reset password' : mode === 'signup' ? 'Create account' : 'Sign in'}</button>
    </form>
      <button className="link-button" onClick={() => setMode(resetMode ? 'login' : 'reset')}>{resetMode ? 'Back to sign in' : 'Reset password'}</button>
      {!resetMode && <button className="link-button" onClick={() => setMode(mode === 'signup' ? 'login' : 'signup')}>{mode === 'signup' ? 'Back to sign in' : 'Create an account'}</button>}
    {error && <p className="error" role="alert">{error}</p>}
  </main>
}

function EmailAction({ action }) {
  const [message, setMessage] = useState('Processing link...')
  useEffect(() => {
    const token = new URLSearchParams(window.location.search).get('token')
    window.history.replaceState({}, document.title, window.location.pathname)
    if (!token) {
      setMessage('This link is missing its security token.')
      return
    }
    api(action, {
      method: 'POST',
      body: JSON.stringify({ token }),
    }).then(async (response) => {
      const body = await response.json()
      if (!response.ok) throw new Error(body.detail || 'This link is invalid or expired.')
      setMessage(action === '/verify-email'
        ? 'Email verified. You can now sign in.'
        : action === '/verify-device'
          ? 'Device verified. You can now sign in.'
          : 'The sign-in session has been cancelled.')
    }).catch((reason) => setMessage(reason.message))
  }, [action])
  return <main className="auth-card"><h1>SessionSentinel</h1><p>{message}</p><Link className="button" to="/">Continue</Link></main>
}

function Layout({ children }) {
  const navigate = useNavigate()
  async function logout() {
    await api('/logout', { method: 'POST' })
    localStorage.removeItem('token')
    navigate('/')
  }
  return <div className="shell">
    <header><strong>SessionSentinel</strong><nav><Link to="/account">Account</Link><Link to="/security">My Security</Link><button className="link-button" onClick={logout}>Log out</button></nav></header>
    {children}
  </div>
}

function Account() {
  const [user, setUser] = useState(null)
  useEffect(() => { api('/me').then((response) => response.json()).then(setUser) }, [])
  return <Layout><main><h1>Welcome back</h1>{user ? <p>Signed in as <strong>{user.email}</strong>.</p> : <p>Loading account...</p>}<Link className="button" to="/security">Review security activity</Link></main></Layout>
}

function Security() {
  const [activity, setActivity] = useState([])
  const [sessions, setSessions] = useState([])
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  useEffect(() => {
    Promise.all([api('/me/activity'), api('/me/sessions')])
      .then(async ([activityResponse, sessionsResponse]) => {
        if (!activityResponse.ok || !sessionsResponse.ok) throw new Error('Could not load security data')
        setActivity(await activityResponse.json())
        setSessions(await sessionsResponse.json())
      })
      .catch((reason) => setError(reason.message))
  }, [])
  return <Layout><main><h1>My Security</h1>{error && <p className="error">{error}</p>}{message && <p className="success">{message}</p>}
    <section className="panel"><h2>Active sessions</h2>{sessions.length === 0 ? <p>No active sessions.</p> : <ul className="session-list">{sessions.map((session) => <li key={session.id}><strong>{session.device_id}</strong><span>{session.current ? 'Current device' : 'Active'} · {new Date(session.created_at).toLocaleString()}</span></li>)}</ul>}</section>
    <section className="panel"><h2>Recent activity</h2>{activity.length === 0 ? <p>No recent activity.</p> : <ul className="activity-list">{activity.map((event) => <li key={event.id} className={event.type === 'new_device' ? 'new-device' : ''}><div><strong>{event.type.replaceAll('_', ' ')}</strong><span>{new Date(event.created_at).toLocaleString()}</span></div></li>)}</ul>}</section>
  </main></Layout>
}

function ProtectedRoutes() {
  if (!localStorage.getItem('token')) return <Navigate to="/" replace />
  return <Routes><Route path="/account" element={<Account />} /><Route path="/security" element={<Security />} /><Route path="*" element={<Navigate to="/account" replace />} /></Routes>
}

export default function App() {
  return <BrowserRouter><Routes>
    <Route path="/" element={<Login />} />
    <Route path="/verify-email" element={<EmailAction action="/verify-email" />} />
    <Route path="/verify-device" element={<EmailAction action="/verify-device" />} />
    <Route path="/cancel-session" element={<EmailAction action="/cancel-session" />} />
    <Route path="*" element={<ProtectedRoutes />} />
  </Routes></BrowserRouter>
}
