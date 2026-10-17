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

function Login() {
  const navigate = useNavigate()
  const [email, setEmail] = useState('ali@test.com')
  const [password, setPassword] = useState('Test@12345')
  const [error, setError] = useState('')

  async function submit(event) {
    event.preventDefault()
    setError('')
    const response = await api('/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, device_id: deviceId() }),
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
    localStorage.setItem('token', body.token)
    navigate('/account')
  }

  return <main className="auth-card">
    <h1>SessionSentinel</h1>
    <p>Secure account access for the demo site.</p>
    <form onSubmit={submit}>
      <label>Email<input value={email} onChange={(event) => setEmail(event.target.value)} /></label>
      <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
      <button type="submit">Sign in</button>
    </form>
    {error && <p className="error" role="alert">{error}</p>}
  </main>
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
  useEffect(() => {
    Promise.all([api('/me/activity'), api('/me/sessions')])
      .then(async ([activityResponse, sessionsResponse]) => {
        if (!activityResponse.ok || !sessionsResponse.ok) throw new Error('Could not load security data')
        setActivity(await activityResponse.json())
        setSessions(await sessionsResponse.json())
      })
      .catch((reason) => setError(reason.message))
  }, [])
  return <Layout><main><h1>My Security</h1>{error && <p className="error">{error}</p>}
    <section className="panel"><h2>Active sessions</h2>{sessions.length === 0 ? <p>No active sessions.</p> : <ul className="session-list">{sessions.map((session) => <li key={session.id}><strong>{session.device_id}</strong><span>{session.current ? 'Current device' : 'Active'} · {new Date(session.created_at).toLocaleString()}</span></li>)}</ul>}</section>
    <section className="panel"><h2>Recent activity</h2>{activity.length === 0 ? <p>No recent activity.</p> : <ul className="activity-list">{activity.map((event) => <li key={event.id} className={event.type === 'new_device' ? 'new-device' : ''}><div><strong>{event.type === 'new_device' ? 'New device detected' : event.type.replaceAll('_', ' ')}</strong><span>{new Date(event.created_at).toLocaleString()}</span></div>{event.type === 'new_device' && <span className="warning">Review this login</span>}</li>)}</ul>}</section>
  </main></Layout>
}

function ProtectedRoutes() {
  if (!localStorage.getItem('token')) return <Navigate to="/" replace />
  return <Routes><Route path="/account" element={<Account />} /><Route path="/security" element={<Security />} /><Route path="*" element={<Navigate to="/account" replace />} /></Routes>
}

export default function App() {
  return <BrowserRouter><Routes><Route path="/" element={<Login />} /><Route path="*" element={<ProtectedRoutes />} /></Routes></BrowserRouter>
}
