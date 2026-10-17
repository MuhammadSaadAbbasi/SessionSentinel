import { useEffect, useState } from 'react'
import { BrowserRouter, Link, Navigate, Route, Routes, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { api } from './api'
import './App.css'

function AdminLogin() {
  const navigate = useNavigate()
  const [email, setEmail] = useState('admin@test.com')
  const [password, setPassword] = useState('Admin@12345')
  const [error, setError] = useState('')

  async function submit(event) {
    event.preventDefault()
    setError('')
    const response = await api('/login', { method: 'POST', body: JSON.stringify({ email, password, device_id: 'admin-panel' }) })
    const body = await response.json()
    if (!response.ok) {
      setError(body.detail?.message || body.detail || 'Login failed')
      return
    }
    if (body.role !== 'admin') {
      setError('This account is not an administrator')
      return
    }
    localStorage.setItem('token', body.token)
    navigate('/dashboard')
  }

  return <main className="auth-card">
    <h1>SessionSentinel Admin</h1>
    <p>Sign in to investigate security incidents.</p>
    <form onSubmit={submit}>
      <label>Email<input value={email} onChange={(event) => setEmail(event.target.value)} /></label>
      <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
      <button type="submit">Sign in</button>
    </form>
    {error && <p className="error">{error}</p>}
  </main>
}

function Layout({ children }) {
  const navigate = useNavigate()
  return <div className="shell">
    <header><strong>SessionSentinel</strong><nav><Link to="/dashboard">Dashboard</Link><Link to="/incidents">Incidents</Link><button className="link-button" onClick={() => { localStorage.removeItem('token'); navigate('/') }}>Log out</button></nav></header>
    {children}
  </div>
}

function useIncidents() {
  const [incidents, setIncidents] = useState([])
  const [error, setError] = useState('')
  useEffect(() => {
    api('/admin/incidents').then(async (response) => {
      if (!response.ok) throw new Error('Could not load incidents')
      setIncidents(await response.json())
    }).catch((reason) => setError(reason.message))
  }, [])
  return { incidents, error }
}

function Dashboard() {
  const { incidents, error } = useIncidents()
  return <Layout><main><h1>Dashboard</h1>{error && <p className="error">{error}</p>}<div className="stats">
    <article><span>Open incidents</span><strong>{incidents.filter((i) => i.status === 'open').length}</strong></article>
    <article><span>High severity</span><strong>{incidents.filter((i) => i.severity === 'high').length}</strong></article>
    <article><span>Medium severity</span><strong>{incidents.filter((i) => i.severity === 'medium').length}</strong></article>
  </div><Link className="button" to="/incidents">Review incidents</Link></main></Layout>
}

function Incidents() {
  const { incidents, error } = useIncidents()
  const [params, setParams] = useSearchParams()
  const severity = params.get('severity') || ''
  const status = params.get('status') || ''
  const filtered = incidents.filter((incident) => (!severity || incident.severity === severity) && (!status || incident.status === status))
  return <Layout><main><h1>Incidents</h1><div className="filters">
    <select value={severity} onChange={(event) => setParams({ severity: event.target.value, status })}><option value="">All severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
    <select value={status} onChange={(event) => setParams({ severity, status: event.target.value })}><option value="">All statuses</option><option value="open">Open</option><option value="resolved">Resolved</option></select>
  </div>{error && <p className="error">{error}</p>}{!error && filtered.length === 0 && <p>No incidents match these filters.</p>}
  <div className="incident-list">{filtered.map((incident) => <Link className="incident" key={incident.id} to={`/incidents/${incident.id}`}><div><strong>{incident.email || 'Unknown account'}</strong><p>{incident.explanation}</p></div><span className={`badge ${incident.severity}`}>{incident.severity}</span><span>{incident.status}</span></Link>)}</div>
  </main></Layout>
}

function IncidentDetail() {
  const { id } = useParams()
  const [incident, setIncident] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    api(`/admin/incidents/${id}`).then(async (response) => {
      if (!response.ok) throw new Error('Incident not found')
      setIncident(await response.json())
    }).catch((reason) => setError(reason.message))
  }, [id])
  return <Layout><main><Link to="/incidents">Back to incidents</Link>{error && <p className="error">{error}</p>}{!incident && !error && <p>Loading incident...</p>}{incident && <>
    <div className="title-row"><h1>Incident #{incident.id}</h1><span className={`badge ${incident.risk_level}`}>{incident.risk_level} priority</span></div>
    <p>Account: <strong>{incident.email || 'Unknown'}</strong></p>
    <section className="panel"><h2>Explanation</h2><pre>{incident.explanation}</pre></section>
    <section className="panel"><h2>Evidence</h2><ul>{incident.evidence.map((item) => <li key={item}>{item}</li>)}</ul><p><strong>Recommended:</strong> {incident.recommended_action}</p></section>
    <section className="panel"><h2>Timeline</h2><ol className="timeline">{incident.timeline.map((event) => <li key={event.id}><strong>{event.type}</strong><span>{new Date(event.created_at).toLocaleString()}</span><small>{event.device_id}{event.ip ? ` · ${event.ip}` : ''}</small></li>)}</ol></section>
  </>}</main></Layout>
}

function ProtectedRoutes() {
  if (!localStorage.getItem('token')) return <Navigate to="/" replace />
  return <Routes><Route path="/dashboard" element={<Dashboard />} /><Route path="/incidents" element={<Incidents />} /><Route path="/incidents/:id" element={<IncidentDetail />} /><Route path="*" element={<Navigate to="/dashboard" replace />} /></Routes>
}

export default function App() {
  return <BrowserRouter><Routes><Route path="/" element={<AdminLogin />} /><Route path="*" element={<ProtectedRoutes />} /></Routes></BrowserRouter>
}
