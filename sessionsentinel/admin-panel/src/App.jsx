import { useEffect, useMemo, useState } from 'react'
import { BrowserRouter, Link, Navigate, Route, Routes, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { api } from './api'
import './App.css'

const ruleNames = {
  R1: 'Brute force',
  R2: 'Post-failure success',
  R3: 'New device / location',
  R4: 'High-risk correlation',
  R5: 'User reported',
  R6: 'Shared IP',
}

function ruleFor(explanation = '') {
  const match = explanation.match(/\bR[1-6]\b/)
  return match ? match[0] : 'Review'
}

function formatDate(value) {
  return new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
}

function Badge({ value, className = '' }) {
  return <span className={`badge ${String(value).toLowerCase()} ${className}`}>{value}</span>
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

  return <main className="auth-page"><section className="auth-card">
    <div className="brand-mark">SS</div>
    <p className="eyebrow">SECURITY OPERATIONS</p>
    <h1>SessionSentinel</h1>
    <p className="muted">Investigate authentication threats and protect active sessions.</p>
    <form onSubmit={submit}>
      <label>Email<input value={email} onChange={(event) => setEmail(event.target.value)} /></label>
      <label>Password<PasswordField value={password} onChange={(event) => setPassword(event.target.value)} /></label>
      <button type="submit">Open console <span aria-hidden="true">→</span></button>
    </form>
    {error && <p className="error">{error}</p>}
  </section></main>
}

function Layout({ children }) {
  const navigate = useNavigate()
  return <div className="app-shell">
    <aside className="sidebar">
      <Link className="brand" to="/dashboard"><span className="brand-mark">SS</span><span>Session<span>Sentinel</span></span></Link>
      <p className="sidebar-label">Workspace</p>
      <nav className="side-nav">
        <Link to="/dashboard"><span>▦</span>Overview</Link>
        <Link to="/incidents"><span>◈</span>Incidents</Link>
        <Link to="/audit"><span>⌁</span>Audit trail</Link>
      </nav>
      <div className="sidebar-footer"><span className="status-dot" />Monitoring active</div>
    </aside>
    <div className="content-shell">
      <header className="topbar"><div><p className="eyebrow">SECURITY OPERATIONS CENTER</p><h2>Threat monitoring</h2></div><div className="topbar-actions"><span className="live-pill"><span className="status-dot" />Live</span><button className="logout-button" onClick={() => { localStorage.removeItem('token'); navigate('/') }}>Log out</button></div></header>
      {children}
    </div>
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

function Stats({ incidents }) {
  const open = incidents.filter((item) => item.status === 'open').length
  const highRisk = incidents.filter((item) => ['high', 'critical'].includes(item.severity)).length
  const critical = incidents.filter((item) => item.severity === 'critical').length
  return <div className="stats">
    <article className="stat-card"><span className="stat-icon blue">◈</span><div><p>Open incidents</p><strong>{open}</strong><small>Needs attention</small></div></article>
    <article className="stat-card"><span className="stat-icon red">!</span><div><p>High-risk activity</p><strong>{highRisk}</strong><small>High or critical severity</small></div></article>
    <article className="stat-card"><span className="stat-icon orange">⚠</span><div><p>Critical alerts</p><strong>{critical}</strong><small>Account lock threshold</small></div></article>
  </div>
}

function Dashboard() {
  const { incidents, error } = useIncidents()
  const recent = incidents.slice(0, 5)
  return <Layout><main className="page">
    <div className="page-heading"><div><p className="eyebrow">OVERVIEW</p><h1>Good morning, Admin</h1><p className="muted">Here is the latest security activity across your environment.</p></div><Link className="button" to="/incidents">Review incidents <span>→</span></Link></div>
    {error && <p className="error">{error}</p>}<Stats incidents={incidents} />
    <section className="dashboard-grid"><div className="panel"><div className="section-heading"><div><p className="eyebrow">PRIORITY QUEUE</p><h3>Recent incidents</h3></div><Link to="/incidents">View all →</Link></div>{recent.length === 0 && <p className="muted">No incidents recorded.</p>}<div className="compact-list">{recent.map((incident) => <IncidentRow incident={incident} key={incident.id} />)}</div></div>
      <div className="panel rule-panel"><p className="eyebrow">DETECTION COVERAGE</p><h3>Rules R1–R6</h3><p className="muted">Active controls protecting the environment.</p>{Object.entries(ruleNames).map(([rule, name]) => <div className="rule-row" key={rule}><span className="rule-code">{rule}</span><span>{name}</span><span className="rule-check">✓</span></div>)}</div></section>
  </main></Layout>
}

function IncidentRow({ incident }) {
  const rule = ruleFor(incident.explanation)
  return <Link className="incident-row" to={`/incidents/${incident.id}`}><span className={`incident-indicator ${incident.severity}`} /><div className="incident-row-main"><strong>{incident.email || 'Shared infrastructure'}</strong><span>{rule} · {ruleNames[rule] || 'Security review'}</span></div><Badge value={incident.severity} /><span className="row-date">{formatDate(incident.created_at)}</span></Link>
}

function Incidents() {
  const { incidents, error } = useIncidents()
  const [params, setParams] = useSearchParams()
  const severity = params.get('severity') || ''
  const status = params.get('status') || ''
  const filtered = useMemo(() => incidents.filter((incident) => (!severity || incident.severity === severity) && (!status || incident.status === status)), [incidents, severity, status])
  return <Layout><main className="page"><div className="page-heading"><div><p className="eyebrow">INVESTIGATION QUEUE</p><h1>Incidents</h1><p className="muted">{filtered.length} incidents require monitoring or review.</p></div></div>
    <div className="filters"><select value={severity} onChange={(event) => setParams({ severity: event.target.value, status })}><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><select value={status} onChange={(event) => setParams({ severity, status: event.target.value })}><option value="">All statuses</option><option value="open">Open</option><option value="investigating">Investigating</option><option value="contained">Contained</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select></div>
    {error && <p className="error">{error}</p>}{!error && filtered.length === 0 && <div className="empty-state">No incidents match these filters.</div>}<div className="incident-list">{filtered.map((incident) => <IncidentRow incident={incident} key={incident.id} />)}</div>
  </main></Layout>
}

function IncidentDetail() {
  const { id } = useParams()
  const [incident, setIncident] = useState(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  useEffect(() => {
    api(`/admin/incidents/${id}`).then(async (response) => {
      if (!response.ok) throw new Error('Incident not found')
      setIncident(await response.json())
    }).catch((reason) => setError(reason.message))
  }, [id])
  async function updateStatus(status) {
    const response = await api(`/admin/incidents/${id}/status`, { method: 'POST', body: JSON.stringify({ status, note: 'Updated from admin panel' }) })
    if (!response.ok) { setError('Could not update incident status'); return }
    setMessage(`Incident marked ${status.replace('_', ' ')}.`)
    setIncident({ ...incident, status })
  }
  async function retryNotification(notificationId) {
    const response = await api(`/admin/notifications/${notificationId}/retry`, { method: 'POST' })
    if (!response.ok) { setError('Could not retry notification'); return }
    const result = await response.json()
    setMessage(`Notification ${result.status}.`)
    setIncident({
      ...incident,
      notification_status: incident.notification_status.map((item) => item.id === notificationId
        ? { ...item, status: result.status, attempts: result.attempts }
        : item),
    })
  }
  return <Layout><main className="page">{error && <p className="error">{error}</p>}{!incident && !error && <p>Loading incident...</p>}{incident && <><Link className="back-link" to="/incidents">← Back to incidents</Link><div className="detail-heading"><div><div className="rule-label"><span className="rule-code">{ruleFor(incident.explanation)}</span>{ruleNames[ruleFor(incident.explanation)] || 'Security rule'}</div><h1>Incident #{incident.id}</h1><p className="muted">{incident.email || 'Shared infrastructure'} · Reported {formatDate(incident.created_at)}</p></div><div className="detail-badges"><Badge value={incident.severity} /><Badge value={incident.status} /></div></div>
      {message && <p className="success">{message}</p>}<div className="actions"><button onClick={() => updateStatus('investigating')}>Investigate</button><button className="button-secondary" onClick={() => updateStatus('contained')}>Contain</button><button className="button-quiet" onClick={() => updateStatus('resolved')}>Resolve</button></div>
      <div className="detail-grid"><div><section className="panel"><div className="section-heading"><h3>Assessment</h3><span className="assessment-dot" /></div><pre>{incident.explanation}</pre></section><section className="panel"><h3>Evidence collected</h3><ul className="evidence-list">{incident.evidence.map((item) => <li key={item}><span>✓</span>{item}</li>)}</ul><div className="recommendation"><strong>Recommended response</strong><p>{incident.recommended_action}</p></div></section>{incident.notification_status?.length > 0 && <section className="panel"><h3>Email notifications</h3><div className="notification-list">{incident.notification_status.map((item) => <div className="notification-row" key={item.id}><div><strong>{item.kind.replaceAll('_', ' ')}</strong><span>{item.status} · {item.attempts} attempt{item.attempts === 1 ? '' : 's'}</span>{item.last_error && <small>{item.last_error}</small>}</div>{item.status === 'failed' && <button className="button-secondary" onClick={() => retryNotification(item.id)}>Retry</button>}</div>)}</div></section>}</div><section className="panel"><h3>Event timeline</h3><ol className="timeline">{incident.timeline.map((event) => <li key={event.id}><span className="timeline-dot" /><div><strong>{event.type.replaceAll('_', ' ')}</strong><span>{formatDate(event.created_at)}</span><small>{event.device_id}{event.ip ? ` · ${event.ip}` : ''}</small></div></li>)}</ol></section></div>
    </>}</main></Layout>
}

function AuditLog() {
  const [entries, setEntries] = useState([])
  const [verification, setVerification] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => { api('/audit').then(async (response) => { if (!response.ok) throw new Error('Could not load audit log'); setEntries(await response.json()) }).catch((reason) => setError(reason.message)) }, [])
  async function verifyAudit() { const response = await api('/audit/verify'); setVerification(await response.json()) }
  return <Layout><main className="page"><div className="page-heading"><div><p className="eyebrow">COMPLIANCE</p><h1>Audit trail</h1><p className="muted">Tamper-evident record of security actions.</p></div><button onClick={verifyAudit}>Verify integrity</button></div>{error && <p className="error">{error}</p>}{verification && <p className={verification.status === 'valid' ? 'success' : 'error'}>{verification.status === 'valid' ? '✓ Audit chain is valid.' : `Broken entry: ${verification.entry_id}`}</p>}<div className="audit-list">{entries.map((entry) => <article className="audit-entry" key={entry.id}><span className="audit-icon">⌁</span><div><strong>{entry.action.replaceAll('_', ' ')}</strong><span>{entry.actor} · {formatDate(entry.created_at)}</span><p>{entry.details}</p></div></article>)}</div></main></Layout>
}

function ProtectedRoutes() {
  if (!localStorage.getItem('token')) return <Navigate to="/" replace />
  return <Routes><Route path="/dashboard" element={<Dashboard />} /><Route path="/incidents" element={<Incidents />} /><Route path="/incidents/:id" element={<IncidentDetail />} /><Route path="/audit" element={<AuditLog />} /><Route path="*" element={<Navigate to="/dashboard" replace />} /></Routes>
}

export default function App() {
  return <BrowserRouter><Routes><Route path="/" element={<AdminLogin />} /><Route path="*" element={<ProtectedRoutes />} /></Routes></BrowserRouter>
}
