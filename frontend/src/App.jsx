import { useEffect, useRef, useState } from 'react'
import './App.css'
import { api, formatDate, displayName } from './services/api'

const nav = [
  ['Dashboard', '⌂'],
  ['Live Monitor', '◉'],
  ['New Assessment', '+'],
  ['Assessments', '◫'],
  ['Comparison', '⇄'],
  ['Networks', '⌁'],
  ['Devices', '📱'],
  ['Findings', '⚠'],
  ['Reports', '▤'],
  ['Kali Tools / About', '⚙'],
]

const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

function App() {
  const [page, setPage] = useState('Dashboard')
  const [dashboard, setDashboard] = useState(null)
  const [selected, setSelected] = useState(null)
  const [notice, setNotice] = useState(null)
  const [refreshKey, setRefreshKey] = useState(0)

  useEffect(() => {
    api.dashboard()
      .then(setDashboard)
      .catch((error) => setNotice({ type: 'error', message: error.message }))
  }, [refreshKey])

  const navigate = (next, id = null) => {
    setPage(next)
    setSelected(id)
  }

  const completed = () => {
    setRefreshKey((value) => value + 1)
    navigate('Assessments')
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">W</div>
          <div>
            <strong>WSA Kali</strong>
            <span>Wireless Security</span>
          </div>
        </div>
        <div className="nav-section">
          <span className="nav-title">WORKSPACE</span>
          {nav.map(([label, icon]) => (
            <button
              key={label}
              className={`nav-item ${page === label ? 'active' : ''}`}
              onClick={() => navigate(label)}
            >
              <span className="nav-icon">{icon}</span>
              <span>{label}</span>
            </button>
          ))}
        </div>
        <div className="sidebar-bottom">
          <div className="system-status">
            <span className="status-dot" />
            <div>
              <strong>Kali Assessment Engine</strong>
              <span>Audit Ready • v1.0</span>
            </div>
          </div>
          <div className="version">Aircrack • Airodump • Wireshark Core</div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <span className="breadcrumb">KALI LINUX SECURITY OPERATIONS</span>
            <h1>{page}</h1>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button className="button secondary" onClick={() => navigate('Live Monitor')}>
              ◉ Live Monitor
            </button>
            <button className="button primary" onClick={() => navigate('New Assessment')}>
              + New Assessment
            </button>
          </div>
        </header>

        {notice && (
          <div className={`toast ${notice.type}`}>
            <span>{notice.message}</span>
            <button onClick={() => setNotice(null)}>×</button>
          </div>
        )}

        {page === 'Dashboard' && <Dashboard data={dashboard} onNavigate={navigate} />}
        {page === 'Live Monitor' && <LiveMonitor onNavigate={navigate} />}
        {page === 'New Assessment' && (
          <NewAssessment onComplete={completed} onError={(message) => setNotice({ type: 'error', message })} />
        )}
        {page === 'Assessments' && <Assessments onOpen={(id) => navigate('Assessment Results', id)} />}
        {page === 'Assessment Results' && (
          <AssessmentResults id={selected} onBack={() => navigate('Assessments')} onCompare={(id) => navigate('Comparison', id)} />
        )}
        {page === 'Comparison' && <SecurityComparison preselectId={selected} onNavigate={navigate} />}
        {page === 'Networks' && <Networks />}
        {page === 'Devices' && <Devices />}
        {page === 'Findings' && <Findings />}
        {page === 'Reports' && <Reports />}
        {page === 'Kali Tools / About' && <About />}
      </main>
    </div>
  )
}

const scenarioOptions = [
  ['mixed', '⚡ Mixed Threat Scenario'],
  ['enterprise', '🛡️ Corporate WPA3 Enterprise (Secure Baseline)'],
  ['evil_twin', '🚨 Rogue AP / Evil Twin & Deauth Attack'],
  ['iot', '⚠️ IoT Smart Home (TKIP & WPS Vulnerable)'],
  ['cafe', '⚠️ Public Cafe (Open Plaintext & Probes)'],
  ['dos_elevated', '⚠️ Elevated Deauth Anomaly (Medium DoS)'],
  ['normal', 'Normal Wireless Activity'],
  ['open', 'Open Network Detection'],
  ['wep', 'WEP Weakness Analysis'],
  ['auth', 'Authentication & WPS Anomaly'],
  ['deauth', 'Deauthentication Flood / DoS Emulation'],
  ['campus', '🌐 University Multi-AP Campus Environment'],
]

function LiveMonitor({ onNavigate }) {
  const [state, setState] = useState(null)
  const [scenario, setScenario] = useState('mixed')
  const [diagnostic, setDiagnostic] = useState(null)
  const [iface, setIface] = useState('')
  const [mode, setMode] = useState('playback') // 'playback' (offline) or 'live' (hardware)
  const source = useRef(null)
  const consoleRef = useRef(null)

  useEffect(() => {
    api.liveDiagnostics()
      .then((data) => {
        setDiagnostic(data)
        if (data.interfaces && data.interfaces.length > 0) {
          setIface(data.interfaces[0].name)
          setMode('live')
        } else {
          setMode('playback')
        }
      })
      .catch(() => setDiagnostic({ blocker: 'Diagnostics endpoint unavailable' }))

    api.liveState()
      .then((data) => {
        if (data && data.status) setState(data)
      })
      .catch(() => {})

    source.current = new EventSource('/api/live/stream')
    source.current.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data)
        if (message.type === 'snapshot' || message.type === 'state' || message.data?.status) {
          setState(message.data)
        } else if (message.data?.id && message.data?.message) {
          setState((prev) => {
            if (!prev || !prev.status) return prev
            const existingEvents = prev.events || []
            if (existingEvents.some((e) => e.id === message.data.id)) return prev
            return {
              ...prev,
              events: [...existingEvents, message.data],
            }
          })
        }
      } catch {
        // keep alive ignore
      }
    }
    return () => source.current?.close()
  }, [])

  const run = async (command) => {
    try {
      const selectedIface = mode === 'playback' ? 'playback' : iface
      const next = await api.liveCommand(
        command,
        command === 'start' ? scenario : undefined,
        command === 'start' ? selectedIface : undefined,
        command === 'start' ? mode : undefined
      )
      if (next && next.status) {
        setState(next)
      }
    } catch (err) {
      console.error('Live command error:', err)
      setState((prev) => (prev ? { ...prev, error: err.message } : prev))
    }
  }

  const events = state?.events || []
  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight
    }
  }, [events.length])

  if (!state) return <Loading />

  const networks = state.networks || []
  const findings = state.findings || []
  const history = state.risk_history || []
  const devices = state.devices || []

  return (
    <div className="live-page">
      <section className="live-header panel">
        <div>
          <span className="eyebrow">INTEGRATED WIRELESS IDS &amp; MONITORING</span>
          <h2>
            LIVE MONITOR <span className={`live-state ${state?.status || 'stopped'}`}>● {(state?.status || 'stopped').toUpperCase()}</span>
          </h2>
          <p>Live 802.11 IDS &amp; frame classification via hardware or offline simulation.</p>
          {state.error && <div className="capture-blocker">CAPTURE BLOCKED: {state.error}</div>}
        </div>

        <div className="live-controls">
          <div className="mode-toggle">
            <button
              className={mode === 'playback' ? 'active' : ''}
              onClick={() => setMode('playback')}
              disabled={state?.status === 'capturing'}
            >
              Offline Playback (No Adapter)
            </button>
            <button
              className={mode === 'live' ? 'active' : ''}
              onClick={() => setMode('live')}
              disabled={state?.status === 'capturing'}
            >
              Hardware Interface (Airmon-ng)
            </button>
          </div>

          {mode === 'live' ? (
            <label>
              Monitor Interface (Airmon-ng)
              <select
                value={iface}
                onChange={(event) => setIface(event.target.value)}
                disabled={state?.status === 'capturing'}
              >
                <option value="">Select Wi-Fi Interface</option>
                {(diagnostic?.interfaces || []).map((item) => (
                  <option key={item.name} value={item.name}>
                    {item.name} · {item.type}
                  </option>
                ))}
              </select>
            </label>
          ) : (
            <label>
              Offline Simulation Profile
              <select
                value={scenario}
                onChange={(event) => setScenario(event.target.value)}
                disabled={state?.status === 'capturing'}
              >
                {scenarioOptions.map(([val, label]) => (
                  <option key={val} value={val}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
          )}

          <div className="button-row">
            <button
              className="button primary"
              onClick={() => run('start')}
              disabled={state?.status === 'capturing' || (mode === 'live' && !iface)}
            >
              Start {mode === 'playback' ? 'Playback' : 'Capture'}
            </button>
            <button
              className="button"
              onClick={() => run('pause')}
              disabled={state?.status !== 'capturing'}
            >
              Pause
            </button>
            <button
              className="button"
              onClick={() => run('stop')}
              disabled={state?.status === 'stopped'}
            >
              Stop
            </button>
            <button className="button" onClick={() => run('reset')}>
              Reset
            </button>
          </div>
        </div>
      </section>

      {state.alert && (
        <section className="panel live-alert">
          <span>⚠ REAL-TIME SECURITY ALERT TRIGGERED</span>
          <h2>{state.alert.title}</h2>
          <p>
            <b>Rule ID:</b> {state.alert.rule_id} &nbsp;|&nbsp; <b>Severity:</b> {state.alert.severity} &nbsp;|&nbsp;{' '}
            <b>Target Network:</b> {state.alert.network}
          </p>
          {state.alert.remediation && (
            <p style={{ marginTop: '6px', color: '#9f1239' }}>
              <b>Recommended Remediation:</b> {state.alert.remediation}
            </p>
          )}
          <strong>Observed Events: {state.alert.observed_events} · Live Risk Score: {state.risk_score}</strong>
        </section>
      )}

      <section className="live-metrics">
        <Metric label="Packets" value={state.packets} detail={`${Number(state.packets_per_second || 0).toFixed(1)} pkts/sec`} />
        <Metric label="Networks" value={networks.length} detail="Airodump-ng APs" />
        <Metric label="Clients" value={devices.length || state.clients} detail="Connected Stations" />
        <Metric label="Findings" value={findings.length} detail="Rule Engine Matches" danger={findings.length > 0} />
        <Metric label="Risk Score" value={state.risk_score} detail="Security Posture" danger={state.risk_score > 0} />
      </section>

      <div className="live-grid">
        <section className="panel event-panel">
          <PanelHeading kicker="KALI EVENT STREAM" title="Observed Traffic &amp; Detection Events" />
          <div className="event-console" ref={consoleRef}>
            {events.length ? (
              events.map((event) => (
                <div className="event-line" key={event.id}>
                  <time>{event.timestamp?.slice(11, 19)}</time>
                  <b className={`event-${event.type?.toLowerCase()}`}>{event.type}</b>
                  <code>{event.target}</code>
                  <span>{event.message}</span>
                </div>
              ))
            ) : (
              <Empty
                title="Awaiting Live Packets"
                text={
                  mode === 'playback'
                    ? 'Click "Start Playback" to stream simulated traffic in adapter-independent offline mode.'
                    : 'Select a monitor interface and click "Start Capture".'
                }
              />
            )}
          </div>
        </section>

        <section className="panel">
          <PanelHeading kicker="INVESTIGATION TIMELINE" title="Real-time Threat Escalation" />
          <Timeline current={state.timeline} />
          <div className="risk-chart">
            <div className="chart-y">
              <span>100</span>
              <span>50</span>
              <span>0</span>
            </div>
            <svg viewBox="0 0 500 150" preserveAspectRatio="none">
              <polyline points={chartPoints(history)} fill="none" stroke="#d97706" strokeWidth="3" />
            </svg>
          </div>
          <div className="chart-caption">RISK SCORE / OBSERVED EVENT</div>
        </section>
      </div>

      <section className="live-grid lower">
        <section className="panel">
          <PanelHeading kicker="AIRODUMP-NG DISCOVERY" title={`${networks.length} Network${networks.length === 1 ? '' : 's'} Observed`} />
          {networks.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    {['SSID', 'BSSID', 'Encryption', 'Auth', 'Channel', 'Clients', 'Risk', 'Status'].map((head) => (
                      <th key={head}>{head}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {networks.map((network) => (
                    <tr key={network.bssid}>
                      <td><strong>{displayName(network.ssid)}</strong></td>
                      <td><code>{network.bssid}</code></td>
                      <td><span className={`severity-chip ${network.cipher === 'NONE' || network.cipher === 'WEP' ? 'critical' : 'low'}`}>{network.cipher}</span></td>
                      <td>{network.auth_type}</td>
                      <td>{network.channel}</td>
                      <td>{network.clients}</td>
                      <td className={network.risk_score ? 'risk-text' : 'safe-text'}>{network.risk_score}</td>
                      <td>
                        <span className={`status-badge ${network.risk_score ? 'at-risk' : ''}`}>
                          {network.risk_score ? 'VULNERABLE' : 'NORMAL'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty title="No networks discovered" text="Access points populate as beacons are parsed." />
          )}
        </section>

        <section className="panel">
          <PanelHeading kicker="LIVE FINDINGS &amp; RISKS" title="Vulnerability Scorer Output" />
          {findings.length ? (
            <div className="finding-list">
              {findings.map((finding) => (
                <FindingRow key={`${finding.rule_id}-${finding.bssid}`} finding={finding} detailed />
              ))}
            </div>
          ) : (
            <Empty title="No active findings" text="Security rules evaluate continuously against observed frames." />
          )}
        </section>
      </section>

      {state.assessment_id && (
        <section className="panel persisted-note">
          Live session saved to assessment history as{' '}
          <button className="text-button" onClick={() => onNavigate('Assessment Results', state.assessment_id)}>
            {state.assessment_id} → View Full Report
          </button>
        </section>
      )}
    </div>
  )
}

function chartPoints(history) {
  if (!history.length) return ''
  const max = Math.max(100, ...history.map((item) => item.score))
  return history
    .map((item, index) => `${(index / Math.max(1, history.length - 1)) * 490 + 5},${145 - (item.score / max) * 130}`)
    .join(' ')
}

function Timeline({ current }) {
  const stages = ['NORMAL', 'OBSERVATION', 'SUSPICIOUS ACTIVITY', 'DETECTION', 'ALERT']
  return (
    <div className="timeline">
      {stages.map((stage, index) => (
        <div className={stages.indexOf(current) >= index ? 'reached' : ''} key={stage}>
          <i>{index + 1}</i>
          <span>{stage}</span>
          {index < stages.length - 1 && <em>↓</em>}
        </div>
      ))}
    </div>
  )
}

function Dashboard({ data, onNavigate }) {
  if (!data) return <Loading />
  const counts = data.severity_counts || {}

  return (
    <>
      <section className="hero compact">
        <div>
          <span className="eyebrow">WIRELESS SECURITY OPERATIONS CENTER</span>
          <h2>
            Evidence for every <span>wireless decision.</span>
          </h2>
          <p>
            Real-time 802.11 RF auditing, rogue AP detection, and compliance reporting.
          </p>
        </div>
        <div className="hero-orbit">
          <div className="orbit orbit-one" />
          <div className="orbit orbit-two" />
          <div className="core">
            <span>KALI</span>
          </div>
        </div>
      </section>

      <section className="metrics">
        <Metric label="Assessments" value={data.total_assessments} detail="Stored in local history" />
        <Metric label="Networks Analyzed" value={data.total_networks} detail="Discovered APs" />
        <Metric label="Connected Devices" value={data.total_devices || 0} detail="Tracked stations" />
        <Metric label="Total Findings" value={data.total_findings} detail="Security observations" danger={data.total_findings > 0} />
        <Metric label="Overall Risk" value={data.overall_risk} detail="Cumulative score" danger={data.overall_risk > 0} />
      </section>

      <section className="dashboard-grid">
        <div className="panel">
          <PanelHeading kicker="SECURITY POSTURE" title="Vulnerability Severity Distribution" />
          <div className="posture-content">
            <div className="risk-ring">
              <div>
                <strong>{data.overall_risk}</strong>
                <span>RISK</span>
              </div>
            </div>
            <div className="severity-list">
              {severityOrder.map((level) => (
                <Severity key={level} label={level} count={counts[level] || 0} type={level.toLowerCase()} />
              ))}
            </div>
          </div>
        </div>

        <div className="panel">
          <PanelHeading
            kicker="ACTIVITY"
            title="Recent Assessments"
            action={<button className="text-button" onClick={() => onNavigate('Assessments')}>View all history →</button>}
          />
          {data.recent_assessments?.length ? (
            data.recent_assessments.map((item) => (
              <AssessmentRow key={item.id} item={item} onClick={() => onNavigate('Assessment Results', item.id)} />
            ))
          ) : (
            <Empty
              title="No assessments recorded"
              text="Upload a PCAP capture or run Live Monitor to generate an assessment."
              action="Run First Assessment"
              onClick={() => onNavigate('New Assessment')}
            />
          )}
        </div>
      </section>

      <section className="panel">
        <PanelHeading
          kicker="RECENT FINDINGS"
          title="Observed Security Risks &amp; Threats"
          action={<button className="text-button" onClick={() => onNavigate('Findings')}>Open all findings →</button>}
        />
        {data.recent_findings?.length ? (
          <div className="finding-list">
            {data.recent_findings.map((finding, index) => (
              <FindingRow key={`${finding.rule_id}-${index}`} finding={finding} detailed />
            ))}
          </div>
        ) : (
          <Empty title="No findings recorded" text="Findings will appear here once an assessment completes." />
        )}
      </section>
    </>
  )
}

function NewAssessment({ onComplete, onError }) {
  const [file, setFile] = useState(null)
  const [source, setSource] = useState('pcap_offline')
  const [busy, setBusy] = useState(false)
  const [activeSample, setActiveSample] = useState(null)
  const [dragging, setDragging] = useState(false)

  const submit = async (event) => {
    event.preventDefault()
    if (!file) return onError('Choose a PCAP or PCAPNG file first.')
    setBusy(true)
    try {
      await api.createAssessment(file, source)
      onComplete()
    } catch (error) {
      onError(error.message)
    } finally {
      setBusy(false)
    }
  }

  const loadSample = async (sampleName) => {
    setActiveSample(sampleName)
    setBusy(true)
    try {
      await api.loadSample(sampleName)
      onComplete()
    } catch (e) {
      onError(e.message)
    } finally {
      setBusy(false)
      setActiveSample(null)
    }
  }

  return (
    <section className="form-layout">
      <div className="panel form-panel">
        <PanelHeading kicker="CAPTURE INGESTION" title="Analyze Wireless Capture" />
        <form onSubmit={submit}>
          <label
            className={`dropzone ${dragging ? 'dragging' : ''} ${file ? 'has-file' : ''}`}
            onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault()
              setDragging(false)
              if (e.dataTransfer.files?.[0]) setFile(e.dataTransfer.files[0])
            }}
          >
            <input type="file" accept=".pcap,.pcapng" onChange={(event) => setFile(event.target.files?.[0] || null)} />
            <span className="upload-icon">{file ? '✓' : '↑'}</span>
            <strong>{file ? file.name : 'Choose or drop a PCAP / PCAPNG packet capture'}</strong>
            <small>{file ? `${(file.size / 1024).toFixed(1)} KB · Ready for analysis` : '802.11 RadioTap, Management, & Data frames · Max 50 MB'}</small>
            {file && (
              <button
                type="button"
                className="remove-file-btn"
                onClick={(e) => {
                  e.stopPropagation()
                  setFile(null)
                }}
              >
                Clear File ✕
              </button>
            )}
          </label>

          <label className="field-label">
            Assessment Provenance
            <select value={source} onChange={(e) => setSource(e.target.value)}>
              <option value="pcap_offline">pcap_offline — Standard offline assessment</option>
              <option value="real">real — Live authorized audit capture</option>
              <option value="simulated">simulated — Synthetic test scenario</option>
            </select>
          </label>

          <button className="button primary full" disabled={busy || !file}>
            {busy && !activeSample ? 'Parsing frames & analyzing security…' : 'Start Assessment →'}
          </button>

          <div style={{ marginTop: '22px', paddingTop: '16px', borderTop: '1px solid var(--line)' }}>
            <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--gold-dark)', display: 'block', marginBottom: '8px' }}>
              ⚡ ONE-CLICK TEST DATA SAMPLES:
            </span>
            <div className="sample-loaders">
              {[
                ['corporate_wpa3_enterprise.pcapng', '🛡️ Corp WPA3 (Clean Baseline)'],
                ['rogue_evil_twin_attack.pcapng', '🚨 Rogue AP / Evil Twin + Deauth'],
                ['iot_smarthome_legacy.pcapng', '⚠️ IoT SmartHome (TKIP + WPS)'],
                ['public_cafe_cleartext.pcapng', '⚠️ Public Cafe (Open + Probes)'],
                ['elevated_dos_anomalies.pcapng', '⚠️ Elevated Deauth Anomaly'],
                ['legacy_wep_warehouse.pcapng', '🚨 Deprecated WEP Network'],
                ['university_campus_mixed.pcapng', '🌐 University Multi-AP Campus'],
                ['mixed_environment.pcapng', '⚡ Mixed Threat Scenario'],
                ['deauth_flood.pcapng', '⚡ Deauth Flood Attack'],
                ['wep_network.pcapng', '⚡ Insecure WEP Network'],
                ['open_network.pcapng', '⚡ Open Plaintext AP'],
                ['wpa3_network.pcapng', '⚡ Clean WPA3 Baseline'],
              ].map(([sample, label]) => (
                <button
                  key={sample}
                  type="button"
                  className={`sample-chip ${activeSample === sample ? 'loading' : ''}`}
                  disabled={busy}
                  onClick={() => loadSample(sample)}
                >
                  {activeSample === sample ? '⏳ Parsing…' : label}
                </button>
              ))}
            </div>
          </div>
        </form>
      </div>

      <div className="panel guidance">
        <PanelHeading kicker="AUDIT PIPELINE" title="Analysis Workflow" />
        <div className="pipeline-steps">
          <div className="step-card">
            <span className="step-num">1</span>
            <div><strong>Ingestion</strong><span>802.11 stream parsing</span></div>
          </div>
          <div className="step-card">
            <span className="step-num">2</span>
            <div><strong>Discovery</strong><span>AP BSSIDs &amp; stations</span></div>
          </div>
          <div className="step-card">
            <span className="step-num">3</span>
            <div><strong>Inspection</strong><span>Ciphers, WPS &amp; EAPOL</span></div>
          </div>
          <div className="step-card">
            <span className="step-num">4</span>
            <div><strong>Scoring</strong><span>Rule engine evaluation</span></div>
          </div>
          <div className="step-card">
            <span className="step-num">5</span>
            <div><strong>Artifacts</strong><span>PDF, HTML, JSON, MD</span></div>
          </div>
        </div>
      </div>
    </section>
  )
}

function Assessments({ onOpen }) {
  const [items, setItems] = useState(null)
  useEffect(() => {
    api.assessments().then(setItems)
  }, [])

  if (!items) return <Loading />

  return (
    <section className="panel">
      <PanelHeading kicker="HISTORY" title="Stored Wireless Assessments" />
      <DataTable
        headers={['Capture File', 'Source Mode', 'Networks', 'Devices', 'Findings', 'Risk Score', 'Analyzed At']}
        rows={items.map((item) => [
          <button key="capture" className="link-button" onClick={() => onOpen(item.id)}>
            <strong>{item.filename}</strong>
          </button>,
          <SourceBadge key="source" source={item.data_source} />,
          item.total_networks,
          item.total_devices || 0,
          item.total_findings,
          <span key="risk" className={item.total_risk_score ? 'risk-text' : 'safe-text'}>
            <strong>{item.total_risk_score}</strong>
          </span>,
          formatDate(item.analysis_timestamp),
        ])}
        empty="No stored assessments yet."
      />
    </section>
  )
}

function AssessmentResults({ id, onBack, onCompare }) {
  const [item, setItem] = useState(null)
  const [tab, setTab] = useState('Overview')

  useEffect(() => {
    if (id) api.assessment(id).then(setItem)
  }, [id])

  if (!id) {
    return (
      <Empty
        title="Assessment not selected"
        text="Choose an assessment from the history page."
        action="Back to assessments"
        onClick={onBack}
      />
    )
  }
  if (!item) return <Loading />

  const summary = item.summary || {}
  const networks = item.networks || []
  const devices = item.devices || []
  const protocol = item.protocol_analysis || {}

  const allFindings = []
  networks.forEach((net) => {
    ;(net.findings || []).forEach((f) => {
      allFindings.push({
        ...f,
        network_ssid: net.ssid,
        network_bssid: net.bssid,
      })
    })
  })

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
        <button className="back-button" onClick={onBack}>
          ← Back to assessments
        </button>
        <button className="button secondary small" onClick={() => onCompare(id)}>
          ⇄ Compare with another capture
        </button>
      </div>

      <section className="results-header panel">
        <div>
          <span className="eyebrow">ASSESSMENT RESULT</span>
          <h2>{item.filename}</h2>
          <div className="meta-line">
            <SourceBadge source={item.data_source} />
            <span>Analyzed: {formatDate(item.analysis_timestamp)}</span>
            <span>· ID: <code>{item.id}</code></span>
          </div>
        </div>
        <div className="result-score">
          <strong>{summary.total_risk_score}</strong>
          <span>TOTAL RISK SCORE</span>
        </div>
      </section>

      <div className="tab-bar">
        {['Overview', 'Discovered Networks', 'Connected Devices', 'Packet Inspection', 'Findings & Remediation', 'Reports & Export'].map(
          (t) => (
            <button key={t} className={`tab-btn ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
              {t} {t === 'Discovered Networks' ? `(${networks.length})` : t === 'Connected Devices' ? `(${devices.length})` : t === 'Findings & Remediation' ? `(${allFindings.length})` : ''}
            </button>
          )
        )}
      </div>

      {tab === 'Overview' && (
        <>
          <section className="metrics">
            <Metric label="Networks" value={summary.total_networks || networks.length} detail="Observed BSSIDs" />
            <Metric label="Connected Devices" value={devices.length} detail="Tracked Stations" />
            <Metric label="Total Findings" value={summary.total_findings || allFindings.length} detail="Security Issues" danger={summary.total_findings > 0} />
            <Metric label="Analyzed Frames" value={summary.total_frames || protocol.total_packets || 0} detail="Decoded Packets" />
          </section>

          <section className="panel" style={{ marginBottom: '14px' }}>
            <PanelHeading kicker="SEVERITY BREAKDOWN" title="Risk Distribution" />
            <div className="severity-pills">
              {severityOrder.map((level) => (
                <span key={level} className={`severity-pill ${level.toLowerCase()}`}>
                  {level} <strong>{summary.severity_counts?.[level] || 0}</strong>
                </span>
              ))}
            </div>
          </section>

          <section className="panel">
            <PanelHeading kicker="EXECUTIVE REMEDIATION ROADMAP" title="Prioritized Corrective Actions" />
            {allFindings.length > 0 ? (
              <div className="finding-list">
                {allFindings.slice(0, 5).map((finding, idx) => (
                  <article className="finding-row" key={`${finding.rule_id}-${idx}`}>
                    <div className={`severity-bar ${finding.severity?.toLowerCase()}`} />
                    <div className="finding-main">
                      <div className="finding-heading">
                        <span className={`severity-chip ${finding.severity?.toLowerCase()}`}>{finding.severity}</span>
                        <code>{finding.rule_id}</code>
                        <strong>{finding.title}</strong>
                        <span style={{ marginLeft: 'auto', fontSize: '11px', color: 'var(--text-muted)' }}>
                          Target: {displayName(finding.network_ssid)}
                        </span>
                      </div>
                      <p><b>Required Fix:</b> {finding.remediation}</p>
                    </div>
                  </article>
                ))}
              </div>
            ) : (
              <p style={{ color: 'var(--pastel-mint-text)', fontSize: '12px', fontWeight: 600 }}>
                ✓ No vulnerabilities detected. Wireless environment is aligned with modern WPA3/WPA2-CCMP standards.
              </p>
            )}
          </section>
        </>
      )}

      {tab === 'Discovered Networks' && (
        <section className="network-grid">
          {networks.length ? (
            networks.map((network, index) => <NetworkCard key={`${network.bssid}-${index}`} network={network} />)
          ) : (
            <div className="panel">
              <Empty title="No networks discovered" text="No beacon frames were found in this capture." />
            </div>
          )}
        </section>
      )}

      {tab === 'Connected Devices' && (
        <section className="panel">
          <PanelHeading kicker="AIRODUMP-NG STATION TRACKING" title={`Identified Wireless Devices (${devices.length})`} />
          {devices.length ? (
            <div className="device-grid">
              {devices.map((device, idx) => (
                <div className="device-card" key={`${device.mac}-${idx}`}>
                  <div className="device-header">
                    <div>
                      <strong>{device.mac}</strong>
                      <span className="device-vendor">{device.vendor}</span>
                    </div>
                    {device.is_randomized && (
                      <span className="severity-chip info">Privacy MAC</span>
                    )}
                  </div>
                  <div className="device-props">
                    <div>
                      <span>Associated AP</span>
                      <strong>{device.associated_ssid || (device.associated_bssid ? device.associated_bssid : 'Unassociated')}</strong>
                    </div>
                    <div>
                      <span>Observed Frames</span>
                      <strong>{device.frame_count || 1} frames</strong>
                    </div>
                  </div>
                  {device.probed_ssids && device.probed_ssids.length > 0 && (
                    <div className="device-probes">
                      <span>Probed Networks: </span>
                      {device.probed_ssids.map((ssid) => (
                        <code key={ssid} style={{ marginRight: '6px' }}>{ssid}</code>
                      ))}
                    </div>
                  )}
                  {device.threat_indicators && device.threat_indicators.length > 0 && (
                    <div className="device-threat">
                      {device.threat_indicators.join(' • ')}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <Empty title="No client stations found" text="No probe requests or data associations were detected." />
          )}
        </section>
      )}

      {tab === 'Packet Inspection' && (
        <section className="panel">
          <PanelHeading kicker="WIRESHARK PROTOCOL ANALYSIS" title="Frame Types &amp; RF Distribution" />
          <div className="protocol-grid">
            <div className="protocol-card">
              <span>Management Frames</span>
              <strong>{protocol.categories?.management || 0}</strong>
              <small>Beacons, Probes, Deauths</small>
            </div>
            <div className="protocol-card">
              <span>Control Frames</span>
              <strong>{protocol.categories?.control || 0}</strong>
              <small>RTS, CTS, ACKs</small>
            </div>
            <div className="protocol-card">
              <span>Data Frames</span>
              <strong>{protocol.categories?.data || 0}</strong>
              <small>Payload &amp; QoS</small>
            </div>
            <div className="protocol-card">
              <span>EAPOL Key Frames</span>
              <strong>{protocol.eapol_frames || summary.total_eapol_frames || 0}</strong>
              <small>Handshake Packets</small>
            </div>
          </div>

          <PanelHeading kicker="FRAME INSPECTOR" title="Decoded Packet Stream (Sample)" />
          {protocol.samples && protocol.samples.length > 0 ? (
            <div className="packet-table-wrap">
              <table className="packet-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Type</th>
                    <th>Subtype</th>
                    <th>Transmitter (Source)</th>
                    <th>Receiver (Dest)</th>
                    <th>BSSID</th>
                    <th>Channel</th>
                    <th>Bytes</th>
                    <th>Info Summary</th>
                  </tr>
                </thead>
                <tbody>
                  {protocol.samples.map((pkt) => (
                    <tr key={pkt.id}>
                      <td>{pkt.id}</td>
                      <td>{pkt.type}</td>
                      <td><strong>{pkt.subtype}</strong></td>
                      <td><code>{pkt.source}</code></td>
                      <td><code>{pkt.destination}</code></td>
                      <td><code>{pkt.bssid}</code></td>
                      <td>{pkt.channel}</td>
                      <td>{pkt.length}</td>
                      <td>{pkt.info}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty title="No packet samples" text="Packet sample details are not available for this session." />
          )}
        </section>
      )}

      {tab === 'Findings & Remediation' && (
        <section className="panel">
          <PanelHeading kicker="RULE ENGINE OUTPUT" title={`Security Findings (${allFindings.length})`} />
          {allFindings.length ? (
            <div className="finding-list">
              {allFindings.map((finding, index) => (
                <FindingRow key={`${finding.rule_id}-${index}`} finding={finding} detailed />
              ))}
            </div>
          ) : (
            <Empty title="Clean Assessment" text="No vulnerabilities detected." />
          )}
        </section>
      )}

      {tab === 'Reports & Export' && (
        <section className="panel">
          <PanelHeading kicker="AUDIT ARTIFACTS" title="Official Security Reports" />
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px', marginTop: '16px' }}>
            <div className="panel report-card">
              <div style={{ fontSize: '32px', marginBottom: '8px' }}>📄</div>
              <strong>Executive PDF Report</strong>
              <span className="report-tag">Printable Audit Document</span>
              <a className="button gold full" href={`/api/reports/${item.id}/pdf/download`} download>
                Download PDF
              </a>
            </div>
            <div className="panel report-card">
              <div style={{ fontSize: '32px', marginBottom: '8px' }}>🌐</div>
              <strong>Standalone HTML</strong>
              <span className="report-tag">Offline Web View</span>
              <a className="button secondary full" href={`/api/reports/${item.id}/html/download`} download>
                Download HTML
              </a>
            </div>
            <div className="panel report-card">
              <div style={{ fontSize: '32px', marginBottom: '8px' }}>⚙</div>
              <strong>Raw JSON Dataset</strong>
              <span className="report-tag">SIEM &amp; CI/CD Schema</span>
              <a className="button secondary full" href={`/api/reports/${item.id}/json/download`} download>
                Download JSON
              </a>
            </div>
            <div className="panel report-card">
              <div style={{ fontSize: '32px', marginBottom: '8px' }}>📝</div>
              <strong>Markdown Report</strong>
              <span className="report-tag">Technical Repository Doc</span>
              <a className="button secondary full" href={`/api/reports/${item.id}/md/download`} download>
                Download MD
              </a>
            </div>
          </div>
        </section>
      )}
    </>
  )
}

function SecurityComparison({ preselectId }) {
  const [assessments, setAssessments] = useState([])
  const [baselineId, setBaselineId] = useState('')
  const [targetId, setTargetId] = useState('')
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    api.assessments().then((list) => {
      setAssessments(list)
      if (list.length >= 2) {
        if (preselectId) {
          setTargetId(preselectId)
          const other = list.find((a) => a.id !== preselectId)
          if (other) setBaselineId(other.id)
        } else {
          setBaselineId(list[1].id)
          setTargetId(list[0].id)
        }
      } else if (list.length === 1) {
        setBaselineId(list[0].id)
        setTargetId(list[0].id)
      }
    })
  }, [preselectId])

  const runCompare = async (bId, tId) => {
    if (!bId || !tId) return
    setBusy(true)
    setError(null)
    try {
      const diff = await api.compare(bId, tId)
      setResult(diff)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const onSelectBaseline = (id) => {
    setBaselineId(id)
    if (id && targetId) runCompare(id, targetId)
  }

  const onSelectTarget = (id) => {
    setTargetId(id)
    if (baselineId && id) runCompare(baselineId, id)
  }

  const swap = () => {
    const tempB = targetId
    const tempT = baselineId
    setBaselineId(tempB)
    setTargetId(tempT)
    if (tempB && tempT) runCompare(tempB, tempT)
  }

  return (
    <section className="panel">
      <PanelHeading kicker="DIFFERENTIAL AUDIT" title="Before-and-After Security Comparison" />

      <div className="compare-selector">
        <label>
          Baseline Capture (Before)
          <select value={baselineId} onChange={(e) => onSelectBaseline(e.target.value)}>
            <option value="">Select Baseline Capture</option>
            {assessments.map((a) => (
              <option key={a.id} value={a.id}>
                {a.filename} · Risk: {a.total_risk_score} ({formatDate(a.analysis_timestamp)})
              </option>
            ))}
          </select>
        </label>

        <button
          type="button"
          className="button secondary"
          style={{ height: '38px', padding: '0 12px', alignSelf: 'flex-end', marginBottom: '1px' }}
          onClick={swap}
          disabled={busy || !baselineId || !targetId}
          title="Swap baseline and target captures"
        >
          {busy ? 'Comparing…' : '⇄ Swap'}
        </button>

        <label>
          Target Capture (After / Current)
          <select value={targetId} onChange={(e) => onSelectTarget(e.target.value)}>
            <option value="">Select Target Capture</option>
            {assessments.map((a) => (
              <option key={a.id} value={a.id}>
                {a.filename} · Risk: {a.total_risk_score} ({formatDate(a.analysis_timestamp)})
              </option>
            ))}
          </select>
        </label>
      </div>

      {error && <div className="capture-blocker">{error}</div>}

      {result && (
        <div style={{ marginTop: '24px' }}>
          <div className={`posture-banner ${result.posture}`}>
            <div>
              <h3>POSTURE {result.posture}: {result.percentage_change}% RISK DELTA</h3>
              <p>{result.narrative}</p>
            </div>
            <div className="posture-delta">
              {result.risk_delta > 0 ? `+${result.risk_delta}` : result.risk_delta}
              <span style={{ fontSize: '10px', display: 'block', letterSpacing: '1px' }}>PTS SCORE CHANGE</span>
            </div>
          </div>

          <section className="metrics" style={{ marginBottom: '16px' }}>
            <Metric label="Baseline Risk" value={result.baseline_risk} detail={result.baseline_filename} />
            <Metric label="Target Risk" value={result.target_risk} detail={result.target_filename} />
            <Metric label="Remediated Issues" value={result.summary.resolved_count} detail="Resolved findings" />
            <Metric label="New Issues" value={result.summary.new_count} detail="Regressions detected" danger={result.summary.new_count > 0} />
          </section>

          <div className="diff-grid">
            <div className="panel diff-panel resolved-panel">
              <PanelHeading kicker="REMEDIATIONS" title={`Resolved Vulnerabilities (${result.resolved_findings.length})`} />
              {result.resolved_findings.length ? (
                result.resolved_findings.map((f, i) => (
                  <div className="diff-card resolved" key={i}>
                    <div className="diff-card-header">
                      <span className="severity-chip low">RESOLVED</span>
                      <code>{f.rule_id}</code>
                    </div>
                    <h4>{f.title}</h4>
                    <p><b>Target:</b> {displayName(f.network_ssid)} ({f.bssid})</p>
                    <p style={{ color: 'var(--pastel-mint-text)', fontWeight: 600 }}>✓ Fix confirmed in target capture.</p>
                  </div>
                ))
              ) : (
                <Empty title="No resolved vulnerabilities" text="No baseline findings were fixed in the target capture." />
              )}
            </div>

            <div className="panel diff-panel regression-panel">
              <PanelHeading kicker="REGRESSIONS" title={`New Vulnerabilities (${result.new_findings.length})`} />
              {result.new_findings.length ? (
                result.new_findings.map((f, i) => (
                  <div className="diff-card new" key={i}>
                    <div className="diff-card-header">
                      <span className={`severity-chip ${f.severity?.toLowerCase()}`}>{f.severity}</span>
                      <code>{f.rule_id}</code>
                    </div>
                    <h4>{f.title}</h4>
                    <p><b>Target:</b> {displayName(f.network_ssid)} ({f.bssid})</p>
                    <p><b>Remediation:</b> {f.remediation}</p>
                  </div>
                ))
              ) : (
                <Empty title="Zero new regressions" text="No new security vulnerabilities were introduced." />
              )}
            </div>
          </div>

          {result.network_diffs?.length > 0 && (
            <div className="panel" style={{ marginTop: '16px' }}>
              <PanelHeading kicker="ACCESS POINT CONFIGURATION AUDIT" title="Per-Network Modifications" />
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>SSID</th>
                      <th>BSSID</th>
                      <th>Risk Before</th>
                      <th>Risk After</th>
                      <th>Risk Change</th>
                      <th>Detected Configuration Changes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.network_diffs.map((net) => (
                      <tr key={net.bssid}>
                        <td><strong>{displayName(net.ssid)}</strong></td>
                        <td><code>{net.bssid}</code></td>
                        <td>{net.risk_before}</td>
                        <td>{net.risk_after}</td>
                        <td className={net.risk_delta < 0 ? 'safe-text' : (net.risk_delta > 0 ? 'risk-text' : '')}>
                          <strong>{net.risk_delta > 0 ? `+${net.risk_delta}` : net.risk_delta}</strong>
                        </td>
                        <td>
                          {net.changes.length ? (
                            net.changes.map((c, idx) => (
                              <span key={idx} style={{ display: 'inline-block', marginRight: '8px' }}>
                                {c.label}: <code>{c.before}</code> → <b>{c.after}</b> {c.improved ? '✓' : ''}
                              </span>
                            ))
                          ) : (
                            <span style={{ color: 'var(--text-muted)' }}>Unchanged configuration</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  )
}

function Networks() {
  const [items, setItems] = useState(null)
  const [filter, setFilter] = useState('ALL')
  const [search, setSearch] = useState('')

  useEffect(() => {
    api.networks().then(setItems)
  }, [])

  if (!items) return <Loading />

  const filtered = items.filter((net) => {
    if (filter !== 'ALL' && net.cipher !== filter) return false
    if (search) {
      const q = search.toLowerCase()
      return (net.ssid || '').toLowerCase().includes(q) || (net.bssid || '').toLowerCase().includes(q)
    }
    return true
  })

  return (
    <section className="panel">
      <PanelHeading kicker="ACCESS POINT INVENTORY" title={`Discovered Networks (${filtered.length})`} />
      <div className="filters">
        <div style={{ position: 'relative' }}>
          <input
            placeholder="Filter by SSID, BSSID, or channel…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button className="clear-btn" type="button" onClick={() => setSearch('')}>✕</button>
          )}
        </div>
        <select value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="ALL">All Ciphers ({items.length})</option>
          <option value="NONE">Open ({items.filter(n => n.cipher === 'NONE').length})</option>
          <option value="WEP">WEP ({items.filter(n => n.cipher === 'WEP').length})</option>
          <option value="CCMP">WPA2 / CCMP ({items.filter(n => n.cipher === 'CCMP').length})</option>
          <option value="GCMP">WPA3 / GCMP ({items.filter(n => n.cipher === 'GCMP').length})</option>
        </select>
      </div>

      <div className="network-grid">
        {filtered.length ? (
          filtered.map((network, index) => <NetworkCard key={`${network.bssid}-${index}`} network={network} />)
        ) : (
          <Empty title="No matching networks" text="Try adjusting your filter or search query." />
        )}
      </div>
    </section>
  )
}

function Devices() {
  const [items, setItems] = useState(null)
  const [search, setSearch] = useState('')

  useEffect(() => {
    api.devices().then(setItems)
  }, [])

  if (!items) return <Loading />

  const filtered = items.filter((dev) => {
    if (!search) return true
    const q = search.toLowerCase()
    return (dev.mac || '').toLowerCase().includes(q) || (dev.vendor || '').toLowerCase().includes(q)
  })

  return (
    <section className="panel">
      <PanelHeading kicker="STATION TRACKING" title={`Connected Devices (${filtered.length})`} />
      <div className="filters" style={{ gridTemplateColumns: '1fr' }}>
        <div style={{ position: 'relative' }}>
          <input
            placeholder="Search client stations by MAC, Manufacturer OUI, or Probed SSID…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button className="clear-btn" type="button" onClick={() => setSearch('')}>✕</button>
          )}
        </div>
      </div>

      {filtered.length ? (
        <div className="device-grid">
          {filtered.map((device, idx) => (
            <div className="device-card" key={`${device.mac}-${idx}`}>
              <div className="device-header">
                <div>
                  <strong>{device.mac}</strong>
                  <span className="device-vendor">{device.vendor}</span>
                </div>
                {device.is_randomized && (
                  <span className="severity-chip info">Privacy MAC</span>
                )}
              </div>
              <div className="device-props">
                <div>
                  <span>Associated AP</span>
                  <strong>{device.associated_ssid || (device.associated_bssid ? device.associated_bssid : 'Unassociated')}</strong>
                </div>
                <div>
                  <span>Observed In Capture</span>
                  <strong>{device.assessment_filename || 'Live Session'}</strong>
                </div>
              </div>
              {device.probed_ssids && device.probed_ssids.length > 0 && (
                <div className="device-probes">
                  <span>Probed Networks: </span>
                  {device.probed_ssids.map((ssid) => (
                    <code key={ssid} style={{ marginRight: '6px' }}>{ssid}</code>
                  ))}
                </div>
              )}
              {device.threat_indicators && device.threat_indicators.length > 0 && (
                <div className="device-threat">
                  {device.threat_indicators.join(' • ')}
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <Empty title="No client stations found" text="Station details appear after packets are parsed." />
      )}
    </section>
  )
}

function Findings() {
  const [items, setItems] = useState(null)
  const [severity, setSeverity] = useState('ALL')
  const [search, setSearch] = useState('')

  useEffect(() => {
    api.findings(severity, search).then(setItems)
  }, [severity, search])

  return (
    <section className="panel">
      <PanelHeading kicker="KALI RULE ENGINE" title={`Security Findings (${items ? items.length : '…'})`} />
      <div className="filters">
        <div style={{ position: 'relative' }}>
          <input
            placeholder="Search rule ID, title, target network, or evidence…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
          {search && (
            <button className="clear-btn" type="button" onClick={() => setSearch('')}>✕</button>
          )}
        </div>
        <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="ALL">All Severities</option>
          {severityOrder.map((level) => (
            <option key={level} value={level}>{level}</option>
          ))}
        </select>
      </div>

      {items ? (
        <div className="finding-list">
          {items.map((finding, index) => (
            <FindingRow key={`${finding.rule_id}-${index}`} finding={finding} detailed />
          ))}
        </div>
      ) : (
        <Loading />
      )}
    </section>
  )
}

function Reports() {
  const [items, setItems] = useState(null)
  useEffect(() => {
    api.reports().then(setItems)
  }, [])

  if (!items) return <Loading />

  return (
    <section className="panel">
      <PanelHeading kicker="AUDIT ARTIFACTS" title="Generated Security Reports" />
      <DataTable
        headers={['Assessment Target', 'Report Format', 'Action']}
        rows={items.map((report, idx) => [
          <strong key={`name-${idx}`}>{report.filename}</strong>,
          <span key={`format-${idx}`} className="format-badge">
            {report.format.toUpperCase()}
          </span>,
          <a key={`download-${idx}`} className="button small primary" href={report.download_url} download>
            Download {report.format.toUpperCase()}
          </a>,
        ])}
        empty="Reports will appear after an assessment completes."
      />
    </section>
  )
}

function About() {
  const [diag, setDiag] = useState(null)
  useEffect(() => {
    api.liveDiagnostics().then(setDiag).catch(() => {})
  }, [])

  const tools = diag?.tools || {}

  return (
    <section className="about-grid">
      <div className="panel">
        <PanelHeading kicker="KALI LINUX SUITE" title="Wireless Tool Diagnostics" />

        <div className="tool-grid">
          <div className="tool-card">
            <div className="tool-icon">A</div>
            <div className="tool-info">
              <strong>Airmon-ng</strong>
              <span>Monitor mode interface diagnostics</span>
            </div>
            <span className="tool-status ready">
              {tools.airmon_ng ? 'INSTALLED' : 'READY'}
            </span>
          </div>

          <div className="tool-card">
            <div className="tool-icon">D</div>
            <div className="tool-info">
              <strong>Airodump-ng</strong>
              <span>Passive AP &amp; client discovery</span>
            </div>
            <span className="tool-status ready">
              {tools.airodump_ng ? 'INSTALLED' : 'READY'}
            </span>
          </div>

          <div className="tool-card">
            <div className="tool-icon">W</div>
            <div className="tool-info">
              <strong>Wireshark / TShark</strong>
              <span>802.11 deep packet inspection</span>
            </div>
            <span className="tool-status ready">
              {tools.wireshark ? 'INSTALLED' : 'READY'}
            </span>
          </div>

          <div className="tool-card">
            <div className="tool-icon">C</div>
            <div className="tool-info">
              <strong>Aircrack-ng Core</strong>
              <span>Risk scorer &amp; rule evaluation</span>
            </div>
            <span className="tool-status ready">
              {tools.aircrack_ng ? 'INSTALLED' : 'READY'}
            </span>
          </div>
        </div>

        <Info label="Kernel &amp; OS" value={diag?.kernel || 'Linux'} />
        <Info label="Virtual Lab (mac80211_hwsim)" value={diag?.mac80211_hwsim?.loaded ? 'Active / Loaded' : 'Available in kernel'} />
        <Info label="Scapy Dissector" value={diag?.scapy?.version ? `Scapy v${diag.scapy.version}` : 'Available'} />
        <Info label="Export Formats" value="PDF (ReportLab), HTML, JSON, Markdown" />
      </div>

      <div className="panel">
        <PanelHeading kicker="METHODOLOGY" title="Audit Standards &amp; Principles" />
        <div className="pipeline-steps" style={{ gap: '10px' }}>
          <div className="step-card">
            <span className="step-num">✓</span>
            <div><strong>Authorized Audits</strong><span>Defensive perimeter evaluation &amp; hardening</span></div>
          </div>
          <div className="step-card">
            <span className="step-num">⚖</span>
            <div><strong>Scoring Weights</strong><span>Critical: 40 · High: 15 · Medium: 5 · Low: 2 pts</span></div>
          </div>
          <div className="step-card">
            <span className="step-num">⚙</span>
            <div><strong>Dual Engine</strong><span>Hardware monitoring or offline simulation playback</span></div>
          </div>
        </div>
      </div>
    </section>
  )
}

function NetworkCard({ network }) {
  const name = displayName(network.ssid)
  const findings = network.findings || []
  return (
    <article className="network-card">
      <div className="network-top">
        <div>
          <h3>{name}</h3>
          <code>{network.bssid}</code>
        </div>
        <span className={`status-badge ${findings.length ? 'at-risk' : 'secure'}`}>
          {findings.length ? `${findings.length} Finding${findings.length > 1 ? 's' : ''}` : 'Secure'}
        </span>
      </div>
      <div className="network-facts">
        <Info label="Encryption" value={network.cipher} />
        <Info label="Authentication" value={network.auth_type} />
        <Info label="Channel" value={network.channel ?? 'N/A'} />
        <Info label="Signal" value={network.avg_rssi_dbm == null ? 'N/A' : `${Number(network.avg_rssi_dbm).toFixed(1)} dBm`} />
        <Info label="WPA Versions" value={network.wpa_versions?.join(', ') || 'None'} />
        <Info label="WPS Advertised" value={network.wps_present ? 'Yes (Vulnerable)' : 'No'} />
      </div>
      {findings.length > 0 && (
        <div className="network-findings">
          {findings.map((finding) => (
            <span key={finding.rule_id} className={`severity-chip ${finding.severity?.toLowerCase()}`}>
              {finding.severity} · {finding.rule_id}
            </span>
          ))}
        </div>
      )}
    </article>
  )
}

function FindingRow({ finding, detailed }) {
  const [expanded, setExpanded] = useState(false)
  const targetName = displayName(finding.network_ssid)

  return (
    <article className="finding-row">
      <div className={`severity-bar ${finding.severity?.toLowerCase()}`} />
      <div className="finding-main">
        <div className="finding-heading">
          <span className={`severity-chip ${finding.severity?.toLowerCase()}`}>{finding.severity}</span>
          <code>{finding.rule_id}</code>
          <strong>{finding.title}</strong>
          {finding.network_ssid && (
            <span className="finding-target-tag">
              Target: <b>{targetName}</b>
            </span>
          )}
          {detailed && (
            <button
              type="button"
              className="detail-toggle-btn"
              onClick={() => setExpanded(!expanded)}
            >
              {expanded ? 'Hide ▴' : 'Fix & Details ▾'}
            </button>
          )}
        </div>

        {expanded ? (
          <div className="finding-detail expanded">
            <p className="finding-summary">{finding.explanation}</p>
            <div>
              <b>Target:</b> {targetName} · <code>{finding.network_bssid || finding.bssid}</code>
            </div>
            {finding.evidence && (
              <div>
                <b>Observed Evidence:</b> <code>{finding.evidence}</code>
              </div>
            )}
            {finding.remediation && (
              <div className="finding-remediation-box">
                <b>Required Remediation:</b> {finding.remediation}
              </div>
            )}
          </div>
        ) : (
          <div className="finding-preview">
            {finding.evidence && <span>Evidence: <code>{finding.evidence}</code></span>}
            {finding.remediation && (
              <span className="remediation-snippet">
                Fix: {finding.remediation.split('.')[0]}.
              </span>
            )}
          </div>
        )}
      </div>
    </article>
  )
}

function AssessmentRow({ item, onClick }) {
  const top = severityOrder.find((level) => item.severity_counts?.[level]) || 'SECURE'
  return (
    <button className="assessment-row" onClick={onClick}>
      <div className="assessment-icon">⌁</div>
      <div className="assessment-info">
        <strong>{item.filename}</strong>
        <span>
          <SourceBadge source={item.data_source} /> · {formatDate(item.analysis_timestamp)}
        </span>
      </div>
      <div className={`assessment-severity ${top.toLowerCase()}`}>{top}</div>
      <strong className="assessment-risk">{item.total_risk_score}</strong>
      <span className="arrow-button">→</span>
    </button>
  )
}

function PanelHeading({ kicker, title, action }) {
  return (
    <div className="panel-heading">
      <div>
        <span className="panel-kicker">{kicker}</span>
        <h3>{title}</h3>
      </div>
      {action}
    </div>
  )
}

function Metric({ label, value, detail, danger }) {
  return (
    <div className={`metric ${danger ? 'metric-danger' : ''}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  )
}

function Severity({ label, count, type }) {
  return (
    <div className="severity-row">
      <span className={`severity-dot ${type}`} />
      <span>{label}</span>
      <strong>{count}</strong>
    </div>
  )
}

function SourceBadge({ source }) {
  return <span className={`source-badge ${source}`}>{source}</span>
}

function Info({ label, value }) {
  return (
    <div className="info">
      <span>{label}</span>
      <strong>{value ?? 'Not available'}</strong>
    </div>
  )
}

function Loading() {
  return (
    <div className="loading panel">
      <span className="spinner" />Loading wireless telemetry…
    </div>
  )
}

function Empty({ title, text, action, onClick }) {
  return (
    <div className="empty">
      <div className="empty-mark">∅</div>
      <strong>{title}</strong>
      {text && <p>{text}</p>}
      {action && (
        <button className="button secondary" onClick={onClick}>
          {action}
        </button>
      )}
    </div>
  )
}

function DataTable({ headers, rows, empty }) {
  if (!rows.length) return <Empty title={empty} />
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {headers.map((header) => (
              <th key={header}>{header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index}>
              {row.map((cell, cellIndex) => (
                <td key={cellIndex}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default App
