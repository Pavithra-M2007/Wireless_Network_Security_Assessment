const request = async (path, options = {}) => {
  const response = await fetch(`/api${path}`, options)
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(body.error || 'The API request failed')
  return body
}

export const api = {
  dashboard: () => request('/dashboard'),
  assessments: async () => (await request('/assessments')).items,
  assessment: (id) => request(`/assessments/${id}`),
  networks: async () => (await request('/networks')).items,
  devices: async () => (await request('/devices')).items,
  compare: (baseline, target) => request('/compare', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ baseline, target }),
  }),
  findings: async (severity, search) =>
    (await request(`/findings?severity=${encodeURIComponent(severity)}&search=${encodeURIComponent(search)}`)).items,
  reports: async () => (await request('/reports')).items,
  createAssessment: (file, dataSource) => {
    const form = new FormData()
    form.append('file', file)
    form.append('data_source', dataSource)
    return request('/assessments', { method: 'POST', body: form })
  },
  loadSample: (sample, dataSource = 'simulated') =>
    request('/assessments/sample', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sample, data_source: dataSource }),
    }),
  liveCommand: (command, scenario, interfaceName, mode) =>
    request(`/live/${command}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...(scenario ? { scenario } : {}),
        ...(interfaceName ? { interface: interfaceName } : {}),
        ...(mode ? { mode } : {}),
      }),
    }),
  liveState: () => request('/live/state'),
  liveDiagnostics: () => request('/live/diagnostics'),
}

export function formatDate(value) {
  if (!value) return 'Unknown time'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
}

export function displayName(value) {
  return value === null || value === undefined ? '(SSID unavailable)' : value === '' ? '(Hidden SSID)' : value
}
