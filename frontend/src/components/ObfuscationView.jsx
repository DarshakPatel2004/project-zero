import { useState, useEffect, useCallback } from 'react'
import '../styles/ObfuscationView.css'

const TECH_COLORS = ['rose', 'amber', 'cyan', 'violet']

export default function ObfuscationView({ sample, apiUrl }) {
  const [obfuscationData, setObfuscationData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [deobfInput, setDeobfInput] = useState('')
  const [deobfHint, setDeobfHint] = useState('')
  const [deobfResult, setDeobfResult] = useState(null)
  const [deobfLoading, setDeobfLoading] = useState(false)

  const sampleId = sample?.sampleId || sample?.sha256 || sample?.uploadId
  const API_URL = apiUrl || 'http://localhost:8000'

  const fetchObfuscation = useCallback(async () => {
    try {
      setLoading(true)
      const response = await fetch(`${API_URL}/api/sample/${sampleId}/obfuscation`)
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const data = await response.json()
      setObfuscationData(data)
      setError(null)
    } catch (err) {
      setError('Failed to load obfuscation analysis: ' + err.message)
    } finally {
      setLoading(false)
    }
  }, [sampleId, API_URL])

  const runDeobfuscation = async () => {
    if (!deobfInput.trim() || !sampleId) return
    try {
      setDeobfLoading(true)
      const response = await fetch(`${API_URL}/api/sample/${sampleId}/deobfuscate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: deobfInput, hint: deobfHint || undefined }),
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const data = await response.json()
      setDeobfResult(data)
    } catch (err) {
      setDeobfResult({ original: deobfInput, results: [{ type: 'error', value: err.message, status: 'error' }] })
    } finally {
      setDeobfLoading(false)
    }
  }

  useEffect(() => {
    if (!sampleId) return
    fetchObfuscation() // eslint-disable-line react-hooks/set-state-in-effect
  }, [sampleId, fetchObfuscation])

  if (!sample) {
    return (
      <div className="state-container">
        <span className="state-icon">🔐</span>
        <h3 className="state-title">No sample selected</h3>
        <p className="state-description">Analyze an APK first to view obfuscation analysis.</p>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="state-container">
        <div className="analysis-loading-spinner"></div>
        <h3 className="state-title">Loading Obfuscation Analysis</h3>
        <p className="state-description">Scanning for reflection, dynamic loading, crypto APIs, and packing...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="state-container error-container">
        <span className="state-icon">⚠</span>
        <h3 className="state-title">Obfuscation Analysis Error</h3>
        <p className="state-description">{error}</p>
      </div>
    )
  }

  if (!obfuscationData) {
    return (
      <div className="state-container">
        <span className="state-icon">📭</span>
        <h3 className="state-title">No obfuscation data</h3>
        <p className="state-description">Obfuscation analysis was not available for this sample.</p>
      </div>
    )
  }

  const score = Math.round(obfuscationData.obfuscation_score || 0)
  const level = obfuscationData.obfuscation_level || 'low'
  const techniques = obfuscationData.techniques || []
  const techGrid = techniques.slice(0, 4).map((t, i) => ({
    name: t.name || t.key,
    percent: Math.min(t.count * 10, 99),
    api: t.items?.[0]?.class || t.items?.[0]?.detail || '',
    color: TECH_COLORS[i] || 'cyan',
  }))

  return (
    <div className="obfuscation-view">
      <div className="obf-head">
        <div>
          <p className="section-title">EVASION ASSESSMENT</p>
          <h2>Obfuscation score <span style={{ color: `var(--risk-${level})` }}>{score}/100</span></h2>
        </div>
        <div className="obf-meter" style={{ width: '100%', maxWidth: 300 }}>
          <div className="meter-bg">
            <div className="meter-fill" style={{ width: `${score}%`, background: `var(--risk-${level})` }} />
          </div>
        </div>
      </div>

      {techniques.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
          <h3 style={{ margin: 0, color: 'var(--text-primary)' }}>No obfuscation indicators detected</h3>
          <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem' }}>The sample scored {score}/100.</p>
        </div>
      ) : (
        <div className="tech-grid">
          {techGrid.map(t => (
            <section className="tech-card" key={t.name}>
              <small>{t.name}</small>
              <strong>{t.percent}%</strong>
              <div className="meter-bg" style={{ height: 6 }}>
                <div className="meter-fill" style={{ width: `${t.percent}%`, background: `var(--accent-${t.color})` }} />
              </div>
              <p className="text-mono" style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>{t.api}</p>
            </section>
          ))}
        </div>
      )}

      <section className="card" style={{ padding: '1.25rem' }}>
        <h3 className="section-title">Deobfuscation Tool</h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: 14, margin: '0 0 0.75rem' }}>Paste an obfuscated string to try Base64, hex, URL, and XOR decoders.</p>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <input
            type="text"
            placeholder="e.g. SGVsbG8gV29ybGQ= or 48656c6c6f..."
            value={deobfInput}
            onChange={(e) => setDeobfInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && runDeobfuscation()}
            style={{ flex: 1, minWidth: 200, padding: '10px 12px', background: 'var(--bg-primary)', border: '1px solid var(--border-color)', borderRadius: 6, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}
          />
          <select value={deobfHint} onChange={(e) => setDeobfHint(e.target.value)} style={{ padding: '10px 12px', background: 'var(--bg-primary)', border: '1px solid var(--border-color)', borderRadius: 6, color: 'var(--text-primary)' }}>
            <option value="">Auto-detect</option>
            <option value="base64">Base64</option>
            <option value="hex">Hex</option>
            <option value="url_decode">URL decode</option>
          </select>
          <button onClick={runDeobfuscation} disabled={deobfLoading} style={{ padding: '10px 20px', background: 'var(--accent-cyan)', border: 'none', borderRadius: 6, color: 'white', fontWeight: 600, cursor: 'pointer' }}>
            {deobfLoading ? 'Decoding...' : 'Decode'}
          </button>
        </div>

        {deobfResult && (
          <div className="deobf-results">
            <div className="deobf-original">
              <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Original:</span>
              <code style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{deobfResult.original}</code>
            </div>
            {deobfResult.results.length === 0 ? (
              <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No decodings produced printable output.</p>
            ) : (
              deobfResult.results.map((r, idx) => (
                <div key={idx} className={`deobf-result deobf-${r.status}`}>
                  <span className="deobf-type">{r.type}</span>
                  <code className="deobf-value">{r.value}</code>
                  {r.raw_bytes && <span className="deobf-raw">hex: {r.raw_bytes}</span>}
                </div>
              ))
            )}
          </div>
        )}
      </section>
    </div>
  )
}
