import { useState, useEffect } from 'react'
import '../styles/ObfuscationView.css'

const TECHNIQUE_COLORS = {
  dynamic_loading: 'rose',
  native_loading: 'violet',
  reflection: 'amber',
  crypto_apis: 'cyan',
  suspicious_apis: 'emerald',
  dangerous_permissions: 'slate',
}

export default function ObfuscationView({ sample, apiUrl, result }) {
  const [obfuscationData, setObfuscationData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [deobfInput, setDeobfInput] = useState('')
  const [deobfHint, setDeobfHint] = useState('')
  const [deobfResult, setDeobfResult] = useState(null)
  const [deobfLoading, setDeobfLoading] = useState(false)

  const sampleId = sample?.sampleId || sample?.sha256 || sample?.uploadId
  const API_URL = apiUrl || 'http://localhost:8000'
  const packing = result?.binary_packing || {}
  const reflective = result?.reflective_tracing || {}
  const strings = result?.string_clustering || {}

  useEffect(() => {
    if (!sampleId) return
    fetchObfuscation()
  }, [sampleId])

  const fetchObfuscation = async () => {
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
  }

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
  const packedDex = obfuscationData.packed_dex || []
  const nativeArtifacts = obfuscationData.native_library_artifacts || []

  return (
    <div className="obfuscation-view view-wrapper">
      <div className="obfuscation-header card">
        <div className="obfuscation-header-main">
          <h2>Obfuscation Analysis</h2>
          <p>Detected obfuscation techniques, packing indicators, and deobfuscation tools</p>
        </div>
        <div className={`obfuscation-score score-${level}`}>
          <span className="score-value">{score}</span>
          <span className="score-label">/ 100</span>
          <span className="score-level">{level}</span>
        </div>
      </div>

      {techniques.length === 0 && packedDex.length === 0 && nativeArtifacts.length === 0 ? (
        <div className="obfuscation-empty card">
          <span className="empty-icon">🔍</span>
          <h3>No obfuscation indicators detected</h3>
          <p>The sample scored {score}/100. No reflection, dynamic loading, crypto APIs, or packing were found.</p>
        </div>
      ) : (
        <>
          <div className="obfuscation-techniques">
            {techniques.map(tech => (
              <TechniqueCard key={tech.key} technique={tech} color={TECHNIQUE_COLORS[tech.key] || 'cyan'} />
            ))}
          </div>

          {(packedDex.length > 0 || nativeArtifacts.length > 0) && (
            <div className="obfuscation-grid">
              {packedDex.length > 0 && (
                <div className="obfuscation-card card">
                  <h3 className="section-title">Packed / Encrypted DEX</h3>
                  <div className="dex-list">
                    {packedDex.map((dex, idx) => (
                      <div key={idx} className="dex-item">
                        <span className="dex-name text-mono">{dex.file}</span>
                        <span className="dex-entropy">entropy {dex.entropy}</span>
                        <span className="badge badge-high">likely packed</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {nativeArtifacts.length > 0 && (
                <div className="obfuscation-card card">
                  <h3 className="section-title">Native Library Artifacts</h3>
                  <div className="native-list">
                    {nativeArtifacts.map((lib, idx) => (
                      <div key={idx} className="native-item">
                        <span className="native-name text-mono">{lib.library}</span>
                        <span className="native-meta">{lib.total_strings} strings / {lib.artifact_count} artifacts</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {(packing.packer_detected || reflective.has_reflection) && (
        <div className="obfuscation-grid">
          {packing.packer_detected && (
            <div className="obfuscation-card card">
              <h3 className="section-title">Binary Packing</h3>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: 0 }}>
                Packer detected: <strong>{packing.packer_name || 'Unknown'}</strong>
              </p>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: 0 }}>
                Entropy: {packing.entropy?.toFixed(2) || '—'}
              </p>
            </div>
          )}
          {reflective.has_reflection && (
            <div className="obfuscation-card card">
              <h3 className="section-title">Reflective Calls</h3>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: 0 }}>
                Count: <strong>{reflective.call_count ?? 0}</strong>
              </p>
              {reflective.permission_mismatch && (
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: 0 }}>
                  Permission mismatch detected
                </p>
              )}
            </div>
          )}
          {strings.total_clusters > 0 && (
            <div className="obfuscation-card card">
              <h3 className="section-title">String Clusters</h3>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: 0 }}>
                Clusters: <strong>{strings.total_clusters}</strong> / Strings: <strong>{strings.total_strings}</strong>
              </p>
            </div>
          )}
        </div>
      )}

      <div className="obfuscation-card card deobf-card">
        <h3 className="section-title">Deobfuscation Tool</h3>
        <p className="deobf-subtitle">Paste an obfuscated string to try Base64, hex, URL, and XOR decoders.</p>
        <div className="deobf-inputs">
          <input
            type="text"
            className="deobf-text"
            placeholder="e.g. SGVsbG8gV29ybGQ= or 48656c6c6f..."
            value={deobfInput}
            onChange={(e) => setDeobfInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && runDeobfuscation()}
          />
          <select
            className="deobf-hint"
            value={deobfHint}
            onChange={(e) => setDeobfHint(e.target.value)}
          >
            <option value="">Auto-detect</option>
            <option value="base64">Base64</option>
            <option value="hex">Hex</option>
            <option value="url_decode">URL decode</option>
          </select>
          <button className="deobf-button" onClick={runDeobfuscation} disabled={deobfLoading}>
            {deobfLoading ? 'Decoding...' : 'Decode'}
          </button>
        </div>

        {deobfResult && (
          <div className="deobf-results">
            <div className="deobf-original">
              <span className="deobf-label">Original:</span>
              <code className="text-mono">{deobfResult.original}</code>
            </div>
            {deobfResult.results.length === 0 ? (
              <p className="deobf-no-results">No decodings produced printable output.</p>
            ) : (
              deobfResult.results.map((r, idx) => (
                <div key={idx} className={`deobf-result deobf-${r.status}`}>
                  <span className="deobf-type">{r.type}</span>
                  <code className="deobf-value text-mono">{r.value}</code>
                  {r.raw_bytes && <span className="deobf-raw">hex: {r.raw_bytes}</span>}
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function TechniqueCard({ technique, color }) {
  const [expanded, setExpanded] = useState(false)
  const visibleItems = expanded ? technique.items : technique.items.slice(0, 5)

  return (
    <div className={`obfuscation-card card technique-${color}`}>
      <div className="technique-header">
        <div>
          <h4 className="technique-name">{technique.name}</h4>
          <span className="technique-count">{technique.count} occurrence(s)</span>
        </div>
        <span className={`technique-badge badge-${color}`}>{technique.count}</span>
      </div>
      <div className="technique-items">
        {visibleItems.map((item, idx) => (
          <div key={idx} className="technique-item">
            {item.class ? (
              <>
                <span className="technique-class text-mono" title={item.class}>{item.class}</span>
                <span className="technique-method text-mono">{item.method}</span>
              </>
            ) : (
              <span className="technique-method text-mono">{item.method}</span>
            )}
          </div>
        ))}
      </div>
      {technique.items.length > 5 && (
        <button className="technique-expand" onClick={() => setExpanded(!expanded)}>
          {expanded ? 'Show less' : `Show ${technique.items.length - 5} more`}
        </button>
      )}
    </div>
  )
}
