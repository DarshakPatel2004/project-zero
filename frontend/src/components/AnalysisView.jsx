import { useState, useEffect, useMemo, useCallback, memo } from 'react'
import './AnalysisView.css'
import ObfuscationView from './ObfuscationView'
import ManifestView from './ManifestView'

/**
 * Format seconds into human-readable duration.
 * e.g., 65 -> "1m 5s", 3661 -> "1h 1m 1s"
 */
function formatDuration(seconds) {
  if (seconds === null || seconds === undefined) return '—'
  if (seconds === 0) return '0s'

  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = Math.floor(seconds % 60)

  const parts = []
  if (h > 0) parts.push(`${h}h`)
  if (m > 0) parts.push(`${m}m`)
  if (s > 0) parts.push(`${s}s`)

  return parts.join(' ')
}

/**
 * Memoized KPI Card: prevents re-render unless its specific metrics change.
 */
const KPICard = memo(({ label, value, icon, color }) => (
  <div className="kpi-card" style={{ borderTopColor: color }}>
    <div className="kpi-icon" style={{ color }}>{icon}</div>
    <div className="kpi-content">
      <p className="kpi-label">{label}</p>
      <p className="kpi-value">{value}</p>
    </div>
  </div>
))

KPICard.displayName = 'KPICard'

/**
 * Memoized Loading State: shows progress bar, ETA, and live metrics.
 */
const LoadingState = memo(({ analysisState }) => {
  const { progress, eta } = analysisState

  return (
    <div className="analysis-loading">
      <div className="loading-radar">
        <svg viewBox="0 0 100 100" style={{ animation: 'spin 3s linear infinite' }}>
          <circle cx="50" cy="50" r="40" stroke="var(--accent-cyan)" strokeWidth="2" fill="none" opacity="0.3" />
          <circle cx="50" cy="50" r="30" stroke="var(--accent-cyan)" strokeWidth="1.5" fill="none" opacity="0.5" />
          <circle cx="50" cy="50" r="10" fill="var(--accent-cyan)" />
        </svg>
      </div>

      <h2>Static Analysis Running</h2>
      <p className="loading-status">
        {eta !== null && eta > 0
          ? `ETA: ${formatDuration(eta)}`
          : 'Preparing analysis environment...'}
      </p>

      <div className="progress-container">
        <div className="progress-bar-wrapper">
          <div
            className="progress-bar-fill"
            style={{ width: `${progress || 0}%` }}
          />
        </div>
        <span className="progress-percent">{Math.round(progress || 0)}%</span>
      </div>

      <div className="kpi-strip">
        <KPICard
          label="Encodings"
          value={analysisState.metrics?.encoding_count || 0}
          icon="🔐"
          color="var(--accent-amber)"
        />
        <KPICard
          label="Payloads"
          value={analysisState.metrics?.payload_count || 0}
          icon="💾"
          color="var(--accent-rose)"
        />
        <KPICard
          label="C2 Endpoints"
          value={analysisState.metrics?.c2_count || 0}
          icon="🌐"
          color="var(--accent-emerald)"
        />
        <KPICard
          label="Threat Chains"
          value={analysisState.metrics?.threat_chain_count || 0}
          icon="⛓️"
          color="var(--accent-violet)"
        />
      </div>
    </div>
  )
})

LoadingState.displayName = 'LoadingState'

/**
 * Memoized Result View: shown when analysis completes.
 * Handles loading full result JSON and rendering tabs.
 */
const ResultView = memo(({ analysisState, apiUrl, sample }) => {
  const [fullResult, setFullResult] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [activeResultTab, setActiveResultTab] = useState('overview')

  const sampleId = analysisState.sampleId

  // Fetch full result once analysis completes.
  // Prefer SHA-256 from the sample prop (backend key) over analysisState.sampleId
  // for robustness against any ID type inconsistency.
  const effectiveSampleId = sample?.sha256 || sampleId

  useEffect(() => {
    if (!effectiveSampleId) return

    let cancelled = false

    const fetchResult = async () => {
      try {
        setLoading(true)
        setError(null)

        const response = await fetch(`${apiUrl}/api/sample/${effectiveSampleId}`)

        if (response.status === 404) {
          setError('Analysis results not yet available. Pipeline may still be processing.')
          return
        }

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}))
          throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`)
        }

        const data = await response.json()
        if (!data) {
          throw new Error('Empty response from server')
        }

        if (!cancelled) {
          setFullResult(data)
          setError(null)
        }
      } catch (err) {
        console.error('Result fetch failed:', err)
        if (!cancelled) {
          setError(err.message || 'Failed to fetch analysis results')
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    // Small delay to allow backend to write pipeline_result.json
    const timer = setTimeout(fetchResult, 500)
    return () => { cancelled = true; clearTimeout(timer) }
  }, [effectiveSampleId, apiUrl])

  if (loading) {
    return (
      <div className="result-loading" style={{ textAlign: 'center', padding: '40px', fontSize: '16px' }}>
        <div style={{ marginBottom: '16px' }}>⏳</div>
        <p>Loading analysis results...</p>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '8px' }}>
          This may take a moment while the backend processes your analysis.
        </p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="result-error" style={{
        padding: '32px',
        backgroundColor: 'var(--bg-secondary)',
        borderRadius: '8px',
        border: '1px solid var(--accent-rose)',
        marginTop: '16px'
      }}>
        <div style={{ fontSize: '24px', marginBottom: '12px' }}>⚠️</div>
        <h3 style={{ marginBottom: '8px' }}>Analysis Results Unavailable</h3>
        <p style={{ color: 'var(--text-secondary)', marginBottom: '12px' }}>
          {error}
        </p>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
          <strong>Troubleshooting:</strong>
        </p>
        <ul style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '8px', paddingLeft: '20px' }}>
          <li>Check that the analysis completed successfully (backend logs)</li>
          <li>Verify the backend is running on {apiUrl}</li>
          <li>Ensure pipeline_result.json was generated in the work directory</li>
          <li>Try uploading a different APK to test the pipeline</li>
        </ul>
      </div>
    )
  }

  if (!fullResult) {
    return (
      <div className="result-error">
        <p>No analysis data available.</p>
      </div>
    )
  }

  const metadata = fullResult.metadata || {}
  const verdict = analysisState.verdictData

  return (
    <div className="analysis-result">
      {/* Hero Section */}
      <div className="result-hero">
        <div className="hero-accent" style={{ backgroundColor: verdict?.verdict === 'malware' ? 'var(--accent-rose)' : 'var(--accent-emerald)' }} />
        <div className="hero-content">
          <h1>{metadata.package_name || 'Unknown Package'}</h1>
          <div className="hero-badges">
            <span className="badge badge-cyan">{metadata.sha256?.slice(0, 16)}...</span>
            <span className="badge badge-slate">{(metadata.file_size_bytes / 1024 / 1024).toFixed(2)} MB</span>
          </div>
        </div>

        <div className="result-metrics">
          <div className="metric">
            <span className="metric-label">Verdict</span>
            <span className={`metric-value badge badge-${verdict?.verdict === 'malware' ? 'rose' : 'emerald'}`}>
              {verdict?.verdict?.toUpperCase() || '—'}
            </span>
          </div>
          <div className="metric">
            <span className="metric-label">Risk Score</span>
            <span className="metric-value">{verdict?.riskScore || 0} / 100</span>
          </div>
          <div className="metric">
            <span className="metric-label">Analysis Time</span>
            <span className="metric-value">{formatDuration(verdict?.totalDuration)}</span>
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="result-tabs">
        {[
          { id: 'overview', label: 'Overview' },
          { id: 'secrets', label: 'Secrets' },
          { id: 'llm', label: 'LLM Summary' },
          { id: 'dissection-summary', label: 'Dissection Summary' },
          { id: 'obfuscation', label: 'Obfuscation' },
          { id: 'chains', label: 'Threat Chains' },
          { id: 'manifest', label: 'Manifest' },
        ].map(tab => (
          <button
            key={tab.id}
            className={`tab-button ${activeResultTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveResultTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="tab-content">
        {activeResultTab === 'overview' && (
          <OverviewTab result={fullResult} />
        )}
        {activeResultTab === 'secrets' && (
          <SecretsTab result={fullResult} />
        )}
        {activeResultTab === 'llm' && (
          <LLMSummaryTab result={fullResult} />
        )}
        {activeResultTab === 'dissection-summary' && (
          <DissectionSummaryTab sampleId={effectiveSampleId} apiUrl={apiUrl} />
        )}
        {activeResultTab === 'obfuscation' && (
          <ObfuscationView sample={sample} apiUrl={apiUrl} />
        )}
        {activeResultTab === 'chains' && (
          <ChainsTab result={fullResult} apiUrl={apiUrl} sampleId={effectiveSampleId} />
        )}
        {activeResultTab === 'manifest' && (
          <ManifestView sample={sample} apiUrl={apiUrl} />
        )}
      </div>
    </div>
  )
})

ResultView.displayName = 'ResultView'

/**
 * Overview Tab Content
 */
const OverviewTab = memo(({ result }) => (
  <div className="tab-panel">
    <div className="card">
      <h3>Assessment Summary</h3>
      <p>{result?.llm_assessment?.narrative || 'No narrative available.'}</p>
    </div>

    <div className="card">
      <h3>Recommended Actions</h3>
      <ul>
        {(result?.llm_assessment?.recommended_actions || []).map((action, i) => (
          <li key={i}>{action}</li>
        ))}
      </ul>
    </div>

    <div className="metrics-grid">
      <div className="card">
        <h4>Strings</h4>
        <p className="metric-value">{result?.extraction?.total_strings_extracted || 0}</p>
      </div>
      <div className="card">
        <h4>Classes</h4>
        <p className="metric-value">{result?.extraction?.decompiled_classes || 0}</p>
      </div>
      <div className="card">
        <h4>C2 Endpoints</h4>
        <p className="metric-value">{(result?.c2_infrastructure || []).length}</p>
      </div>
      <div className="card">
        <h4>Threat Chains</h4>
        <p className="metric-value">{(result?.threat_chains || []).length}</p>
      </div>
      <div className="card">
        <h4>Secrets</h4>
        <p className="metric-value">{result?.secret_risk?.total_secrets || 0}</p>
        <p className="metric-sub" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          {result?.secret_risk?.severity || 'none'}
        </p>
      </div>
    </div>
  </div>
))

OverviewTab.displayName = 'OverviewTab'

/**
 * LLM Summary Tab
 */
const LLMSummaryTab = memo(({ result }) => {
  const llm = result?.llm_assessment || {}
  const narrative = llm.narrative || 'No LLM analysis available.'
  const methods = llm.suspicious_methods || []
  const actions = llm.recommended_actions || []

  return (
    <div className="tab-panel">
      <div className="card">
        <h3>LLM Analysis Narrative</h3>
        <div className="llm-narrative" style={{
          padding: '16px',
          backgroundColor: 'var(--bg-secondary)',
          borderRadius: '8px',
          lineHeight: '1.6',
          color: 'var(--text-secondary)'
        }}>
          {narrative}
        </div>
      </div>

      {methods.length > 0 && (
        <div className="card">
          <h3>Suspicious Methods ({methods.length})</h3>
          <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
            {methods.slice(0, 10).map((method, i) => (
              <div
                key={i}
                style={{
                  padding: '12px',
                  marginBottom: '8px',
                  backgroundColor: 'var(--bg-tertiary)',
                  borderLeft: '3px solid var(--accent-rose)',
                  borderRadius: '4px',
                  fontSize: '13px',
                  fontFamily: 'monospace'
                }}
              >
                <div style={{ fontWeight: 500, marginBottom: '4px' }}>
                  {method.method_name || method}
                </div>
                {method.reason && (
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    {method.reason}
                  </div>
                )}
              </div>
            ))}
          </div>
          {methods.length > 10 && (
            <p style={{ marginTop: '12px', color: 'var(--text-muted)' }}>
              … and {methods.length - 10} more
            </p>
          )}
        </div>
      )}

      {actions.length > 0 && (
        <div className="card">
          <h3>Recommended Actions</h3>
          <ul style={{ paddingLeft: '20px' }}>
            {actions.map((action, i) => (
              <li key={i} style={{ marginBottom: '8px', lineHeight: '1.5' }}>
                {action}
              </li>
            ))}
          </ul>
        </div>
      )}

      {methods.length === 0 && actions.length === 0 && !narrative && (
        <div style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
          <p>No LLM analysis data available yet.</p>
        </div>
      )}
    </div>
  )
})

LLMSummaryTab.displayName = 'LLMSummaryTab'

/**
 * Dissection Summary Tab — real-time LLM threat assessment from dissection data
 * FIXED: Sanitizes response to prevent "Objects are not valid as React child" error
 */
const DissectionSummaryTab = memo(({ sampleId, apiUrl }) => {
  const [summary, setSummary] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!sampleId) return
    let cancelled = false

    const fetchSummary = async () => {
      try {
        setLoading(true)
        setError(null)
        const res = await fetch(`${apiUrl}/api/sample/${sampleId}/dissection/summary`)
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}))
          throw new Error(errData.detail || `HTTP ${res.status}`)
        }
        const data = await res.json()
        if (!cancelled) {
          // Backend (_format_behavior_item / _format_c2_item in step7) already
          // normalizes list entries to strings. Re-sanitizing here caused
          // drift (e.g. {"value":"x.com","indicator_type":"domain"} rendered
          // as just "domain"). Only guarantee that primitives are strings so
          // React can't choke on accidental objects.
          const asStringArray = (items) => (
            Array.isArray(items)
              ? items.filter(b => b != null).map(b => typeof b === 'string' ? b : (b.value || b.text || String(b)))
              : []
          )
          const sanitized = {
            ...data,
            summary: typeof data?.summary === 'string' ? data.summary : 'No summary available.',
            threat_level: typeof data?.threat_level === 'string' ? data.threat_level : 'unknown',
            risk_score: typeof data?.risk_score === 'number' ? data.risk_score : 0,
            status: data?.status,
            key_behaviors: asStringArray(data?.key_behaviors),
            suspicious_methods: Array.isArray(data?.suspicious_methods)
              ? data.suspicious_methods.filter(m => m != null)
              : [],
            c2_indicators: asStringArray(data?.c2_indicators),
            recommended_focus: Array.isArray(data?.recommended_focus)
              ? data.recommended_focus.filter(r => typeof r === 'string').map(r => r)
              : [],
          }
          setSummary(sanitized)
        }
      } catch (err) {
        if (!cancelled) setError(err.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    fetchSummary()
    return () => { cancelled = true }
  }, [sampleId, apiUrl])

  if (loading) {
    return (
      <div className="tab-panel" style={{ textAlign: 'center', padding: '40px' }}>
        <div className="analysis-loading-spinner" />
        <p style={{ marginTop: '12px', color: 'var(--text-muted)' }}>
          Generating LLM threat assessment from dissection data...
        </p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="tab-panel" style={{ textAlign: 'center', padding: '40px', color: 'var(--accent-rose)' }}>
        <p>Failed to load dissection summary: {error}</p>
        <button
          className="filter-button filter-cyan"
          style={{ marginTop: '12px' }}
          onClick={() => { setError(null); setLoading(true); /* re-trigger effect */ }}
        >
          Retry
        </button>
      </div>
    )
  }

  if (!summary || summary.status === 'fallback') {
    return (
      <div className="tab-panel" style={{ textAlign: 'center', padding: '42px', color: 'var(--text-muted)' }}>
        <p>{summary?.summary || 'No dissection summary available.'}</p>
      </div>
    )
  }

  const threatColors = {
    critical: 'var(--accent-rose)',
    high: '#f97316',
    medium: 'var(--accent-amber)',
    low: 'var(--accent-emerald)',
    unknown: 'var(--text-muted)',
  }
  const threatColor = threatColors[summary.threat_level] || threatColors.unknown

  return (
    <div className="tab-panel">
      {/* Threat Level Badge + Risk Score */}
      <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
        <div style={{
          padding: '8px 20px',
          borderRadius: '8px',
          backgroundColor: threatColor,
          color: '#fff',
          fontWeight: 700,
          fontSize: '14px',
          textTransform: 'uppercase',
          letterSpacing: '0.5px',
        }}>
          {summary.threat_level}
        </div>
        <div>
          <span style={{ color: 'var(--text-muted)', fontSize: '13px' }}>Risk Score: </span>
          <span style={{ fontWeight: 600, fontSize: '18px' }}>{summary.risk_score}/100</span>
        </div>
      </div>

      {/* Summary Narrative */}
      <div className="card">
        <h3>Threat Assessment</h3>
        <p style={{ lineHeight: '1.7', color: 'var(--text-secondary)' }}>
          {summary.summary}
        </p>
      </div>

      {/* Key Behaviors */}
      {summary.key_behaviors?.length > 0 && (
        <div className="card">
          <h3>Key Behaviors ({summary.key_behaviors.length})</h3>
          <ul style={{ paddingLeft: '20px' }}>
            {summary.key_behaviors.map((b, i) => (
              <li key={i} style={{ marginBottom: '8px', lineHeight: '1.5' }}>
                {b}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Suspicious Methods */}
      {summary.suspicious_methods?.length > 0 && (
        <div className="card">
          <h3>Suspicious Methods ({summary.suspicious_methods.length})</h3>
          <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
            {summary.suspicious_methods.slice(0, 15).map((m, i) => (
              <div
                key={i}
                style={{
                  padding: '10px 12px',
                  marginBottom: '6px',
                  backgroundColor: 'var(--bg-tertiary)',
                  borderLeft: '3px solid var(--accent-rose)',
                  borderRadius: '4px',
                  fontSize: '13px',
                  fontFamily: 'monospace',
                }}
              >
                <div style={{ fontWeight: 500 }}>
                  {typeof m === 'string'
                    ? m
                    : `${m.class || '?'}.${m.method || m.name || '?'}`}
                </div>
                {typeof m === 'object' && m && typeof m.reason === 'string' && (
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                    {m.reason}
                  </div>
                )}
              </div>
            ))}
          </div>
          {summary.suspicious_methods.length > 15 && (
            <p style={{ marginTop: '8px', color: 'var(--text-muted)' }}>
              … and {summary.suspicious_methods.length - 15} more
            </p>
          )}
        </div>
      )}

      {/* C2 Indicators */}
      {summary.c2_indicators?.length > 0 && (
        <div className="card">
          <h3>C2 Indicators ({summary.c2_indicators.length})</h3>
          <ul style={{ paddingLeft: '20px' }}>
            {summary.c2_indicators.map((c, i) => (
              <li key={i} style={{
                marginBottom: '6px',
                fontFamily: 'monospace',
                fontSize: '13px',
                color: 'var(--accent-rose)',
              }}>
                {typeof c === 'string' ? c : String(c)}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Recommended Focus */}
      {summary.recommended_focus?.length > 0 && (
        <div className="card">
          <h3>Recommended Focus</h3>
          <ul style={{ paddingLeft: '20px' }}>
            {summary.recommended_focus.map((r, i) => (
              <li key={i} style={{ marginBottom: '6px', lineHeight: '1.5' }}>
                {typeof r === 'string' ? r : String(r)}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
})

DissectionSummaryTab.displayName = 'DissectionSummaryTab'

/**
 * Human-readable label for chain step types.
 */
const STEP_TYPE_LABELS = {
  encoded_string: 'Encoded String',
  decoding_function: 'Decoding Function',
  decoded_artifact: 'Decoded Payload',
  usage: 'Usage Site',
  c2_infrastructure: 'C2 Endpoint',
}

const STEP_TYPE_ICONS = {
  encoded_string: '🔒',
  decoding_function: '⚙️',
  decoded_artifact: '🔓',
  usage: '📍',
  c2_infrastructure: '🌐',
}

const SEVERITY_META = {
  critical: { badge: 'rose', icon: '🚨', description: 'High-confidence chain to confirmed public C2.' },
  high: { badge: 'rose', icon: '🔴', description: 'Strong indicators of malicious infrastructure.' },
  medium: { badge: 'amber', icon: '🟡', description: 'Moderate indicators — may be benign or partial chain.' },
  low: { badge: 'emerald', icon: '🟢', description: 'Weak indicators — likely benign or incomplete.' },
}

const CHAIN_THREAT_TYPE_LABELS = {
  c2_communication: 'C2 Communication',
  data_exfiltration: 'Data Exfiltration',
  payload_delivery: 'Payload Delivery',
  command_execution: 'Command Execution',
  benign: 'Benign',
  unknown: 'Unknown',
}

const CHAIN_THREAT_TYPE_COLORS = {
  c2_communication: 'rose',
  data_exfiltration: 'rose',
  payload_delivery: 'amber',
  command_execution: 'rose',
  benign: 'emerald',
  unknown: 'slate',
}

/**
 * Individual Chain Card with on-demand LLM explanation.
 */
const STEP_DESCRIPTIONS = {
  encoded_string: 'The original obfuscated or encoded string as found in the APK bytecode or resources.',
  decoding_function: 'The Java/Kotlin method or library responsible for decoding the encoded string.',
  decoded_artifact: 'The result after decoding — often a URL, domain, IP, or command payload.',
  usage: 'Where the decoded artifact is consumed — typically a network call or intent.',
  c2_infrastructure: 'The command-and-control server or endpoint contacted by the decoded payload.',
}

function ChainCard({ chain, sampleId, apiUrl }) {
  const [expanded, setExpanded] = useState(false)
  const [selectedStep, setSelectedStep] = useState(null)
  const [llmResult, setLlmResult] = useState(null)
  const [llmLoading, setLlmLoading] = useState(false)
  const sevMeta = SEVERITY_META[chain.severity] || SEVERITY_META.medium

  // Fetch LLM explanation when first expanded
  useEffect(() => {
    if (!expanded || llmResult || llmLoading || !sampleId || !apiUrl) return
    setLlmLoading(true) // eslint-disable-line react-hooks/set-state-in-effect
    fetch(`${apiUrl}/api/sample/${sampleId}/explain-chain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chain }),
    })
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data?.llm) setLlmResult(data.llm) })
      .catch(() => { })
      .finally(() => setLlmLoading(false))
  }, [expanded, llmResult, llmLoading, sampleId, apiUrl, chain])

  const threatType = llmResult?.threat_type
  const threatLabel = CHAIN_THREAT_TYPE_LABELS[threatType]
  const threatColor = CHAIN_THREAT_TYPE_COLORS[threatType] || 'slate'

  return (
    <div className={`card chain-card chain-severity-${chain.severity}`}>
      {/* Clickable header */}
      <div
        className="chain-header"
        onClick={() => setExpanded(v => !v)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setExpanded(v => !v) }}
      >
        <div className="chain-header-left">
          <span className="chain-expand">{expanded ? '▾' : '▸'}</span>
          <h4>{chain.chain_id.replace('chain_', 'Chain #')}</h4>
        </div>
        <div className="chain-header-right">
          <span className="chain-step-count">{chain.steps?.length || 0} steps</span>
          <span className={`badge badge-${sevMeta.badge}`}>{sevMeta.icon} {chain.severity.toUpperCase()}</span>
          <span className="chain-confidence-badge">{Math.round(chain.confidence * 100)}%</span>
        </div>
      </div>

      {/* Expanded body */}
      {expanded && (
        <div className="chain-body">
          <p className="chain-severity-desc">{sevMeta.description}</p>

          {/* Step flow visualization */}
          <div className="chain-steps">
            {(chain.steps || []).map((step, idx) => {
              const isSelected = selectedStep === idx
              return (
                <div key={idx} className={`chain-step ${isSelected ? 'chain-step-selected' : ''}`}>
                  <div className="chain-step-number">
                    {step.step || idx + 1}
                  </div>
                  <div
                    className="chain-step-content chain-step-clickable"
                    onClick={() => setSelectedStep(isSelected ? null : idx)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setSelectedStep(isSelected ? null : idx) }}
                  >
                    <div className="chain-step-header">
                      <span className="chain-step-icon">{STEP_TYPE_ICONS[step.type] || '❓'}</span>
                      <span className="chain-step-type">
                        {STEP_TYPE_LABELS[step.type] || step.type}
                      </span>
                      <span className="chain-step-expand-hint">{isSelected ? '▾' : '▸'}</span>
                    </div>
                    <div className="chain-step-artifact">
                      {step.artifact || '—'}
                    </div>

                    {/* Detail panel — shown when step is selected */}
                    {isSelected && (
                      <div className="chain-step-detail">
                        <p className="chain-step-description">
                          {STEP_DESCRIPTIONS[step.type] || 'Step in the threat chain.'}
                        </p>

                        <div className="chain-step-detail-grid">
                          <div className="chain-step-detail-row">
                            <span className="detail-label">Artifact Content</span>
                            <span className="detail-value detail-artifact">
                              {step.artifact || '—'}
                            </span>
                          </div>
                          {step.source_location && (
                            <div className="chain-step-detail-row">
                              <span className="detail-label">Source</span>
                              <span className="detail-value detail-source">
                                {step.source_location}
                              </span>
                            </div>
                          )}
                          {step.confidence !== undefined && (
                            <div className="chain-step-detail-row">
                              <span className="detail-label">Confidence</span>
                              <span className="detail-value">
                                <span className="confidence-bar-wrapper">
                                  <span
                                    className="confidence-bar-fill"
                                    style={{ width: `${Math.round(step.confidence * 100)}%` }}
                                  />
                                </span>
                                {Math.round(step.confidence * 100)}%
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {!isSelected && step.source_location && (
                      <div className="chain-step-source">
                        📄 {step.source_location}
                      </div>
                    )}
                    {!isSelected && step.confidence !== undefined && (
                      <div className="chain-step-confidence">
                        Confidence: {Math.round(step.confidence * 100)}%
                      </div>
                    )}
                  </div>
                  {idx < (chain.steps?.length || 0) - 1 && (
                    <div className="chain-step-connector" />
                  )}
                </div>
              )
            })}
          </div>

          {/* LLM explanation section */}
          <div className="chain-llm-section">
            {llmLoading ? (
              <div className="llm-shimmer">
                <div className="shimmer-bar shimmer-bar-long" />
                <div className="shimmer-bar shimmer-bar-medium" />
              </div>
            ) : llmResult ? (
              <div className="llm-result">
                <div className="llm-result-header">
                  <span className="llm-icon">🧠</span>
                  <span className="llm-label">AI Analysis</span>
                  {threatLabel && (
                    <span className={`badge badge-${threatColor}`} style={{ fontSize: '0.7rem', padding: '0.15rem 0.4rem' }}>
                      {threatLabel}
                    </span>
                  )}
                  {llmResult.confidence != null && (
                    <span className="llm-confidence">
                      {Math.round(llmResult.confidence * 100)}% confidence
                    </span>
                  )}
                </div>
                <p className="llm-summary-text">{llmResult.summary}</p>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  )
}

/**
 * Severity ordering for sort-by-severity.
 */
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }

const SORT_OPTIONS = [
  { id: 'severity', label: 'Severity' },
  { id: 'confidence', label: 'Confidence' },
  { id: 'steps', label: 'Step Count' },
]

/**
 * Threat Chains Tab
 */
const ChainsTab = memo(({ result, apiUrl, sampleId }) => {
  const chains = useMemo(() => result?.threat_chains || [], [result?.threat_chains])
  const [filterSeverity, setFilterSeverity] = useState('all')
  const [sortBy, setSortBy] = useState('severity')

  // Summary stats
  const severityCounts = chains.reduce((acc, c) => {
    acc[c.severity] = (acc[c.severity] || 0) + 1
    return acc
  }, {})
  const avgConfidence = chains.length > 0
    ? Math.round((chains.reduce((s, c) => s + c.confidence, 0) / chains.length) * 100)
    : 0

  // Filtered + sorted chains
  const visibleChains = useMemo(() => {
    let list = chains
    if (filterSeverity !== 'all') {
      list = list.filter(c => c.severity === filterSeverity)
    }
    list = [...list].sort((a, b) => {
      if (sortBy === 'severity') {
        return (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4)
      }
      if (sortBy === 'confidence') {
        return b.confidence - a.confidence
      }
      // sortBy === 'steps'
      return (b.steps?.length || 0) - (a.steps?.length || 0)
    })
    return list
  }, [chains, filterSeverity, sortBy])

  if (chains.length === 0) {
    return (
      <div className="tab-panel">
        <div className="card chains-explainer">
          <h3>⛓️ What Are Threat Chains?</h3>
          <p>
            Threat chains are <strong>directed evidence links</strong> that trace how an obfuscated string
            flows through the APK — from its encoded form, through decoding logic, to the final
            command-and-control (C2) endpoint it reveals.
          </p>
          <p>
            Each chain represents a single "attack path": an encoded string is identified in Step 3,
            decoded in Step 4, and correlated with C2 infrastructure in Step 5. Chains with higher
            confidence scores indicate that multiple independent indicators agree on the same malicious
            behavior.
          </p>
          <p className="chains-explainer-note">
            No threat chains were detected in this sample. This may mean the APK does not use
            obfuscated C2 communication, or the decoded payloads did not match known infrastructure.
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="tab-panel">
      {/* Explanation card */}
      <div className="card chains-explainer">
        <h3>⛓️ What Are Threat Chains?</h3>
        <p>
          Threat chains are <strong>directed evidence links</strong> that trace how an obfuscated string
          flows through the APK — from its encoded form, through decoding logic, to the final
          command-and-control (C2) endpoint it reveals.
        </p>
        <p>
          Each chain has up to 5 steps: <strong>Encoded String</strong> → <strong>Decoding Function</strong> →
          <strong>Decoded Payload</strong> → <strong>Usage Site</strong> → <strong>C2 Endpoint</strong>. Chains
          with higher confidence scores indicate that multiple independent indicators agree on the same
          malicious behavior.
        </p>
      </div>

      {/* Summary stats */}
      <div className="chains-summary">
        <div className="chains-summary-stat">
          <span className="chains-summary-value">{chains.length}</span>
          <span className="chains-summary-label">Total Chains</span>
        </div>
        <div className="chains-summary-stat">
          <span className="chains-summary-value">{avgConfidence}%</span>
          <span className="chains-summary-label">Avg Confidence</span>
        </div>
        {severityCounts.critical > 0 && (
          <div className="chains-summary-stat chains-summary-critical">
            <span className="chains-summary-value">{severityCounts.critical}</span>
            <span className="chains-summary-label">Critical</span>
          </div>
        )}
        {severityCounts.high > 0 && (
          <div className="chains-summary-stat chains-summary-high">
            <span className="chains-summary-value">{severityCounts.high}</span>
            <span className="chains-summary-label">High</span>
          </div>
        )}
        {severityCounts.medium > 0 && (
          <div className="chains-summary-stat chains-summary-medium">
            <span className="chains-summary-value">{severityCounts.medium}</span>
            <span className="chains-summary-label">Medium</span>
          </div>
        )}
        {severityCounts.low > 0 && (
          <div className="chains-summary-stat chains-summary-low">
            <span className="chains-summary-value">{severityCounts.low}</span>
            <span className="chains-summary-label">Low</span>
          </div>
        )}
      </div>

      {/* Filter / Sort toolbar */}
      <div className="chains-toolbar">
        <div className="chains-toolbar-filters">
          <span className="chains-toolbar-label">Filter</span>
          <button
            className={`chains-filter-btn ${filterSeverity === 'all' ? 'active' : ''}`}
            onClick={() => setFilterSeverity('all')}
          >
            All ({chains.length})
          </button>
          {['critical', 'high', 'medium', 'low'].filter(sev => severityCounts[sev] > 0).map(sev => (
            <button
              key={sev}
              className={`chains-filter-btn chains-filter-${sev} ${filterSeverity === sev ? 'active' : ''}`}
              onClick={() => setFilterSeverity(filterSeverity === sev ? 'all' : sev)}
            >
              {SEVERITY_META[sev]?.icon || '❓'} {sev.charAt(0).toUpperCase() + sev.slice(1)} ({severityCounts[sev]})
            </button>
          ))}
        </div>
        <div className="chains-toolbar-sort">
          <span className="chains-toolbar-label">Sort</span>
          <select
            className="chains-sort-select"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
          >
            {SORT_OPTIONS.map(opt => (
              <option key={opt.id} value={opt.id}>{opt.label}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Results count when filtered */}
      {filterSeverity !== 'all' && (
        <p className="chains-filter-count">
          Showing {visibleChains.length} of {chains.length} chains
        </p>
      )}

      {/* Chain list */}
      <div className="chains-list">
        {visibleChains.length === 0 ? (
          <p className="chains-empty-filter">No chains match the current filter.</p>
        ) : (
          visibleChains.map(chain => (
            <ChainCard
              key={chain.chain_id}
              chain={chain}
              sampleId={sampleId}
              apiUrl={apiUrl}
            />
          ))
        )}
      </div>
    </div>
  )
})

ChainsTab.displayName = 'ChainsTab'

const MAX_RETRIES = 3
const RETRY_BASE_MS = 2000

const ERROR_MESSAGES = {
  timeout: 'Analysis timed out. The APK may be very large or complex.',
  malformed: 'The APK file appears to be corrupted or invalid.',
  disk_space: 'Server ran out of disk space. Contact administrators.',
  not_found: 'APK file not found on the server.',
  network: 'Network error. Check your connection and try again.',
  internal_error: 'An unexpected server error occurred.',
  pipeline_error: 'Analysis pipeline failed. Contact administrators.',
}

function useRetryState() {
  const [retryCount, setRetryCount] = useState(0)
  const [isRetrying, setIsRetrying] = useState(false)
  const [countdown, setCountdown] = useState(0)

  const scheduleRetry = useCallback((onRetry) => {
    if (retryCount >= MAX_RETRIES) return
    setIsRetrying(true)

    const delay = RETRY_BASE_MS * Math.pow(2, retryCount)
    const seconds = Math.ceil(delay / 1000)
    setCountdown(seconds)

    const interval = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(interval)
          return 0
        }
        return prev - 1
      })
    }, 1000)

    setTimeout(() => {
      clearInterval(interval)
      setIsRetrying(false)
      setCountdown(0)
      setRetryCount((c) => c + 1)
      if (onRetry) onRetry()
    }, delay)
  }, [retryCount])

  const reset = useCallback(() => {
    setRetryCount(0)
    setIsRetrying(false)
    setCountdown(0)
  }, [])

  return { retryCount, isRetrying, countdown, scheduleRetry, reset }
}

function ErrorState({ analysisState, onRetry }) {
  const { retryCount, isRetrying, countdown, scheduleRetry } = useRetryState()

  const errorType = analysisState.errorType || 'internal_error'
  const errorMessage = analysisState.error || ERROR_MESSAGES[errorType] || 'Unknown error'
  const isRetryable = retryCount < MAX_RETRIES && errorType !== 'malformed' && errorType !== 'disk_space'

  const handleRetry = () => {
    scheduleRetry(() => {
      if (onRetry) onRetry()
    })
  }

  return (
    <div className="analysis-error">
      <h2>Analysis Failed</h2>
      <p>{errorMessage}</p>

      {isRetrying && (
        <div className="retry-loading">
          <div className="retry-spinner" />
          <p className="retry-countdown">Retrying in {countdown}s... (Attempt {retryCount + 1}/{MAX_RETRIES})</p>
        </div>
      )}

      {!isRetrying && isRetryable && (
        <div className="retry-actions">
          <p className="retry-attempt-info">Attempt {retryCount + 1} of {MAX_RETRIES}</p>
          <button className="retry-button" onClick={handleRetry}>
            Retry Analysis
          </button>
        </div>
      )}

      {!isRetryable && !isRetrying && (
        <div className="retry-exhausted">
          <p>Maximum retries reached. Please contact support.</p>
          <a className="retry-support-link" href="mailto:support@droidforenix.local">
            Contact Support
          </a>
        </div>
      )}
    </div>
  )
}

/**
 * Main AnalysisView Component
 */
function AnalysisView({ sample, analysisState, apiUrl, onRetry }) {
  const isAnalyzing = analysisState.status === 'running'
  const isComplete = analysisState.status === 'complete'
  const hasError = analysisState.status === 'error'

  if (hasError) {
    return <ErrorState analysisState={analysisState} onRetry={onRetry} />
  }

  if (isAnalyzing) {
    return <LoadingState analysisState={analysisState} />
  }

  if (isComplete) {
    return <ResultView analysisState={analysisState} apiUrl={apiUrl} sample={sample} />
  }

  return (
    <div className="analysis-idle">
      <p>Upload an APK to begin analysis.</p>
    </div>
  )
}

const SEVERITY_CONFIG = {
  critical: { color: 'var(--accent-rose)', badge: 'rose', order: 0 },
  high: { color: 'var(--accent-rose)', badge: 'rose', order: 1 },
  medium: { color: 'var(--accent-amber)', badge: 'amber', order: 2 },
  low: { color: 'var(--accent-emerald)', badge: 'emerald', order: 3 },
}

function SevBadge({ severity }) {
  const cfg = SEVERITY_CONFIG[severity] || { color: 'var(--text-muted)', badge: 'slate' }
  return <span style={{
    padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700,
    background: cfg.color + '22', color: cfg.color, textTransform: 'uppercase',
  }}>{severity}</span>
}

const SecretsTab = memo(({ result }) => {
  const secrets = result?.hardcoded_secrets || []
  const risk = result?.secret_risk || {}
  const bySev = risk?.by_severity || {}
  const total = (bySev.critical || 0) + (bySev.high || 0) + (bySev.medium || 0) + (bySev.low || 0)

  if (!secrets.length) {
    return (
      <div className="tab-panel">
        <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
          <p style={{ color: 'var(--text-muted)' }}>No hardcoded secrets detected.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="tab-panel">
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap', marginBottom: 16, padding: 16, background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)' }}>
        <div>
          <small style={{ fontFamily: 'JetBrains Mono', fontSize: 10, letterSpacing: '.08em', color: 'var(--text-muted)' }}>EXPOSED SECRET POSTURE</small>
          <strong style={{ display: 'block', fontSize: 20, color: 'var(--text-primary)' }}>{total} findings</strong>
        </div>
        <div style={{ display: 'flex', gap: 12, marginLeft: 'auto' }}>
          {['critical', 'high', 'medium'].map(s => (
            <div key={s} style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 18, fontWeight: 800, color: SEVERITY_CONFIG[s].color }}>{bySev[s] || 0}</div>
              <small style={{ fontFamily: 'JetBrains Mono', fontSize: 9, textTransform: 'uppercase', color: 'var(--text-muted)' }}>{s}</small>
            </div>
          ))}
        </div>
        <div style={{ textAlign: 'right' }}>
          <small style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--text-muted)' }}>SECRETS RISK</small>
          <strong style={{ display: 'block', fontSize: 22, color: risk.risk_score > 60 ? 'var(--accent-rose)' : 'var(--accent-amber)' }}>{risk.risk_score || 0}</strong>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 4, marginBottom: 16, height: 8 }}>
        {['critical', 'high', 'medium', 'low'].map(s => {
          const cfg = SEVERITY_CONFIG[s]
          const count = bySev[s] || 0
          return count > 0 ? (
            <div key={s} style={{ flex: count, height: 8, borderRadius: 4, background: cfg.color, opacity: 0.7 }} />
          ) : null
        })}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: 12 }}>
        {secrets.sort((a, b) => (SEVERITY_CONFIG[a.severity]?.order ?? 9) - (SEVERITY_CONFIG[b.severity]?.order ?? 9)).map((s, i) => {
          const cfg = SEVERITY_CONFIG[s.severity] || { color: 'var(--text-muted)' }
          const loc = s.source || s.source_file || '?'
          return (
            <article key={i} style={{
              padding: 14, background: 'var(--bg-surface)', border: '1px solid var(--border-color)',
              borderTop: `3px solid ${cfg.color}`, borderRadius: 'var(--radius-md)',
              display: 'flex', flexDirection: 'column', gap: 8,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <SevBadge severity={s.severity} />
                <strong style={{ fontSize: 13 }}>{s.secret_type}</strong>
              </div>
              <p style={{ margin: 0, fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--accent-cyan)', wordBreak: 'break-all' }}>{s.value}</p>
              {s.decoded && (
                <p style={{ margin: 0, fontSize: 12, color: 'var(--accent-emerald)' }}>✓ {s.decoded}</p>
              )}
              <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {loc}{s.occurrence_count > 1 ? ` · ${s.occurrence_count} occurrences` : ''}
              </div>
            </article>
          )
        })}
      </div>
    </div>
  )
})

SecretsTab.displayName = 'SecretsTab'

export default memo(AnalysisView)