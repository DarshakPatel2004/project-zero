import { useState, useEffect, useMemo, useCallback, memo } from 'react'
import './AnalysisView.css'
import ObfuscationView from './ObfuscationView'
import ThreatIntelView from './ThreatIntelView'
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
          label="Strings"
          value={analysisState.metrics?.encoding_count || 0}
          icon="📝"
          color="var(--accent-cyan)"
        />
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

  // Fetch full result once analysis completes
  useEffect(() => {
    if (!sampleId) return

    const fetchResult = async () => {
      try {
        setLoading(true)
        const response = await fetch(`${apiUrl}/api/sample/${sampleId}`)
        if (!response.ok) throw new Error('Failed to fetch analysis result')
        const data = await response.json()
        setFullResult(data)
        setError(null)
      } catch (err) {
        console.error('Result fetch failed:', err)
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }

    fetchResult()
  }, [sampleId, apiUrl])

  if (loading) {
    return <div className="result-loading">Loading full analysis...</div>
  }

  if (error || !fullResult) {
    return <div className="result-error">Error: {error || 'No result available'}</div>
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
          { id: 'llm', label: 'LLM Summary' },
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
          <OverviewTab result={fullResult} verdict={verdict} />
        )}
        {activeResultTab === 'llm' && (
          <LLMSummaryTab result={fullResult} />
        )}
        {activeResultTab === 'obfuscation' && (
          <ObfuscationView sample={sample} apiUrl={apiUrl} />
        )}
        {activeResultTab === 'chains' && (
          <ChainsTab result={fullResult} sampleId={sampleId} apiUrl={apiUrl} />
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
const OverviewTab = memo(({ result, verdict }) => (
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
 * Threat Chain Step Artifact Badge colors by type
 */
const STEP_COLORS = {
  encoded_string: 'amber',
  decoding_function: 'violet',
  decoded_artifact: 'cyan',
  usage: 'emerald',
  c2_infrastructure: 'rose',
}

/**
 * Individual Chain Card with LLM explanation
 */
const ChainCard = memo(({ chain, apiUrl, sampleId }) => {
  const [expanded, setExpanded] = useState(false)
  const [annotation, setAnnotation] = useState(null)
  const [annotating, setAnnotating] = useState(false)

  const steps = chain.steps || []

  useEffect(() => {
    if (!expanded || annotation || annotating) return
    if (!sampleId || apiUrl === undefined || apiUrl === null) return

    setAnnotating(true)
    fetch(`${apiUrl}/api/sample/${sampleId}/explain-chain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chain }),
    })
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data) setAnnotation(data) })
      .catch(() => {})
      .finally(() => setAnnotating(false))
  }, [expanded])

  return (
    <div className="card chain-card">
      <div className="chain-header" onClick={() => setExpanded(!expanded)} style={{ cursor: 'pointer' }}>
        <div className="chain-header-left">
          <span className="chain-expand">{expanded ? '▼' : '▶'}</span>
          <h4>{chain.chain_id}</h4>
        </div>
        <div className="chain-header-right">
          <span className={`badge badge-${chain.severity === 'critical' || chain.severity === 'high' ? 'rose' : chain.severity === 'medium' ? 'amber' : 'emerald'}`}>
            {chain.severity.toUpperCase()}
          </span>
          <span className="badge badge-slate">{Math.round(chain.confidence * 100)}% confidence</span>
          <span className="badge badge-cyan">{steps.length} steps</span>
        </div>
      </div>

      {expanded && (
        <div className="chain-body">
          <div className="chain-steps">
            {steps.map((s, i) => (
              <div key={i} className="chain-step">
                <div className="chain-step-number">{s.step}</div>
                <div className="chain-step-content">
                  <div className="chain-step-header">
                    <span className="chain-step-type">{s.type}</span>
                    <span className={`badge badge-${STEP_COLORS[s.type] || 'slate'}`}>
                      {Math.round((s.confidence || 0) * 100)}%
                    </span>
                  </div>
                  <div className="chain-step-artifact text-mono">{s.artifact || '—'}</div>
                  <div className="chain-step-source">{s.source_location || ''}</div>
                </div>
              </div>
            ))}
          </div>

          <div className="chain-llm-section">
            {annotating ? (
              <div className="llm-shimmer">
                <div className="shimmer-bar shimmer-bar-long" />
                <div className="shimmer-bar shimmer-bar-medium" />
              </div>
            ) : annotation?.llm ? (
              <div className="llm-result">
                <div className="llm-result-header">
                  <span className="llm-icon">🧠</span>
                  <span className="llm-label">AI Chain Analysis</span>
                  {annotation.llm.threat_type && annotation.llm.threat_type !== 'unknown' && (
                    <span className={`badge badge-rose`}>
                      {annotation.llm.threat_type.replace(/_/g, ' ')}
                    </span>
                  )}
                  {annotation.llm.confidence != null && (
                    <span className="llm-confidence">
                      {Math.round(annotation.llm.confidence * 100)}% confidence
                    </span>
                  )}
                </div>
                <p className="llm-summary-text">{annotation.llm.summary}</p>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  )
})

ChainCard.displayName = 'ChainCard'

/**
 * Threat Chains Tab
 */
const ChainsTab = memo(({ result, sampleId, apiUrl }) => {
  const chains = result?.threat_chains || []
  return (
    <div className="tab-panel">
      {chains.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
          <p>No threat chains detected.</p>
        </div>
      ) : (
        <div className="chains-list">
          {chains.map(chain => (
            <ChainCard key={chain.chain_id} chain={chain} apiUrl={apiUrl} sampleId={sampleId} />
          ))}
        </div>
      )}
    </div>
  )
})

ChainsTab.displayName = 'ChainsTab'

/**
 * Main AnalysisView Component
 */
function AnalysisView({ sample, analysisState, apiUrl }) {
  const isAnalyzing = analysisState.status === 'running'
  const isComplete = analysisState.status === 'complete'
  const hasError = analysisState.status === 'error'

  if (hasError) {
    return (
      <div className="analysis-error">
        <h2>Analysis Failed</h2>
        <p>{analysisState.error}</p>
      </div>
    )
  }

  if (isAnalyzing) {
    return <LoadingState analysisState={analysisState} />
  }

  if (isComplete) {
    return <ResultView analysisState={analysisState} apiUrl={apiUrl} sample={sample} />
  }

  // Idle state (before analysis starts)
  return (
    <div className="analysis-idle">
      <p>Upload an APK to begin analysis.</p>
    </div>
  )
}

export default memo(AnalysisView)