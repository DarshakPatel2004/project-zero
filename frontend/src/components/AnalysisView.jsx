import { useState, useEffect, useMemo, useCallback, memo } from 'react'
import './AnalysisView.css'

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
          { id: 'dissection', label: 'Code Dissection' },
          { id: 'obfuscation', label: 'Obfuscation' },
          { id: 'c2', label: 'C2 Infrastructure' },
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
        {activeResultTab === 'dissection' && (
          <DissectionTab result={fullResult} apiUrl={apiUrl} />
        )}
        {activeResultTab === 'obfuscation' && (
          <ObfuscationTab result={fullResult} />
        )}
        {activeResultTab === 'c2' && (
          <C2Tab result={fullResult} />
        )}
        {activeResultTab === 'chains' && (
          <ChainsTab result={fullResult} />
        )}
        {activeResultTab === 'manifest' && (
          <ManifestTab result={fullResult} />
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
 * Code Dissection Tab: Placeholder for now
 */
const DissectionTab = memo(({ result, apiUrl }) => (
  <div className="tab-panel">
    <p>Code Dissection (advanced tab — will implement virtualization separately)</p>
  </div>
))

DissectionTab.displayName = 'DissectionTab'

/**
 * Obfuscation Tab
 */
const ObfuscationTab = memo(({ result }) => {
  const obf = result?.obfuscation_analysis || {}
  return (
    <div className="tab-panel">
      <div className="card">
        <h3>Obfuscation Analysis</h3>
        <div className="metric">
          <span>Score</span>
          <span className="metric-value">{obf.obfuscation_score || 0}/100</span>
        </div>
        <div className="metric">
          <span>Level</span>
          <span className="badge badge-amber">{(obf.obfuscation_level || 'unknown').toUpperCase()}</span>
        </div>
      </div>

      {obf.indicators && Object.keys(obf.indicators).length > 0 && (
        <div className="card">
          <h4>Detected Techniques</h4>
          <ul>
            {Object.entries(obf.indicators).map(([technique, present]) => (
              present && <li key={technique}>{technique}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
})

ObfuscationTab.displayName = 'ObfuscationTab'

/**
 * C2 Infrastructure Tab
 */
const C2Tab = memo(({ result }) => {
  const c2s = result?.c2_infrastructure || []
  return (
    <div className="tab-panel">
      {c2s.length === 0 ? (
        <p>No C2 infrastructure detected.</p>
      ) : (
        <div className="c2-grid">
          {c2s.map(c2 => (
            <div key={c2.c2_id} className="card c2-card">
              <h4>{c2.domain || c2.ip || 'Unknown'}</h4>
              <div className="c2-details">
                <p><strong>Protocol:</strong> {c2.protocol}</p>
                <p><strong>Port:</strong> {c2.port || '—'}</p>
                <p><strong>Type:</strong> {c2.communication_type}</p>
                <p><strong>Confidence:</strong> {Math.round(c2.confidence * 100)}%</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
})

C2Tab.displayName = 'C2Tab'

/**
 * Threat Chains Tab
 */
const ChainsTab = memo(({ result }) => {
  const chains = result?.threat_chains || []
  return (
    <div className="tab-panel">
      {chains.length === 0 ? (
        <p>No threat chains detected.</p>
      ) : (
        <div className="chains-list">
          {chains.slice(0, 5).map(chain => (
            <div key={chain.chain_id} className="card chain-card">
              <h4>Chain {chain.chain_id}</h4>
              <p className="chain-severity">Severity: <span className={`badge badge-${chain.severity === 'high' ? 'rose' : chain.severity === 'medium' ? 'amber' : 'emerald'}`}>{chain.severity.toUpperCase()}</span></p>
              <p className="chain-confidence">Confidence: {Math.round(chain.confidence * 100)}%</p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
})

ChainsTab.displayName = 'ChainsTab'

/**
 * Manifest Tab
 */
const ManifestTab = memo(({ result }) => {
  const manifest = result?.manifest || {}
  const perms = manifest.uses_permissions || []
  return (
    <div className="tab-panel">
      <div className="card">
        <h3>App Details</h3>
        <p><strong>Version:</strong> {manifest.version_name} ({manifest.version_code})</p>
        <p><strong>Min SDK:</strong> {manifest.min_sdk_version}</p>
        <p><strong>Target SDK:</strong> {manifest.target_sdk_version}</p>
      </div>

      <div className="card">
        <h3>Permissions ({perms.length})</h3>
        <div className="permissions-cloud">
          {perms.map(perm => (
            <span
              key={perm}
              className={`permission-badge ${perm.includes('DANGEROUS') ? 'dangerous' : ''}`}
            >
              {perm}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
})

ManifestTab.displayName = 'ManifestTab'

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
