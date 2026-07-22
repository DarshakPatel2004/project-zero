import { useState, useEffect } from 'react'
/* eslint-disable react-hooks/set-state-in-effect */
import ConfidenceBar from './ConfidenceBar'
import { fetchWithCache } from '../utils/fetchWithCache'

export default function AttributionEvidence({ sampleId, apiUrl }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!sampleId) return
    setLoading(true)
    fetchWithCache(`${apiUrl}/api/sample/${sampleId}/attribution`)
      .then(d => { setData(d); setLoading(false) })
      .catch(e => { setError(e); setLoading(false) })
  }, [sampleId, apiUrl])

  if (loading) return <div className="card" style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)' }}>Loading attribution evidence...</div>
  if (error) return <div className="card" style={{ padding: 24, color: 'var(--accent-rose)' }}>Failed to load: {error.message || error}</div>
  if (!data) return null

  const breakdown = data.confidence_breakdown || {}
  const rawSignals = data.supporting_signals
  const signals = Array.isArray(rawSignals) ? rawSignals : []
  const rawRelated = data.related_samples
  const related = Array.isArray(rawRelated) ? rawRelated : []

  const confidence = typeof data.confidence === 'number' ? data.confidence : 0
  const familyColor = confidence >= 0.9 ? 'var(--accent-emerald)'
    : confidence >= 0.7 ? 'var(--accent-cyan)'
    : confidence >= 0.5 ? 'var(--accent-amber)'
    : 'var(--accent-rose)'

  const dimensions = [
    { key: 'permissions_match', label: 'Permissions Match' },
    { key: 'c2_overlap', label: 'C2 Overlap' },
    { key: 'obfuscation_pattern', label: 'Obfuscation Pattern' },
    { key: 'code_similarity', label: 'Code Similarity' },
  ]

  return (
    <div className="card animate-fade-in">
      <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-color)' }}>
        <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 4 }}>
          MAFIA Attribution
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 8 }}>
          <span style={{ fontSize: 22, fontWeight: 700 }}>{data.family || 'Unknown'}</span>
          <span style={{
            padding: '3px 10px', borderRadius: 6, fontSize: 13, fontWeight: 600,
            background: `${familyColor}22`, color: familyColor,
          }}>
            {Math.round(confidence * 100)}% confidence
          </span>
        </div>
      </div>

      <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-color)' }}>
        <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 14 }}>
          Confidence Breakdown
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {dimensions.map(dim => (
            <ConfidenceBar
              key={dim.key}
              value={breakdown[dim.key] || 0}
              label={dim.label}
            />
          ))}
        </div>
      </div>

      {signals.length > 0 && (
        <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
            Supporting Signals
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {signals.map((signal, i) => (
              <div key={i} style={{
                display: 'flex', alignItems: 'center', gap: 8,
                fontSize: 13, color: 'var(--text-secondary)',
              }}>
                <span style={{ color: 'var(--accent-emerald)' }}>✓</span>
                {signal}
              </div>
            ))}
          </div>
        </div>
      )}

      {related.length > 0 && (
        <div style={{ padding: '16px 24px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
            Related Samples ({related.length})
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {related.map((rel, i) => {
              const sim = typeof rel?.similarity === 'number' ? rel.similarity : 0
              return (
              <div key={i} style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '8px 12px', borderRadius: 6,
                background: 'var(--bg-secondary)', fontSize: 13,
              }}>
                <span className="text-mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  {rel?.sample_id?.substring(0, 16) || 'unknown'}...
                </span>
                <span style={{
                  fontWeight: 600,
                  color: sim >= 0.9 ? 'var(--accent-emerald)'
                    : sim >= 0.7 ? 'var(--accent-cyan)'
                    : 'var(--text-muted)',
                }}>
                  {Math.round(sim * 100)}% similar
                </span>
              </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
