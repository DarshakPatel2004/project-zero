import { useState, useEffect } from 'react'
import ClassSourceViewer from '../ClassSourceViewer'
/* eslint-disable react-hooks/set-state-in-effect */

export default function CodeTab({ sampleId, apiUrl }) {
  const [classes, setClasses] = useState([])
  const [selectedClass, setSelectedClass] = useState(null)
  const [analysis, setAnalysis] = useState(null)
  const [analysisLoading, setAnalysisLoading] = useState(false)
  const [search, setSearch] = useState('')
  const [viewMode, setViewMode] = useState('analysis')

  useEffect(() => {
    if (!sampleId) return
    fetch(`${apiUrl}/api/sample/${sampleId}/dissection/classes?limit=200`)
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { setClasses(d.classes || []) })
      .catch(() => {})
  }, [sampleId, apiUrl])

  useEffect(() => {
    if (!selectedClass || !sampleId) return
    setAnalysisLoading(true)
    setAnalysis(null)
    fetch(`${apiUrl}/api/sample/${sampleId}/code-analysis/${encodeURIComponent(selectedClass)}`)
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { setAnalysis(d); setAnalysisLoading(false) })
      .catch(() => setAnalysisLoading(false))
  }, [selectedClass, sampleId, apiUrl])

  const filtered = classes.filter(c =>
    c.name.toLowerCase().includes(search.toLowerCase())
  )

  const riskColor = level =>
    level === 'CRITICAL' ? 'var(--accent-rose)'
    : level === 'HIGH' ? 'var(--accent-amber)'
    : level === 'MEDIUM' ? 'var(--accent-cyan)'
    : 'var(--accent-emerald)'

  const riskBadge = level =>
    level !== 'LOW' ? (
      <span className="badge" style={{
        background: `${riskColor(level)}22`, color: riskColor(level),
        fontSize: 9, marginLeft: 6,
      }}>{level}</span>
    ) : null

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 16, minHeight: 400 }}>
      <div className="card" style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
        <input
          placeholder="Search classes..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{
            width: '100%', padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border-color)',
            background: 'var(--bg-secondary)', color: 'var(--text-primary)', fontSize: 13,
            outline: 'none',
          }}
        />
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          {filtered.length} of {classes.length} classes
        </div>
        <div style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 2 }}>
          {filtered.map((cls, i) => (
            <button
              key={i}
              onClick={() => setSelectedClass(cls.name)}
              style={{
                textAlign: 'left', padding: '6px 10px', borderRadius: 4, border: 'none',
                fontSize: 12, cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace",
                background: selectedClass === cls.name ? 'var(--accent-cyan-soft)' : 'transparent',
                color: selectedClass === cls.name ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
              }}
            >
              {cls.name.split('.').pop()}
              {cls.method_count > 0 && (
                <span style={{ marginLeft: 6, fontSize: 10, color: 'var(--text-muted)' }}>
                  ({cls.method_count}m)
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      <div className="card" style={{ padding: 16, overflow: 'auto' }}>
        {!selectedClass && (
          <div className="empty-state">Select a class to view code analysis</div>
        )}
        {selectedClass && (
          <div style={{ display: 'flex', gap: 6, marginBottom: 12 }}>
            <button
              onClick={() => setViewMode('analysis')}
              style={{
                padding: '4px 12px', borderRadius: 4, border: 'none', cursor: 'pointer',
                fontSize: 11, fontWeight: 600,
                background: viewMode === 'analysis' ? 'var(--accent-cyan)' : 'var(--bg-secondary)',
                color: viewMode === 'analysis' ? '#fff' : 'var(--text-secondary)',
              }}
            >Attack Flow</button>
            <button
              onClick={() => setViewMode('source')}
              style={{
                padding: '4px 12px', borderRadius: 4, border: 'none', cursor: 'pointer',
                fontSize: 11, fontWeight: 600,
                background: viewMode === 'source' ? 'var(--accent-cyan)' : 'var(--bg-secondary)',
                color: viewMode === 'source' ? '#fff' : 'var(--text-secondary)',
              }}
            >Raw Source</button>
          </div>
        )}
        {viewMode === 'source' && selectedClass && (
          <ClassSourceViewer sampleId={sampleId} className={selectedClass} apiUrl={apiUrl} />
        )}
        {viewMode === 'analysis' && analysisLoading && (
          <div className="empty-state">Loading code analysis...</div>
        )}
        {viewMode === 'analysis' && analysis && (
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16, fontFamily: "'JetBrains Mono', monospace" }}>
              {analysis.class_name}
            </div>

            {analysis.attack_flow?.length > 0 && (
              <div style={{ marginBottom: 20 }}>
                <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
                  Attack Flow
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {analysis.attack_flow.map((step, i) => (
                    <div key={i} style={{
                      display: 'flex', alignItems: 'center', gap: 10,
                      padding: '8px 12px', borderRadius: 6,
                      background: step.risk_level === 'CRITICAL' ? 'rgba(244,63,94,0.08)'
                        : step.risk_level === 'HIGH' ? 'rgba(245,158,11,0.08)'
                        : 'var(--bg-secondary)',
                    }}>
                      <span style={{
                        width: 22, height: 22, borderRadius: '50%', display: 'flex',
                        alignItems: 'center', justifyContent: 'center', fontSize: 11,
                        fontWeight: 700, flexShrink: 0,
                        background: step.risk_level === 'CRITICAL' ? 'var(--accent-rose)'
                          : step.risk_level === 'HIGH' ? 'var(--accent-amber)'
                          : 'var(--text-muted)',
                        color: '#fff',
                      }}>{step.step}</span>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 13, fontWeight: 600, fontFamily: "'JetBrains Mono', monospace" }}>
                          {step.method}()
                          {riskBadge(step.risk_level)}
                        </div>
                        {step.description && step.description !== step.method && step.description !== `${step.method}()` && (
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{step.description}</div>
                        )}
                      </div>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace" }}>
                        L{step.line}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
              Methods ({analysis.methods?.length || 0})
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {analysis.methods?.map((m, i) => (
                <div key={i} className="card" style={{ padding: '10px 14px', background: 'var(--bg-secondary)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                    <div>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, fontWeight: 600 }}>
                        {m.name}()
                      </span>
                      {riskBadge(m.risk_level)}
                    </div>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace" }}>
                      L{m.start_line}–{m.end_line}
                    </span>
                  </div>

                  {m.techniques?.length > 0 && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 8 }}>
                      {m.techniques.map((t, j) => (
                        <span key={j} className="badge" style={{
                          background: 'rgba(245,158,11,0.1)', color: 'var(--accent-amber)',
                          fontSize: 10,
                        }}>{t.replace(/_/g, ' ')}</span>
                      ))}
                    </div>
                  )}

                  {m.suspicious_lines?.length > 0 && (
                    <div style={{ marginTop: 8, fontSize: 12 }}>
                      <div style={{ color: 'var(--accent-rose)', fontWeight: 600, marginBottom: 4 }}>
                        ⚠ {m.suspicious_lines.length} suspicious line{m.suspicious_lines.length > 1 ? 's' : ''}
                      </div>
                      {m.suspicious_lines.slice(0, 5).map((sl, j) => (
                        <div key={j} style={{
                          padding: '4px 8px', marginTop: 2, borderRadius: 4,
                          background: 'rgba(244,63,94,0.05)', fontSize: 12,
                          fontFamily: "'JetBrains Mono', monospace",
                          color: 'var(--text-secondary)',
                        }}>
                          <span style={{ color: 'var(--text-muted)' }}>L{sl.line}: </span>
                          {sl.code?.substring(0, 100)}
                        </div>
                      ))}
                    </div>
                  )}

                  {m.calls?.length > 0 && (
                    <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {m.calls.map((c, j) => (
                        <span key={j} className="badge neutral" style={{ fontSize: 10 }}>
                          → {c.target}()
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>

            {analysis.string_references && Object.keys(analysis.string_references).length > 0 && (
              <div style={{ marginTop: 20 }}>
                <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
                  String References
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {Object.entries(analysis.string_references).slice(0, 20).map(([str, refs], i) => (
                    <div key={i} style={{
                      padding: '6px 10px', borderRadius: 4, fontSize: 12,
                      background: 'var(--bg-secondary)',
                      fontFamily: "'JetBrains Mono', monospace",
                    }}>
                      <span style={{ color: 'var(--accent-amber)' }}>"{str.substring(0, 60)}"</span>
                      <span style={{ color: 'var(--text-muted)', marginLeft: 8 }}>
                        used in {refs.length} location{refs.length > 1 ? 's' : ''}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
