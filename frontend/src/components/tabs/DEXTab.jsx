import { useState, useEffect } from 'react'

export default function DEXTab({ sampleId, apiUrl }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!sampleId) return
    fetch(`${apiUrl}/api/sample/${sampleId}/dissection/dex`)
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { setData(d.dex_stats); setLoading(false) })
      .catch(() => setLoading(false))
  }, [sampleId, apiUrl])

  if (loading) return <div className="empty-state">Loading DEX data...</div>
  if (!data) return <div className="empty-state">No DEX data available</div>

  const rows = [
    { label: 'DEX Files', value: data.dex_count ?? 'N/A' },
    { label: 'Total Classes', value: data.total_classes ?? 'N/A' },
    { label: 'Total Methods', value: data.total_methods ?? 'N/A' },
    { label: 'Total Strings', value: data.total_strings ?? 'N/A' },
    { label: 'Total Bytes', value: data.total_bytes ?? 'N/A' },
    { label: 'Is Multidex', value: data.is_multidex !== undefined ? (data.is_multidex ? 'Yes' : 'No') : 'N/A' },
  ]

  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 20 }}>
        {rows.map((r, i) => (
          <div key={i} className="card" style={{ padding: '14px 16px', textAlign: 'center' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>{r.label}</div>
            <div style={{ fontSize: 22, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>
              {r.value}
            </div>
          </div>
        ))}
      </div>

      {typeof data.entropy === 'number' && (
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
            DEX Entropy
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <div style={{
              width: 60, height: 60, borderRadius: '50%', display: 'flex',
              alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: 18,
              fontFamily: "'JetBrains Mono', monospace",
              background: data.entropy > 7 ? 'rgba(244,63,94,0.15)' : data.entropy > 5 ? 'rgba(245,158,11,0.15)' : 'rgba(16,185,129,0.15)',
              color: data.entropy > 7 ? 'var(--accent-rose)' : data.entropy > 5 ? 'var(--accent-amber)' : 'var(--accent-emerald)',
            }}>
              {data.entropy.toFixed(1)}
            </div>
            <div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                Shannon entropy of DEX contents
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                {data.entropy > 7 ? 'High entropy — possible packing/obfuscation' :
                 data.entropy > 5 ? 'Moderate entropy' : 'Normal entropy range'}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
