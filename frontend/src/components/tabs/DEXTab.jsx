import { useState, useEffect } from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts'

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

  const entropy = typeof data.entropy === 'number' ? data.entropy : null
  const entropyColor = entropy > 7 ? '#f43f5e' : entropy > 5 ? '#f59e0b' : '#10b981'
  const entropyPie = entropy !== null ? [
    { name: 'Entropy', value: entropy },
    { name: 'Remaining', value: 8 - entropy },
  ] : []

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

      {entropy !== null && (
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
            DEX Entropy
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
            <div style={{ width: 100, height: 100 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={entropyPie}
                    cx="50%" cy="50%"
                    innerRadius={30}
                    outerRadius={45}
                    startAngle={180}
                    endAngle={0}
                    dataKey="value"
                  >
                    {entropyPie.map((entry, idx) => (
                      <Cell key={idx} fill={idx === 0 ? entropyColor : 'rgba(148,163,184,0.1)'} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div>
              <div style={{ fontSize: 28, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace", color: entropyColor }}>
                {entropy.toFixed(2)}
              </div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                Shannon entropy of DEX contents
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                {entropy > 7 ? 'High entropy — possible packing/obfuscation' :
                 entropy > 5 ? 'Moderate entropy' : 'Normal entropy range'}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
