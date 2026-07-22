import { useState, useEffect } from 'react'

const PERM_RISK = {
  dangerous: { color: 'var(--accent-rose)', bg: 'rgba(244,63,94,0.1)' },
  signature: { color: 'var(--accent-amber)', bg: 'rgba(245,158,11,0.1)' },
  normal: { color: 'var(--accent-emerald)', bg: 'rgba(16,185,129,0.1)' },
}

export default function PermissionsTab({ sampleId, apiUrl }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')

  useEffect(() => {
    if (!sampleId) return
    fetch(`${apiUrl}/api/sample/${sampleId}/dissection/permissions`)
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { setData(d.permissions); setLoading(false) })
      .catch(() => setLoading(false))
  }, [sampleId, apiUrl])

  if (loading) return <div className="empty-state">Loading permissions...</div>
  if (!data?.length) return <div className="empty-state">No permissions declared</div>

  const groups = { dangerous: [], signature: [], normal: [], other: [] }
  data.forEach(p => {
    const level = p.protection_level || 'normal'
    if (groups[level]) groups[level].push(p)
    else groups.other.push(p)
  })

  const filtered = filter === 'all' ? data : groups[filter] || []

  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
        {[
          { id: 'all', label: `All (${data.length})` },
          { id: 'dangerous', label: `Dangerous (${groups.dangerous.length})` },
          { id: 'signature', label: `Signature (${groups.signature.length})` },
          { id: 'normal', label: `Normal (${groups.normal.length})` },
        ].map(g => (
          <button key={g.id} onClick={() => setFilter(g.id)} style={{
            padding: '6px 14px', borderRadius: 6, border: 'none', cursor: 'pointer',
            fontSize: 12, fontWeight: 600,
            background: filter === g.id ? 'var(--accent-cyan)' : 'var(--bg-surface)',
            color: filter === g.id ? '#fff' : 'var(--text-secondary)',
          }}>{g.label}</button>
        ))}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {filtered.map((p, i) => {
          const style = PERM_RISK[p.protection_level] || PERM_RISK.normal
          return (
            <div key={i} className="card" style={{
              padding: '10px 14px', display: 'flex', alignItems: 'center',
              justifyContent: 'space-between', gap: 12,
            }}>
              <div>
                <div className="text-mono" style={{ fontSize: 13 }}>{p.name}</div>
                {p.label && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{p.label}</div>}
              </div>
              <span className="badge" style={{ background: style.bg, color: style.color }}>
                {p.protection_level || 'normal'}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
