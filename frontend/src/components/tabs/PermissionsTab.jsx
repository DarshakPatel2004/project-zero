import { useState, useEffect } from 'react'
import PermissionCard from '../PermissionCard'

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
        {filtered.map((p, i) => (
          <PermissionCard
            key={i}
            name={p.name}
            label={p.label}
            protectionLevel={p.protection_level}
            description={p.description}
          />
        ))}
      </div>
    </div>
  )
}
