import { useState, useEffect, useMemo } from 'react'

function classifyString(s) {
  if (!s || s.length === 0) return 'empty'
  if (s.length < 3) return 'short'

  const printable = s.split('').filter(c => c >= ' ' && c <= '~').length / s.length
  if (printable < 0.6) return 'binary'

  const isBase64 = /^[A-Za-z0-9+/]*={0,2}$/.test(s) && s.length > 12 && s.length % 4 === 0
  if (isBase64) return 'base64'

  const isHex = /^[0-9a-fA-F]+$/.test(s) && s.length > 8 && s.length % 2 === 0
  if (isHex) return 'hex'

  if (/^https?:\/\//i.test(s)) return 'url'
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(s)) return 'ip'
  if (s.includes('/') || s.includes('\\')) return 'path'
  if (/^[a-zA-Z0-9_\.\-]+@[a-zA-Z0-9_\.\-]+/.test(s)) return 'email'

  return 'plain'
}

function tryDecode(s, type) {
  try {
    if (type === 'base64') {
      const dec = atob(s)
      if (dec.split('').every(c => c >= ' ' && c <= '~')) return dec
    }
    if (type === 'hex') {
      const dec = s.match(/.{1,2}/g).map(b => String.fromCharCode(parseInt(b, 16))).join('')
      if (dec.split('').every(c => c >= ' ' && c <= '~')) return dec
    }
    if (type === 'url') {
      const dec = decodeURIComponent(s)
      if (dec !== s) return dec
    }
  } catch {}
  return null
}

const TYPE_META = {
  url: { label: 'URL', color: 'var(--accent-cyan)', bg: 'rgba(6,182,212,0.1)' },
  ip: { label: 'IP', color: 'var(--accent-rose)', bg: 'rgba(244,63,94,0.1)' },
  base64: { label: 'Base64', color: 'var(--accent-amber)', bg: 'rgba(245,158,11,0.1)' },
  hex: { label: 'Hex', color: 'var(--accent-violet)', bg: 'rgba(139,92,246,0.1)' },
  path: { label: 'Path', color: 'var(--accent-emerald)', bg: 'rgba(16,185,129,0.1)' },
  email: { label: 'Email', color: 'var(--accent-cyan)', bg: 'rgba(6,182,212,0.1)' },
  plain: { label: 'Text', color: 'var(--text-muted)', bg: 'transparent' },
  binary: { label: 'Binary', color: 'var(--accent-rose)', bg: 'rgba(244,63,94,0.06)' },
  short: { label: 'Short', color: 'var(--text-muted)', bg: 'transparent' },
  empty: { label: 'Empty', color: 'var(--text-muted)', bg: 'transparent' },
}

export default function StringsTab({ sampleId, apiUrl }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [filterType, setFilterType] = useState('all')

  useEffect(() => {
    if (!sampleId) return
    fetch(`${apiUrl}/api/sample/${sampleId}/dissection/strings`)
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { setData(d); setLoading(false) })
      .catch(() => setLoading(false))
  }, [sampleId, apiUrl])

  const allStrings = useMemo(() => {
    const raw = data?.string_literals || data?.categories?.string_literals || []
    return raw.map(s => {
      const str = typeof s === 'string' ? s : typeof s === 'number' ? String(s) : s?.value || s?.text || JSON.stringify(s)
      const type = classifyString(str)
      return { raw: str, type, decoded: tryDecode(str, type) }
    })
  }, [data])

  const filtered = useMemo(() => {
    let list = allStrings
    if (filterType !== 'all') list = list.filter(s => s.type === filterType)
    if (search) list = list.filter(s => s.raw.toLowerCase().includes(search.toLowerCase()) || (s.decoded && s.decoded.toLowerCase().includes(search.toLowerCase())))
    return list
  }, [allStrings, filterType, search])

  const typeCounts = useMemo(() => {
    const counts = {}
    allStrings.forEach(s => { counts[s.type] = (counts[s.type] || 0) + 1 })
    return counts
  }, [allStrings])

  if (loading) return <div className="empty-state">Loading strings...</div>
  if (!data) return <div className="empty-state">No strings data available</div>

  return (
    <div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 12, padding: '8px 12px', background: 'var(--bg-secondary)', borderRadius: 6, lineHeight: 1.5 }}>
        Strings detected as Base64, hex, or URL-encoded are auto-decoded inline. Use the Type filter to focus on suspicious categories.
      </div>

      <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          placeholder="Search raw or decoded strings..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{
            flex: 1, minWidth: 200, padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border-color)',
            background: 'var(--bg-secondary)', color: 'var(--text-primary)', fontSize: 13,
            outline: 'none',
          }}
        />
        <select
          value={filterType}
          onChange={e => setFilterType(e.target.value)}
          style={{
            padding: '7px 10px', borderRadius: 6, border: '1px solid var(--border-color)',
            background: 'var(--bg-secondary)', color: 'var(--text-primary)', fontSize: 12,
            outline: 'none', cursor: 'pointer',
          }}
        >
          <option value="all">All types ({allStrings.length})</option>
          {Object.entries(typeCounts).sort().map(([type, count]) => (
            <option key={type} value={type}>{TYPE_META[type]?.label || type} ({count})</option>
          ))}
        </select>
      </div>

      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 12 }}>
        {filtered.length} of {allStrings.length} strings
        {search ? ` matching "${search}"` : ''}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        {filtered.slice(0, 300).map((s, i) => {
          const meta = TYPE_META[s.type] || TYPE_META.plain
          return (
            <div key={i} style={{
              padding: '8px 10px', borderRadius: 4, fontSize: 12,
              fontFamily: "'JetBrains Mono', monospace",
              background: s.type === 'binary' || s.type === 'base64' || s.type === 'hex'
                ? (i % 2 === 0 ? 'rgba(245,158,11,0.04)' : 'rgba(245,158,11,0.08)')
                : (i % 2 === 0 ? 'transparent' : 'var(--bg-secondary)'),
              color: 'var(--text-secondary)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: s.decoded ? 4 : 0 }}>
                <span style={{
                  padding: '1px 6px', borderRadius: 3, fontSize: 9, fontWeight: 600,
                  background: meta.bg, color: meta.color, flexShrink: 0,
                }}>{meta.label}</span>
                <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  &quot;{s.raw.substring(0, 120)}&quot;
                </span>
              </div>
              {s.decoded && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingLeft: 50 }}>
                  <span style={{ color: 'var(--accent-emerald)', fontSize: 10, flexShrink: 0 }}>→</span>
                  <span style={{ color: 'var(--accent-emerald)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {s.decoded.substring(0, 160)}
                  </span>
                </div>
              )}
            </div>
          )
        })}
        {filtered.length > 300 && (
          <div style={{ color: 'var(--text-muted)', fontSize: 12, textAlign: 'center', padding: 8 }}>
            + {filtered.length - 300} more strings (showing first 300)
          </div>
        )}
      </div>
    </div>
  )
}
