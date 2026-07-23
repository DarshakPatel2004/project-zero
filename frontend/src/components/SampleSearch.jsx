import { useState, useCallback } from 'react'
import { apiFetch } from '../api/client'

export default function SampleSearch({ apiUrl, onSelect, samples }) {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState(samples || [])
  const [searching, setSearching] = useState(false)

  const doSearch = useCallback(async () => {
    if (!query.trim()) {
      setResults(samples || [])
      return
    }
    setSearching(true)
    try {
      const data = await apiFetch(`${apiUrl || 'http://localhost:8000'}/api/samples?q=${encodeURIComponent(query)}&limit=20`)
      setResults(data.samples || data || [])
    } catch {
      setResults([])
    } finally {
      setSearching(false)
    }
  }, [query, samples, apiUrl])

  return (
    <div className="card" style={{ padding: 16 }}>
      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <input
          placeholder="Search by hash, package name, or family..."
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && doSearch()}
          style={{
            flex: 1, padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border-color)',
            background: 'var(--bg-secondary)', color: 'var(--text-primary)', fontSize: 13,
            outline: 'none',
          }}
        />
        <button className="primary" onClick={doSearch} disabled={searching} style={{ padding: '8px 16px' }}>
          {searching ? '...' : 'Search'}
        </button>
      </div>
      {results.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 300, overflow: 'auto' }}>
          {results.map((s, i) => (
            <button
              key={i}
              onClick={() => onSelect?.(s)}
              style={{
                textAlign: 'left', padding: '8px 12px', borderRadius: 6, border: 'none',
                background: 'var(--bg-secondary)', cursor: 'pointer', fontSize: 12,
                color: 'var(--text-secondary)', fontFamily: "'JetBrains Mono', monospace",
              }}
              onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-surface-hover)'}
              onMouseLeave={e => e.currentTarget.style.background = 'var(--bg-secondary)'}
            >
              {s.sha256?.substring(0, 16) || s.sample_id?.substring(0, 16)}...
              {s.package_name && <span style={{ color: 'var(--text-muted)', marginLeft: 8 }}>{s.package_name}</span>}
              {s.family && <span style={{ color: 'var(--accent-amber)', marginLeft: 8 }}>{s.family}</span>}
            </button>
          ))}
        </div>
      )}
      {!searching && query && results.length === 0 && (
        <div className="empty-state">No samples found</div>
      )}
    </div>
  )
}
