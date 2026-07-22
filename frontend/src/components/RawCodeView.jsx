import { useState, useEffect, useMemo } from 'react'
import ClassSourceViewer from './ClassSourceViewer'

export default function RawCodeView({ sample, apiUrl }) {
  const sampleId = sample?.sampleId || sample?.sha256 || sample?.uploadId
  const [classes, setClasses] = useState([])
  const [selectedClass, setSelectedClass] = useState(null)
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!sampleId) return
    let cancelled = false

    const fetchClasses = async () => {
      try {
        setLoading(true)
        setError(null)
        const res = await fetch(`${apiUrl}/api/sample/${sampleId}/dissection/classes?limit=200`)
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const data = await res.json()
        if (!cancelled) {
          const classList = data.classes || []
          classList.sort((a, b) => a.name.localeCompare(b.name))
          setClasses(classList)
        }
      } catch (err) {
        if (!cancelled) setError(err.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    fetchClasses()
    return () => { cancelled = true }
  }, [sampleId, apiUrl])

  const filtered = useMemo(() => {
    if (!search.trim()) return classes
    const q = search.toLowerCase()
    return classes.filter(c => c.name.toLowerCase().includes(q))
  }, [classes, search])

  if (!sampleId) {
    return <div className="empty-state">No sample selected.</div>
  }

  return (
    <div className="raw-code-layout" style={{
      display: 'grid', gridTemplateColumns: '300px 1fr', gap: 16,
      minHeight: 'calc(100vh - 200px)',
    }}>
      <div className="card" style={{
        display: 'flex', flexDirection: 'column', gap: 8, padding: 12,
        overflow: 'hidden',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <input
            placeholder="Search classes..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{
              flex: 1, padding: '8px 12px', borderRadius: 6,
              border: '1px solid var(--border-color)',
              background: 'var(--bg-secondary)', color: 'var(--text-primary)',
              fontSize: 13, outline: 'none',
            }}
          />
        </div>

        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          {filtered.length} of {classes.length} classes
        </div>

        <div style={{
          flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 1,
        }}>
          {loading && <div className="empty-state" style={{ padding: '2rem' }}>Loading classes...</div>}
          {error && <div className="empty-state" style={{ padding: '2rem', color: 'var(--accent-rose)' }}>{error}</div>}

          {!loading && !error && filtered.map((cls, i) => (
            <button
              key={i}
              onClick={() => setSelectedClass(cls.name)}
              style={{
                textAlign: 'left', padding: '7px 10px', borderRadius: 4, border: 'none',
                fontSize: 12, cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace",
                background: selectedClass === cls.name ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
                color: selectedClass === cls.name ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                transition: 'all 0.12s ease',
              }}
              onMouseEnter={e => { if (selectedClass !== cls.name) e.target.style.background = 'var(--bg-secondary)' }}
              onMouseLeave={e => { if (selectedClass !== cls.name) e.target.style.background = 'transparent' }}
            >
              {cls.name.split('.').pop()}
              {cls.method_count > 0 && (
                <span style={{ marginLeft: 6, fontSize: 10, color: 'var(--text-muted)' }}>
                  ({cls.method_count}m)
                </span>
              )}
            </button>
          ))}

          {!loading && !error && filtered.length === 0 && (
            <div className="empty-state" style={{ padding: '2rem' }}>
              {search ? 'No classes match your search.' : 'No classes found.'}
            </div>
          )}
        </div>
      </div>

      <div style={{ overflow: 'auto' }}>
        {!selectedClass ? (
          <div className="card" style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            minHeight: 400, color: 'var(--text-muted)',
          }}>
            Select a class to view its decompiled source code
          </div>
        ) : (
          <ClassSourceViewer sampleId={sampleId} className={selectedClass} apiUrl={apiUrl} />
        )}
      </div>
    </div>
  )
}
