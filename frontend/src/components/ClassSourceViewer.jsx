import { useState, useEffect } from 'react'
import '../styles/ClassSourceViewer.css'

export default function ClassSourceViewer({ sampleId, className, apiUrl }) {
  const [source, setSource] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const API_URL = apiUrl || 'http://localhost:8000'

  useEffect(() => {
    if (!sampleId || !className) {
      return
    }

    let stale = false
    const controller = new AbortController()

    const fetchSource = async () => {
      setLoading(true)
      setError(null)
      try {
        const encoded = encodeURIComponent(className)
        const response = await fetch(
          `${API_URL}/api/sample/${sampleId}/dissection/code/${encoded}`,
          { signal: controller.signal }
        )
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        const data = await response.json()
        if (stale) return
        setSource(data.code || '')
      } catch (err) {
        if (stale || err.name === 'AbortError') return
        setError(err.message)
      } finally {
        if (!stale) setLoading(false)
      }
    }

    fetchSource()
    return () => {
      stale = true
      controller.abort()
    }
  }, [sampleId, className, API_URL])

  if (!className) {
    return (
      <div className="source-viewer empty">
        <p>Select a class from the list to view its decompiled source.</p>
      </div>
    )
  }

  return (
    <div className="source-viewer">
      <div className="source-header">
        <h4 className="source-class-name text-mono">{className}</h4>
      </div>
      {loading && <div className="source-loading">Loading source…</div>}
      {error && <div className="source-error">Error loading source: {error}</div>}
      {!loading && !error && source !== null && (
        <pre className="source-code">
          <code>{source}</code>
        </pre>
      )}
    </div>
  )
}
