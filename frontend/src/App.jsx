import { useState, useEffect, useCallback, useRef } from 'react'
import './App.css'
import UploadPanel from './components/UploadPanel'
import AnalysisView from './components/AnalysisView'
import ThreatIntelView from './components/ThreatIntelView'

const API_URL = 'http://localhost:8000'
const WS_URL = 'ws://localhost:8000/ws'

const NAV_ITEMS = [
  { id: 'upload', label: 'Upload & Analyze', icon: '⬆' },
  { id: 'analysis', label: 'Analysis Results', icon: '🔍' },
  { id: 'threat-intel', label: 'Threat Intelligence', icon: '🌐' },
]

function App() {
  const [activeTab, setActiveTab] = useState('upload')
  const [samples, setSamples] = useState([])
  const [selectedSample, setSelectedSample] = useState(null)
  const [analysisStatus, setAnalysisStatus] = useState({})
  const [liveEvents, setLiveEvents] = useState({})
  const [wsState, setWsState] = useState('connecting')
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [backendReady, setBackendReady] = useState(true)
  const wsRef = useRef(null)

  useEffect(() => {
    fetch(`${API_URL}/`)
      .then(r => setBackendReady(r.ok))
      .catch(() => setBackendReady(false))
  }, [])

  // WebSocket connection for live pipeline events
  useEffect(() => {
    let ws
    let reconnectTimer
    let pingTimer

    const connect = () => {
      try {
        console.log('[WS] Connecting to', WS_URL)
        ws = new WebSocket(WS_URL)
        wsRef.current = ws

        ws.onopen = () => {
          console.log('[WS] Connected')
          setWsState('connected')
          ws.send(JSON.stringify({ action: 'ping' }))
          pingTimer = setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ action: 'ping' }))
            }
          }, 20000)
        }

        ws.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data)
            console.log('[WS] Message:', message.event_type, message.data)
            handleWsMessage(message)
          } catch (err) {
            console.error('Failed to parse WebSocket message:', err)
          }
        }

        ws.onclose = () => {
          console.log('[WS] Disconnected, reconnecting in 3s...')
          clearInterval(pingTimer)
          setWsState('disconnected')
          reconnectTimer = setTimeout(connect, 3000)
        }

        ws.onerror = (err) => {
          console.error('[WS] Error:', err)
          setWsState('error')
        }
      } catch (err) {
        console.error('Failed to create WebSocket:', err)
        setWsState('error')
        reconnectTimer = setTimeout(connect, 5000)
      }
    }

    connect()

    return () => {
      clearTimeout(reconnectTimer)
      clearInterval(pingTimer)
      if (ws) ws.close()
    }
  }, [])

  const handleWsMessage = (message) => {
    if (message.event_type === 'pong') return

    const sampleId = message.data?.sample_id
    if (!sampleId) return

    setLiveEvents(prev => {
      const existing = prev[sampleId] || []
      return {
        ...prev,
        [sampleId]: [...existing, message]
      }
    })
  }

  const handleUpload = useCallback(async (file) => {
    const formData = new FormData()
    formData.append('file', file)

    try {
      const response = await fetch(`${API_URL}/api/upload`, {
        method: 'POST',
        body: formData,
      })
      const data = await response.json()

      const newSample = {
        uploadId: data.upload_id,
        sha256: data.sha256,
        fileName: file.name,
        status: 'uploaded',
        uploadedAt: new Date().toISOString(),
      }

      setSamples(prev => [newSample, ...prev])
      setSelectedSample(newSample)
      setActiveTab('analysis')
      analyzeUpload(data.upload_id)
    } catch (error) {
      console.error('Upload failed:', error)
      alert('Upload failed: ' + error.message)
    }
  }, [])

  const analyzeUpload = async (uploadId) => {
    try {
      const response = await fetch(`${API_URL}/api/analyze/${uploadId}`, {
        method: 'POST',
      })
      const data = await response.json()

      setAnalysisStatus(prev => ({
        ...prev,
        [uploadId]: { status: 'analyzing', jobId: data.job_id }
      }))

      pollAnalysisStatus(uploadId)
    } catch (error) {
      console.error('Analysis failed:', error)
      setAnalysisStatus(prev => ({
        ...prev,
        [uploadId]: { status: 'failed', error: error.message }
      }))
    }
  }

  const pollAnalysisStatus = async (uploadId) => {
    const maxAttempts = 240
    let attempts = 0

    const checkStatus = async () => {
      try {
        const response = await fetch(`${API_URL}/api/sample/${uploadId}/status`)
        const data = await response.json()

        const sampleId = data.sample_id || uploadId

        setAnalysisStatus(prev => ({
          ...prev,
          [uploadId]: { status: data.status, jobId: uploadId, sampleId, error: data.error }
        }))

        if (data.status === 'completed' || data.status === 'failed') {
          setSamples(prev =>
            prev.map(s => s.uploadId === uploadId
              ? { ...s, status: data.status, sampleId: sampleId === uploadId ? null : sampleId }
              : s
            )
          )
        } else if (attempts < maxAttempts) {
          attempts++
          setTimeout(checkStatus, 1500)
        }
      } catch (error) {
        console.error('Status check failed:', error)
        if (attempts < maxAttempts) {
          attempts++
          setTimeout(checkStatus, 2000)
        }
      }
    }

    checkStatus()
  }

  const handleSelectSample = (sample) => {
    setSelectedSample(sample)
    setActiveTab('analysis')
    setSidebarOpen(false)
  }

  const activeLabel = NAV_ITEMS.find(n => n.id === activeTab)?.label || ''

  const selectedSampleId = selectedSample?.sampleId || selectedSample?.sha256 || selectedSample?.uploadId
  const selectedEvents = selectedSampleId ? (liveEvents[selectedSampleId] || []) : []

  return (
    <div className="app-layout">
      <aside className={`app-sidebar ${sidebarOpen ? 'open' : ''}`}>
        <div className="sidebar-brand">
          <div className="brand-icon">DF</div>
          <div className="brand-text">
            <h1>DroidForensix</h1>
            <p>Android Malware Intelligence</p>
          </div>
        </div>

        <nav className="sidebar-nav">
          {NAV_ITEMS.map(item => (
            <button
              key={item.id}
              className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
              onClick={() => {
                setActiveTab(item.id)
                setSidebarOpen(false)
              }}
              disabled={item.id !== 'upload' && !selectedSample}
            >
              <span className="nav-icon">{item.icon}</span>
              <span>{item.label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <p>Static Analysis Pipeline</p>
          <p className={`ws-indicator ws-${wsState}`}>{wsState}</p>
        </div>
      </aside>

      <div className="app-main">
        <header className="app-topbar">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <button className="sidebar-toggle" onClick={() => setSidebarOpen(o => !o)}>
              ☰
            </button>
            <span className="topbar-title">{activeLabel}</span>
          </div>
          <div className="topbar-status">
            <span className={`status-dot ${backendReady ? 'online' : 'offline'}`}></span>
            <span>{backendReady ? 'Backend Online' : 'Backend Offline'}</span>
          </div>
        </header>

        <main className="app-content">
          {activeTab === 'upload' && (
            <div className="view-wrapper">
              <UploadPanel
                onUpload={handleUpload}
                samples={samples}
                onSelectSample={handleSelectSample}
              />
            </div>
          )}

          {activeTab === 'analysis' && (
            <div className="view-wrapper">
              <AnalysisView
                sample={selectedSample}
                status={analysisStatus[selectedSample?.uploadId]}
                events={selectedEvents}
                wsState={wsState}
                apiUrl={API_URL}
              />
            </div>
          )}

          {activeTab === 'threat-intel' && (
            <div className="view-wrapper">
              <ThreatIntelView
                sample={selectedSample}
                apiUrl={API_URL}
              />
            </div>
          )}
        </main>
      </div>
    </div>
  )
}

export default App
