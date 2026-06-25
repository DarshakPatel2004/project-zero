import { useState, useEffect, useCallback, useRef, useReducer } from 'react'
import './App.css'
import UploadPanel from './components/UploadPanel'
import AnalysisView from './components/AnalysisView'
import ThreatIntelView from './components/ThreatIntelView'
import DissectionPage from './components/DissectionPage'

const API_URL = 'http://localhost:8000'
const WS_URL = 'ws://localhost:8000/ws'

const NAV_ITEMS = [
  { id: 'upload', label: 'Upload & Analyze', icon: '⬆' },
  { id: 'analysis', label: 'Analysis Results', icon: '🔍' },
  { id: 'dissection', label: 'Code Dissection', icon: '🔬' },
  { id: 'threat-intel', label: 'Threat Intelligence', icon: '🌐' },
]

/**
 * Estimate total analysis duration from APK size.
 * Mirrors backend/_estimate_remaining_eta for the full 9-step pipeline.
 */
function estimateEtaSeconds(fileSizeBytes) {
  if (fileSizeBytes < 1_000_000) return 2.0 * 9
  if (fileSizeBytes < 10_000_000) return 3.5 * 9
  return 5.0 * 9
}

/**
 * Analysis state reducer: maintains single source of truth for live analysis.
 * Replaces the old "liveEvents" array with a compact state dict.
 */
function analysisReducer(state, action) {
  switch (action.type) {
    case 'RESET':
      return {
        sampleId: null,
        status: null,
        progress: 0,
        eta: null,
        startTime: null,
        metrics: {
          c2_count: 0,
          encoding_count: 0,
          payload_count: 0,
          threat_chain_count: 0,
        },
        stepTimings: {},
        verdictData: null,
        llmVerifications: {},
        fullReport: null,
        error: null,
      }

    case 'ANALYSIS_STARTED':
      return {
        ...state,
        sampleId: action.payload.sample_id,
        status: 'running',
        progress: 0,
        eta: action.payload.predicted_eta_seconds || null,
        startTime: state.startTime || Date.now(),
        stepTimings: {},
        llmVerifications: {},
        error: null,
      }

    case 'STEP_COMPLETED':
      const { step_number, duration_seconds, remaining_eta_seconds, progress_percent, step_name } = action.payload
      const llmVerification = action.payload.llm_verification
      const newState = {
        ...state,
        progress: progress_percent || step_number / 9 * 100,
        eta: remaining_eta_seconds,
        stepTimings: {
          ...state.stepTimings,
          [step_name]: duration_seconds,
        },
      }
      if (llmVerification) {
        newState.llmVerifications = {
          ...newState.llmVerifications,
          [step_name]: llmVerification,
        }
      }
      return newState

    case 'METRIC_UPDATED':
      const { metric_name, metric_value } = action.payload
      return {
        ...state,
        metrics: {
          ...state.metrics,
          [metric_name]: metric_value,
        },
      }

    case 'ANALYSIS_COMPLETE':
      return {
        ...state,
        sampleId: action.payload.sample_id || state.sampleId,
        status: 'complete',
        progress: 100,
        eta: 0,
        verdictData: {
          verdict: action.payload.final_verdict,
          riskScore: action.payload.risk_score,
          totalDuration: action.payload.total_duration_seconds,
        },
        fullReport: action.payload.full_report || null,
      }

    case 'ERROR':
      return {
        ...state,
        status: 'error',
        error: action.payload.error_message,
      }

    default:
      return state
  }
}

function App() {
  const [activeTab, setActiveTab] = useState('upload')
  const [samples, setSamples] = useState([])
  const [selectedSample, setSelectedSample] = useState(null)
  const [wsState, setWsState] = useState('connecting')
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [backendReady, setBackendReady] = useState(true)
  const wsRef = useRef(null)

  // Unified analysis state (replaces liveEvents + analysisStatus)
  const [analysisState, dispatch] = useReducer(analysisReducer, {
    sampleId: null,
    status: null,
    progress: 0,
    eta: null,
    startTime: null,
    metrics: {
      c2_count: 0,
      encoding_count: 0,
      payload_count: 0,
      threat_chain_count: 0,
    },
    stepTimings: {},
    verdictData: null,
    llmVerifications: {},
    fullReport: null,
    error: null,
  })

  // Check backend health on mount
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
          // Send ping to keep connection alive
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
            handleWsMessage(message)
          } catch (err) {
            console.error('[WS] Failed to parse message:', err)
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
        console.error('[WS] Failed to create WebSocket:', err)
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

  /**
   * Unified WebSocket message handler.
   * No event array; just update the analysis state directly.
   */
  const handleWsMessage = useCallback((message) => {
    const { event_type, data } = message

    console.log('[WS]', event_type, data?.sample_id)

    switch (event_type) {
      case 'pong':
        break // Ignore pong

      case 'analysis_started':
        dispatch({ type: 'ANALYSIS_STARTED', payload: data })
        break

      case 'step_completed':
        dispatch({ type: 'STEP_COMPLETED', payload: data })
        break

      case 'metric_updated':
        dispatch({ type: 'METRIC_UPDATED', payload: data })
        break

      case 'analysis_complete':
        dispatch({ type: 'ANALYSIS_COMPLETE', payload: data })
        break

      case 'error':
        dispatch({ type: 'ERROR', payload: data })
        break

      default:
        console.log('[WS] Unknown event:', event_type)
    }
  }, [])

  const handleUpload = useCallback(async (file) => {
    // Frontend file size check (matches backend MAX_UPLOAD_SIZE_MB=100)
    const MAX_SIZE_MB = 100
    if (file.size > MAX_SIZE_MB * 1024 * 1024) {
      alert(`File is too large (${(file.size / 1024 / 1024).toFixed(1)}MB). Maximum allowed size is ${MAX_SIZE_MB}MB.`)
      return
    }

    const formData = new FormData()
    formData.append('file', file)

    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 300000) // 5 min timeout

    try {
      const response = await fetch(`${API_URL}/api/upload`, {
        method: 'POST',
        body: formData,
        signal: controller.signal,
      })
      clearTimeout(timeoutId)

      if (!response.ok) {
        const errorBody = await response.text()
        throw new Error(`Server error (${response.status}): ${errorBody}`)
      }

      const data = await response.json()

      const newSample = {
        uploadId: data.upload_id,
        sha256: data.sha256,
        fileName: file.name,
        status: 'uploaded',
        uploadedAt: new Date().toISOString(),
      }

      // Reset analysis state for new sample
      dispatch({ type: 'RESET' })

      setSamples(prev => [newSample, ...prev])
      setSelectedSample(newSample)
      setActiveTab('analysis')

      // Optimistically start the running state so the UI shows the loading
      // screen immediately while the backend begins the pipeline.
      dispatch({
        type: 'ANALYSIS_STARTED',
        payload: {
          sample_id: data.upload_id,
          sample_name: file.name,
          file_size_bytes: file.size,
          total_steps: 9,
          predicted_eta_seconds: estimateEtaSeconds(file.size),
        },
      })

      // Start analysis
      analyzeUpload(data.upload_id)
    } catch (error) {
      console.error('Upload failed:', error)
      if (error.name === 'AbortError') {
        alert('Upload timed out. The file may be too large or the backend is not responding. Make sure the backend is running (python -m uvicorn backend.main:app --port 8000).')
      } else if (error.message === 'Failed to fetch' || error.message.includes('Failed to fetch')) {
        alert('Upload failed: Cannot reach the backend. Ensure the backend is running at http://localhost:8000 (run run_backend.bat or "python -m uvicorn backend.main:app --port 8000" from the backend/ directory).')
      } else {
        alert('Upload failed: ' + error.message)
      }
    }
  }, [])

  const analyzeUpload = useCallback(async (uploadId) => {
    try {
      const response = await fetch(`${API_URL}/api/analyze/${uploadId}`, {
        method: 'POST',
      })
      const data = await response.json()
      console.log('Analysis triggered:', data)
      // WebSocket events will drive the UI from here
    } catch (error) {
      console.error('Analysis failed:', error)
      dispatch({ type: 'ERROR', payload: { error_message: error.message } })
    }
  }, [])

  const handleSelectSample = (sample) => {
    setSelectedSample(sample)
    setActiveTab('analysis')
    setSidebarOpen(false)

    const sampleId = sample?.sampleId || sample?.sha256 || sample?.uploadId
    const isAnalyzed = sample?.status === 'analyzed' || sample?.status === 'completed'

    if (isAnalyzed && sampleId) {
      // Show the completed result view immediately for previously analyzed samples
      dispatch({
        type: 'ANALYSIS_COMPLETE',
        payload: {
          sample_id: sampleId,
          total_duration_seconds: null,
          step_timings: {},
          final_verdict: sample?.severity || 'unknown',
          risk_score: sample?.risk_score || 0,
        },
      })
    } else {
      // Reset analysis state when switching to a fresh/uploaded sample
      dispatch({ type: 'RESET' })
    }
  }

  const activeLabel = NAV_ITEMS.find(n => n.id === activeTab)?.label || ''
  const selectedSampleId = selectedSample?.uploadId

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

          {activeTab === 'analysis' && selectedSample && (
            <div className="view-wrapper">
              <AnalysisView
                sample={selectedSample}
                analysisState={analysisState}
                apiUrl={API_URL}
              />
            </div>
          )}

          {activeTab === 'dissection' && selectedSample && (
            <div className="view-wrapper">
              <DissectionPage
                sample={selectedSample}
                apiUrl={API_URL}
              />
            </div>
          )}

          {activeTab === 'threat-intel' && selectedSample && (
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
