import { useState, useCallback } from 'react'
import '../styles/UploadPanel.css'

const FEATURES = [
  { icon: '🧬', title: 'String Extraction', desc: 'Enumerate literals, byte arrays, and constants from decompiled APK code.' },
  { icon: '🔐', title: 'Encoding Detection', desc: 'Identify Base64, hex, XOR, and custom encoding schemes.' },
  { icon: '🌐', title: 'C2 Discovery', desc: 'Extract and classify command-and-control endpoints with confidence scores.' },
  { icon: '⛓', title: 'Threat Chains', desc: 'Map encoded strings through decoding functions to final payloads.' },
  { icon: '🛡', title: 'Obfuscation Score', desc: 'Score reflection, dynamic loading, and crypto API usage patterns.' },
  { icon: '⚡', title: 'Risk Assessment', desc: 'LLM-assisted verdict with rule-based fallback scoring.' },
]

export default function UploadPanel({ onUpload, samples, onSelectSample }) {
  const [dragActive, setDragActive] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)

  const handleDrag = useCallback((e) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }, [])

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    const files = e.dataTransfer.files
    if (files && files[0]) {
      processFile(files[0])
    }
  }, [])

  const handleChange = useCallback((e) => {
    if (e.target.files && e.target.files[0]) {
      processFile(e.target.files[0])
    }
  }, [])

  const processFile = async (file) => {
    if (!file.name.toLowerCase().endsWith('.apk')) {
      alert('Please upload an APK file')
      return
    }

    setUploading(true)
    setUploadProgress(0)

    const progressInterval = setInterval(() => {
      setUploadProgress(p => Math.min(p + Math.random() * 15, 90))
    }, 250)

    try {
      await onUpload(file)
      setUploadProgress(100)
    } finally {
      clearInterval(progressInterval)
      setTimeout(() => {
        setUploading(false)
        setUploadProgress(0)
      }, 400)
    }
  }

  return (
    <div className="upload-panel">
      <section className="upload-hero card">
        <div
          className={`upload-dropzone ${dragActive ? 'active' : ''} ${uploading ? 'uploading' : ''}`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
        >
          <div className="upload-dropzone-content">
            <div className="upload-illustration">📦</div>
            <h2>{uploading ? 'Uploading APK...' : 'Drop your APK here'}</h2>
            <p className="upload-subtitle">
              {uploading ? 'Scanning file signature and beginning static analysis' : 'or click below to browse your device'}
            </p>

            {!uploading && (
              <label className="upload-primary-button">
                Browse Files
                <input
                  type="file"
                  accept=".apk"
                  onChange={handleChange}
                  disabled={uploading}
                  style={{ display: 'none' }}
                />
              </label>
            )}

            {uploading && (
              <div className="upload-progress">
                <div className="upload-progress-track">
                  <div className="upload-progress-bar" style={{ width: `${uploadProgress}%` }}></div>
                </div>
                <span className="upload-progress-text">{Math.round(uploadProgress)}%</span>
              </div>
            )}

            <p className="upload-hint">APK files only &bull; Max 500MB</p>
          </div>
        </div>
      </section>

      <section className="upload-grid">
        {samples.length > 0 && (
          <div className="recent-samples card">
            <div className="card-header">
              <h3>Recent Samples</h3>
              <span className="sample-count">{samples.length}</span>
            </div>
            <div className="samples-list">
              {samples.map((sample, idx) => (
                <div key={idx} className="sample-row">
                  <div className="sample-row-icon">📱</div>
                  <div className="sample-row-info">
                    <p className="sample-row-name" title={sample.fileName}>{sample.fileName}</p>
                    <p className="sample-row-hash">{sample.sha256.substring(0, 24)}...</p>
                    <p className="sample-row-time">{new Date(sample.uploadedAt).toLocaleString()}</p>
                  </div>
                  <div className="sample-row-actions">
                    <span className={`status-pill ${sample.status}`}>
                      {sample.status === 'uploaded' && 'Queued'}
                      {sample.status === 'analyzing' && 'Analyzing'}
                      {sample.status === 'completed' && 'Done'}
                      {sample.status === 'failed' && 'Failed'}
                    </span>
                    <button
                      className="view-sample-btn"
                      onClick={() => onSelectSample(sample)}
                      disabled={sample.status === 'analyzing'}
                    >
                      View
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="features card">
          <div className="card-header">
            <h3>What DroidForensix Does</h3>
          </div>
          <div className="features-grid">
            {FEATURES.map((f, i) => (
              <div key={i} className="feature-item">
                <span className="feature-icon">{f.icon}</span>
                <div>
                  <h4>{f.title}</h4>
                  <p>{f.desc}</p>
                </div>
              </div>
            ))}
          </div>

          <div className="validation-banner">
            <div className="validation-stat">
              <span className="validation-value">92%</span>
              <span className="validation-label">Accuracy</span>
            </div>
            <div className="validation-stat">
              <span className="validation-value">100%</span>
              <span className="validation-label">Precision</span>
            </div>
            <div className="validation-stat">
              <span className="validation-value">84%</span>
              <span className="validation-label">Recall</span>
            </div>
            <div className="validation-stat">
              <span className="validation-value">100</span>
              <span className="validation-label">Test Samples</span>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}
