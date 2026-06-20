import { useState } from 'react'
import './AnalysisView.css'
import SmartDissection from './SmartDissection'
import ClassSourceViewer from './ClassSourceViewer'

export default function DissectionPage({ sample, apiUrl }) {
  const [selectedClass, setSelectedClass] = useState(null)
  const [showSource, setShowSource] = useState(false)

  const sampleId = sample?.sampleId || sample?.sha256 || sample?.uploadId

  if (!sampleId) {
    return (
      <div className="analysis-idle">
        <p>Select a sample to view code dissection.</p>
      </div>
    )
  }

  return (
    <div className="view-wrapper">
      <SmartDissection
        sample={sample}
        apiUrl={apiUrl}
        onSelectClass={(name) => {
          setSelectedClass(name)
          setShowSource(true)
        }}
      />
      {showSource && (
        <div className="source-overlay">
          <div className="source-overlay-header">
            <h4 className="source-class-name text-mono">{selectedClass}</h4>
            <button
              className="source-close-button"
              onClick={() => {
                setShowSource(false)
                setSelectedClass(null)
              }}
              aria-label="Close source view"
            >
              Close
            </button>
          </div>
          <div className="source-overlay-content">
            <ClassSourceViewer
              sampleId={sampleId}
              className={selectedClass}
              apiUrl={apiUrl}
            />
          </div>
        </div>
      )}
    </div>
  )
}
