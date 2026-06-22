You are helping build DroidForensix, a full-stack Android malware analysis platform. The user wants to add APK dissection (manifest, permissions, decompiled code, strings, etc.) to the dashboard.

Current State

The backend has:


FastAPI server with upload, analysis trigger, and WebSocket streaming
Pipeline that runs Steps 1-8 (extraction, strings, encodings, C2, chains, LLM, obfuscation)
Config-driven settings (Pydantic)


The frontend has:


React + Three.js scaffold
Dashboard, sample browser, sample detail pages
UploadDropzone and PipelineTimeline components


Goal

Add APK dissection layer that extracts and displays:


AndroidManifest.xml — parsed permissions, activities, services, broadcast receivers
APK Metadata — file size, min/target SDK, package name, version
Decompiled Code — Java classes (from JADX output or smali fallback)
Strings — extracted string constants (from Step 2)
Native Libraries — list of .so files
Resources — drawable/layout/values structure
DEX Statistics — class count, method count, entropy


Backend Requirements

1. Create backend/dissection.py

This module extracts APK metadata and structure without running the full pipeline.

pythonfrom pathlib import Path
from typing import Optional, Dict, Any
import json
import zipfile
import re
import struct
import axmlrpc  # or similar library for parsing binary XML

class APKDissector:
    def __init__(self, apk_path: str):
        self.apk_path = Path(apk_path)
        self.zip = zipfile.ZipFile(apk_path, 'r')
    
    def dissect(self) -> Dict[str, Any]:
        """Return all dissected APK data."""
        return {
            'metadata': self.extract_metadata(),
            'manifest': self.extract_manifest(),
            'permissions': self.extract_permissions(),
            'components': self.extract_components(),  # activities, services, etc.
            'native_libs': self.extract_native_libs(),
            'resources': self.extract_resources_structure(),
            'dex_stats': self.extract_dex_stats(),
            'file_structure': self.extract_file_structure(),
        }
    
    def extract_metadata(self) -> Dict[str, Any]:
        """Extract basic APK metadata."""
        # Parse AndroidManifest.xml for:
        # - package name
        # - version code
        # - version name
        # - min/target SDK
        # - compileSdkVersion
        pass
    
    def extract_manifest(self) -> str:
        """Return decompiled/readable AndroidManifest.xml."""
        # Use axmlrpc to parse binary XML
        # Return as JSON-serializable dict
        pass
    
    def extract_permissions(self) -> list:
        """Return list of declared permissions with risk levels."""
        # Parse <uses-permission> tags
        # Categorize as dangerous/normal/signature
        pass
    
    def extract_components(self) -> Dict[str, list]:
        """Return activities, services, broadcast receivers, content providers."""
        pass
    
    def extract_native_libs(self) -> list:
        """Return list of .so files and architectures."""
        # Scan lib/ directory in APK
        pass
    
    def extract_resources_structure(self) -> Dict[str, Any]:
        """Return high-level resource tree."""
        # Parse res/ directory structure
        # Count drawable, layout, values, etc.
        pass
    
    def extract_dex_stats(self) -> Dict[str, int]:
        """Parse DEX header for stats."""
        # Extract classes.dex
        # Read DEX magic header and counts
        # Return: {class_count, method_count, string_count, ...}
        pass
    
    def extract_file_structure(self) -> Dict[str, list]:
        """Return directory tree of APK contents."""
        # Walk zip and group by top-level dir
        pass

Key Steps:


Use zipfile to read APK (it's a ZIP archive)
Parse AndroidManifest.xml (binary XML) using axmlrpc or manual parsing
Extract classes.dex header for statistics
Walk the ZIP to get file structure
Return all data as JSON-serializable dicts


2. Create API Endpoint in backend/main.py

pythonfrom backend.dissection import APKDissector

@app.get("/api/sample/{sample_id}/dissection")
async def get_apk_dissection(sample_id: str):
    """Get dissected APK structure (quick, no full pipeline)."""
    status = sample_status[sample_id]
    if not status:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    file_path = status['file_path']
    
    try:
        dissector = APKDissector(file_path)
        dissection_data = dissector.dissect()
        return dissection_data
    except Exception as e:
        logger.error(f"Dissection failed for {sample_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/sample/{sample_id}/dissection/manifest")
async def get_manifest(sample_id: str):
    """Get just the AndroidManifest.xml (readable)."""
    status = sample_status[sample_id]
    if not status:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    dissector = APKDissector(status['file_path'])
    return {"manifest": dissector.extract_manifest()}

@app.get("/api/sample/{sample_id}/dissection/code/{class_name}")
async def get_class_code(sample_id: str, class_name: str):
    """Get decompiled source for a specific class."""
    # Load from analysis/work/{sample_id}/decompiled/{class_name}.java
    # Or parse on-the-fly from JADX cache
    pass

@app.get("/api/sample/{sample_id}/dissection/strings")
async def get_strings(sample_id: str):
    """Get extracted strings from Step 2."""
    # Load from analysis/work/{sample_id}/step2_result.json
    pass

3. Store Dissection Data

When analysis completes, save dissection to disk:

python# In run_analysis_task(), after pipeline completes:
dissector = APKDissector(file_path)
dissection_data = dissector.dissect()

sample_work_dir = settings.WORK_DIR / sample_id
with open(sample_work_dir / "dissection.json", "w") as f:
    json.dump(dissection_data, f, indent=2)

Frontend Requirements

1. Create frontend/src/components/APKDissection.jsx

Tabbed interface showing:


Manifest — tree view of permissions, components
Metadata — SDK versions, file size, package name
Code Browser — searchable list of classes, click to view
Strings — searchable string constants
Native Libs — .so files and architectures
Resources — drawable/layout/values tree
DEX Stats — class/method counts, entropy chart


jsximport React, { useState, useEffect } from 'react'
import '../styles/APKDissection.css'

export default function APKDissection({ sampleId }) {
  const [dissection, setDissection] = useState(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('manifest')
  const [selectedClass, setSelectedClass] = useState(null)
  const [classCode, setClassCode] = useState(null)

  useEffect(() => {
    fetchDissection()
  }, [sampleId])

  async function fetchDissection() {
    try {
      const res = await fetch(`/api/sample/${sampleId}/dissection`)
      const data = await res.json()
      setDissection(data)
    } catch (err) {
      console.error('Failed to fetch dissection:', err)
    } finally {
      setLoading(false)
    }
  }

  async function fetchClassCode(className) {
    try {
      const res = await fetch(`/api/sample/${sampleId}/dissection/code/${className}`)
      const data = await res.json()
      setClassCode(data.code)
      setSelectedClass(className)
    } catch (err) {
      console.error('Failed to fetch class code:', err)
    }
  }

  if (loading) return <div>Loading dissection...</div>
  if (!dissection) return <div>No dissection data</div>

  return (
    <div className="apk-dissection">
      <div className="dissection-tabs">
        <button
          className={`tab ${activeTab === 'manifest' ? 'active' : ''}`}
          onClick={() => setActiveTab('manifest')}
        >
          📋 Manifest
        </button>
        <button
          className={`tab ${activeTab === 'metadata' ? 'active' : ''}`}
          onClick={() => setActiveTab('metadata')}
        >
          ℹ️ Metadata
        </button>
        <button
          className={`tab ${activeTab === 'code' ? 'active' : ''}`}
          onClick={() => setActiveTab('code')}
        >
          💻 Code
        </button>
        <button
          className={`tab ${activeTab === 'strings' ? 'active' : ''}`}
          onClick={() => setActiveTab('strings')}
        >
          📝 Strings
        </button>
        <button
          className={`tab ${activeTab === 'native' ? 'active' : ''}`}
          onClick={() => setActiveTab('native')}
        >
          🔧 Native Libs
        </button>
        <button
          className={`tab ${activeTab === 'dex' ? 'active' : ''}`}
          onClick={() => setActiveTab('dex')}
        >
          📊 DEX Stats
        </button>
      </div>

      <div className="dissection-content">
        {activeTab === 'manifest' && (
          <ManifestTab manifest={dissection.manifest} />
        )}
        {activeTab === 'metadata' && (
          <MetadataTab metadata={dissection.metadata} />
        )}
        {activeTab === 'code' && (
          <CodeTab
            sampleId={sampleId}
            onSelectClass={fetchClassCode}
            selectedClass={selectedClass}
            classCode={classCode}
          />
        )}
        {activeTab === 'strings' && (
          <StringsTab sampleId={sampleId} />
        )}
        {activeTab === 'native' && (
          <NativeTab nativeLibs={dissection.native_libs} />
        )}
        {activeTab === 'dex' && (
          <DEXTab dexStats={dissection.dex_stats} />
        )}
      </div>
    </div>
  )
}

// Sub-components for each tab
function ManifestTab({ manifest }) {
  return (
    <div className="manifest-view">
      <pre>{JSON.stringify(manifest, null, 2)}</pre>
    </div>
  )
}

function MetadataTab({ metadata }) {
  return (
    <div className="metadata-view">
      <table>
        <tbody>
          {Object.entries(metadata).map(([key, value]) => (
            <tr key={key}>
              <td className="label">{key}</td>
              <td className="value">{String(value)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function CodeTab({ sampleId, onSelectClass, selectedClass, classCode }) {
  const [classes, setClasses] = useState([])
  const [search, setSearch] = useState('')

  useEffect(() => {
    // Fetch list of classes from backend
    fetch(`/api/sample/${sampleId}/dissection/classes`)
      .then(r => r.json())
      .then(d => setClasses(d.classes || []))
  }, [sampleId])

  const filtered = classes.filter(c =>
    c.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="code-view">
      <div className="code-sidebar">
        <input
          type="text"
          placeholder="Search classes..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <div className="class-list">
          {filtered.map((cls) => (
            <div
              key={cls}
              className={`class-item ${selectedClass === cls ? 'selected' : ''}`}
              onClick={() => onSelectClass(cls)}
            >
              {cls}
            </div>
          ))}
        </div>
      </div>
      <div className="code-editor">
        {classCode ? (
          <pre>{classCode}</pre>
        ) : (
          <p>Select a class to view code</p>
        )}
      </div>
    </div>
  )
}

function StringsTab({ sampleId }) {
  const [strings, setStrings] = useState([])
  const [search, setSearch] = useState('')

  useEffect(() => {
    fetch(`/api/sample/${sampleId}/dissection/strings`)
      .then(r => r.json())
      .then(d => setStrings(d.strings || []))
  }, [sampleId])

  const filtered = strings.filter(s =>
    s.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="strings-view">
      <input
        type="text"
        placeholder="Search strings..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />
      <div className="strings-list">
        {filtered.map((str, idx) => (
          <div key={idx} className="string-item">
            <code>{str}</code>
          </div>
        ))}
      </div>
    </div>
  )
}

function NativeTab({ nativeLibs }) {
  return (
    <div className="native-view">
      <table>
        <thead>
          <tr>
            <th>Architecture</th>
            <th>Library</th>
            <th>Size</th>
          </tr>
        </thead>
        <tbody>
          {nativeLibs?.map((lib, idx) => (
            <tr key={idx}>
              <td>{lib.arch}</td>
              <td>{lib.name}</td>
              <td>{lib.size} bytes</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function DEXTab({ dexStats }) {
  return (
    <div className="dex-view">
      <h3>DEX Statistics</h3>
      <table>
        <tbody>
          {Object.entries(dexStats).map(([key, value]) => (
            <tr key={key}>
              <td>{key}</td>
              <td>{value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

2. Integrate into SampleDetail Page

jsx// In frontend/src/pages/SampleDetail.jsx
import APKDissection from '../components/APKDissection'

export default function SampleDetail() {
  // ... existing code ...
  
  return (
    <div className="sample-detail">
      {/* ... header, timeline ... */}
      
      <section>
        <h2>APK Dissection</h2>
        <APKDissection sampleId={sampleId} />
      </section>
      
      {/* ... threat graph ... */}
    </div>
  )
}

3. Create Styling

css/* frontend/src/styles/APKDissection.css */

.apk-dissection {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}

.dissection-tabs {
  display: flex;
  border-bottom: 1px solid var(--border);
  background: var(--bg-dark);
}

.dissection-tabs .tab {
  flex: 1;
  padding: 1rem;
  background: none;
  border: none;
  color: var(--text-muted);
  cursor: pointer;
  text-align: center;
  transition: all 0.2s;
}

.dissection-tabs .tab:hover {
  color: var(--primary);
}

.dissection-tabs .tab.active {
  color: var(--primary);
  border-bottom: 2px solid var(--primary);
}

.dissection-content {
  padding: 2rem;
  max-height: 600px;
  overflow-y: auto;
}

.manifest-view,
.metadata-view,
.strings-view,
.dex-view {
  font-size: 0.9rem;
}

.manifest-view pre,
.code-editor pre {
  background: var(--bg-dark);
  padding: 1rem;
  border-radius: 4px;
  overflow-x: auto;
  font-family: 'Monaco', monospace;
  color: var(--primary);
}

.metadata-view table,
.native-view table,
.dex-view table {
  width: 100%;
  border-collapse: collapse;
}

.metadata-view table td {
  padding: 0.75rem;
  border-bottom: 1px solid var(--border);
}

.metadata-view table .label {
  color: var(--secondary);
  font-weight: bold;
  width: 30%;
}

.code-view {
  display: grid;
  grid-template-columns: 250px 1fr;
  gap: 1rem;
  height: 600px;
}

.code-sidebar {
  border-right: 1px solid var(--border);
  overflow-y: auto;
}

.code-sidebar input {
  width: 100%;
  padding: 0.5rem;
  background: var(--bg-dark);
  border: none;
  color: var(--text);
  border-bottom: 1px solid var(--border);
}

.class-list {
  max-height: 100%;
  overflow-y: auto;
}

.class-item {
  padding: 0.75rem;
  cursor: pointer;
  border-bottom: 1px solid var(--border);
  transition: background 0.2s;
}

.class-item:hover {
  background: var(--bg-dark);
}

.class-item.selected {
  background: var(--bg-dark);
  color: var(--primary);
  border-left: 3px solid var(--primary);
}

.code-editor {
  overflow-y: auto;
}

.strings-view input {
  width: 100%;
  padding: 0.75rem;
  background: var(--bg-dark);
  border: 1px solid var(--border);
  color: var(--text);
  margin-bottom: 1rem;
  border-radius: 4px;
}

.strings-list {
  display: grid;
  grid-template-columns: 1fr;
  gap: 0.5rem;
}

.string-item {
  padding: 0.5rem;
  background: var(--bg-dark);
  border-left: 3px solid var(--secondary);
  border-radius: 3px;
}

.string-item code {
  color: var(--secondary);
  font-size: 0.85rem;
  word-break: break-all;
}

Implementation Checklist

Backend


 Create backend/dissection.py with APKDissector class
 Implement all extraction methods (manifest, metadata, components, etc.)
 Add endpoints: /api/sample/{id}/dissection, /api/sample/{id}/dissection/manifest, etc.
 Wire dissection into run_analysis_task() to save dissection.json
 Handle errors (invalid APK, missing DEX, etc.)
 Test with your existing APKs


Frontend


 Create APKDissection.jsx with tabbed interface
 Implement ManifestTab, MetadataTab, CodeTab, StringsTab, NativeTab, DEXTab
 Create APKDissection.css styling
 Integrate into SampleDetail page
 Add search/filter to CodeTab and StringsTab
 Test with sample data


Dependencies to Add

Backend:

bashpip install axmlrpc  # for parsing binary XML

Frontend: (already in package.json)

react, react-dom, react-router-dom

Notes


Quick dissection: APKDissector doesn't run the full pipeline—it's fast (sub-second) for showing manifest, metadata, file structure.
Decompiled code: Load from JADX output or cache it during Step 1 (extraction).
Large APKs: Lazy-load code tabs (don't fetch all classes at once).
Search: Implement client-side search for strings and classes (fast, no backend roundtrip).
Threat context: Link dissection to threat analysis (highlight dangerous permissions, suspicious APIs).



Hand this prompt to Kimi and ask them to:


Implement backend/dissection.py with full APKDissector class
Add the three new endpoints to backend/main.py
Create frontend/src/components/APKDissection.jsx with all sub-components
Add styling to frontend/src/styles/APKDissection.css
Test the dissection flow end-to-end with one of your labeled samples
