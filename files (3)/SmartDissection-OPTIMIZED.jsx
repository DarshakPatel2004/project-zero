import { useState, useEffect, useMemo, useReducer, useCallback, memo } from 'react'
import '../styles/SmartDissection.css'

const UNWANTED_PATTERNS = [
  /android\.support\..*/,
  /androidx\..*\.R\$/,
  /androidx\..*\.BuildConfig/,
  /com\.android\.internal\..*/,
  /android\.view\.View\$/,
  /com\.google\.android\..*BuildConfig/,
  /\$\d+/,
  /\$StaticInjectorHolder/,
  /\$Lambda/,
  /kotlin\.jvm\.JvmStatic/,
  /kotlin\.jvm\.JvmOverloads/,
  /kotlin\.Metadata/,
  /super\(\)/,
  /onCreate\(\)/,
  /onDestroy\(\)/,
  /getIntent\(\)/,
  /setContentView\(/,
  /findViewById\(/,
]

const SUSPICIOUS_KEYWORDS = [
  'invoke', 'Cipher', 'ClassLoader', 'reflect', 'DexClassLoader',
  'Runtime.exec', 'ProcessBuilder', 'HttpURLConnection', 'Base64',
  'decode', 'encrypt', 'socket', 'intent', 'permission',
]

const KEYWORD_COLORS = {
  'Cipher': 'violet', 'ClassLoader': 'cyan', 'DexClassLoader': 'cyan',
  'reflect': 'amber', 'Runtime.exec': 'rose', 'ProcessBuilder': 'rose',
  'HttpURLConnection': 'emerald', 'socket': 'emerald', 'Base64': 'amber',
  'decode': 'amber', 'encrypt': 'violet', 'permission': 'cyan',
}

const METHODS_PREVIEW_LIMIT = 20
const VIRTUALIZATION_BUFFER = 50

// ============================================================================
// State Reducer for Better Performance
// ============================================================================
const initialState = {
  dissectionData: null,
  obfuscationData: null,
  loading: true,
  filter: 'malicious',
  search: '',
  expandAll: false,
  error: null,
  expandedClasses: new Set(),
}

function stateReducer(state, action) {
  switch (action.type) {
    case 'SET_DISSECTION_DATA':
      return { ...state, dissectionData: action.payload }
    case 'SET_OBFUSCATION_DATA':
      return { ...state, obfuscationData: action.payload }
    case 'SET_LOADING':
      return { ...state, loading: action.payload }
    case 'SET_FILTER':
      return { ...state, filter: action.payload }
    case 'SET_SEARCH':
      return { ...state, search: action.payload }
    case 'SET_ERROR':
      return { ...state, error: action.payload }
    case 'SET_EXPAND_ALL':
      return { ...state, expandAll: action.payload }
    case 'TOGGLE_CLASS':
      const newExpanded = new Set(state.expandedClasses)
      if (newExpanded.has(action.payload)) {
        newExpanded.delete(action.payload)
      } else {
        newExpanded.add(action.payload)
      }
      return { ...state, expandedClasses: newExpanded }
    default:
      return state
  }
}

// ============================================================================
// Memoized ClassItem Component (prevents re-renders of off-screen items)
// ============================================================================
const ClassItem = memo(function ClassItem({
  classObj,
  isExpanded,
  onToggle,
  obfuscationData,
}) {
  if (!classObj) return null

  const hitCount = classObj.hits || 0
  const suspiciousKeywords = classObj.suspicious_keywords || []
  const suspicious = classObj.suspicious || false
  const obfuscated = classObj.obfuscated || false

  const obfuscationInfo = obfuscationData?.classes?.[classObj.class_name] || {}
  const obfuscationScore = obfuscationInfo.score || 0

  return (
    <div className="class-item">
      <div className="class-header" onClick={onToggle}>
        <span className={`chevron ${isExpanded ? 'expanded' : ''}`}>▶</span>
        <span className="class-name">{classObj.class_name}</span>
        <div className="class-badges">
          {suspicious && (
            <span className="badge suspicious">Suspicious</span>
          )}
          {obfuscated && (
            <span className="badge obfuscated">Obfuscated</span>
          )}
          {hitCount > 0 && (
            <span className="badge hit-count">{hitCount} hit(s)</span>
          )}
          {obfuscationScore > 0.7 && (
            <span className="badge obfuscation">
              {(obfuscationScore * 100).toFixed(0)}%
            </span>
          )}
        </div>
      </div>

      {isExpanded && (
        <div className="class-details">
          {suspiciousKeywords.length > 0 && (
            <div className="methods-list">
              <div className="methods-label">
                Suspicious methods ({suspiciousKeywords.length}):
              </div>
              {suspiciousKeywords.slice(0, METHODS_PREVIEW_LIMIT).map((kw, i) => {
                const colorClass = KEYWORD_COLORS[kw] || 'gray'
                return (
                  <span key={i} className={`keyword keyword-${colorClass}`}>
                    {kw}
                  </span>
                )
              })}
              {suspiciousKeywords.length > METHODS_PREVIEW_LIMIT && (
                <span className="keywords-overflow">
                  +{suspiciousKeywords.length - METHODS_PREVIEW_LIMIT} more
                </span>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
})

// ============================================================================
// Main Component
// ============================================================================
export default function SmartDissection({ sample, apiUrl, onSelectClass }) {
  const [state, dispatch] = useReducer(stateReducer, initialState)
  const [scrollTop, setScrollTop] = useState(0)

  const sampleId = sample?.sampleId || sample?.sha256 || sample?.uploadId

  useEffect(() => {
    fetchDissection()
  }, [sampleId])

  const fetchDissection = async () => {
    if (!sampleId) return
    try {
      dispatch({ type: 'SET_LOADING', payload: true })
      const [classesRes, obfRes] = await Promise.all([
        fetch(`${apiUrl}/api/sample/${sampleId}/dissection/classes`),
        fetch(`${apiUrl}/api/sample/${sampleId}/obfuscation`),
      ])
      if (!classesRes.ok) throw new Error(`HTTP ${classesRes.status}`)
      const classesData = await classesRes.json()
      const obfData = obfRes.ok ? await obfRes.json() : null

      // Check if JADX decompilation failed
      if (!classesData.jadx_success && classesData.error) {
        dispatch({
          type: 'SET_ERROR',
          payload: `Code Decompilation Failed: ${classesData.error}. ${classesData.details ? classesData.details.join('; ') : 'Check JADX installation.'}`,
        })
        dispatch({ type: 'SET_DISSECTION_DATA', payload: classesData })
      } else {
        dispatch({ type: 'SET_DISSECTION_DATA', payload: classesData })
        dispatch({ type: 'SET_ERROR', payload: null })
      }

      dispatch({ type: 'SET_OBFUSCATION_DATA', payload: obfData })
    } catch (err) {
      dispatch({
        type: 'SET_ERROR',
        payload: 'Failed to load dissection: ' + err.message,
      })
      console.error(err)
    } finally {
      dispatch({ type: 'SET_LOADING', payload: false })
    }
  }

  // ========================================================================
  // Filtering Logic (memoized to prevent recalculation on every render)
  // ========================================================================
  const filteredClasses = useMemo(() => {
    if (!state.dissectionData?.classes) return []

    let classes = state.dissectionData.classes

    // Apply filter
    if (state.filter === 'suspicious') {
      classes = classes.filter((cls) => cls.suspicious)
    } else if (state.filter === 'obfuscated') {
      classes = classes.filter((cls) => cls.obfuscated)
    }

    // Apply search
    if (state.search.trim()) {
      const query = state.search.toLowerCase()
      classes = classes.filter((cls) =>
        cls.class_name.toLowerCase().includes(query) ||
        (cls.suspicious_keywords || []).some((kw) =>
          kw.toLowerCase().includes(query)
        )
      )
    }

    return classes
  }, [state.dissectionData, state.filter, state.search])

  // ========================================================================
  // Virtualization: Only render visible items + buffer
  // ========================================================================
  const itemHeight = 48 // Approximate height of a class item
  const containerHeight = 800 // Approximate visible height

  const startIndex = Math.max(
    0,
    Math.floor(scrollTop / itemHeight) - VIRTUALIZATION_BUFFER
  )
  const endIndex = Math.min(
    filteredClasses.length,
    Math.ceil((scrollTop + containerHeight) / itemHeight) + VIRTUALIZATION_BUFFER
  )

  const visibleClasses = filteredClasses.slice(startIndex, endIndex)
  const offsetY = startIndex * itemHeight

  const handleScroll = useCallback((e) => {
    setScrollTop(e.target.scrollTop)
  }, [])

  const handleToggleClass = useCallback((className) => {
    dispatch({ type: 'TOGGLE_CLASS', payload: className })
  }, [])

  // ========================================================================
  // Render
  // ========================================================================
  if (error && !state.dissectionData?.classes) {
    return (
      <div className="dissection-error">
        <div className="error-icon">⚠</div>
        <div className="error-title">Dissection Error</div>
        <div className="error-message">{error}</div>
      </div>
    )
  }

  if (state.loading) {
    return (
      <div className="dissection-loading">
        <div className="spinner"></div>
        <p>Fetching decompiled classes and suspicious method analysis...</p>
      </div>
    )
  }

  const allClasses = state.dissectionData?.classes || []
  const suspiciousCount = allClasses.filter((c) => c.suspicious).length
  const obfuscatedCount = allClasses.filter((c) => c.obfuscated).length

  return (
    <div className="smart-dissection">
      {error && (
        <div className="dissection-warning">
          <span>⚠</span>
          <span>{error}</span>
        </div>
      )}

      <div className="dissection-toolbar">
        <div className="filter-buttons">
          <button
            className={`filter-btn ${state.filter === 'malicious' ? 'active' : ''}`}
            onClick={() => dispatch({ type: 'SET_FILTER', payload: 'malicious' })}
          >
            <span className="icon">⚡</span>
            Suspicious ({suspiciousCount})
          </button>
          <button
            className={`filter-btn ${state.filter === 'obfuscated' ? 'active' : ''}`}
            onClick={() => dispatch({ type: 'SET_FILTER', payload: 'obfuscated' })}
          >
            <span className="icon">🔐</span>
            Obfuscated ({obfuscatedCount})
          </button>
          <button
            className={`filter-btn ${state.filter === 'all' ? 'active' : ''}`}
            onClick={() => dispatch({ type: 'SET_FILTER', payload: 'all' })}
          >
            <span className="icon">📦</span>
            All Classes ({allClasses.length})
          </button>
        </div>

        <div className="toolbar-controls">
          <button
            className="expand-btn"
            onClick={() => {
              dispatch({ type: 'SET_EXPAND_ALL', payload: !state.expandAll })
              if (!state.expandAll) {
                const newExpanded = new Set(
                  filteredClasses.map((c) => c.class_name)
                )
                // Update expanded classes in a way that doesn't break performance
                filteredClasses.forEach((cls) => {
                  dispatch({ type: 'TOGGLE_CLASS', payload: cls.class_name })
                })
              }
            }}
          >
            {state.expandAll ? 'Collapse all' : 'Expand all'}
          </button>
          <input
            type="text"
            className="search-input"
            placeholder="Search class or method name..."
            value={state.search}
            onChange={(e) =>
              dispatch({ type: 'SET_SEARCH', payload: e.target.value })
            }
          />
        </div>
      </div>

      <div className="classes-list-container" onScroll={handleScroll}>
        <div className="classes-list-header">
          <span className="result-count">
            {filteredClasses.length} result(s)
          </span>
        </div>

        <div
          className="classes-list"
          style={{ height: filteredClasses.length * itemHeight }}
        >
          <div style={{ transform: `translateY(${offsetY}px)` }}>
            {visibleClasses.map((classObj) => (
              <ClassItem
                key={classObj.class_name}
                classObj={classObj}
                isExpanded={state.expandedClasses.has(classObj.class_name)}
                onToggle={() => handleToggleClass(classObj.class_name)}
                obfuscationData={state.obfuscationData}
              />
            ))}
          </div>
        </div>

        {filteredClasses.length === 0 && (
          <div className="no-results">No matching classes found</div>
        )}
      </div>
    </div>
  )
}
