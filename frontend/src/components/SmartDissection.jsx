import { useState, useEffect, useMemo } from 'react'
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

export default function SmartDissection({ sample, apiUrl, onSelectClass }) {
  const [dissectionData, setDissectionData] = useState(null)
  const [obfuscationData, setObfuscationData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('malicious')
  const [search, setSearch] = useState('')
  const [expandAll, setExpandAll] = useState(false)
  const [error, setError] = useState(null)

  const sampleId = sample?.sampleId || sample?.sha256 || sample?.uploadId

  useEffect(() => {
    fetchDissection()
  }, [sampleId])

  const fetchDissection = async () => {
    if (!sampleId) return
    try {
      setLoading(true)
      const [classesRes, obfRes] = await Promise.all([
        fetch(`${apiUrl}/api/sample/${sampleId}/dissection/classes`),
        fetch(`${apiUrl}/api/sample/${sampleId}/obfuscation`),
      ])
      if (!classesRes.ok) throw new Error(`HTTP ${classesRes.status}`)
      const classesData = await classesRes.json()
      const obfData = obfRes.ok ? await obfRes.json() : null
      setDissectionData(classesData)
      setObfuscationData(obfData)
      setError(null)
    } catch (err) {
      setError('Failed to load dissection: ' + err.message)
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const allClasses = dissectionData?.classes || []

  const obfuscatedClasses = useMemo(() => {
    const names = new Set()
    const techniques = obfuscationData?.techniques || []
    techniques.forEach(tech => {
      (tech.items || []).forEach(item => {
        if (item.class) names.add(item.class)
      })
    })
    return names
  }, [obfuscationData])

  const isObfuscatedClass = (cls) => obfuscatedClasses.has(cls.name)

  const filteredClasses = useMemo(() => {
    let classes = allClasses
    if (filter === 'malicious') {
      classes = classes.filter(cls => isSuspiciousClass(cls))
    } else if (filter === 'obfuscated') {
      classes = classes.filter(cls => isObfuscatedClass(cls))
    }

    if (search.trim()) {
      const q = search.toLowerCase()
      classes = classes.filter(cls =>
        cls.name.toLowerCase().includes(q) ||
        (cls.methods || []).some(m => m.name.toLowerCase().includes(q)) ||
        (cls.network_calls || []).some(c => c.toLowerCase().includes(q))
      )
    }

    return classes
  }, [allClasses, filter, search, obfuscatedClasses])

  const suspiciousCount = allClasses.filter(isSuspiciousClass).length
  const obfuscatedCount = allClasses.filter(isObfuscatedClass).length

  if (loading) {
    return (
      <div className="state-container modern-empty">
        <div className="analysis-loading-spinner"></div>
        <h3 className="state-title">Loading Code Dissection</h3>
        <p className="state-description">Fetching decompiled classes and suspicious method analysis...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="state-container error-container modern-empty">
        <span className="state-icon">⚠</span>
        <h3 className="state-title">Dissection Error</h3>
        <p className="state-description">{error}</p>
      </div>
    )
  }

  return (
    <div className="dissection">
      <div className="dissection-toolbar card">
        <div className="dissection-filters">
          <FilterButton
            active={filter === 'malicious'}
            onClick={() => setFilter('malicious')}
            label="Suspicious"
            count={suspiciousCount}
            color="rose"
          />
          <FilterButton
            active={filter === 'obfuscated'}
            onClick={() => setFilter('obfuscated')}
            label="Obfuscated"
            count={obfuscatedCount}
            color="violet"
          />
          <FilterButton
            active={filter === 'all'}
            onClick={() => setFilter('all')}
            label="All Classes"
            count={allClasses.length}
            color="cyan"
          />
        </div>
        <div className="dissection-toolbar-right">
          <button
            className={`expand-all-button ${expandAll ? 'active' : ''}`}
            onClick={() => setExpandAll(v => !v)}
            title={expandAll ? 'Collapse all method bodies' : 'Expand all method bodies'}
          >
            {expandAll ? 'Collapse code' : 'Expand code'}
          </button>
          <div className="dissection-search">
            <span className="search-icon">🔎</span>
            <input
              type="text"
              placeholder="Search class or method name..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>
      </div>

      <div className="dissection-results card">
        <div className="dissection-results-header">
          <span className="section-title">
            {filter === 'malicious' ? 'Suspicious Classes' : filter === 'obfuscated' ? 'Obfuscated Classes' : 'All Classes'}
          </span>
          <span className="results-count">{filteredClasses.length} result(s)</span>
        </div>

        {filteredClasses.length === 0 ? (
          <div className="dissection-empty">
            <span className="empty-icon">🔍</span>
            <p>No matching classes found</p>
          </div>
        ) : (
          <div className="classes-list">
            {filteredClasses.map((cls, idx) => (
              <ClassCard
                key={idx}
                classData={cls}
                isObfuscated={isObfuscatedClass(cls)}
                expandAll={expandAll}
                onSelectClass={onSelectClass}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function FilterButton({ active, onClick, label, count, color }) {
  return (
    <button
      className={`filter-button filter-${color} ${active ? 'active' : ''}`}
      onClick={onClick}
    >
      <span>{label}</span>
      <span className="filter-count">{count}</span>
    </button>
  )
}

function ClassCard({ classData, isObfuscated, expandAll, onSelectClass }) {
  const [expanded, setExpanded] = useState(false)
  const [showAllMethods, setShowAllMethods] = useState(false)

  const methods = useMemo(() => {
    const list = (classData.methods || []).slice().sort((a, b) => {
      const sa = methodSuspicionScore(a)
      const sb = methodSuspicionScore(b)
      return sb - sa
    })
    return list
  }, [classData.methods])

  const suspiciousMethodCount = methods.filter(m => methodSuspicionScore(m) > 0).length
  const isSuspicious = suspiciousMethodCount > 0 || hasNetworkCall(classData)
  const displayMethods = showAllMethods ? methods : methods.slice(0, METHODS_PREVIEW_LIMIT)

  return (
    <div className={`class-card ${isSuspicious ? 'suspicious' : ''} ${isObfuscated ? 'obfuscated' : ''}`}>
      <div className="class-header" onClick={() => setExpanded(!expanded)}>
        <div className="class-header-left">
          <span className="class-expand">{expanded ? '▼' : '▶'}</span>
          <span className="class-name text-mono" title={classData.name}>{classData.name}</span>
        </div>
        <div className="class-header-right">
          {isObfuscated && <span className="class-badge badge-violet">Obfuscated</span>}
          {isSuspicious && <span className="class-badge badge-high">Suspicious</span>}
          {suspiciousMethodCount > 0 && (
            <span className="class-badge badge-amber">{suspiciousMethodCount} hit(s)</span>
          )}
          {(classData.network_calls || []).length > 0 && (
            <span className="class-badge badge-cyan">{classData.network_calls.length} network</span>
          )}
          {onSelectClass && (
            <button
              className="class-badge view-source-btn"
              onClick={(e) => {
                e.stopPropagation()
                onSelectClass(classData.name)
              }}
              title="View decompiled source"
            >
              View source
            </button>
          )}
          <span className="class-badge badge-slate">{methods.length} method(s)</span>
        </div>
      </div>

      {expanded && (
        <div className="class-body">
          <div className="class-section">
            <div className="class-section-header">
              <h4 className="section-title">Methods</h4>
              <span className="class-section-meta">{methods.length} total</span>
            </div>
            {methods.length > 0 ? (
              <div className="methods-list">
                {displayMethods.map((method, idx) => (
                  <MethodCard key={idx} method={method} expandAll={expandAll} />
                ))}
                {methods.length > METHODS_PREVIEW_LIMIT && (
                  <button
                    className="show-more-methods"
                    onClick={() => setShowAllMethods(v => !v)}
                  >
                    {showAllMethods ? `Show first ${METHODS_PREVIEW_LIMIT} methods` : `Show ${methods.length - METHODS_PREVIEW_LIMIT} more methods`}
                  </button>
                )}
              </div>
            ) : (
              <p className="class-empty">No methods available</p>
            )}
          </div>

          <div className="class-section">
            <h4 className="section-title">Network Activity</h4>
            {classData.network_calls && classData.network_calls.length > 0 ? (
              <div className="network-calls">
                {classData.network_calls.map((call, idx) => (
                  <div key={idx} className="network-call-chip text-mono" title={call}>{call}</div>
                ))}
              </div>
            ) : (
              <p className="class-empty">No network activity detected</p>
            )}
          </div>

          <div className="class-section">
            <h4 className="section-title">Permissions Used</h4>
            {classData.permissions_used && classData.permissions_used.length > 0 ? (
              <div className="permissions-cloud">
                {classData.permissions_used.map((perm, idx) => (
                  <span key={idx} className="permission-mini">{perm.split('.').pop()}</span>
                ))}
              </div>
            ) : (
              <p className="class-empty">No permission checks detected</p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function MethodCard({ method, expandAll }) {
  const [expanded, setExpanded] = useState(false)

  useEffect(() => {
    setExpanded(expandAll)
  }, [expandAll])

  const matchedKeyword = SUSPICIOUS_KEYWORDS.find(kw =>
    method.name.toLowerCase().includes(kw.toLowerCase()) ||
    (method.body && method.body.toLowerCase().includes(kw.toLowerCase()))
  )

  const bodyLines = method.body ? method.body.split('\n').filter(l => l.trim() !== '') : []
  const previewLines = bodyLines.slice(0, 3)

  return (
    <div className={`method-card ${matchedKeyword ? 'method-suspicious' : ''}`}>
      <div className="method-header" onClick={() => setExpanded(!expanded)}>
        <div className="method-header-left">
          <span className="method-expand">{expanded ? '▼' : '▶'}</span>
          <span className="method-name text-mono">{method.name}</span>
        </div>
        <div className="method-header-right">
          {bodyLines.length > 0 && (
            <span className="method-line-count">{bodyLines.length} lines</span>
          )}
          {matchedKeyword && (
            <span className={`method-keyword keyword-${KEYWORD_COLORS[matchedKeyword] || 'rose'}`}>
              {matchedKeyword}
            </span>
          )}
        </div>
      </div>

      {method.body && (
        <div className={`method-body ${expanded ? 'expanded' : 'preview'}`}>
          {expanded ? (
            <CodeHighlight code={method.body} />
          ) : (
            <div className="method-preview">
              <CodeHighlight code={previewLines.join('\n')} />
              {bodyLines.length > 3 && (
                <button className="preview-expand" onClick={() => setExpanded(true)}>
                  Show full code ({bodyLines.length - 3} more lines)
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function CodeHighlight({ code }) {
  const lines = code.split('\n')
  return (
    <pre className="code-block">
      {lines.map((line, idx) => {
        const isSuspicious = SUSPICIOUS_KEYWORDS.some(kw => line.toLowerCase().includes(kw.toLowerCase()))
        return (
          <div key={idx} className={`code-line ${isSuspicious ? 'suspicious-line' : ''}`}>
            <span className="line-num">{idx + 1}</span>
            <code>{highlightSyntax(line)}</code>
          </div>
        )
      })}
    </pre>
  )
}

function highlightSyntax(line) {
  let highlighted = line
  SUSPICIOUS_KEYWORDS.forEach(keyword => {
    const regex = new RegExp(`\\b${keyword}\\b`, 'gi')
    highlighted = highlighted.replace(regex, `<span class="code-keyword">${keyword}</span>`)
  })
  return <code dangerouslySetInnerHTML={{ __html: highlighted }} />
}

function methodSuspicionScore(method) {
  let score = 0
  if (!method.body) return score
  SUSPICIOUS_KEYWORDS.forEach(kw => {
    if (method.name.toLowerCase().includes(kw.toLowerCase())) score += 2
    const bodyLower = method.body.toLowerCase()
    if (bodyLower.includes(kw.toLowerCase())) score += 1
  })
  return score
}

function isSuspiciousClass(cls) {
  if (UNWANTED_PATTERNS.some(pattern => pattern.test(cls.name))) {
    return false
  }
  if ((cls.methods || []).some(method => methodSuspicionScore(method) > 0)) {
    return true
  }
  return hasNetworkCall(cls)
}

function hasNetworkCall(cls) {
  const networkPatterns = ['HttpURLConnection', 'socket', 'URLConnection', 'okhttp', 'retrofit']
  return networkPatterns.some(pattern =>
    (cls.methods || []).some(method =>
      method.name.toLowerCase().includes(pattern.toLowerCase()) ||
      (method.body && method.body.toLowerCase().includes(pattern.toLowerCase()))
    )
  )
}
