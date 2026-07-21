import { useCallback, useEffect, useMemo, useReducer, useRef, useState, type DragEvent } from "react";

const API_URL = 'http://localhost:8000';
const WS_URL = 'ws://localhost:8000/ws';

type Page = "upload" | "analysis" | "dissection" | "intel";
type Tab = "Overview" | "Secrets" | "LLM Summary" | "Dissection Summary" | "Obfuscation" | "Threat Chains" | "Manifest";

function riskTone(risk: number) { return risk > 80 ? "critical" : risk > 40 ? "warning" : "safe"; }
function Badge({ children, tone = "neutral" }: { children: React.ReactNode; tone?: string }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}
function Meter({ value, className = "" }: { value: number; className?: string }) {
  return <div className={`meter ${className}`}><i style={{ width: `${value}%` }} /></div>;
}

function estimateEtaSeconds(fileSizeBytes: number) {
  if (fileSizeBytes < 1_000_000) return 2.0 * 9;
  if (fileSizeBytes < 10_000_000) return 3.5 * 9;
  return 5.0 * 9;
}

interface Sample {
  id?: string;
  sha256: string;
  fileName: string;
  status: string;
  uploadedAt: string;
  uploadId?: string;
  fileSize?: number;
  severity?: string;
  risk_score?: number;
}

interface Secret {
  severity: string;
  secret_type: string;
  value: string;
  decoded: string;
  source: string;
  occurrence_count: number;
}

interface ThreatChain {
  chain_id: string;
  severity: string;
  confidence: number;
  steps: Array<{
    step: number;
    type: string;
    artifact: string;
    source_location: string;
    confidence: number;
  }>;
}

interface C2Endpoint {
  c2_id: string;
  domain?: string;
  ip?: string;
  protocol?: string;
  port?: number;
  path?: string;
  status?: string;
  classification?: string;
}

interface FullResult {
  metadata: {
    sample_name?: string;
    package_name?: string;
    sha256?: string;
    file_size_bytes?: number;
  };
  llm_assessment?: {
    severity?: string;
    risk_score?: number;
    narrative?: string;
    primary_threat?: string;
    recommended_actions?: string[];
    confidence?: number;
    suspicious_methods?: Array<{ method_name: string; reason: string }>;
  };
  extraction?: {
    total_strings_extracted?: number;
    decompiled_classes?: number;
  };
  hardcoded_secrets?: Secret[];
  secret_risk?: {
    total_secrets: number;
    risk_score: number;
    by_severity?: { critical?: number; high?: number; medium?: number; low?: number };
  };
  c2_infrastructure?: C2Endpoint[];
  threat_chains?: ThreatChain[];
  manifest?: {
    version_name?: string;
    version_code?: string;
    package?: string;
    target_sdk_version?: string;
    min_sdk_version?: string;
    uses_permissions?: string[];
  };
}

interface ObfuscationData {
  obfuscation_score: number;
  obfuscation_level: string;
  techniques?: Array<{
    name: string;
    key: string;
    count: number;
    items: Array<{ class: string; detail: string }>;
  }>;
}

interface DissectionSummary {
  threat_level: string;
  risk_score: number;
  summary: string;
  key_behaviors: string[];
  suspicious_methods: string[];
  c2_indicators: string[];
  recommended_focus: string[];
}

interface ThreatIntelData {
  dns: { active: number; likely_active: number; dead: number };
  classification: { malicious: number; suspicious: number; benign: number };
  ips_geolocated: Array<{
    ip: string; country: string; region: string; isp: string;
    latitude: number; longitude: number;
  }>;
  c2s: C2Endpoint[];
  family: {
    family: string; confidence: number; method: string;
    reasoning: string; candidates: Array<{ family: string; source: string; confidence: number }>;
  } | null;
}

interface DissectionClass {
  name: string;
  method_count: number;
  method_names: string[];
  network_calls: string[];
  permissions_used: string[];
}

const apiGet = async <T,>(path: string): Promise<T> => {
  const res = await fetch(`${API_URL}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
  return res.json();
};

function analysisReducer(state: any, action: any) {
  switch (action.type) {
    case 'RESET':
      return {
        sampleId: null, status: null, progress: 0, eta: null, startTime: null,
        metrics: { c2_count: 0, encoding_count: 0, payload_count: 0, threat_chain_count: 0 },
        stepTimings: {}, verdictData: null, fullReport: null, error: null, errorType: null,
      };
    case 'ANALYSIS_STARTED':
      return { ...state, sampleId: action.payload.sample_id, status: 'running', progress: 0, eta: action.payload.predicted_eta_seconds || null, startTime: state.startTime || Date.now(), stepTimings: {}, error: null };
    case 'STEP_COMPLETED':
      return { ...state, progress: action.payload.progress_percent || action.payload.step_number / 9 * 100, eta: action.payload.remaining_eta_seconds, stepTimings: { ...state.stepTimings, [action.payload.step_name]: action.payload.duration_seconds } };
    case 'METRIC_UPDATED':
      return { ...state, metrics: { ...state.metrics, [action.payload.metric_name]: action.payload.metric_value } };
    case 'ANALYSIS_COMPLETE':
      return { ...state, sampleId: action.payload.sample_id || state.sampleId, status: 'complete', progress: 100, eta: 0, verdictData: { verdict: action.payload.final_verdict, riskScore: action.payload.risk_score, totalDuration: action.payload.total_duration_seconds }, fullReport: action.payload.full_report || null };
    case 'ERROR':
      return { ...state, status: 'error', error: action.payload.error_message, errorType: action.payload.error_type || 'internal_error' };
    default: return state;
  }
}

export default function App() {
  const [page, setPage] = useState<Page>("upload");
  const [tab, setTab] = useState<Tab>("Overview");
  const [toast, setToast] = useState("");
  const [drawer, setDrawer] = useState(false);

  const [samples, setSamples] = useState<Sample[]>([]);
  const [selectedSample, setSelectedSample] = useState<Sample | null>(null);
  const [fullResult, setFullResult] = useState<FullResult | null>(null);
  const [obfuscationData, setObfuscationData] = useState<ObfuscationData | null>(null);
  const [dissectionSummary, setDissectionSummary] = useState<DissectionSummary | null>(null);
  const [threatIntel, setThreatIntel] = useState<ThreatIntelData | null>(null);
  const [dissectionClasses, setDissectionClasses] = useState<DissectionClass[]>([]);
  const [dissectionMethods, setDissectionMethods] = useState<any>(null);
  const [expandedClass, setExpandedClass] = useState<string | null>(null);
  const [sourceCode, setSourceCode] = useState<string | null>(null);
  const [sourceClass, setSourceClass] = useState<string | null>(null);
  const [explainResult, setExplainResult] = useState<any>(null);
  const [chainExplains, setChainExplains] = useState<Record<string, any>>({});
  const [backendOnline, setBackendOnline] = useState(false);

  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [uploadFileName, setUploadFileName] = useState("");
  const timer = useRef<number | undefined>(undefined);
  const wsRef = useRef<WebSocket | null>(null);

  const [analysisState, dispatch] = useReducer(analysisReducer, {
    sampleId: null, status: null, progress: 0, eta: null, startTime: null,
    metrics: { c2_count: 0, encoding_count: 0, payload_count: 0, threat_chain_count: 0 },
    stepTimings: {}, verdictData: null, fullReport: null, error: null, errorType: null,
  });

  const fetchSamples = useCallback(async () => {
    try {
      const data = await apiGet<{ samples: any[]; total: number }>('/api/samples');
      setSamples(data.samples.map((s: any) => ({
        sha256: s.sha256 || s.id,
        fileName: s.name || s.sample_name,
        status: s.status,
        uploadedAt: s.analyzed_at || '',
        uploadId: s.upload_id || s.id,
        fileSize: s.file_size_bytes,
        severity: s.severity,
        risk_score: s.risk_score,
      })));
    } catch { }
  }, []);

  useEffect(() => {
    const checkBackend = async () => {
      try {
        const res = await fetch(`${API_URL}/`, { signal: AbortSignal.timeout(3000) });
        if (res.ok) {
          setBackendOnline(true);
          setToast("Live scanner connected — waiting for an APK.");
          fetchSamples();
        }
      } catch { setBackendOnline(false); }
    };
    checkBackend();
    const interval = setInterval(checkBackend, 10000);
    return () => clearInterval(interval);
  }, [fetchSamples]);

  useEffect(() => {
    let ws: WebSocket;
    let pingTimer: number;
    const connect = () => {
      ws = new WebSocket(WS_URL);
      wsRef.current = ws;
      ws.onopen = () => {
        ws.send(JSON.stringify({ action: 'ping' }));
        pingTimer = window.setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ action: 'ping' }));
        }, 20000);
      };
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          const { event_type, data } = msg;
          switch (event_type) {
            case 'analysis_started':
              dispatch({ type: 'ANALYSIS_STARTED', payload: data });
              break;
            case 'step_completed':
              dispatch({ type: 'STEP_COMPLETED', payload: data });
              break;
            case 'metric_updated':
              dispatch({ type: 'METRIC_UPDATED', payload: data });
              break;
            case 'analysis_complete':
              dispatch({ type: 'ANALYSIS_COMPLETE', payload: data });
              if (data.sample_id || selectedSample?.sha256) {
                const sid = data.sample_id || selectedSample?.sha256;
                apiGet<FullResult>(`/api/sample/${sid}`).then(r => setFullResult(r)).catch(() => { });
                fetchSamples();
              }
              break;
            case 'error':
              dispatch({ type: 'ERROR', payload: data });
              break;
          }
        } catch { }
      };
      ws.onclose = () => {
        clearInterval(pingTimer);
        setTimeout(connect, 3000);
      };
    };
    connect();
    return () => { clearInterval(pingTimer); ws?.close(); };
  }, []);

  const loadSampleData = useCallback(async (sample: Sample) => {
    const sampleId = sample.sha256 || sample.uploadId;
    if (!sampleId) return;
    try {
      const result = await apiGet<FullResult>(`/api/sample/${sampleId}`);
      setFullResult(result);

      apiGet<DissectionSummary>(`/api/sample/${sampleId}/dissection/summary`)
        .then(s => setDissectionSummary(s)).catch(() => setDissectionSummary(null));
      apiGet<ObfuscationData>(`/api/sample/${sampleId}/obfuscation`)
        .then(o => setObfuscationData(o)).catch(() => setObfuscationData(null));
      apiGet<ThreatIntelData>(`/api/sample/${sampleId}/threat-intel`)
        .then(t => setThreatIntel(t)).catch(() => setThreatIntel(null));
      apiGet<{ classes: DissectionClass[] }>(`/api/sample/${sampleId}/dissection/classes`)
        .then(c => setDissectionClasses(c.classes || [])).catch(() => setDissectionClasses([]));

      dispatch({ type: 'ANALYSIS_COMPLETE', payload: { sample_id: sampleId, final_verdict: result.llm_assessment?.severity || 'unknown', risk_score: result.llm_assessment?.risk_score || 0 } });
    } catch { }
  }, []);

  const handleSelectSample = (sample: Sample) => {
    setSelectedSample(sample);
    setPage('analysis');
    setDrawer(false);
    loadSampleData(sample);
  };

  const beginUpload = async (file?: File) => {
    if (file && !file.name.endsWith(".apk")) {
      setToast("Only signed Android APK files are accepted.");
      return;
    }
    if (!file) {
      setToast("No file selected.");
      return;
    }
    setUploadFileName(file.name);
    if (timer.current) window.clearInterval(timer.current);
    setUploading(true);
    setProgress(4);
    setToast(`Ingesting ${file.name} into the secure sandbox...`);

    timer.current = window.setInterval(() => setProgress(p => {
      const next = Math.min(p + Math.max(3, Math.round((100 - p) / 8)), 100);
      return next;
    }), 350);

    try {
      const formData = new FormData();
      formData.append('file', file);
      const res = await fetch(`${API_URL}/api/upload`, { method: 'POST', body: formData });
      if (!res.ok) throw new Error(`Upload failed: HTTP ${res.status}`);
      const data = await res.json();

      window.clearInterval(timer.current);
      setProgress(100);
      dispatch({ type: 'RESET' });

      const newSample: Sample = {
        uploadId: data.upload_id,
        sha256: data.sha256,
        fileName: file.name,
        status: 'uploaded',
        uploadedAt: new Date().toISOString(),
        fileSize: file.size,
      };
      setSamples(prev => [newSample, ...prev]);
      setSelectedSample(newSample);

      dispatch({
        type: 'ANALYSIS_STARTED',
        payload: { sample_id: data.sha256, sample_name: file.name, file_size_bytes: file.size, total_steps: 9, predicted_eta_seconds: estimateEtaSeconds(file.size) },
      });

      await fetch(`${API_URL}/api/analyze/${data.upload_id}`, { method: 'POST' });

      setToast("Analysis complete — fetching results.");
      setPage('analysis');

      setTimeout(async () => {
        try {
          const result = await apiGet<FullResult>(`/api/sample/${data.sha256}`);
          setFullResult(result);
          apiGet<DissectionSummary>(`/api/sample/${data.sha256}/dissection/summary`).then(s => setDissectionSummary(s)).catch(() => { });
          apiGet<ObfuscationData>(`/api/sample/${data.sha256}/obfuscation`).then(o => setObfuscationData(o)).catch(() => { });
          apiGet<ThreatIntelData>(`/api/sample/${data.sha256}/threat-intel`).then(t => setThreatIntel(t)).catch(() => { });
          apiGet<{ classes: DissectionClass[] }>(`/api/sample/${data.sha256}/dissection/classes`).then(c => setDissectionClasses(c.classes || [])).catch(() => { });
        } catch { }
      }, 2000);
    } catch (err: any) {
      setToast(`Upload failed: ${err.message}`);
      setUploading(false);
      setProgress(0);
    }
  };

  const handleExplainChain = async (chain: ThreatChain) => {
    if (chainExplains[chain.chain_id]) return;
    try {
      const res = await fetch(`${API_URL}/api/sample/${selectedSample?.sha256 || selectedSample?.uploadId}/explain-chain`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chain }),
      });
      const data = await res.json();
      if (data.llm) setChainExplains(prev => ({ ...prev, [chain.chain_id]: data.llm }));
    } catch { }
  };

  const handleExpandClass = async (className: string) => {
    if (expandedClass === className) { setExpandedClass(null); return; }
    setExpandedClass(className);
    const sampleId = selectedSample?.sha256 || selectedSample?.uploadId;
    if (!sampleId) return;
    try {
      const data = await apiGet<{ methods: Array<{ name: string; body: string }> }>(`/api/sample/${sampleId}/dissection/class-methods/${encodeURIComponent(className)}`);
      setDissectionMethods(data.methods || []);
    } catch { setDissectionMethods([]); }
  };

  const handleShowSource = async (className: string) => {
    setSourceClass(className);
    const sampleId = selectedSample?.sha256 || selectedSample?.uploadId;
    if (!sampleId) return;
    try {
      const data = await apiGet<{ code: string }>(`/api/sample/${sampleId}/dissection/code/${encodeURIComponent(className)}`);
      setSourceCode(data.code || '// No source available');
    } catch { setSourceCode('// Failed to load source'); }
  };

  const getActiveSampleName = () => selectedSample?.fileName || 'pulse-update.apk';
  const sampleIdForApi = selectedSample?.sha256 || selectedSample?.uploadId || '';

  const samplesList: Sample[] = samples.length > 0 ? samples : [];

  return <div className="app-shell">
    <aside className={`sidebar ${drawer ? "open" : ""}`}>
      <div className="brand"><span className="brand-mark">D</span><span>DROID<span>FORENSIX</span></span></div>
      <div className="nav-caption">WORKSPACE</div>
      {([["upload", "📤", "Upload"], ["analysis", "📊", "Analysis"], ["dissection", "🔍", "Dissection"], ["intel", "🛡️", "Threat Intel"]] as [Page, string, string][]).map(([id, icon, label]) => (
        <button key={id} onClick={() => { setPage(id); setDrawer(false); }} className={`nav-item ${page === id ? "active" : ""}`} disabled={id !== "upload" && !selectedSample}>
          <b>{icon}</b>{label}{id === "analysis" && fullResult?.hardcoded_secrets?.length ? <em>{fullResult.hardcoded_secrets.length}</em> : null}
        </button>
      ))}
      <div className="sidebar-bottom">
        <div className="case-card">
          <small>CURRENT CASE</small>
          <strong>{getActiveSampleName()}</strong>
          <span><i className={`pulse ${backendOnline ? "" : "offline"}`} /> {fullResult?.llm_assessment?.severity ? `${fullResult.llm_assessment.severity.toUpperCase()} · ${fullResult.llm_assessment.risk_score}/100` : backendOnline ? "SCANNER ONLINE" : "OFFLINE"}</span>
        </div>
        <button className="help">? &nbsp; Documentation</button>
      </div>
    </aside>
    <main className="main">
      <header className="topbar">
        <button className="menu" onClick={() => setDrawer(!drawer)}>☰</button>
        <div className="crumb">CASE / <strong>{page === "upload" ? "UPLOAD" : page.toUpperCase()}</strong></div>
        <div className="top-actions">
          <button className="selector">{getActiveSampleName()} <span>⌄</span></button>
          <span className={`online ${backendOnline ? "" : "offline"}`}><i />{backendOnline ? "SCANNER ONLINE" : "OFFLINE"}</span>
          <button className="avatar">DF</button>
        </div>
      </header>
      <section className="content">
        {page === "upload" && (
          <UploadPage
            samples={samplesList}
            uploading={uploading}
            progress={progress}
            onUpload={beginUpload}
            onSelectSample={handleSelectSample}
            analysisMetrics={analysisState.metrics}
            analysisStatus={analysisState.status}
          />
        )}
        {page === "analysis" && (
          <AnalysisPage
            tab={tab}
            setTab={setTab}
            fullResult={fullResult}
            dissectionSummary={dissectionSummary}
            obfuscationData={obfuscationData}
            threatIntel={threatIntel}
            sampleId={sampleIdForApi}
            analysisState={analysisState}
            chainExplains={chainExplains}
            onExplainChain={handleExplainChain}
            getActiveSampleName={getActiveSampleName}
          />
        )}
        {page === "dissection" && (
          <DissectionPage
            classes={dissectionClasses}
            expandedClass={expandedClass}
            dissectionMethods={dissectionMethods}
            sourceCode={sourceCode}
            sourceClass={sourceClass}
            onExpandClass={handleExpandClass}
            onShowSource={handleShowSource}
            onCloseSource={() => { setSourceCode(null); setSourceClass(null); }}
          />
        )}
        {page === "intel" && (
          <IntelPage threatIntel={threatIntel} sampleId={sampleIdForApi} />
        )}
      </section>
    </main>
    {toast && (
      <div className="toast">
        <span>✓</span>{toast}
        <button onClick={() => setToast("")}>×</button>
      </div>
    )}
  </div>;
}

function UploadPage({
  samples, uploading, progress, onUpload, onSelectSample, analysisMetrics, analysisStatus,
}: {
  samples: Sample[]; uploading: boolean; progress: number; onUpload: (file?: File) => void;
  onSelectSample: (s: Sample) => void; analysisMetrics: any; analysisStatus: string | null;
}) {
  const [search, setSearch] = useState("");
  const input = useRef<HTMLInputElement>(null);
  const onDrop = (e: DragEvent<HTMLDivElement>) => { e.preventDefault(); onUpload(e.dataTransfer.files[0]); };
  const filtered = useMemo(() => samples.filter(s =>
    s.sha256?.toLowerCase().includes(search.toLowerCase()) ||
    s.fileName?.toLowerCase().includes(search.toLowerCase()) ||
    s.status?.toLowerCase().includes(search.toLowerCase())
  ), [samples, search]);

  return <><div className="page-heading"><div><p className="eyebrow">ANDROID APPLICATION SECURITY</p><h1>Secure APK <span>analysis</span></h1><p>Drop an artifact into the sandbox. We map every suspicious execution path.</p></div><div className="live-stat"><i className="pulse" /> <b>{samples.length || 0}</b> APKs analyzed <span>• 0 false positives</span></div></div>
    <div className="upload-grid">
      <div className={`dropzone ${uploading ? "scanning" : ""}`} onDragOver={e => e.preventDefault()} onDrop={onDrop} onClick={() => !uploading && input.current?.click()}>
        <input ref={input} type="file" accept=".apk" onChange={e => onUpload(e.target.files?.[0])} />
        <div className="scan-orbit"><span>↑</span></div>
        {uploading ? (
          <><h2>Dissecting your artifact</h2><p>Unpacking DEX and mapping runtime behaviour</p><Meter value={progress} className="large" /><div className="progress-row"><b>{progress}% complete</b><span>ETA {Math.max(1, Math.ceil((100 - progress) / 18))} sec</span></div></>
        ) : (
          <><h2>Drop an APK here</h2><p>or click to browse from a secure local source</p><button className="primary">Choose APK file <span>→</span></button><small>APK only · maximum size 500 MB · SHA-256 preserved</small></>
        )}
      </div>
      <div className="scan-feed">
        <div className="panel-title"><span className="signal" /> LIVE TELEMETRY</div>
        {[
          ["Strings extracted", analysisStatus === 'running' ? "processing..." : (progress > 0 && progress < 100 ? "analyzing..." : "—"), "cyan"],
          ["Encodings found", analysisMetrics.encoding_count || "—", "violet"],
          ["Payloads unpacked", analysisMetrics.payload_count || "—", "amber"],
          ["C2 endpoints", analysisMetrics.c2_count || "—", "rose"],
          ["Threat chains", analysisMetrics.threat_chain_count || "—", "emerald"],
        ].map(x => (
          <div className="metric-row" key={x[0]}><span className={`dot ${x[2]}`} />{x[0]}<b>{x[1]}</b></div>
        ))}
        <div className="feed-lines">
          <p>› sandbox initialized</p>
          <p>› signatures loaded: 20</p>
          <p className={analysisStatus === 'running' || uploading ? "active-log" : ""}>
            › {uploading ? "analyzing classes.dex…" : analysisStatus === 'running' ? "running pipeline…" : "waiting for artifact"}
          </p>
        </div>
      </div>
    </div>
    <div className="history-head"><div><p className="eyebrow">RECENT ARTIFACTS</p><h2>Sample history</h2></div><div className="filter"><span>⌕</span><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search SHA or name" /></div></div>
    <div className="table-card"><table><thead><tr><th>FILE NAME</th><th>SHA256</th><th>STATUS</th><th>RISK SCORE</th><th /></tr></thead><tbody>{filtered.length === 0 ? (
      <tr><td colSpan={5} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>No samples analyzed yet. Upload an APK to get started.</td></tr>
    ) : filtered.map(s => (
      <tr key={s.sha256 || s.uploadId} onClick={() => onSelectSample(s)} style={{ cursor: 'pointer' }}>
        <td>{s.fileName}</td>
        <td className="mono">{(s.sha256 || '').substring(0, 16)}…</td>
        <td><Badge tone={riskTone(s.risk_score || 0)}>{s.status || s.severity || 'Unknown'}</Badge></td>
        <td><span className={`risk ${riskTone(s.risk_score || 0)}`}>{s.risk_score || 0}</span><Meter value={s.risk_score || 0} /></td>
        <td><button className="tiny-btn" onClick={(e) => { e.stopPropagation(); onSelectSample(s); }}>View →</button></td>
      </tr>
    ))}</tbody></table></div></>;
}

function AnalysisPage({
  tab, setTab, fullResult, dissectionSummary, obfuscationData, threatIntel, sampleId,
  analysisState, chainExplains, onExplainChain, getActiveSampleName,
}: {
  tab: Tab; setTab: (t: Tab) => void; fullResult: FullResult | null;
  dissectionSummary: DissectionSummary | null; obfuscationData: ObfuscationData | null;
  threatIntel: ThreatIntelData | null; sampleId: string; analysisState: any;
  chainExplains: Record<string, any>; onExplainChain: (chain: ThreatChain) => void;
  getActiveSampleName: () => string;
}) {
  const tabs: Tab[] = ["Overview", "Secrets", "LLM Summary", "Dissection Summary", "Obfuscation", "Threat Chains", "Manifest"];
  const secrets = fullResult?.hardcoded_secrets || [];
  const c2Count = fullResult?.c2_infrastructure?.length || 0;
  const chainCount = fullResult?.threat_chains?.length || 0;
  const riskScore = fullResult?.llm_assessment?.risk_score || 0;
  const severity = fullResult?.llm_assessment?.severity || 'unknown';

  if (analysisState.status === 'running') {
    return <div className="analysis-banner"><div><p className="eyebrow">ANALYSIS IN PROGRESS</p><h1>{getActiveSampleName()}<span> scanning...</span></h1></div><div className="score-box"><span>PROGRESS</span><strong>{Math.round(analysisState.progress)}<small>%</small></strong><Meter value={analysisState.progress} /></div></div>;
  }
  if (analysisState.status === 'error') {
    return <div className="analysis-banner"><div><p className="eyebrow">ANALYSIS ERROR</p><h1>Error <span>encountered</span></h1><p>{analysisState.error || 'An unknown error occurred.'}</p></div></div>;
  }

  return <><div className="analysis-banner">
    <div><p className="eyebrow">ANALYSIS REPORT · {secrets.length + chainCount} FINDINGS</p>
      <h1>{getActiveSampleName()} <span>v{fullResult?.manifest?.version_name || '?'}</span></h1>
      <p className="mono dim">SHA256 {fullResult?.metadata?.sha256?.substring(0, 16) || sampleId?.substring(0, 16) || '…'} · {fullResult?.metadata?.file_size_bytes ? `${(fullResult.metadata.file_size_bytes / 1024 / 1024).toFixed(1)} MB` : ''}</p></div>
    <div className="score-box"><span>RISK SCORE</span><strong>{riskScore}<small>/100</small></strong><Badge tone={riskTone(riskScore)}>{severity.toUpperCase()}</Badge></div>
  </div>
  <div className="tabs">{tabs.map(t => <button className={tab === t ? "selected" : ""} onClick={() => setTab(t)} key={t}>{t}{t === "Secrets" && secrets.length ? <em>{secrets.length}</em> : null}</button>)}</div>
  <div className="tab-body">
    {tab === "Overview" && <OverviewTab fullResult={fullResult} />}
    {tab === "Secrets" && <SecretsTab secrets={secrets} secretRisk={fullResult?.secret_risk} />}
    {tab === "LLM Summary" && <LlmTab llm={fullResult?.llm_assessment} />}
    {tab === "Dissection Summary" && <DissectionSummaryTab summary={dissectionSummary} />}
    {tab === "Obfuscation" && <ObfuscationTab data={obfuscationData} sampleId={sampleId} />}
    {tab === "Threat Chains" && <ChainsTab chains={fullResult?.threat_chains || []} chainExplains={chainExplains} onExplainChain={onExplainChain} sampleId={sampleId} />}
    {tab === "Manifest" && <ManifestTab manifest={fullResult?.manifest} />}
  </div></>;
}

function OverviewTab({ fullResult }: { fullResult: FullResult | null }) {
  if (!fullResult) return <div className="empty-state">No analysis data available.</div>;
  const llm = fullResult.llm_assessment;
  const extraction = fullResult.extraction;
  const stringsCount = extraction?.total_strings_extracted || 0;
  const classesCount = extraction?.decompiled_classes || 0;
  const c2Count = fullResult.c2_infrastructure?.length || 0;
  const chainCount = fullResult.threat_chains?.length || 0;
  const secretCount = fullResult.hardcoded_secrets?.length || 0;
  const actions = llm?.recommended_actions || [];
  const behaviors = llm?.suspicious_methods?.slice(0, 4) || [];

  return <><div className="assessment"><div className="scan-watermark">◈</div><p className="eyebrow">ASSESSMENT</p><h2>{llm?.narrative?.substring(0, 100) || llm?.primary_threat || 'No assessment available.'}</h2><p>{llm?.narrative || ''}</p><div><button className="primary">Export incident report →</button><button className="secondary">Open threat chains</button></div></div>
    <div className="kpi-grid">
      {[[(stringsCount || 0).toLocaleString(), "STRINGS EXTRACTED", "cyan"], [(classesCount || 0).toLocaleString(), "CLASSES", "violet"], [String(c2Count), "C2 ENDPOINTS", "rose"], [String(chainCount), "THREAT CHAINS", "amber"], [String(secretCount), "EXPOSED SECRETS", "rose"]].map(x => (
        <div className="kpi" key={x[1]}><span className={x[2]} /> <strong>{x[0]}</strong><small>{x[1]}</small></div>
      ))}
    </div>
    <div className="two-col">
      <section className="panel"><div className="panel-title">OBSERVED BEHAVIOURS <Badge tone="critical">HIGH CONFIDENCE</Badge></div>
        {behaviors.length === 0 ? <p className="muted">No behaviors recorded.</p> : behaviors.map((x: any, i: number) => (
          <p className="check" key={i}><b>{String(i + 1).padStart(2, "0")}</b>{typeof x === 'string' ? x : `${x.method_name}: ${x.reason}`}</p>
        ))}
      </section>
      <section className="panel"><div className="panel-title">RECOMMENDED ACTIONS</div>
        {actions.length === 0 ? <p className="muted">No recommendations.</p> : actions.map((a: string, i: number) => (
          <p className="action" key={i}><b>{String(i + 1).padStart(2, "0")} / </b>{a}</p>
        ))}
      </section>
    </div></>;
}

function SecretsTab({ secrets, secretRisk }: { secrets: Secret[]; secretRisk: any }) {
  if (!secrets.length) return <div className="empty-state">No secrets detected.</div>;
  const bySeverity = secretRisk?.by_severity || { critical: 0, high: 0, medium: 0 };
  return <><div className="severity-bar">
    <div><small>EXPOSED SECRET POSTURE</small><strong>{secrets.length} findings</strong></div>
    <div className="sev-count">
      <b className="critical">{bySeverity.critical || 0} <span>Critical</span></b>
      <b className="warning">{bySeverity.high || 0} <span>High</span></b>
      <b className="amber-text">{bySeverity.medium || 0} <span>Medium</span></b>
    </div>
    <div className="secret-score"><small>SECRETS RISK</small><strong>{secretRisk?.risk_score || 0}</strong><Meter value={secretRisk?.risk_score || 0} /></div>
  </div>
    <div className="secret-list">{secrets.map(s => (
      <article className="secret-card" key={s.secret_type}>
        <div><Badge tone={s.severity === "medium" ? "warning" : s.severity}>{s.severity?.toUpperCase() || 'MEDIUM'}</Badge><h3>{s.secret_type}</h3><p className="mono secret-value">{s.value?.substring(0, 60)}</p></div>
        <div className="decoded"><small>DECODED PREVIEW</small><p>✓ {s.decoded?.substring(0, 80)}</p></div>
        <div className="location"><small>SOURCE LOCATION</small><p className="mono">{s.source}</p><span>{s.occurrence_count} occurrence{s.occurrence_count !== 1 ? "s" : ""}</span></div>
      </article>
    ))}</div></>;
}

function LlmTab({ llm }: { llm: any }) {
  if (!llm) return <div className="empty-state">No LLM assessment available.</div>;
  return <div className="two-col">
    <section className="panel prose"><div className="panel-title"><span className="ai">✦</span> ANALYST MODEL SUMMARY</div>
      <h2>{llm.primary_threat || 'Analysis complete'}</h2>
      <p>{llm.narrative || 'No narrative provided.'}</p>
      {llm.confidence ? <p>Model confidence: {(llm.confidence * 100).toFixed(0)}%</p> : null}
    </section>
    <section className="panel"><div className="panel-title">SUSPICIOUS METHODS</div>
      {(llm.suspicious_methods || []).length === 0 ? <p className="muted">No suspicious methods identified.</p> :
        (llm.suspicious_methods || []).map((m: any, i: number) => (
          <p className="method" key={i}>{m.method_name || m}<span>→</span></p>
        ))
      }
      <button className="secondary wide">View method annotations</button>
    </section>
  </div>;
}

function DissectionSummaryTab({ summary }: { summary: DissectionSummary | null }) {
  if (!summary) return <div className="empty-state">No dissection summary available.</div>;
  return <div className="summary-layout">
    <section className="threat-dial"><div><small>THREAT LEVEL</small><strong>{summary.threat_level?.toUpperCase() || 'UNKNOWN'}</strong><p>{summary.risk_score} / 100 risk</p></div></section>
    <section className="panel"><div className="panel-title">KEY DISSECTION SIGNALS</div>
      <div className="signal-grid">
        {(summary.key_behaviors || []).length === 0 ? <p className="muted">No key behaviors identified.</p> :
          summary.key_behaviors?.slice(0, 4).map((b, i) => (
            <div key={i}><small>{i === 0 ? 'Runtime code' : i === 1 ? 'Network' : i === 2 ? 'Persistence' : 'Evasion'}</small><b>{b}</b><Badge tone={summary.threat_level || 'neutral'}>{summary.threat_level || 'info'}</Badge></div>
          ))
        }
      </div>
    </section>
  </div>;
}

function ObfuscationTab({ data, sampleId }: { data: ObfuscationData | null; sampleId: string }) {
  const [deobfInput, setDeobfInput] = useState("");
  const [deobfHint, setDeobfHint] = useState("");
  const [deobfResult, setDeobfResult] = useState<any>(null);
  const [deobfLoading, setDeobfLoading] = useState(false);

  const runDeobfuscate = async () => {
    if (!deobfInput.trim() || !sampleId) return;
    setDeobfLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/sample/${sampleId}/deobfuscate`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: deobfInput, hint: deobfHint || undefined }),
      });
      const result = await res.json();
      setDeobfResult(result);
    } catch (err: any) {
      setDeobfResult({ error: err.message });
    }
    setDeobfLoading(false);
  };

  if (!data) return <div className="empty-state">No obfuscation data available.</div>;
  const techs = data.techniques || [];
  return <><div className="obf-head"><div><p className="eyebrow">EVASION ASSESSMENT</p><h2>Obfuscation score <span>{data.obfuscation_score}/100</span></h2></div><Meter value={data.obfuscation_score} className="obf-meter" /></div>
    <div className="tech-grid">{techs.slice(0, 4).map((t: any) => (
      <section className="tech" key={t.key || t.name}>
        <small>{t.name}</small><strong>{Math.round(t.count > 100 ? t.count / 10 : t.count)}%</strong><Meter value={Math.min(t.count, 100)} />
        <p className="mono">{t.items?.[0]?.detail || t.name}</p>
      </section>
    ))}</div>
    <div className="obf-head" style={{ marginTop: '2rem' }}>
      <div><p className="eyebrow">DEOBFUSCATION TOOL</p><h2>Try to decode <span>an obfuscated string</span></h2></div>
    </div>
    <div style={{ display: 'flex', gap: '1rem', padding: '0 2rem 2rem' }}>
      <input value={deobfInput} onChange={e => setDeobfInput(e.target.value)} placeholder="Paste obfuscated string..." style={{ flex: 1, background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)', padding: '0.75rem 1rem', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }} />
      <input value={deobfHint} onChange={e => setDeobfHint(e.target.value)} placeholder="Hint (optional)" style={{ width: 200, background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)', padding: '0.75rem 1rem', color: 'var(--text-primary)' }} />
      <button className="primary" onClick={runDeobfuscate} disabled={deobfLoading}>{deobfLoading ? 'Decoding...' : 'Decode'}</button>
    </div>
    {deobfResult && (
      <div style={{ padding: '0 2rem 2rem' }}>
        <div className="panel">
          <div className="panel-title">DECODING RESULT</div>
          {deobfResult.results?.map((r: any, i: number) => (
            <div key={i} style={{ margin: '0.5rem 0' }}>
              <Badge tone={r.status === 'success' ? 'safe' : 'critical'}>{r.type}</Badge>
              <p className="mono" style={{ marginTop: '0.25rem' }}>{r.value}</p>
            </div>
          ))}
          {deobfResult.error && <p style={{ color: 'var(--accent-rose)' }}>{deobfResult.error}</p>}
        </div>
      </div>
    )}
  </>;
}

function ChainsTab({ chains, chainExplains, onExplainChain, sampleId }: {
  chains: ThreatChain[]; chainExplains: Record<string, any>; onExplainChain: (c: ThreatChain) => void; sampleId: string;
}) {
  if (!chains.length) return <div className="empty-state">No threat chains identified.</div>;
  return <><div className="chain-filter"><span>FILTER BY SEVERITY</span>{["All chains", "Critical", "High", "Medium"].map(x => <button className={x === "All chains" ? "selected" : ""} key={x}>{x}</button>)}</div>
    {chains.map((chain, i) => {
      const explain = chainExplains[chain.chain_id];
      return <section className="chain-card" key={chain.chain_id}>
        <div className="chain-title">
          <Badge tone={chain.severity === 'critical' ? 'critical' : 'warning'}>{chain.severity.toUpperCase()}</Badge>
          <h3>{chain.steps?.[0]?.artifact?.substring(0, 40) || `Chain ${i + 1}`}</h3>
          <span>CONFIDENCE {Math.round((chain.confidence || 0) * 100)}%</span>
          <button onClick={() => onExplainChain(chain)}>✦</button>
        </div>
        <div className="flow">{(chain.steps || []).map((step, si) => (
          <span key={si} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <div><b>{String(step.step).padStart(2, '0')}</b><small>{step.type.replace('_', ' ').toUpperCase()}</small><p className="mono">{step.artifact?.substring(0, 30)}</p></div>
            {si < (chain.steps?.length || 0) - 1 && <i>→</i>}
          </span>
        ))}</div>
        {explain && <p className="explain"><span>✦ LLM EXPLANATION</span> {explain.summary}</p>}
      </section>;
    })}
  </>;
}

function ManifestTab({ manifest }: { manifest: any }) {
  if (!manifest) return <div className="empty-state">No manifest data available.</div>;
  const perms = manifest.uses_permissions || [];
  const dangerousPerms = perms.filter((p: string) =>
    ['SMS', 'ACCESSIBILITY', 'BOOT_COMPLETED', 'SYSTEM_ALERT', 'READ_CONTACTS', 'CAMERA', 'RECORD_AUDIO', 'GET_ACCOUNTS']
      .some(k => p.includes(k))
  );
  return <div className="manifest-grid">
    <section className="panel"><div className="panel-title">PERMISSIONS <Badge tone={dangerousPerms.length ? 'critical' : 'safe'}>{dangerousPerms.length} DANGEROUS</Badge></div>
      <div className="permission-cloud">{perms.map((p: string, i: number) => <span className={dangerousPerms.includes(p) ? 'danger' : ''} key={p}>{p}</span>)}</div>
    </section>
    <section className="panel component-list">
      <div><small>PACKAGE</small><p className="mono">{manifest.package || 'N/A'}</p></div>
      <div><small>VERSION</small><p className="mono">{manifest.version_name || '?'} (code {manifest.version_code || '?'})</p></div>
      <div><small>SDK</small><p className="mono">min {manifest.min_sdk_version || '?'} · target {manifest.target_sdk_version || '?'}</p></div>
    </section>
  </div>;
}

function DissectionPage({ classes, expandedClass, dissectionMethods, sourceCode, sourceClass, onExpandClass, onShowSource, onCloseSource }: {
  classes: DissectionClass[]; expandedClass: string | null; dissectionMethods: any; sourceCode: string | null; sourceClass: string | null;
  onExpandClass: (name: string) => void; onShowSource: (name: string) => void; onCloseSource: () => void;
}) {
  const [method, setMethod] = useState("decryptConfig");
  const [search, setSearch] = useState("");

  if (!classes.length) return <div className="page-heading"><div><p className="eyebrow">DEX EXPLORER</p><h1>Code <span>dissection</span></h1></div><div className="empty-state">No classes loaded. Select a completed sample first.</div></div>;

  const filtered = classes.filter(c =>
    c.name.toLowerCase().includes(search.toLowerCase())
  );

  return <><div className="page-heading compact"><div><p className="eyebrow">DEX EXPLORER</p><h1>Code <span>dissection</span></h1></div><div className="filter"><span>⌕</span><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Find class or symbol" /></div></div>
    <div className="dissection">
      <aside className="class-tree">
        <div className="tree-head">CLASSES <span>{classes.length.toLocaleString()}</span></div>
        {filtered.slice(0, 100).map((c) => {
          const hasSuspicious = c.network_calls?.length > 0 || c.permissions_used?.length > 0;
          return <button
            key={c.name}
            className={`${hasSuspicious ? "suspicious" : ""} ${expandedClass === c.name ? "active-tree" : ""}`}
            onClick={() => onExpandClass(c.name)}
          >
            {c.name?.split('/')?.pop() || c.name}
            {hasSuspicious ? ' ⚠' : ''}
          </button>;
        })}
        {filtered.length > 100 && <p style={{ padding: '0.5rem 1rem', color: 'var(--text-muted)', fontSize: '0.75rem' }}>Showing 100 of {filtered.length} classes</p>}
      </aside>
      <section className="source">
        {sourceCode && sourceClass ? (
          <>
            <div className="source-bar"><span>{sourceClass}</span><span className="mono">decompiled</span><button style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }} onClick={onCloseSource}>×</button></div>
            <pre><code>{sourceCode.split('\n').slice(0, 50).map((line, i) => (
              <span key={i}><span className="muted-code">{i + 1}</span> {line}{'\n'}</span>
            ))}</code></pre>
            {sourceCode.split('\n').length > 50 && <p style={{ padding: '1rem', color: 'var(--text-muted)', textAlign: 'center' }}>... truncated to 50 lines</p>}
          </>
        ) : expandedClass && dissectionMethods ? (
          <>
            <div className="source-bar"><span>{expandedClass}</span><span className="mono">decompiled · {dissectionMethods.length} methods</span><button style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'var(--text-primary)', cursor: 'pointer', fontSize: '0.8rem' }} onClick={() => onShowSource(expandedClass)}>view source →</button></div>
            <pre><code>{dissectionMethods.slice(0, 5).map((m: any, i: number) => (
              <span key={i}>
                <span className="muted-code">{i + 1}</span> <b>public</b> void <mark onClick={() => setMethod(m.name)}>{m.name}</mark>(...) {'{'}{'\n'}
                {m.body?.split('\n').slice(0, 8).map((line: string, li: number) => (
                  <span key={li}><span className="muted-code">{String(i + 2 + li).padStart(2, ' ')}</span>   {line}{'\n'}</span>
                ))}
                {'}'}{'\n\n'}
              </span>
            ))}</code></pre>
            {dissectionMethods.length > 5 && <p style={{ padding: '0.5rem 1rem', color: 'var(--text-muted)', fontSize: '0.75rem' }}>Showing 5 of {dissectionMethods.length} methods</p>}
          </>
        ) : (
          <>
            <div className="source-bar"><span>Select a class</span><span className="mono">decompiled</span></div>
            <div className="empty-state" style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>Click a class in the tree to view its methods</div>
          </>
        )}
      </section>
    </div></>;
}

function IntelPage({ threatIntel, sampleId }: { threatIntel: ThreatIntelData | null; sampleId: string }) {
  if (!threatIntel) return <div className="page-heading"><div><p className="eyebrow">INFRASTRUCTURE CORRELATION</p><h1>Threat <span>intelligence</span></h1><p>Live network enrichment for the current artifact.</p></div><div className="empty-state">No threat intelligence data available.</div></div>;

  const c2s = threatIntel.c2s || [];
  const family = threatIntel.family;
  const geo = threatIntel.ips_geolocated || [];
  const dnsCount = threatIntel.dns || { active: 0, likely_active: 0, dead: 0 };

  return <><div className="page-heading"><div><p className="eyebrow">INFRASTRUCTURE CORRELATION</p><h1>Threat <span>intelligence</span></h1><p>Live network enrichment for the current artifact.</p></div><button className="primary">⇩ Export PDF report</button></div>
    <div className="intel-stats">
      {[[String(c2s.length), "C2 ENDPOINTS", "rose"], [String(dnsCount.likely_active || 0), "LIKELY ACTIVE", "amber"], [String(dnsCount.active || 0), "DNS VERIFIED", "emerald"], [family?.family ? "1" : "0", "MALWARE FAMILY", "violet"]].map(x => (
        <div key={x[1]}><span className={x[2]} /><strong>{x[0]}</strong><small>{x[1]}</small></div>
      ))}
    </div>
    <div className="intel-grid">
      <section className="map"><div className="panel-title">C2 GEOLOCATION</div>
        <div className="map-world">
          {geo.slice(0, 5).map((g, i) => (
            <span key={i} className={`pin p${i + 1}`} title={`${g.ip} (${g.country})`}>{g.country?.substring(0, 2) || '??'}</span>
          ))}
        </div>
        <div className="map-legend"><span><i className="dot rose" /> likely active</span><span><i className="dot amber" /> unresolved</span></div>
      </section>
      <section className="family">
        <div className="panel-title">FAMILY ATTRIBUTION</div>
        {family ? (
          <>
            <div className="family-mark">{family.family?.charAt(0) || '?'}</div>
            <h2>{family.family || 'Unknown'}</h2>
            <p>{family.method?.replace('_', ' ') || 'Analysis'}</p>
            <Badge tone={family.confidence > 0.7 ? 'critical' : 'warning'}>{Math.round((family.confidence || 0) * 100)}% MATCH</Badge>
            <hr />
            <small>CLUSTER SIGNALS</small>
            <p className="mono">method: {family.method}<br />confidence: {family.confidence?.toFixed(2) || '0.00'}</p>
          </>
        ) : (
          <>
            <div className="family-mark">?</div>
            <h2>Unidentified</h2>
            <p>No family match found</p>
          </>
        )}
      </section>
    </div>
    <section className="endpoint-panel"><div className="panel-title">IDENTIFIED ENDPOINTS <span>DNS re-verified 4m ago</span></div>
      {c2s.length === 0 ? <p style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>No endpoints identified.</p> :
        c2s.map((c2: any) => {
          const statusClass = c2.status === 'active' ? 'active' : c2.status === 'likely_active' ? 'likely_active' : 'dead';
          return <div className="endpoint" key={c2.c2_id}>
            <span className={`endpoint-status ${statusClass}`} />
            <div><b>{c2.domain || c2.ip || 'N/A'}</b><small>{c2.ip || ''}</small></div>
            <span>{c2.protocol || 'TCP'} · {c2.port || ''}</span>
            <span>{geo.find((g: any) => g.ip === c2.ip)?.country || ''}</span>
            <Badge tone={statusClass === 'active' ? 'critical' : statusClass === 'likely_active' ? 'warning' : 'neutral'}>{c2.status || 'unknown'}</Badge>
            <button className="tiny-btn">Inspect →</button>
          </div>;
        })
      }
    </section></>;
}
