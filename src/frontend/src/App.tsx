import { useEffect, useMemo, useRef, useState } from "react";
import { API_BASE, createApi, type Analysis, type Correlation, type EmailEvidence, type Incident, type Intel, type IOC, type TelemetryEvent, type TimelineEvent } from "./api";
import { buildClientReport, downloadClientReport } from "./report";

type Section = "Overview" | "Email evidence" | "Artifact analysis" | "IOCs & YARA" | "Threat intelligence" | "Endpoint telemetry" | "Correlation & timeline" | "Investigation report";
const sections: Section[] = ["Overview", "Email evidence", "Artifact analysis", "IOCs & YARA", "Threat intelligence", "Endpoint telemetry", "Correlation & timeline", "Investigation report"];
const prettyDate = (date?: string) => date ? new Date(date).toLocaleString() : "Not recorded";
const messageOf = (error: unknown) => error instanceof Error ? error.message : "The request failed. Try again.";

export default function App() {
  const [apiKey, setApiKey] = useState("");
  const [apiBase, setApiBase] = useState(API_BASE);
  const [api, setApi] = useState(() => createApi());
  const [health, setHealth] = useState<"checking" | "online" | "offline">("checking");
  const [section, setSection] = useState<Section>("Overview");
  const [incident, setIncident] = useState<Incident | null>(null);
  const [incidentId, setIncidentId] = useState("");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [email, setEmail] = useState<EmailEvidence | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [analysisArtifact, setAnalysisArtifact] = useState<{ id: number; filename: string } | null>(null);
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [intel, setIntel] = useState<Intel[]>([]);
  const [telemetry, setTelemetry] = useState<TelemetryEvent[]>([]);
  const [correlation, setCorrelation] = useState<Correlation | null>(null);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const operationLock = useRef(false);
  const incidentEpoch = useRef(0);

  const apiClient = useMemo(() => api, [api]);
  useEffect(() => {
    let active = true;
    void apiClient.health().then(() => { if (active) setHealth("online"); }).catch(() => { if (active) setHealth("offline"); });
    return () => { active = false; };
  }, [apiClient]);

  async function run<T>(label: string, action: () => Promise<T>, done?: (value: T) => void, isCurrent: () => boolean = () => true) {
    if (operationLock.current) return undefined;
    operationLock.current = true;
    setBusy(label); setError(""); setNotice("");
    try {
      const result = await action();
      if (!isCurrent()) return undefined;
      done?.(result); setNotice(`${label} completed.`);
      return result;
    } catch (err) { if (isCurrent()) setError(messageOf(err)); return undefined; }
    finally { operationLock.current = false; setBusy(""); }
  }
  const resetInvestigation = () => { setEmail(null); setAnalysis(null); setAnalysisArtifact(null); setIocs([]); setIntel([]); setTelemetry([]); setCorrelation(null); setTimeline([]); };
  async function loadIncident(id: number) {
    const epoch = ++incidentEpoch.current;
    await run("Loading incident", async () => {
      const loadedIncident = await apiClient.getIncident(id);
      const evidenceResults = await Promise.allSettled([apiClient.getIncidentIocs(id), apiClient.getIncidentIntel(id), apiClient.getTelemetry(id)]);
      const correlationResult = (await Promise.allSettled([apiClient.getCorrelation(id)]))[0];
      const timelineResult = (await Promise.allSettled([apiClient.getTimeline(id)]))[0];
      return { loadedIncident, evidenceResults, correlationResult, timelineResult };
    }, ({ loadedIncident, evidenceResults, correlationResult, timelineResult }) => {
      setIncident(loadedIncident); setIncidentId(String(loadedIncident.id)); resetInvestigation();
      const [iocResult, intelResult, telemetryResult] = evidenceResults;
      if (iocResult.status === "fulfilled") setIocs(iocResult.value);
      if (intelResult.status === "fulfilled") setIntel(intelResult.value);
      if (telemetryResult.status === "fulfilled") setTelemetry(telemetryResult.value);
      if (correlationResult.status === "fulfilled") setCorrelation(correlationResult.value);
      if (timelineResult.status === "fulfilled") setTimeline(timelineResult.value);
      const failed = [...evidenceResults, correlationResult, timelineResult].filter((result) => result.status === "rejected");
      if (failed.length) setError(`Incident opened, but ${failed.length} evidence request(s) failed: ${messageOf((failed[0] as PromiseRejectedResult).reason)}`);
    }, () => incidentEpoch.current === epoch);
  }
  async function createIncident(event: React.FormEvent) {
    event.preventDefault();
    if (!title.trim()) { setError("Enter an incident title."); return; }
    const epoch = incidentEpoch.current;
    await run("Creating incident", () => apiClient.createIncident({ title: title.trim(), description: description.trim() }), (value) => { incidentEpoch.current++; setIncident(value); setIncidentId(String(value.id)); resetInvestigation(); setTitle(""); setDescription(""); }, () => incidentEpoch.current === epoch);
  }
  function updateConnection(event: React.FormEvent) {
    event.preventDefault();
    if (operationLock.current) { setError("Wait for the current API request to finish before changing the connection."); return; }
    setApi(createApi(apiBase.trim(), apiKey)); setHealth("checking"); setNotice("API connection settings updated for this session."); setError("");
  }
  async function uploadEmail(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]; event.target.value = "";
    if (!file || !incident) return;
    if (!file.name.toLowerCase().endsWith(".eml")) { setError("Choose an .eml file."); return; }
    const epoch = incidentEpoch.current;
    await run("Email upload", () => apiClient.uploadEmail(incident.id, file), (value) => {
      if (value.incident_id !== incident.id) throw new Error("Email response belongs to a different incident.");
      setEmail(value); setAnalysis(null); setAnalysisArtifact(null); setCorrelation(null); setTimeline([]);
    }, () => incidentEpoch.current === epoch);
  }
  async function uploadTelemetry(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]; event.target.value = "";
    if (!file || !incident) return;
    const epoch = incidentEpoch.current;
    await run("Telemetry upload", () => apiClient.uploadTelemetry(incident.id, file), (value) => {
      if (value.events.some((event) => event.incident_id !== incident.id)) throw new Error("Telemetry response contains events outside the selected incident.");
      setTelemetry(value.events); setCorrelation(null); setTimeline([]);
      setNotice(`Telemetry ingested: ${value.ingested_count} new, ${value.duplicate_count} duplicate.`);
    }, () => incidentEpoch.current === epoch);
  }
  async function analyze(artifactId: number, filename: string) {
    if (operationLock.current) return;
    setAnalysisArtifact({ id: artifactId, filename }); setAnalysis(null); setError("");
    const epoch = incidentEpoch.current;
    await run("Static analysis", async () => {
      const value = await apiClient.analyzeArtifact(artifactId);
      const isRecord = (candidate: unknown): candidate is Record<string, unknown> => typeof candidate === "object" && candidate !== null && !Array.isArray(candidate);
      if (!value || value.artifact_id !== artifactId || value.incident_id !== incident?.id || typeof value.status !== "string" || typeof value.is_pe !== "boolean" || !isRecord(value.pe_headers) || !Array.isArray(value.sections) || !Array.isArray(value.imports) || !Array.isArray(value.yara_matches) || !Array.isArray(value.iocs) || !Array.isArray(value.extracted_strings) || !value.extracted_strings.every((item) => typeof item === "string")) throw new Error("Analysis response is incomplete or does not match the selected artifact and incident.");
      return value;
    }, (value) => { setAnalysis(value); setIocs(value.iocs); setCorrelation(null); setTimeline([]); }, () => incidentEpoch.current === epoch);
  }
  async function enrich() {
    if (!incident) return;
    const epoch = incidentEpoch.current;
    const results = await run("Threat intelligence enrichment", () => apiClient.enrichIncident(incident.id), (value) => { setIntel(value); setCorrelation(null); setTimeline([]); }, () => incidentEpoch.current === epoch);
    if (results?.length === 0) setNotice("No eligible IOCs were available for enrichment, or the provider returned no results.");
  }
  async function refreshCorrelation() {
    if (!incident) return;
    const epoch = incidentEpoch.current;
    await run("Correlation", async () => {
      const result = (await Promise.allSettled([apiClient.correlate(incident.id)]))[0];
      const events = (await Promise.allSettled([apiClient.getTimeline(incident.id)]))[0];
      return { result, events };
    }, ({ result, events }) => {
      if (result.status === "fulfilled") setCorrelation(result.value);
      if (events.status === "fulfilled") setTimeline(events.value);
      if (result.status === "rejected" || events.status === "rejected") {
        const failure = result.status === "rejected" ? result.reason : (events as PromiseRejectedResult).reason;
        setError(`Correlation workflow partially failed: ${messageOf(failure)}`);
      }
    }, () => incidentEpoch.current === epoch);
  }
  function downloadReport() {
    if (!incident || operationLock.current) return;
    const report = buildClientReport({ incident, emailEvidence: email, analysis, analysisFilename: analysis && analysisArtifact?.id === analysis.artifact_id ? analysisArtifact.filename : null, iocs, threatIntelligence: intel, endpointTelemetry: telemetry, correlation, timeline });
    downloadClientReport(report, `malcie-incident-${incident.id}-report.json`);
  }
  function clearIncident() { incidentEpoch.current++; setIncident(null); resetInvestigation(); }

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">M</div><div><strong>MALCIE</strong><span>INVESTIGATION WORKSPACE</span></div></div>
      <div className="workspace-label">WORKSPACE</div>
      <nav aria-label="Investigation sections">{sections.map((item, index) => <button key={item} className={`nav-item ${section === item ? "active" : ""}`} onClick={() => setSection(item)}><span className="nav-index">{String(index + 1).padStart(2, "0")}</span>{item}</button>)}</nav>
      <div className="sidebar-bottom"><div className="service-pill"><i className={health === "online" ? "status-dot live" : "status-dot"} />API {health === "checking" ? "checking" : health}</div><span className="version">MALCIE · ANALYST CONSOLE</span></div>
    </aside>
    <main className="main-area">
      <header className="topbar"><div className="crumb">Workspace <span>/</span> Investigation</div><div className="topbar-right"><span className="live-label"><i className={health === "online" ? "status-dot live" : "status-dot"} />{health === "online" ? "SYSTEM OPERATIONAL" : health === "checking" ? "CHECKING API" : "API UNAVAILABLE"}</span><div className="avatar">A</div></div></header>
      <div className="content">
        <section className="page-heading"><div><div className="eyebrow">MALWARE ANALYSIS · LINKAGE · CORRELATION</div><h1>{section === "Overview" ? "Investigation workspace" : section}</h1><p>{incident ? <>Active case <b>INC-{String(incident.id).padStart(4, "0")}</b> · {incident.title}</> : "Collect, analyze, and connect evidence across a single incident."}</p></div><div className="case-badge"><span>ACTIVE CASE</span><strong>{incident ? `INC-${String(incident.id).padStart(4, "0")}` : "—"}</strong></div></section>
        {error && <div className="alert error" role="alert"><b>Request could not be completed</b><span>{error}</span><button onClick={() => setError("")} aria-label="Dismiss error">×</button></div>}
        {notice && <div className="alert success" role="status"><span>{notice}</span><button onClick={() => setNotice("")} aria-label="Dismiss message">×</button></div>}
        <div className="dashboard-grid">
          <section className="panel incident-panel"><div className="panel-head"><div><div className="eyebrow">CASE MANAGEMENT</div><h2>{incident ? "Selected incident" : "Start an investigation"}</h2></div><span className="icon-box">⌕</span></div>
            {incident ? <div className="incident-summary"><div className="summary-id">INC-{String(incident.id).padStart(4, "0")} <span className="status-tag">{incident.status}</span></div><h3>{incident.title}</h3><p>{incident.description || "No description provided."}</p><div className="summary-meta"><span>CREATED</span><b>{prettyDate(incident.created_at)}</b></div><button className="text-button" disabled={!!busy} onClick={clearIncident}>Switch or clear case <span>→</span></button></div> : <><form className="lookup-form" onSubmit={(e) => { e.preventDefault(); const parsed = Number(incidentId); if (!Number.isInteger(parsed) || parsed < 1) { setError("Enter a valid incident ID."); return; } void loadIncident(parsed); }}><label htmlFor="incident-id">Open existing incident by ID</label><div className="inline-field"><input id="incident-id" value={incidentId} onChange={(e) => setIncidentId(e.target.value)} inputMode="numeric" placeholder="e.g. 12"/><button className="button secondary" disabled={!!busy}>Open</button></div></form><div className="divider"><span>OR CREATE A NEW CASE</span></div><form className="create-form" onSubmit={(e) => void createIncident(e)}><label htmlFor="incident-title">Incident title</label><input id="incident-title" value={title} onChange={(e) => setTitle(e.target.value)} maxLength={255} placeholder="Suspicious email investigation" required/><label htmlFor="incident-description">Description <span className="optional">OPTIONAL</span></label><textarea id="incident-description" value={description} onChange={(e) => setDescription(e.target.value)} rows={2} placeholder="Context for this investigation"/><button className="button primary" disabled={!!busy}>{busy || "Create incident"}<span>→</span></button></form></>}
          </section>
          <section className="panel pipeline-panel"><div className="panel-head"><div><div className="eyebrow">INVESTIGATION PIPELINE</div><h2>Evidence at a glance</h2></div><span className="muted-small">LIVE CASE DATA</span></div><div className="metrics-grid"><Metric label="Emails" value={email ? 1 : "—"} icon="✉" /><Metric label="Artifacts" value={email?.artifacts.length || (analysis ? 1 : "—")} icon="▤" /><Metric label="Indicators" value={iocs.length || "—"} icon="⌘" /><Metric label="Endpoint events" value={telemetry.length || "—"} icon="⌁" /></div><div className="pipeline-flow">{["Collect", "Analyze", "Enrich", "Correlate"].map((step, i) => <div className="flow-step" key={step}><div className={`flow-node ${[!!email,!!analysis,!!intel.length,!!correlation][i] ? "complete" : ""}`}>{["↓", "⌕", "◎", "⤳"][i]}</div><span>{step}</span>{i < 3 && <i className="flow-line"/>}</div>)}</div><p className="panel-footnote">Counts reflect evidence loaded in this session or returned by the API.</p></section>
          <section className="panel evidence-panel"><div className="panel-head"><div><div className="eyebrow">EVIDENCE COLLECTION</div><h2>Bring evidence into this case</h2></div><span className="icon-box">＋</span></div><div className="action-row"><div className="action-icon email-icon">✉</div><div className="action-copy"><b>Upload suspicious email</b><span>Parse an original .eml file and extract metadata</span></div><label className={`button secondary upload-button ${!incident || !!busy ? "disabled" : ""}`}>Choose .eml<input type="file" accept=".eml,message/rfc822" disabled={!incident || !!busy} onChange={(e) => void uploadEmail(e)} /></label></div><div className="action-row"><div className="action-icon telemetry-icon">⌁</div><div className="action-copy"><b>Ingest endpoint telemetry</b><span>Upload Sysmon XML or JSON for this incident</span></div><label className={`button secondary upload-button ${!incident || !!busy ? "disabled" : ""}`}>Upload log<input type="file" accept=".xml,.json,application/xml,application/json" disabled={!incident || !!busy} onChange={(e) => void uploadTelemetry(e)} /></label></div><div className="action-row"><div className="action-icon correlate-icon">⤳</div><div className="action-copy"><b>Run evidence correlation</b><span>Recalculate risk, confidence, and linkages</span></div><button className="button secondary" disabled={!incident || !!busy} onClick={() => void refreshCorrelation()}>{busy === "Correlation" ? "Running…" : "Run correlation"}</button></div></section>
          <section className="panel connection-panel"><div className="panel-head"><div><div className="eyebrow">CONNECTION</div><h2>Backend configuration</h2></div><span className="service-pill compact"><i className={health === "online" ? "status-dot live" : "status-dot"}/>{health}</span></div><form onSubmit={updateConnection} className="connection-form"><label htmlFor="api-base">API base URL</label><input id="api-base" value={apiBase} onChange={(e) => setApiBase(e.target.value)} spellCheck={false}/><label htmlFor="api-key">API key <span className="optional">OPTIONAL · SESSION ONLY</span></label><input id="api-key" type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} autoComplete="off" placeholder="Required only when backend authentication is enabled"/><button className="button secondary">Apply connection</button></form></section>
        </div>
        <section className="panel workbench"><div className="workbench-head"><div><div className="eyebrow">CASE WORKBENCH</div><h2>{section}</h2></div><div className="workbench-tabs">{sections.slice(1).map((item) => <button key={item} className={section === item ? "selected" : ""} onClick={() => setSection(item)}>{item}</button>)}</div></div>
          {!incident ? <Empty text="Open an incident by ID or create a new case to begin the investigation."/> : <Workbench section={section} incident={incident} email={email} analysis={analysis} analysisArtifact={analysisArtifact} iocs={iocs} intel={intel} telemetry={telemetry} correlation={correlation} timeline={timeline} busy={busy} onAnalyze={analyze} onEnrich={() => void enrich()} onCorrelate={() => void refreshCorrelation()} onReport={downloadReport} />}
        </section>
        <footer className="footer"><span>MALCIE INVESTIGATION PLATFORM</span><span>Evidence is presented as returned by connected analysis services.</span></footer>
      </div>
    </main>
  </div>;
}

function Metric({ label, value, icon }: { label: string; value: string | number; icon: string }) { return <div className="metric"><div className="metric-top"><span>{label}</span><i>{icon}</i></div><strong>{value}</strong><span className="metric-caption">{value === "—" ? "Awaiting evidence" : "From current case"}</span></div>; }
function Empty({ text }: { text: string }) { return <div className="empty-state"><span className="empty-mark">◎</span><b>No evidence loaded</b><p>{text}</p></div>; }
function Workbench({ section, incident, email, analysis, analysisArtifact, iocs, intel, telemetry, correlation, timeline, busy, onAnalyze, onEnrich, onCorrelate, onReport }: { section: Section; incident: Incident; email: EmailEvidence | null; analysis: Analysis | null; analysisArtifact: { id: number; filename: string } | null; iocs: IOC[]; intel: Intel[]; telemetry: TelemetryEvent[]; correlation: Correlation | null; timeline: TimelineEvent[]; busy: string; onAnalyze: (id: number, filename: string) => void; onEnrich: () => void; onCorrelate: () => void; onReport: () => void }) {
  const activeAnalysis = analysis && analysis.artifact_id === analysisArtifact?.id ? analysis : null;
  if (section === "Email evidence") return email ? <><div className="detail-header"><div><span className="eyebrow">EMAIL EVIDENCE · #{email.id}</span><h3>{email.subject || "(No subject)"}</h3></div><span className="status-tag">{email.source}</span></div><div className="detail-grid"><Info label="Sender" value={email.sender}/><Info label="Recipients" value={email.recipients.join(", ") || null}/><Info label="Received" value={email.sent_at}/><Info label="Message ID" value={email.message_id}/><Info label="Raw evidence SHA-256" value={email.raw_email_sha256} mono/><Info label="URLs extracted" value={String(email.urls.length)}/></div><h4>Headers</h4><KeyValues data={email.headers}/><h4>Body preview</h4><pre className="code-block">{email.body_preview || "No body preview returned."}</pre><h4>Extracted URLs and domains</h4><div className="chips">{[...email.urls, ...email.domains].map((value) => <code key={value}>{value}</code>)}{!email.urls.length && !email.domains.length && <span className="muted">No URLs or domains returned.</span>}</div><h4>Attachments</h4>{email.artifacts.length ? <div className="table-wrap"><table><thead><tr><th>Filename</th><th>Type</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>{email.artifacts.map((a) => <tr key={a.id}><td>{a.filename}</td><td>{a.content_type || "Unknown"}</td><td>{formatBytes(a.size)}</td><td className="mono">{a.sha256}</td></tr>)}</tbody></table></div> : <p className="muted">No attachment metadata returned.</p>}</> : <Empty text="Upload an .eml file from the evidence collection panel to view parsed headers, body, URLs, and attachment metadata."/>;
  if (section === "Artifact analysis") return email?.artifacts.length ? <><div className="detail-header"><div><span className="eyebrow">STATIC ARTIFACT ANALYSIS</span><h3>{activeAnalysis ? `Analysis for ${analysisArtifact?.filename ?? "selected artifact"}` : analysisArtifact && busy === "Static analysis" ? `Analyzing ${analysisArtifact.filename}` : analysisArtifact ? `No successful analysis for ${analysisArtifact.filename}` : "Analyze an attachment"}</h3></div>{activeAnalysis && <span className="status-tag">{activeAnalysis.is_pe ? "PE FILE" : "NON-PE FILE"}</span>}</div>{email.artifacts.map((a) => <div className="artifact-row" key={a.id}><div><b>{a.filename}</b><span className="mono">SHA-256 · {a.sha256}</span></div><button className="button primary" disabled={!!busy} onClick={() => onAnalyze(a.id, a.filename)}>{analysisArtifact?.id === a.id && activeAnalysis ? "Re-analyze" : "Analyze static"}</button></div>)}{activeAnalysis && <><div className="detail-grid"><Info label="File type" value={activeAnalysis.file_type}/><Info label="Status" value={activeAnalysis.status}/><Info label="MD5" value={activeAnalysis.md5} mono/><Info label="SHA-1" value={activeAnalysis.sha1} mono/></div>{activeAnalysis.error_message && <div className="alert error">{activeAnalysis.error_message}</div>}<h4>PE headers</h4><KeyValues data={activeAnalysis.pe_headers}/><h4>Sections</h4><DataTable rows={activeAnalysis.sections}/><h4>Imports</h4><DataTable rows={activeAnalysis.imports}/><h4>Extracted strings <span className="muted">({activeAnalysis.extracted_strings.length})</span></h4><div className="string-list">{activeAnalysis.extracted_strings.slice(0, 80).map((s, i) => <code key={`${i}-${s}`}>{s}</code>)}</div></>}</> : <Empty text="Upload an .eml with attachments first. Artifact metadata is returned from that upload."/>;
  if (section === "IOCs & YARA") return <><div className="detail-header"><div><span className="eyebrow">INDICATORS & SIGNATURES</span><h3>{iocs.length} indicators returned</h3></div><span className="muted-small">YARA hits are supporting evidence</span></div>{activeAnalysis && <><h4>YARA matches · {activeAnalysis.yara_matches.length}</h4><DataTable rows={activeAnalysis.yara_matches}/></>}{analysisArtifact && !activeAnalysis && <p className="muted">Run analysis for {analysisArtifact.filename} to view its YARA findings.</p>}<h4>Extracted indicators</h4>{iocs.length ? <div className="table-wrap"><table><thead><tr><th>Type</th><th>Indicator</th><th>Classification</th><th>Source</th><th>Artifact</th></tr></thead><tbody>{iocs.map((ioc) => <tr key={ioc.id}><td><span className="status-tag">{ioc.ioc_type}</span></td><td className="mono">{ioc.normalized_value}</td><td>{ioc.classification}</td><td>{ioc.source}</td><td>{ioc.artifact_id ?? "—"}</td></tr>)}</tbody></table></div> : <Empty text="IOCs appear after artifact analysis, or when the incident has stored indicator records."/>}</>;
  if (section === "Threat intelligence") return <><div className="detail-header"><div><span className="eyebrow">VIRUSTOTAL ENRICHMENT</span><h3>Provider results</h3></div><button className="button primary" disabled={!!busy} onClick={onEnrich}>{busy.includes("enrichment") ? "Enriching…" : "Enrich incident IOCs"}</button></div>{intel.length ? <div className="table-wrap"><table><thead><tr><th>Indicator</th><th>Provider</th><th>Status</th><th>Reputation</th><th>Malicious</th><th>Suspicious</th><th>Queried</th></tr></thead><tbody>{intel.map((r) => <tr key={r.id}><td><span className="muted">{r.ioc_type} · </span><span className="mono">{r.normalized_value}</span></td><td>{r.provider}</td><td>{r.query_status}</td><td>{r.reputation_score ?? "Not reported"}</td><td>{r.malicious_votes}</td><td>{r.suspicious_votes}</td><td>{prettyDate(r.queried_at)}</td></tr>)}</tbody></table></div> : <Empty text="No threat-intelligence results are stored for this incident. Enrichment uses the configured backend provider."/>}</>;
  if (section === "Endpoint telemetry") return <><div className="detail-header"><div><span className="eyebrow">SYSMON TELEMETRY</span><h3>{telemetry.length} events associated with incident</h3></div><span className="muted-small">Ingest is available from evidence collection</span></div>{telemetry.length ? <div className="table-wrap"><table><thead><tr><th>Timestamp</th><th>Event</th><th>Host</th><th>Process / Image</th><th>Network destination</th></tr></thead><tbody>{telemetry.map((ev) => <tr key={ev.id}><td>{prettyDate(ev.timestamp)}</td><td>{ev.event_id}</td><td>{ev.hostname || ev.endpoint_id || "—"}</td><td className="mono">{ev.image || ev.target_filename || "—"}</td><td>{[ev.destination_hostname, ev.destination_ip, ev.destination_port].filter(Boolean).join(":") || "—"}</td></tr>)}</tbody></table></div> : <Empty text="No endpoint events are associated with this case. Upload Sysmon XML or JSON to ingest telemetry."/>}</>;
  if (section === "Correlation & timeline") return <><div className="detail-header"><div><span className="eyebrow">EVIDENCE LINKAGE</span><h3>Correlation assessment</h3></div><button className="button primary" disabled={!!busy} onClick={onCorrelate}>Recalculate</button></div>{correlation ? <><div className="detail-grid"><Info label="Risk" value={`${correlation.risk.level} · ${correlation.risk.score}`}/><Info label="Confidence" value={`${correlation.confidence.level} · ${correlation.confidence.score}`}/><Info label="Assessed" value={prettyDate(correlation.created_at)}/></div><h4>Risk reasons</h4><ul className="reason-list">{correlation.risk.reasons.map((x) => <li key={x}>{x}</li>)}{!correlation.risk.reasons.length && <li>No reasons were returned.</li>}</ul><h4>Linkages · {correlation.linkages.length}</h4><div className="linkage-list">{correlation.linkages.map((x, i) => <div className="linkage" key={`${i}-${x.relation}`}><span>{x.source_type} #{x.source_id}</span><b>→ {x.relation} →</b><span>{x.target_type} #{x.target_id}</span><p>{x.description}</p></div>)}</div></> : <Empty text="Run correlation to request the current deterministic linkage and risk assessment from the backend."/>}<h4>Incident timeline · {timeline.length}</h4>{timeline.length ? <div className="timeline">{timeline.map((event) => <div className="timeline-item" key={event.id}><i/><div><span>{prettyDate(event.timestamp)} · {event.source} / {event.event_type}</span><p>{event.description}</p></div></div>)}</div> : <p className="muted">No timeline events returned yet.</p>}</>;
  if (section === "Investigation report") return <><div className="detail-header"><div><span className="eyebrow">OBSERVED EVIDENCE SUMMARY</span><h3>{incident.title}</h3></div><button className="button primary" onClick={onReport}>Download JSON report</button></div><p className="report-note">This report is assembled in your browser from data fetched or returned for this session. It does not include an analyst conclusion unless recorded in the source evidence.</p><div className="report-summary"><Info label="Incident status" value={incident.status}/><Info label="Email evidence" value={email ? email.subject || "Uploaded" : "Not loaded"}/><Info label="Artifact analysis" value={analysis?.status || "Not loaded"}/><Info label="Indicators" value={String(iocs.length)}/><Info label="Threat intelligence" value={String(intel.length)}/><Info label="Endpoint events" value={String(telemetry.length)}/><Info label="Risk assessment" value={correlation ? `${correlation.risk.level} · ${correlation.risk.score}` : "Not calculated"}/><Info label="Timeline events" value={String(timeline.length)}/></div></>;
  return <><div className="detail-header"><div><span className="eyebrow">INCIDENT SUMMARY</span><h3>{incident.title}</h3></div><span className="status-tag">{incident.status}</span></div><div className="overview-cards"><OverviewCard label="Email evidence" value={email?.subject || "No email loaded"} detail={email ? `Sender ${email.sender || "not provided"}` : "Upload an .eml to extract evidence"}/><OverviewCard label="File analysis" value={analysis?.file_type || "No artifact analyzed"} detail={analysis ? `${analysis.status} · ${analysis.yara_matches.length} YARA matches` : "Static analysis runs on uploaded attachments"}/><OverviewCard label="Threat assessment" value={correlation?.risk.level || "Not assessed"} detail={correlation ? `${correlation.risk.score} risk score · ${correlation.confidence.level} confidence` : "Run correlation after collecting evidence"}/></div><h4>Latest evidence activity</h4>{timeline.length ? <div className="timeline">{timeline.slice(-5).reverse().map((event) => <div className="timeline-item" key={event.id}><i/><div><span>{prettyDate(event.timestamp)} · {event.source}</span><p>{event.description}</p></div></div>)}</div> : <Empty text="Evidence activity will appear here as the backend returns it."/>}</>;
}
function Info({ label, value, mono = false }: { label: string; value: string | null | undefined; mono?: boolean }) { return <div className="info-cell"><span>{label}</span><b className={mono ? "mono" : ""}>{value || "Not provided"}</b></div>; }
function KeyValues({ data }: { data: Record<string, unknown> }) { const pairs = Object.entries(data); return pairs.length ? <div className="kv-list">{pairs.map(([key, value]) => <div key={key}><span>{key}</span><b>{String(value)}</b></div>)}</div> : <p className="muted">No values returned.</p>; }
function DataTable({ rows }: { rows: Record<string, unknown>[] }) { if (!rows.length) return <p className="muted">No records returned.</p>; const keys = [...new Set(rows.flatMap((r) => Object.keys(r)))].slice(0, 7); return <div className="table-wrap"><table><thead><tr>{keys.map((key) => <th key={key}>{key.replace(/_/g, " ")}</th>)}</tr></thead><tbody>{rows.map((row, i) => <tr key={i}>{keys.map((key) => <td key={key} className={typeof row[key] === "string" && String(row[key]).length > 28 ? "mono" : ""}>{typeof row[key] === "object" ? JSON.stringify(row[key]) : String(row[key] ?? "—")}</td>)}</tr>)}</tbody></table></div>; }
function OverviewCard({ label, value, detail }: { label: string; value: string; detail: string }) { return <div className="overview-card"><span>{label}</span><b>{value}</b><small>{detail}</small></div>; }
function formatBytes(size: number) { return size < 1024 ? `${size} B` : size < 1024 * 1024 ? `${(size / 1024).toFixed(1)} KB` : `${(size / (1024 * 1024)).toFixed(1)} MB`; }
