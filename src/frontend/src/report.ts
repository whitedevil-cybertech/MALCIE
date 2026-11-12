import type { Analysis, Correlation, EmailEvidence, Incident, Intel, IOC, TelemetryEvent, TimelineEvent } from "./api";

export type InvestigationSnapshot = {
  incident: Incident;
  emailEvidence: EmailEvidence | null;
  analysis: Analysis | null;
  analysisFilename: string | null;
  iocs: IOC[];
  threatIntelligence: Intel[];
  endpointTelemetry: TelemetryEvent[];
  correlation: Correlation | null;
  timeline: TimelineEvent[];
};

export function buildClientReport(snapshot: InvestigationSnapshot, generatedAt = new Date().toISOString()) {
  return {
    report_type: "malcie_client_generated_investigation_report",
    persisted_by_backend: false,
    generated_at: generatedAt,
    evidence_scope: "Data returned by the API and loaded in this browser investigation session.",
    incident: snapshot.incident,
    email_evidence: snapshot.emailEvidence,
    artifact_analysis: snapshot.analysis ? {
      artifact_id: snapshot.analysis.artifact_id,
      filename: snapshot.analysisFilename,
      result: snapshot.analysis,
    } : null,
    iocs: snapshot.iocs,
    threat_intelligence: snapshot.threatIntelligence,
    endpoint_telemetry: snapshot.endpointTelemetry,
    correlation: snapshot.correlation,
    timeline: snapshot.timeline,
  };
}

export function downloadClientReport(report: ReturnType<typeof buildClientReport>, filename: string) {
  const href = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = href;
  anchor.download = filename;
  document.body.append(anchor);
  try { anchor.click(); }
  finally {
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(href), 1000);
  }
}
