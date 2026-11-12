const configuredBase = import.meta.env.VITE_API_BASE_URL ?? "";

export type Incident = { id: number; title: string; description: string | null; status: string; created_at: string };
export type Artifact = { id: number; filename: string; content_type: string | null; size: number; sha256: string };
export type EmailEvidence = {
  id: number; incident_id: number; source: string; sender: string | null; recipients: string[];
  subject: string | null; sent_at: string | null; message_id: string | null; headers: Record<string, string>;
  urls: string[]; domains: string[]; body_preview: string; raw_email_sha256: string; artifacts: Artifact[]; created_at: string;
};
export type IOC = { id: number; incident_id: number; artifact_id: number | null; ioc_type: string; value: string; normalized_value: string; source: string; classification: string; context: Record<string, unknown>; created_at: string };
export type Analysis = { id: number; artifact_id: number; incident_id: number; status: string; error_message: string | null; is_pe: boolean; file_type: string | null; pe_headers: Record<string, string | number | null>; sections: Record<string, string | number | boolean>[]; imports: Record<string, unknown>[]; extracted_strings: string[]; md5: string | null; sha1: string | null; yara_matches: Record<string, unknown>[]; iocs: IOC[]; created_at: string; updated_at: string };
export type Intel = { id: number; incident_id: number; artifact_id: number | null; ioc_id: number | null; ioc_type: string; ioc_value: string; normalized_value: string; provider: string; query_status: string; reputation_score: number | null; malicious_votes: number; suspicious_votes: number; harmless_votes: number; undetected_votes: number; total_engines: number; detection_details: Record<string, unknown>; queried_at: string; created_at: string };
export type Correlation = { incident_id: number; confidence: { score: number; level: string; reasons: string[] }; risk: { score: number; level: string; reasons: string[] }; linkages: { source_type: string; source_id: string | number; target_type: string; target_id: string | number; relation: string; description: string; metadata: Record<string, unknown> }[]; created_at: string };
export type TimelineEvent = { id: number; incident_id: number; timestamp: string; event_type: string; source: string; description: string; artifact_id: number | null; ioc_id: number | null; event_data: Record<string, unknown>; created_at: string };
export type TelemetryEvent = { id: number; incident_id: number | null; event_id: number; timestamp: string; hostname: string | null; endpoint_id: string | null; user_name: string | null; process_guid: string | null; process_id: string | null; parent_process_guid: string | null; parent_process_id: string | null; image: string | null; command_line: string | null; hashes: Record<string, string>; destination_ip: string | null; destination_hostname: string | null; destination_port: number | null; protocol: string | null; target_filename: string | null; registry_key: string | null; registry_value_name: string | null; registry_value_data: string | null; raw_evidence: string; provenance: Record<string, unknown>; fingerprint: string; created_at: string };

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); this.name = "ApiError"; }
}

export function createApi(base = configuredBase, apiKey = "") {
  const root = base.replace(/\/+$/, "");
  async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers);
    if (apiKey) headers.set("X-API-Key", apiKey);
    if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    let response: Response;
    try { response = await fetch(`${root}${path}`, { ...init, headers }); }
    catch { throw new ApiError(0, "Cannot reach the MALCIE API. Check the API address and that the backend is running."); }
    if (!response.ok) {
      let message = `Request failed (${response.status})`;
      try {
        const body = await response.json() as { detail?: unknown };
        if (typeof body.detail === "string") message = body.detail;
        else if (Array.isArray(body.detail)) message = body.detail.map((item) => typeof item === "object" && item && "msg" in item ? String(item.msg) : "Invalid request").join("; ");
      } catch { /* retain status message */ }
      if (response.status === 401 || response.status === 403) message = `Authentication or access denied (${response.status}). Check the API key.`;
      throw new ApiError(response.status, message);
    }
    if (response.status === 204) return undefined as T;
    try { return await response.json() as T; }
    catch { throw new ApiError(response.status, "The MALCIE API returned an invalid JSON response."); }
  }
  return {
    health: () => request<{ status: string; service: string }>("/health"),
    createIncident: (payload: { title: string; description: string }) => request<Incident>("/incidents", { method: "POST", body: JSON.stringify(payload) }),
    getIncident: (id: number) => request<Incident>(`/incidents/${id}`),
    uploadEmail: (incidentId: number, file: File) => { const data = new FormData(); data.set("incident_id", String(incidentId)); data.set("eml_file", file); return request<EmailEvidence>("/emails/upload-eml", { method: "POST", body: data }); },
    getEmail: (id: number) => request<EmailEvidence>(`/emails/${id}`),
    analyzeArtifact: (id: number) => request<Analysis>(`/artifacts/${id}/analyze-static`, { method: "POST" }),
    getAnalysis: (id: number) => request<Analysis>(`/artifacts/${id}/analysis-static`),
    getIncidentIocs: (id: number) => request<IOC[]>(`/incidents/${id}/iocs`),
    getIncidentIntel: (id: number) => request<Intel[]>(`/incidents/${id}/threat-intel`),
    enrichIncident: (id: number) => request<Intel[]>(`/incidents/${id}/enrich`, { method: "POST", body: "{}" }),
    getTelemetry: (id: number) => request<TelemetryEvent[]>(`/incidents/${id}/telemetry`),
    uploadTelemetry: (id: number, file: File) => {
      const contentType = /\.xml$/i.test(file.name) ? "application/xml" : /\.json$/i.test(file.name) ? "application/json" : file.type || "application/octet-stream";
      return request<{ ingested_count: number; duplicate_count: number; unassociated_count: number; events: TelemetryEvent[] }>(`/telemetry/upload?incident_id=${id}`, { method: "POST", headers: { "Content-Type": contentType }, body: file });
    },
    getCorrelation: (id: number) => request<Correlation>(`/incidents/${id}/correlations`),
    correlate: (id: number) => request<Correlation>(`/incidents/${id}/correlate`, { method: "POST" }),
    getTimeline: (id: number) => request<TimelineEvent[]>(`/incidents/${id}/timeline`),
  };
}

export const API_BASE = configuredBase;
