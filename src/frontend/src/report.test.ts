import { afterEach, describe, expect, it, vi } from "vitest";
import { buildClientReport, downloadClientReport } from "./report";

const incident = { id: 3, title: "Synthetic test", description: null, status: "new", created_at: "2026-11-12T10:00:00Z" };

afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe("client-generated investigation report", () => {
  it("marks client generation and preserves missing evidence as null/empty values", () => {
    const report = buildClientReport({
      incident, emailEvidence: null, analysis: null, analysisFilename: null,
      iocs: [], threatIntelligence: [], endpointTelemetry: [], correlation: null, timeline: [],
    }, "2026-11-12T11:00:00.000Z");

    expect(report).toMatchObject({
      report_type: "malcie_client_generated_investigation_report",
      persisted_by_backend: false,
      generated_at: "2026-11-12T11:00:00.000Z",
      evidence_scope: expect.any(String),
      incident,
      email_evidence: null,
      artifact_analysis: null,
      iocs: [], threat_intelligence: [], endpoint_telemetry: [], correlation: null, timeline: [],
    });
    expect(() => JSON.parse(JSON.stringify(report))).not.toThrow();
  });

  it("keeps analysis identity attached to the artifact filename", () => {
    const analysis = {
      id: 12, artifact_id: 14, incident_id: 3, status: "completed", error_message: null, is_pe: false,
      file_type: "non_pe", pe_headers: {}, sections: [], imports: [], extracted_strings: ["benign marker"],
      md5: null, sha1: null, yara_matches: [], iocs: [], created_at: "2026-11-12T10:03:00Z", updated_at: "2026-11-12T10:03:00Z",
    };
    const report = buildClientReport({
      incident, emailEvidence: null, analysis, analysisFilename: "fixture.txt", iocs: [],
      threatIntelligence: [], endpointTelemetry: [], correlation: null, timeline: [],
    });

    expect(report.artifact_analysis).toEqual({ artifact_id: 14, filename: "fixture.txt", result: analysis });
    expect(JSON.stringify(report)).toContain("fixture.txt");
  });

  it("downloads JSON through a temporary anchor and revokes its object URL", () => {
    vi.useFakeTimers();
    const createObjectURL = vi.fn(() => "blob:malcie-report");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", { createObjectURL, revokeObjectURL });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    const report = buildClientReport({ incident, emailEvidence: null, analysis: null, analysisFilename: null, iocs: [], threatIntelligence: [], endpointTelemetry: [], correlation: null, timeline: [] });

    downloadClientReport(report, "malcie-incident-3-report.json");

    expect(createObjectURL).toHaveBeenCalledWith(expect.objectContaining({ type: "application/json" }));
    expect(click).toHaveBeenCalledOnce();
    expect(document.querySelector('a[download="malcie-incident-3-report.json"]')).toBeNull();
    expect(revokeObjectURL).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1000);
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:malcie-report");
  });
});
