import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, createApi } from "./api";

afterEach(() => { vi.unstubAllGlobals(); });

describe("MALCIE API client", () => {
  it("sends the configured API key and parses health responses", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ status: "ok", service: "malcie-api" }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const client = createApi("https://malcie.example/api/v1", "session-key");

    await expect(client.health()).resolves.toEqual({ status: "ok", service: "malcie-api" });
    expect(fetchMock).toHaveBeenCalledWith("https://malcie.example/api/v1/health", expect.objectContaining({ headers: expect.any(Headers) }));
    const requestHeaders = fetchMock.mock.calls[0][1].headers as Headers;
    expect(requestHeaders.get("X-API-Key")).toBe("session-key");
  });

  it("surfaces unauthorized responses without exposing response internals", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: "Authentication required" }), { status: 401 })));
    const client = createApi("https://malcie.example/api/v1");

    await expect(client.health()).rejects.toMatchObject({
      name: "ApiError",
      status: 401,
      message: "Authentication or access denied (401). Check the API key.",
    } satisfies Partial<ApiError>);
  });

  it("uses the backend paths, methods, and body shapes for investigation actions", async () => {
    const fetchMock = vi.fn().mockImplementation(async () => new Response("[]", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const client = createApi("https://malcie.example/api/v1/");
    const emailFile = new File(["From: analyst@example.test\n\nSafe fixture"], "fixture.eml", { type: "message/rfc822" });
    const telemetryFile = new File(["<Events />"], "fixture.xml", { type: "application/octet-stream" });

    await client.getIncidentIocs(7);
    await client.createIncident({ title: "Synthetic fixture", description: "" });
    await client.uploadEmail(7, emailFile);
    await client.analyzeArtifact(14);
    await client.enrichIncident(7);
    await client.uploadTelemetry(7, telemetryFile);
    await client.correlate(7);
    await client.getTimeline(7);

    expect(fetchMock.mock.calls.map(([url, init]) => [url, init?.method ?? "GET"])).toEqual([
      ["https://malcie.example/api/v1/incidents/7/iocs", "GET"],
      ["https://malcie.example/api/v1/incidents", "POST"],
      ["https://malcie.example/api/v1/emails/upload-eml", "POST"],
      ["https://malcie.example/api/v1/artifacts/14/analyze-static", "POST"],
      ["https://malcie.example/api/v1/incidents/7/enrich", "POST"],
      ["https://malcie.example/api/v1/telemetry/upload?incident_id=7", "POST"],
      ["https://malcie.example/api/v1/incidents/7/correlate", "POST"],
      ["https://malcie.example/api/v1/incidents/7/timeline", "GET"],
    ]);
    const requests = fetchMock.mock.calls.map(([, init]) => init);
    expect(JSON.parse(requests[1]?.body as string)).toEqual({ title: "Synthetic fixture", description: "" });
    expect(requests[2]?.body).toBeInstanceOf(FormData);
    expect(new Headers(requests[2]?.headers).has("Content-Type")).toBe(false);
    expect(requests[4]?.body).toBe("{}");
    expect(new Headers(requests[5]?.headers).get("Content-Type")).toBe("application/xml");
  });

  it("converts validation errors and successful invalid JSON into readable API errors", async () => {
    const validationResponse = new Response(JSON.stringify({ detail: [{ msg: "title is required" }] }), { status: 422 });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(validationResponse).mockResolvedValueOnce(new Response("not-json", { status: 200 })));
    const client = createApi("https://malcie.example/api/v1");

    await expect(client.health()).rejects.toMatchObject({ status: 422, message: "title is required" });
    await expect(client.health()).rejects.toMatchObject({ status: 200, message: "The MALCIE API returned an invalid JSON response." });
  });
});
