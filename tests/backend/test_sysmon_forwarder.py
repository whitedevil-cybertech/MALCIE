from __future__ import annotations

import httpx

from app.services.sysmon_forwarder import forward_file


def test_forwarder_retries_until_acknowledged_and_leaves_source_intact(tmp_path) -> None:
    source = tmp_path / "events.json"
    original = b'[{"EventID":1}]'
    source.write_bytes(original)
    calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(503)
        assert request.content == original
        return httpx.Response(200, json={"ingested_count": 1, "duplicate_count": 0})

    client = httpx.Client(transport=httpx.MockTransport(respond))
    try:
        assert forward_file(
            client, source, "https://malcie.invalid/api/v1/telemetry/upload", max_retries=1
        )
    finally:
        client.close()
    assert calls == 2
    assert source.read_bytes() == original
