from __future__ import annotations

from email.message import EmailMessage

from app.core.config import settings
from app.services.email_intake import extract_urls_domains, parse_eml_bytes
from app.services.ioc_extraction import extract_iocs_from_text


def test_url_normalization_removes_fragments_default_ports_and_encodes_idn() -> None:
    text = (
        "https://EXAMPLE.com:443/path#tracking "
        "http://example.com:80/path#other "
        "https://例え.テスト:8443/a%20b#fragment"
    )
    iocs = extract_iocs_from_text(text)
    normalized = {ioc.normalized_value for ioc in iocs if ioc.ioc_type == "url"}
    assert "https://example.com/path" in normalized
    assert "http://example.com/path" in normalized
    assert "https://xn--r8jz45g.xn--zckzah:8443/a%20b" in normalized


def test_malformed_mime_charset_is_replaced_without_crashing(monkeypatch) -> None:
    monkeypatch.setattr(settings, "max_attachment_size_bytes", 100)
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["To"] = "recipient@example.com"
    message["Content-Type"] = "text/plain; charset=not-a-real-charset"
    message.set_payload("visit https://example.com")
    parsed = parse_eml_bytes(message.as_bytes())
    assert "https://example.com" in parsed.body_preview


def test_email_domain_normalization_supports_idn_and_rejects_bad_urls() -> None:
    urls, domains = extract_urls_domains(
        "https://例え.テスト/a#fragment https://[not-an-ip]/bad example.com"
    )
    assert urls
    assert "xn--r8jz45g.xn--zckzah" in domains
