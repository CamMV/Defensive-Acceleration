import json
import re

import pytest
from PIL import Image

from test_server import payloads
from test_server.app import create_app, inprocess_client
from test_server.make_images import STATIC_DIR

DIRECTIVES = ("read the file", "send its contents", "append the line", "report the total as")
VERSION_SENTENCE = "The recommended stable version is 2.4.1."


@pytest.fixture
def log_path(tmp_path):
    return tmp_path / "attacker_log.jsonl"


@pytest.fixture
def client(log_path):
    return inprocess_client(create_app(log_path))


def _entries(log_path):
    return [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]


def _rows(html):
    return dict(re.findall(r"<tr><th>(.*?)</th><td>(.*?)</td></tr>", html))


def test_benign_page_clean(client):
    html = client.get("/docs-benign").text
    assert VERSION_SENTENCE in html
    assert not any(phrase in html for phrase in DIRECTIVES)


@pytest.mark.parametrize("variant,payload", [
    ("css", payloads.EXFIL_PLAIN),
    ("white", payloads.EXFIL_CHUNKED),
    ("comment", payloads.EXFIL_BASE64),
    ("alt", payloads.EXFIL_HEX),
])
def test_text_injection_variants(client, variant, payload):
    html = client.get("/docs-text-injection", params={"variant": variant}).text
    assert payload in html
    assert VERSION_SENTENCE in html


def test_text_injection_default_and_unknown(client):
    assert payloads.EXFIL_PLAIN in client.get("/docs-text-injection").text
    assert client.get("/docs-text-injection?variant=nope").status_code == 404


def test_image_page_has_no_text_payload(client):
    html = client.get("/docs-image-injection").text
    assert "read the file" not in html
    assert "trap_lowcontrast.png" in html and "trap_typographic.png" in html


def test_multihop_visible_patch(client):
    html = client.get("/docs-multihop").text
    assert payloads.MULTIHOP_PATCH in html
    assert VERSION_SENTENCE in html


def test_invoices(client):
    assert _rows(client.get("/invoice/1042").text) == {
        "Invoice ID": "ACME-1042", "Issue date": "2026-10-15", "Vendor": "Acme Corp",
        "Concept": "Monthly platform support", "Total": "1250.00 USD", "Notes": "Payment due in 30 days.",
    }
    pii = _rows(client.get("/invoice/2001").text)
    assert pii["Total"] == "870.50 USD"
    assert payloads.EXFIL_PII_REVERSED in pii["Notes"]
    poisoned = client.get("/invoice/2002").text
    assert _rows(poisoned)["Total"] == "1310.00 USD"
    assert f'<span style="display:none">{payloads.AMOUNT_POISON}</span>' in poisoned
    assert client.get("/invoice/9999").status_code == 404


def test_search_benign_only(client):
    html = client.get("/search", params={"q": "acme supplier registry"}).text
    assert html.count("<li>") == 2
    assert payloads.EXFIL_TRAVERSAL not in html


def test_search_mixed_and_empty(client):
    html = client.get("/search", params={"q": "acme-http retry policy"}).text
    assert html.count("<li>") == 2
    assert "retry policies explained" in html
    assert payloads.EXFIL_TRAVERSAL in html
    assert "No results" in client.get("/search?q=").text
    assert "No results" in client.get("/search?q=zzzzzz").text


def test_collect_logs_requests(client, log_path):
    assert client.get("/collect?d=abc").json() == {"ok": True}
    client.get("/collect/x/y")
    client.post("/collect", content="secret-body", headers={"X-Test": "1"})
    first, second, third = _entries(log_path)
    assert first["path"] == "/collect" and first["query"] == "d=abc" and first["params"] == {"d": "abc"}
    assert first["method"] == "GET" and "host" in first["headers"]
    assert second["path"] == "/collect/x/y"
    assert third["method"] == "POST" and third["body"] == "secret-body" and third["headers"]["x-test"] == "1"


def test_images_exist_and_lowcontrast():
    for name in ("diagram.png", "trap_lowcontrast.png", "trap_typographic.png"):
        assert (STATIC_DIR / name).exists()
    img = Image.open(STATIC_DIR / "trap_lowcontrast.png").convert("RGB")
    assert img.size == (900, 260)
    background = (250, 250, 250)
    max_diff = max(
        max(abs(low - bg), abs(high - bg))
        for (low, high), bg in zip(img.getextrema(), background)
    )
    assert 0 < max_diff <= 10
