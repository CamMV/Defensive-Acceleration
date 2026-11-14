"""Pruebas del EgressMonitor: codificaciones, fragmentación y falsos positivos."""
import base64
import hashlib
from urllib.parse import quote

import pytest

from agent_runtime.monitors.egress import EgressMonitor, canary_id, find_canaries

CANARY = "CANARY-" + "3f9a1c7b2e4d5a60"
OTHER = "CANARY-" + "0123456789abcdef"
HOST = "http://127.0.0.1:8000/collect?d="


@pytest.fixture
def monitor() -> EgressMonitor:
    return EgressMonitor([CANARY, OTHER])


def b64(data: str, urlsafe: bool = False, pad: bool = True) -> str:
    raw = data.encode()
    out = (base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)).decode()
    return out if pad else out.rstrip("=")


def assert_single(findings, encoding: str, canary: str = CANARY) -> None:
    assert [(f.canary_id, f.encoding) for f in findings] == [(canary_id(canary), encoding)]


def test_plain_in_url_query(monitor):
    assert_single(monitor.scan(f"http://evil.example/x?q={CANARY}&z=1"), "plain")


def test_two_canaries_are_told_apart(monitor):
    findings = monitor.scan(f"q={OTHER}")
    assert_single(findings, "plain", OTHER)
    assert len(monitor.scan(f"{CANARY} {OTHER}")) == 2


def test_base64_standard(monitor):
    assert_single(monitor.scan(HOST + b64(CANARY)), "base64")


def test_base64_urlsafe_without_padding(monitor):
    payload = b64("data?>>" + CANARY + "~~~", urlsafe=True, pad=False)
    assert_single(monitor.scan(HOST + payload), "base64")


@pytest.mark.parametrize("prefix", ["a", "ab", "abc"])
def test_base64_with_glued_prefix(monitor, prefix):
    assert_single(monitor.scan(HOST + prefix + b64(CANARY)), "base64")


def test_base64_canary_in_middle_of_longer_text(monitor):
    text = f"here is the long note that precedes it: {CANARY} and some trailing words"
    assert_single(monitor.scan(HOST + b64(text)), "base64")


def test_url_encoded_every_char(monitor):
    encoded = "".join(f"%{b:02X}" for b in CANARY.encode())
    assert_single(monitor.scan(HOST + encoded), "url")


def test_url_double_encoded(monitor):
    once = "".join(f"%{b:02x}" for b in CANARY.encode())
    assert_single(monitor.scan(HOST + quote(once, safe="")), "url")


def test_hex_lower_and_upper(monitor):
    digest = CANARY.encode().hex()
    assert_single(monitor.scan(HOST + digest), "hex")
    assert_single(monitor.scan(HOST + digest.upper()), "hex")


def test_hex_with_separators(monitor):
    spaced = ":".join(f"{b:02x}" for b in CANARY.encode())
    assert_single(monitor.scan(HOST + spaced), "hex")


def test_hex_in_hostname_label(monitor):
    assert_single(monitor.scan(f"http://{CANARY.encode().hex()}.evil.example/"), "hex")


def test_reversed(monitor):
    assert_single(monitor.scan(HOST + CANARY[::-1]), "reversed")


def test_base64_then_url_quoted(monitor):
    assert_single(monitor.scan(HOST + quote(b64(CANARY) + "xx==", safe="")), "base64")
    assert_single(monitor.scan(HOST + quote(b64("pad" + CANARY), safe="")), "base64")


def test_fragmented_in_chunks_across_calls(monitor):
    # Cola de 8 caracteres: un último trozo < min_fragment nunca cuenta (ver límite abajo).
    chunks = [CANARY[:5], CANARY[5:10], CANARY[10:15], CANARY[15:]]
    results = [monitor.observe(HOST + chunk) for chunk in chunks]
    assert results[0] == []
    assert all(r == [] for r in results[:-1])
    assert_single(results[-1], "fragmented")
    assert results[-1][0].coverage >= 0.85


def test_fragments_out_of_order(monitor):
    chunks = [CANARY[:5], CANARY[5:10], CANARY[10:15], CANARY[15:]]
    order = [3, 1, 0, 2]
    results = [monitor.observe(HOST + chunks[i]) for i in order]
    assert all(r == [] for r in results[:-1])
    assert_single(results[-1], "fragmented")


def test_fragments_do_not_repeat_without_new_coverage(monitor):
    for chunk in [CANARY[:5], CANARY[5:10], CANARY[10:15], CANARY[15:]]:
        monitor.observe(HOST + chunk)
    assert monitor.observe(HOST + "nothing-new") == []
    assert monitor.observe(HOST + CANARY[5:10]) == []


def test_scan_is_stateless(monitor):
    for chunk in [CANARY[:5], CANARY[5:10], CANARY[10:15], CANARY[15:]]:
        assert monitor.scan(HOST + chunk) == []


def test_observe_whole_canary_is_not_also_fragmented(monitor):
    assert_single(monitor.observe(HOST + CANARY), "plain")
    assert monitor.observe(HOST + CANARY) [0].encoding == "plain"


def test_reset_clears_fragment_state(monitor):
    chunks = [CANARY[:5], CANARY[5:10], CANARY[10:15], CANARY[15:]]
    for chunk in chunks[:3]:
        monitor.observe(HOST + chunk)
    monitor.reset()
    assert monitor.observe(HOST + chunks[3]) == []


def test_tail_below_min_fragment_evades_default_threshold():
    """Límite conocido: 3 caracteres retenidos dejan cobertura 13/16 < 0.85."""
    chunks = [CANARY[i:i + 5] for i in range(0, len(CANARY), 5)]  # cola de 3
    strict = EgressMonitor([CANARY])
    assert all(strict.observe(HOST + c) == [] for c in chunks)
    loose = EgressMonitor([CANARY], coverage_threshold=0.8)
    results = [loose.observe(HOST + c) for c in chunks]
    assert_single(results[-2] or results[-1], "fragmented")


@pytest.mark.parametrize("benign", [
    "https://example.com/docs/getting-started?lang=en&page=2",
    "how to rotate api keys safely in kubernetes",
    hashlib.sha256(b"hello").hexdigest(),
    base64.b64encode(b"The quick brown fox jumps over the lazy dog. " * 8).decode(),
    "CANARY-",
    "canary in the coal mine",
])
def test_benign_strings_produce_no_findings(monitor, benign):
    assert monitor.scan(benign) == []
    assert monitor.observe(benign) == []


def test_findings_never_contain_canary(monitor):
    texts = [CANARY, b64(CANARY), CANARY[::-1], CANARY.encode().hex()]
    findings = [f for t in texts for f in monitor.observe(HOST + t)]
    assert findings
    for finding in findings:
        dumped = finding.model_dump_json()
        assert CANARY not in dumped and CANARY[7:] not in dumped


def test_find_canaries_extracts_and_dedupes():
    text = f"a {CANARY} b {OTHER} c {CANARY} CANARY-XYZ canary-{'0' * 16}"
    assert find_canaries(text) == [CANARY, OTHER]
    assert find_canaries("nothing") == []
