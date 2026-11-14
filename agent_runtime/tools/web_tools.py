"""Herramientas de red (solo Enclave 2, solo vía broker).

Allowlist dura: únicamente el servidor de pruebas local. Nada del red-team sale
a internet real. El broker reutiliza `check_url`, y las funciones la vuelven a
aplicar (defensa en profundidad).
"""
from __future__ import annotations

import base64

import httpx

ALLOWED_NETLOCS: frozenset[tuple[str, int]] = frozenset({("127.0.0.1", 8000)})
SEARCH_URL = "http://127.0.0.1:8000/search"
MAX_TEXT_CHARS = 20_000
MAX_IMAGE_BYTES = 400_000
IMAGE_DATA_PREFIX = "data:image;base64,"


class UrlNotAllowed(ValueError):
    """La URL no pasa la allowlist."""


def check_url(url: str) -> httpx.URL:
    """Valida esquema, ausencia de userinfo y (host, puerto) contra la allowlist."""
    if not isinstance(url, str) or not url or any(ch in url for ch in ("\r", "\n", "\t", "\\", " ")):
        raise UrlNotAllowed("malformed url")
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, ValueError, TypeError) as exc:
        raise UrlNotAllowed("unparseable url") from exc
    if parsed.scheme != "http":
        raise UrlNotAllowed("scheme not allowed")
    if parsed.userinfo:
        raise UrlNotAllowed("userinfo not allowed")
    port = parsed.port or 80
    if (parsed.host, port) not in ALLOWED_NETLOCS:
        raise UrlNotAllowed("host not in allowlist")
    return parsed


def net_target(url: str) -> str:
    """Forma canónica `host:port/path?query` usada para comparar con el scope del token."""
    parsed = check_url(url)
    return f"{parsed.host}:{parsed.port or 80}{parsed.raw_path.decode('ascii', 'replace')}".casefold()


def search_target(query: str) -> str:
    return "search:" + " ".join(query.casefold().split())


def http_client() -> httpx.Client:
    """Cliente real. trust_env=False: ignora proxies del entorno."""
    return httpx.Client(timeout=5.0, trust_env=False, follow_redirects=False)


class WebTools:
    """Envuelve un `httpx.Client` inyectable (real o en proceso para tests)."""

    def __init__(self, client: httpx.Client) -> None:
        self._client = client

    def fetch_url(self, url: str) -> str:
        parsed = check_url(url)
        response = self._client.get(str(parsed), follow_redirects=False)
        content_type = response.headers.get("content-type", "")
        if content_type.startswith("image/"):
            # Las imágenes viajan como data URI para que la Aduana las pase a OCR/VLM.
            return IMAGE_DATA_PREFIX + base64.b64encode(response.content[:MAX_IMAGE_BYTES]).decode("ascii")
        return f"HTTP {response.status_code}\n{response.text[:MAX_TEXT_CHARS]}"

    def web_search(self, query: str) -> str:
        check_url(SEARCH_URL)
        response = self._client.get(SEARCH_URL, params={"q": query}, follow_redirects=False)
        return f"HTTP {response.status_code}\n{response.text[:MAX_TEXT_CHARS]}"
