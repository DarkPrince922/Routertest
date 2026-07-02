"""Independent device-model identification (favicon hash + signature rules).

The nmap/snmp fingerprint only knows a model if the device advertised it (title,
Server header, SNMP sysDescr). This module identifies the model *actively but
non-destructively* — it hashes the favicon (Shodan-compatible MurmurHash3) and
matches title/Server/body/path/port signatures — so a "quiet" router (generic
login page, SNMP closed) can still be pinned to e.g. ``DIR-620``.

All probes are plain GETs through the scope-gated SafeHTTP transport, so this is
safe-mode friendly (no payloads, no mutation).
"""
from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .base import DeviceInfo

log = logging.getLogger(__name__)

_DATA = Path(__file__).parent / "data" / "model_signatures.yaml"
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_WEB_PORTS = (80, 8080, 8000, 8081, 8888, 81, 443, 8443, 4433)


# --------------------------------------------------------------------- murmur3
def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 (reference algorithm). Returns an unsigned 32-bit int."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded = (length // 4) * 4
    for i in range(0, rounded, 4):
        k1 = (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24))
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[rounded:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1


def _signed32(x: int) -> int:
    return x - 0x100000000 if x & 0x80000000 else x


def favicon_hash(raw: bytes) -> int:
    """Shodan-compatible favicon hash: mmh3 over base64.encodebytes(favicon)."""
    return _signed32(murmur3_32(base64.encodebytes(raw), 0))


# ------------------------------------------------------------------ signatures
@dataclass(slots=True)
class Signature:
    vendor: str
    model: str
    title: re.Pattern | None = None
    body: re.Pattern | None = None
    server: re.Pattern | None = None
    paths: list[dict] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    favicon: list[int] = field(default_factory=list)


@dataclass(slots=True)
class ModelMatch:
    vendor: str
    model: str
    confidence: float
    evidence: str


_signatures: list[Signature] | None = None


def _load() -> list[Signature]:
    global _signatures
    if _signatures is not None:
        return _signatures
    out: list[Signature] = []
    try:
        raw = yaml.safe_load(_DATA.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        log.warning("model_signatures load failed: %s", exc)
        _signatures = []
        return _signatures
    for item in raw.get("signatures", []):
        try:
            out.append(Signature(
                vendor=str(item["vendor"]), model=str(item["model"]),
                title=_rx(item.get("title")), body=_rx(item.get("body")),
                server=_rx(item.get("server")), paths=item.get("paths") or [],
                ports=[int(p) for p in item.get("ports", [])],
                favicon=[int(h) for h in item.get("favicon_mmh3", [])]))
        except (KeyError, re.error) as exc:
            log.warning("bad model signature %r: %s", item, exc)
    _signatures = out
    return _signatures


def _rx(pat) -> re.Pattern | None:
    return re.compile(str(pat), re.IGNORECASE) if pat else None


# ------------------------------------------------------------ identification
async def identify_model(device: DeviceInfo, http) -> ModelMatch | None:
    """Probe the device (safe GETs) and return the best model match, or None."""
    title = device.raw_banners.get("http_title", "")
    server = device.raw_banners.get("http_server", "")
    body, fav_hash = await _fetch_evidence(device, http)
    if body and not title:
        m = _TITLE_RE.search(body)
        if m:
            title = " ".join(m.group(1).split())[:120]

    best: ModelMatch | None = None
    for sig in _load():
        if sig.ports and not device.has_port(*sig.ports):
            continue
        score, why = _score(sig, title, server, body, fav_hash)
        if score <= 0:
            continue
        conf = min(0.95, 0.4 + 0.2 * score)
        if best is None or conf > best.confidence:
            best = ModelMatch(sig.vendor, sig.model, conf, "; ".join(why))
    return best


def _score(sig: Signature, title: str, server: str, body: str,
           fav_hash: int | None) -> tuple[int, list[str]]:
    score = 0
    why: list[str] = []
    if fav_hash is not None and fav_hash in sig.favicon:
        score += 3
        why.append(f"favicon mmh3={fav_hash}")
    if sig.title and title and sig.title.search(title):
        score += 2
        why.append("совпал title")
    if sig.body and body and sig.body.search(body):
        score += 2
        why.append("маркер в теле страницы")
    if sig.server and server and sig.server.search(server):
        score += 1
        why.append("Server-заголовок")
    return score, why


async def _fetch_evidence(device: DeviceInfo, http) -> tuple[str, int | None]:
    """One safe GET of the homepage + favicon on the first responsive web port."""
    body, fav = "", None
    for port in _WEB_PORTS:
        if not device.has_port(port):
            continue
        scheme = "https" if port in (443, 8443, 4433) else "http"
        base = f"{scheme}://{device.ip}:{port}"
        try:
            r = await http.get(f"{base}/")
        except Exception:  # noqa: BLE001 - scope/timeouts are non-fatal here
            continue
        body = r.text or ""
        fav = await _favicon(base, http)
        break
    return body, fav


async def _favicon(base: str, http) -> int | None:
    try:
        r = await http.get(f"{base}/favicon.ico")
    except Exception:  # noqa: BLE001
        return None
    raw = r.content or (r.text or "").encode("utf-8", errors="replace")
    if r.status != 200 or not raw:
        return None
    return favicon_hash(raw)


async def enrich(device: DeviceInfo, http) -> ModelMatch | None:
    """Identify the model and, if confident, write it into ``device``."""
    match = await identify_model(device, http)
    if match is None:
        return None
    if not device.vendor:
        device.vendor = match.vendor
    # Only overwrite the model when we don't already have this model string.
    if not device.model or match.model.lower() not in (device.model or "").lower():
        device.model = match.model
    device.http_signatures["model_match"] = match.model
    device.http_signatures["model_match_conf"] = round(match.confidence, 2)
    return match
