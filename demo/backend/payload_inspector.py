"""Static payload evidence extractor for quarantined demo samples."""
from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import urlparse

MAX_BASE64_CHARS = 20000
MAX_DECODED_BYTES = 12000
EXCERPT_CHARS = 260

_B64DECODE_RE = re.compile(
    r"(?:base64|__import__\([\"']base64[\"']\))\.b64decode\(\s*(?:[rubfRUBF]*)?([\"'])(?P<value>[A-Za-z0-9+/=\s]{8,})(?:\1)",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://[^\s'\"\\)]+", re.IGNORECASE)
_SUSPICIOUS_APIS = (
    ("base64.b64decode", re.compile(r"(?:base64|__import__\([\"']base64[\"']\))\.b64decode", re.IGNORECASE)),
    ("exec", re.compile(r"(?<![\w.])exec\s*\(|builtins[\"']?\)\.exec|__import__\([\"']builtins[\"']\)\.exec", re.IGNORECASE)),
    ("eval", re.compile(r"(?<![\w.])eval\s*\(", re.IGNORECASE)),
    ("compile", re.compile(r"(?<![\w.])compile\s*\(", re.IGNORECASE)),
    ("os.system", re.compile(r"os\.system|from\s+os\s+import\s+system", re.IGNORECASE)),
    ("subprocess", re.compile(r"subprocess\.(run|Popen|call)|from\s+subprocess\s+import", re.IGNORECASE)),
    ("urlopen", re.compile(r"urlopen\s*\(|urllib\.request", re.IGNORECASE)),
    ("unpack_archive", re.compile(r"unpack_archive\s*\(", re.IGNORECASE)),
)
_COMMAND_INDICATORS = (
    ("bitsadmin", re.compile(r"\bbitsadmin\b", re.IGNORECASE)),
    ("start command", re.compile(r"\bstart\s+(?:\"\"|\")", re.IGNORECASE)),
    ("shell=True", re.compile(r"shell\s*=\s*True", re.IGNORECASE)),
    ("pythonw.exe", re.compile(r"pythonw\.exe", re.IGNORECASE)),
)
_PERSISTENCE_PATHS = (
    ("Windows Startup folder", re.compile(r"Start Menu\\+Programs\\+Startup|\\+Startup\\+", re.IGNORECASE)),
    ("AppData Roaming", re.compile(r"AppData\\+Roaming", re.IGNORECASE)),
    ("VBScript launcher", re.compile(r"\.vbs\b|CreateObject\([\"']WScript\.Shell[\"']\)", re.IGNORECASE)),
    ("batch launcher", re.compile(r"\.bat\b", re.IGNORECASE)),
)


def inspect_payloads(text: str, filename: str | None = None) -> list[dict]:
    """Return static evidence without executing, importing, or fetching anything."""
    evidence: list[dict] = []
    _append_source_evidence(evidence, text, filename, source="source")

    for match in _B64DECODE_RE.finditer(text):
        encoded = "".join(match.group("value").split())
        if len(encoded) > MAX_BASE64_CHARS:
            evidence.append(_item("base64_skipped", "Base64 payload skipped", f"{len(encoded)} chars exceeds safe demo limit", filename, "source", "medium"))
            continue
        try:
            decoded_bytes = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            evidence.append(_item("base64_decode_error", "Malformed base64 payload", encoded[:80], filename, "source", "medium"))
            continue

        truncated = len(decoded_bytes) > MAX_DECODED_BYTES
        decoded = decoded_bytes[:MAX_DECODED_BYTES].decode("utf-8", errors="replace")
        label = "Decoded base64 payload"
        value = _excerpt(decoded)
        if truncated:
            value += " ... [truncated]"
        evidence.append(_item("decoded_base64", label, value, filename, "decoded", "high"))
        _append_source_evidence(evidence, decoded, filename, source="decoded")

    return _dedupe(evidence)


def _append_source_evidence(evidence: list[dict], text: str, filename: str | None, source: str) -> None:
    for label, pattern in _SUSPICIOUS_APIS:
        if pattern.search(text):
            evidence.append(_item("suspicious_api", label, _context(text, pattern), filename, source, "high"))

    for url in _URL_RE.findall(text):
        parsed = urlparse(url)
        domain = parsed.netloc or url
        evidence.append(_item("network_indicator", "URL/domain", f"{domain} :: {url}", filename, source, "high"))

    for label, pattern in _PERSISTENCE_PATHS:
        if pattern.search(text):
            evidence.append(_item("persistence_indicator", label, _context(text, pattern), filename, source, "high"))

    for label, pattern in _COMMAND_INDICATORS:
        if pattern.search(text):
            evidence.append(_item("command_indicator", label, _context(text, pattern), filename, source, "high"))


def _item(kind: str, label: str, value: str, filename: str | None, source: str, severity: str) -> dict:
    item = {
        "kind": kind,
        "label": label,
        "value": value,
        "source": source,
        "severity": severity,
    }
    if filename:
        item["filename"] = filename
    return item


def _context(text: str, pattern: re.Pattern) -> str:
    match = pattern.search(text)
    if not match:
        return ""
    start = max(0, match.start() - 90)
    end = min(len(text), match.end() + 120)
    return _excerpt(text[start:end])


def _excerpt(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text).strip()
    return normalized[:EXCERPT_CHARS]


def _dedupe(items: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    result: list[dict] = []
    for item in items:
        key = (
            item.get("kind"),
            item.get("label"),
            item.get("value"),
            item.get("filename"),
            item.get("source"),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result
