"""IOC extraction from security alerts using regex patterns."""

import re
from typing import Optional

from app.models.schemas import IOC, IOCType

# Regex patterns for common IOC types
IOC_PATTERNS: dict[IOCType, re.Pattern] = {
    IOCType.IP: re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ),
    IOCType.DOMAIN: re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|local|edu|gov|info|biz|co|uk|de|ru)\b",
        re.IGNORECASE,
    ),
    IOCType.URL: re.compile(
        r"https?://[^\s<>\"']+",
        re.IGNORECASE,
    ),
    IOCType.EMAIL: re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    ),
    IOCType.MD5: re.compile(r"\b[A-Fa-f0-9]{32}\b"),
    IOCType.SHA1: re.compile(r"\b[A-Fa-f0-9]{40}\b"),
    IOCType.SHA256: re.compile(r"\b[A-Fa-f0-9]{64}\b"),
    IOCType.CVE: re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    IOCType.FILE_PATH: re.compile(
        r"(?:[A-Za-z]:\\|/)[^\s<>\"']+",
    ),
    IOCType.REGISTRY_KEY: re.compile(
        r"\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s]+",
        re.IGNORECASE,
    ),
}

# Private/reserved IPs to filter from external threat IOCs
PRIVATE_IP_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                       "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                       "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                       "172.30.", "172.31.", "192.168.", "127.")


def _get_context(text: str, match_start: int, match_end: int, window: int = 60) -> str:
    start = max(0, match_start - window)
    end = min(len(text), match_end + window)
    return text[start:end].strip().replace("\n", " ")


def _is_private_ip(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES)


def extract_iocs(text: str, include_internal_ips: bool = True) -> list[IOC]:
    """Extract indicators of compromise from alert text."""
    found: dict[tuple[IOCType, str], IOC] = {}

    for ioc_type, pattern in IOC_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0).strip().rstrip(".,;:)")

            if ioc_type == IOCType.IP and not include_internal_ips and _is_private_ip(value):
                continue

            if ioc_type == IOCType.DOMAIN and value.lower().endswith(".local"):
                continue

            # Avoid classifying hashes as MD5 when they're SHA256
            if ioc_type == IOCType.MD5 and len(value) != 32:
                continue
            if ioc_type == IOCType.SHA1 and len(value) != 40:
                continue
            if ioc_type == IOCType.SHA256 and len(value) != 64:
                continue

            key = (ioc_type, value.lower())
            if key not in found:
                found[key] = IOC(
                    type=ioc_type,
                    value=value,
                    context=_get_context(text, match.start(), match.end()),
                )

    return sorted(found.values(), key=lambda x: (x.type.value, x.value))


def enrich_iocs_with_llm(iocs: list[IOC], alert_text: str, llm_client) -> list[IOC]:
    """Optional LLM pass to find IOCs missed by regex (requires OpenAI)."""
    if not llm_client:
        return iocs

    from langchain_core.prompts import ChatPromptTemplate
    from langchain_openai import ChatOpenAI

    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a SOC analyst. Extract IOCs from the alert. Return ONLY a JSON array of objects with keys: type, value, context. Types: ip, domain, url, email, md5, sha1, sha256, cve, file_path, registry_key."),
        ("human", "Alert:\n{alert}\n\nAlready found: {existing}"),
    ])

    existing = [{"type": i.type.value, "value": i.value} for i in iocs]
    chain = prompt | llm_client
    try:
        response = chain.invoke({"alert": alert_text, "existing": str(existing)})
        import json
        content = response.content.strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        extra = json.loads(content)
        seen = {(i.type, i.value.lower()) for i in iocs}
        for item in extra:
            ioc_type = IOCType(item["type"])
            key = (ioc_type, item["value"].lower())
            if key not in seen:
                iocs.append(IOC(type=ioc_type, value=item["value"], context=item.get("context")))
                seen.add(key)
    except Exception:
        pass

    return iocs
