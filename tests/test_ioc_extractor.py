"""Tests for IOC extraction."""

from app.services.ioc_extractor import extract_iocs
from app.models.schemas import IOCType


SAMPLE_ALERT = """
Process: powershell.exe
Network: HTTPS to 185.234.72.19:443 (evil-domain.net)
SHA256=3f8a2b1c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a
Email: attacker@secure-mail-gateway.net
CVE-2024-1234
"""


def test_extract_ip():
    iocs = extract_iocs(SAMPLE_ALERT)
    ips = [i for i in iocs if i.type == IOCType.IP]
    assert any(i.value == "185.234.72.19" for i in ips)


def test_extract_sha256():
    iocs = extract_iocs(SAMPLE_ALERT)
    hashes = [i for i in iocs if i.type == IOCType.SHA256]
    assert len(hashes) >= 1
    assert len(hashes[0].value) == 64


def test_extract_email():
    iocs = extract_iocs(SAMPLE_ALERT)
    emails = [i for i in iocs if i.type == IOCType.EMAIL]
    assert any("secure-mail-gateway.net" in i.value for i in emails)


def test_extract_cve():
    iocs = extract_iocs(SAMPLE_ALERT)
    cves = [i for i in iocs if i.type == IOCType.CVE]
    assert any(i.value.upper() == "CVE-2024-1234" for i in cves)


def test_no_duplicate_iocs():
    iocs = extract_iocs(SAMPLE_ALERT + SAMPLE_ALERT)
    values = [(i.type, i.value.lower()) for i in iocs]
    assert len(values) == len(set(values))
