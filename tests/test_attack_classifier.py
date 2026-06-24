"""Tests for MITRE attack classification."""

from app.services.attack_classifier import classify_attack_rule_based


def test_powershell_classification():
    alert = "powershell.exe -EncodedCommand detected from WINWORD.EXE"
    techniques = classify_attack_rule_based(alert)
    ids = [t.technique_id for t in techniques]
    assert "T1059.001" in ids


def test_ransomware_classification():
    alert = "Mass file rename to .lockbit3 extension. Ransom note LockBit-NOTE.txt"
    techniques = classify_attack_rule_based(alert)
    ids = [t.technique_id for t in techniques]
    assert "T1486" in ids


def test_brute_force_classification():
    alert = "847 failed authentication attempts via RDP brute force"
    techniques = classify_attack_rule_based(alert)
    ids = [t.technique_id for t in techniques]
    assert "T1110" in ids


def test_confidence_ordering():
    alert = "powershell.exe phishing attachment ransomware beacon"
    techniques = classify_attack_rule_based(alert)
    if len(techniques) >= 2:
        assert techniques[0].confidence >= techniques[1].confidence
