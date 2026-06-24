"""Tests for alert analysis pipeline."""

from app.models.schemas import AlertAnalysisRequest
from app.services.alert_analyzer import alert_analyzer


SAMPLE = """
[ALERT] Suspicious PowerShell Execution
Severity: High
powershell.exe -EncodedCommand from WINWORD.EXE
Network: 185.234.72.19 evil-domain.net
SHA256=3f8a2b1c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0
"""


def test_full_analysis_offline():
    request = AlertAnalysisRequest(alert_text=SAMPLE, include_report=True)
    result = alert_analyzer.analyze(request)
    assert result.summary
    assert len(result.iocs) > 0
    assert len(result.attack_classification) > 0
    assert len(result.remediation_actions) > 0
    assert result.incident_report is not None


def test_severity_detection():
    request = AlertAnalysisRequest(alert_text=SAMPLE)
    result = alert_analyzer.analyze(request)
    assert result.severity.value in ("critical", "high", "medium", "low", "informational")
