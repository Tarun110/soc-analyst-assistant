"""Incident report generation service."""

from datetime import datetime
from typing import Optional

from app.models.schemas import (
    AlertAnalysisResponse,
    IOC,
    MITRETechnique,
    RemediationAction,
    SeverityLevel,
)


def generate_remediation_actions(
    techniques: list[MITRETechnique],
    iocs: list[IOC],
    severity: SeverityLevel,
) -> list[RemediationAction]:
    """Generate prioritized remediation actions based on classification."""
    actions: list[RemediationAction] = []

    technique_ids = {t.technique_id for t in techniques}

    if severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
        actions.append(RemediationAction(
            priority="P1 - Immediate",
            action="Isolate affected host(s) from the network using EDR containment or network ACLs",
            rationale="Prevent further lateral movement and data exfiltration",
            mitre_mitigation="NIST RS.MI - Mitigation",
        ))

    if iocs:
        ioc_summary = ", ".join(f"{i.type.value}:{i.value}" for i in iocs[:5])
        actions.append(RemediationAction(
            priority="P1 - Immediate",
            action=f"Block identified IOCs at firewall, proxy, and email gateway: {ioc_summary}",
            rationale="Disrupt active command and control and prevent reinfection",
            mitre_mitigation="M1031 - Network Intrusion Prevention",
        ))

    if "T1059.001" in technique_ids:
        actions.append(RemediationAction(
            priority="P2 - Urgent",
            action="Hunt for additional PowerShell execution events with encoded commands across the environment",
            rationale="PowerShell abuse often indicates broader compromise",
            mitre_mitigation="M1049 - Antivirus/Antimalware",
        ))

    if "T1486" in technique_ids or "T1490" in technique_ids:
        actions.append(RemediationAction(
            priority="P1 - Immediate",
            action="Activate ransomware incident response playbook; preserve forensic evidence; do NOT shut down systems",
            rationale="Ransomware requires specialized IR procedures and evidence preservation",
            mitre_mitigation="M1053 - Data Backup",
        ))

    if "T1110" in technique_ids:
        actions.append(RemediationAction(
            priority="P2 - Urgent",
            action="Reset credentials for targeted accounts; enforce MFA; review successful logins after brute force",
            rationale="Successful brute force indicates compromised credentials",
            mitre_mitigation="M1032 - Multi-factor Authentication",
        ))

    if "T1071.001" in technique_ids or any("beacon" in (t.technique_name or "").lower() for t in techniques):
        actions.append(RemediationAction(
            priority="P2 - Urgent",
            action="Block C2 infrastructure and hunt for additional beacons using same indicators",
            rationale="Active C2 enables ongoing adversary control",
            mitre_mitigation="M1031 - Network Intrusion Prevention",
        ))

    if "T1566.001" in technique_ids:
        actions.append(RemediationAction(
            priority="P2 - Urgent",
            action="Remove malicious emails from all mailboxes; block sender domain; scan for mailbox rules",
            rationale="Phishing campaigns typically target multiple users",
            mitre_mitigation="M0954 - Restrict Email Attachments",
        ))

    actions.append(RemediationAction(
        priority="P3 - Standard",
        action="Create incident ticket with full IOC list, timeline, and MITRE mapping; escalate per severity SLA",
        rationale="Ensure proper documentation per NIST SP 800-61",
        mitre_mitigation="NIST RS.AN - Analysis",
    ))

    return actions


def determine_severity(alert_text: str, techniques: list[MITRETechnique]) -> SeverityLevel:
    """Determine alert severity from text and MITRE classification."""
    text_lower = alert_text.lower()

    if any(kw in text_lower for kw in ["critical", "ransomware", "lockbit", "data exfiltration", "domain admin"]):
        return SeverityLevel.CRITICAL

    critical_techniques = {"T1486", "T1003", "T1071.001"}
    high_techniques = {"T1059.001", "T1055", "T1021.001", "T1110"}

    technique_ids = {t.technique_id for t in techniques}

    if technique_ids & critical_techniques:
        return SeverityLevel.CRITICAL
    if technique_ids & high_techniques or "high" in text_lower:
        return SeverityLevel.HIGH
    if "medium" in text_lower:
        return SeverityLevel.MEDIUM
    if "low" in text_lower or "informational" in text_lower:
        return SeverityLevel.LOW

    return SeverityLevel.MEDIUM


def generate_incident_report(
    alert_text: str,
    summary: str,
    severity: SeverityLevel,
    iocs: list[IOC],
    techniques: list[MITRETechnique],
    remediation_actions: list[RemediationAction],
    alert_source: Optional[str] = None,
) -> str:
    """Generate a formatted markdown incident report."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    ioc_table = "| Type | Value | Context |\n|------|-------|----------|\n"
    for ioc in iocs:
        ctx = (ioc.context or "")[:80].replace("|", "/")
        ioc_table += f"| {ioc.type.value} | `{ioc.value}` | {ctx} |\n"
    if not iocs:
        ioc_table += "| - | No IOCs extracted | - |\n"

    mitre_table = "| Technique ID | Name | Tactic | Confidence |\n|--------------|------|--------|------------|\n"
    for t in techniques:
        mitre_table += f"| {t.technique_id} | {t.technique_name} | {t.tactic} | {t.confidence:.0%} |\n"
    if not techniques:
        mitre_table += "| - | No techniques classified | - | - |\n"

    remediation_list = ""
    for i, action in enumerate(remediation_actions, 1):
        remediation_list += f"""
### {i}. [{action.priority}] {action.action}

- **Rationale:** {action.rationale}
- **Framework Reference:** {action.mitre_mitigation or 'N/A'}
"""

    report = f"""# Security Incident Report

| Field | Value |
|-------|-------|
| **Incident ID** | {incident_id} |
| **Generated** | {now} |
| **Severity** | {severity.value.upper()} |
| **Alert Source** | {alert_source or 'Not specified'} |
| **Status** | Open - Under Investigation |

---

## Executive Summary

{summary}

---

## Original Alert

```
{alert_text.strip()}
```

---

## Indicators of Compromise (IOCs)

{ioc_table}

---

## MITRE ATT&CK Classification

{mitre_table}

---

## Remediation Actions

{remediation_list}

---

## Analyst Notes

- [ ] Alert validated (true positive / false positive)
- [ ] Affected assets identified and documented
- [ ] IOCs blocked at perimeter controls
- [ ] Host isolation completed (if applicable)
- [ ] Escalation to Tier-2 completed (if applicable)
- [ ] Stakeholders notified per communication plan

---

*Report generated by AI-Powered SOC Analyst Assistant*
*NIST SP 800-61 | MITRE ATT&CK Framework*
"""
    return report


def save_report(report: str, incident_id: Optional[str] = None) -> str:
    """Save incident report to reports directory."""
    from pathlib import Path

    from app.config import REPORTS_DIR

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"{incident_id or 'incident'}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
    filepath = REPORTS_DIR / filename
    filepath.write_text(report, encoding="utf-8")
    return str(filepath)
