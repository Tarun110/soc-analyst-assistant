# NIST SP 800-61 Rev. 2 - Computer Security Incident Handling Guide

## Incident Handling Steps

### 1. Preparation
Establish incident response capability before incidents occur. Maintain contact lists, playbooks, and communication channels. Ensure logging and monitoring are adequate for detection.

### 2. Detection and Analysis
Analyze alerts to determine if a security incident has occurred. Validate indicators, assess scope and impact, and prioritize based on severity. Document all findings with timestamps and evidence preservation.

**Key activities for Tier-1 analysts:**
- Triage incoming alerts within SLA (typically 15-30 minutes)
- Correlate related events across SIEM, EDR, and email security
- Extract and enrich IOCs (IPs, domains, hashes)
- Escalate confirmed incidents to Tier-2/3 with complete context

### 3. Containment, Eradication, and Recovery
Short-term containment limits damage (isolate host, block IOCs). Long-term containment maintains business operations while eradicating threat. Recovery restores systems to normal operation.

### 4. Post-Incident Activity
Conduct lessons learned, update detection rules, and improve playbooks.

## Severity Classification
- **Critical:** Active ransomware, data exfiltration, domain admin compromise
- **High:** Confirmed malware execution, lateral movement, privilege escalation
- **Medium:** Suspicious activity requiring investigation, policy violations
- **Low:** Reconnaissance, blocked attacks, informational events
