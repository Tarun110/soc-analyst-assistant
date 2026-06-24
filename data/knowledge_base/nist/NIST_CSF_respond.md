# NIST Cybersecurity Framework (CSF) - Respond Function

## RS.RP: Response Planning
Execute response processes during an incident to ensure timely recovery.

## RS.CO: Communications
Coordinate response activities with internal and external stakeholders.

## RS.AN: Analysis
Conduct analysis to ensure adequate response and support recovery activities.

**Analyst guidance:**
- Map observed behaviors to MITRE ATT&CK techniques
- Determine attack stage (initial access, execution, C2, impact)
- Identify affected assets, users, and data classifications

## RS.MI: Mitigation
Contain and mitigate incidents to prevent expansion.

**Immediate mitigation actions:**
1. Isolate compromised endpoints from network (EDR network containment)
2. Block malicious IPs/domains at firewall and proxy
3. Disable compromised user accounts
4. Reset credentials for affected accounts
5. Preserve forensic evidence before remediation

## RS.IM: Improvements
Incorporate lessons learned into incident response plans.
