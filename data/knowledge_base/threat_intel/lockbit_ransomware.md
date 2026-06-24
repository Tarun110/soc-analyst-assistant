# Threat Intelligence: LockBit Ransomware

**Threat Actor:** LockBit Group
**Malware Family:** LockBit 3.0
**Type:** Ransomware-as-a-Service (RaaS)

## Overview
LockBit is a prolific ransomware family operating as RaaS. It uses double extortion (encrypt + exfiltrate). Initial access commonly via RDP brute force, phishing, or exploiting public-facing applications.

## Tactics and Techniques
- T1110 Brute Force (RDP)
- T1021.001 Remote Desktop Protocol (lateral movement)
- T1486 Data Encrypted for Impact
- T1490 Inhibit System Recovery (delete shadow copies)

## Indicators of Compromise
- **File Extension:** .lockbit3, .abcd, random 9-char extensions
- **Ransom Note:** LockBit-NOTE.txt or README-LOCKBIT.txt
- **Commands:** vssadmin delete shadows /all /quiet, wbadmin delete catalog -quiet
- **Services:** Stops backup and security services before encryption

## Containment Playbook
1. IMMEDIATELY isolate affected systems (network disconnect, not shutdown)
2. Block C2 IPs at perimeter firewall
3. Do NOT pay ransom without legal/executive approval
4. Engage incident response team and legal counsel
5. Restore from offline backups after eradication confirmed
