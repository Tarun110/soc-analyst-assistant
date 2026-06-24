# Threat Intelligence: Emotet Malware Campaign

**Threat Actor:** TA542 (Mealybug)
**Malware Family:** Emotet
**Type:** Banking trojan / malware dropper

## Overview
Emotet is a modular malware variant frequently distributed via malicious email attachments (macro-enabled Office documents). It establishes persistence, steals credentials, and downloads secondary payloads including TrickBot and ransomware.

## Indicators of Compromise (IOCs)
- **C2 Domains:** emotet-update[.]com, secure-mail-gateway[.]net (example patterns)
- **File Hashes:** Commonly distributed as .doc/.docm with SHA256 hashes varying per campaign
- **Registry:** HKCU\Software\Microsoft\Windows\CurrentVersion\Run persistence keys
- **Processes:** Parent: WINWORD.EXE -> Child: powershell.exe with encoded commands

## MITRE Mapping
- T1566.001 Spearphishing Attachment
- T1059.001 PowerShell
- T1071.001 Web Protocols (C2)
- T1112 Modify Registry (persistence)

## Recommended Response
1. Block sender domain and attachment hash at email gateway
2. Hunt for same hash across environment via EDR
3. Reset credentials for users who opened the attachment
4. Review mailbox rules created in last 24 hours (T1114)
