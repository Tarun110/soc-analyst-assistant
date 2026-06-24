# Threat Intelligence: Cobalt Strike Beacon Activity

**Tool:** Cobalt Strike (legitimate pentest tool, frequently abused)
**Type:** Command and Control Framework

## Overview
Cobalt Strike beacons provide remote access and post-exploitation capabilities. Threat actors deploy beacons after initial compromise for persistent C2, credential harvesting, and lateral movement.

## Detection Signatures
- **Network:** HTTPS beaconing with jitter (regular intervals with randomization)
- **Named Pipes:** \\.\pipe\msagent_*, \\.\pipe\status_*
- **Process Injection:** svchost.exe with unusual child processes or hollowed processes
- **JA3 Fingerprints:** Known Cobalt Strike TLS fingerprints

## MITRE Mapping
- T1071.001 Web Protocols
- T1055 Process Injection
- T1059 Command and Scripting Interpreter
- T1003 OS Credential Dumping

## Response Actions
1. Block beacon C2 IP/domain at firewall and DNS
2. Terminate beacon process via EDR (preserve memory dump first)
3. Hunt for additional beacons using same C2 infrastructure
4. Review authentication logs for lateral movement indicators
