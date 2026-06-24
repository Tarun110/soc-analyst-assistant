# MITRE ATT&CK Technique: T1071.001 - Application Layer Protocol: Web Protocols

**Tactic:** Command and Control
**Technique ID:** T1071.001
**Name:** Web Protocols

Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.

**Detection:**
- Monitor for beaconing behavior over HTTP/HTTPS
- Analyze DNS queries to newly registered or suspicious domains
- Inspect TLS certificate anomalies and JA3/JA3S fingerprints

**Mitigation M1031:** Network intrusion detection and prevention systems that use network signatures.
