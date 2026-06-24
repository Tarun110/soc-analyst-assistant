# MITRE ATT&CK Technique: T1486 - Data Encrypted for Impact

**Tactic:** Impact
**Technique ID:** T1486
**Name:** Data Encrypted for Impact

Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. This is commonly done to extort victims (ransomware). Encryption may occur after data is exfiltrated.

**Detection:**
- Monitor for mass file rename operations with unusual extensions (.locked, .encrypted, .ryuk)
- Detect shadow copy deletion (vssadmin delete shadows)
- Alert on rapid entropy changes across file shares

**Mitigation M1053:** Maintain offline backups and test restoration procedures regularly.
