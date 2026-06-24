# MITRE ATT&CK Technique: T1110 - Brute Force

**Tactic:** Credential Access
**Technique ID:** T1110
**Name:** Brute Force

Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Brute force attacks include password spraying, credential stuffing, and traditional brute force against authentication services.

**Detection:**
- Multiple failed authentication attempts from single or distributed sources
- Successful login after many failures from same IP
- Authentication against disabled or non-existent accounts

**Mitigation M1032:** Multi-factor authentication and account lockout policies.
