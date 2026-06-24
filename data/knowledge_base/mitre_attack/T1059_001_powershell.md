# MITRE ATT&CK Technique: T1059.001 - Command and Scripting Interpreter: PowerShell

**Tactic:** Execution
**Technique ID:** T1059.001
**Name:** PowerShell

Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code.

**Detection:**
- Monitor for PowerShell execution with encoded commands (-EncodedCommand, -enc)
- Detect suspicious parent-child process relationships (e.g., winword.exe -> powershell.exe)
- Log Script Block Logging and Module Logging

**Mitigation M1049:** Enable PowerShell Constrained Language Mode and script block logging.
