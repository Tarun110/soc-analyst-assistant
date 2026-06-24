# MITRE ATT&CK Technique: T1566.001 - Phishing: Spearphishing Attachment

**Tactic:** Initial Access
**Technique ID:** T1566.001
**Name:** Spearphishing Attachment

Adversaries may send spearphishing emails with a malicious attachment to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email.

Common file types include Office documents (.doc, .docx, .xls, .xlsx), PDFs, and archive files (.zip, .rar). Macros and embedded scripts are frequently used to execute malicious payloads.

**Detection:**
- Monitor email gateway logs for suspicious attachments
- Analyze Office document macro execution
- Correlate email delivery with endpoint process creation events

**Mitigation M0954:** Restrict email attachments by file type and scan with antivirus/EDR before delivery.
