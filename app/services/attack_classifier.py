"""MITRE ATT&CK attack classification using keyword mapping and LLM."""

import re
from typing import Optional

from app.models.schemas import MITRETechnique

# Keyword-to-MITRE technique mapping for rule-based classification
TECHNIQUE_KEYWORDS: dict[str, dict] = {
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "keywords": ["spearphish", "phishing", "malicious attachment", "docm", ".doc", "email attachment", "macro"],
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "keywords": ["powershell", "encodedcommand", "-enc", "executionpolicy bypass", "ps1"],
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "keywords": ["beacon", "c2", "command and control", "https://", "http://", "tls to", "cobalt strike"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "keywords": ["ransomware", "encrypted", "lockbit", ".locked", "ransom note", "mass file rename"],
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "keywords": ["brute force", "failed login", "failed authentication", "password spray", "credential stuffing"],
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "keywords": ["rdp", "remote desktop", "terminal services", "port 3389"],
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "keywords": ["process injection", "dll injection", "reflective dll", "hollow"],
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "keywords": ["lsass", "credential dump", "mimikatz", "sekurlsa"],
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "keywords": ["vssadmin", "delete shadows", "wbadmin delete", "shadow copy"],
    },
    "T1114": {
        "name": "Email Collection",
        "tactic": "Collection",
        "keywords": ["mailbox rule", "email forwarding", "inbox rule"],
    },
}


def classify_attack_rule_based(alert_text: str) -> list[MITRETechnique]:
    """Classify alert using keyword matching against MITRE techniques."""
    text_lower = alert_text.lower()
    matches: list[MITRETechnique] = []

    for technique_id, info in TECHNIQUE_KEYWORDS.items():
        hit_count = sum(1 for kw in info["keywords"] if kw in text_lower)
        if hit_count > 0:
            confidence = min(0.95, 0.4 + (hit_count * 0.15))
            matches.append(
                MITRETechnique(
                    technique_id=technique_id,
                    technique_name=info["name"],
                    tactic=info["tactic"],
                    confidence=round(confidence, 2),
                    description=f"Matched {hit_count} keyword(s) for {technique_id}",
                )
            )

    return sorted(matches, key=lambda x: x.confidence, reverse=True)


def classify_attack_with_llm(
    alert_text: str,
    llm_client,
    rule_based: Optional[list[MITRETechnique]] = None,
) -> list[MITRETechnique]:
    """Enhance classification using LLM with rule-based hints."""
    if not llm_client:
        return rule_based or classify_attack_rule_based(alert_text)

    import json

    from langchain_core.prompts import ChatPromptTemplate

    rule_based = rule_based or classify_attack_rule_based(alert_text)
    hints = [f"{t.technique_id}: {t.technique_name}" for t in rule_based[:5]]

    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a MITRE ATT&CK expert SOC analyst. Classify the security alert into relevant MITRE ATT&CK techniques.
Return ONLY a JSON array with objects: technique_id, technique_name, tactic, confidence (0-1), description.
Include only techniques with confidence >= 0.5. Use official MITRE technique IDs (e.g., T1059.001)."""),
        ("human", "Alert:\n{alert}\n\nRule-based hints: {hints}"),
    ])

    chain = prompt | llm_client
    try:
        response = chain.invoke({"alert": alert_text, "hints": hints})
        content = response.content.strip()
        if content.startswith("```"):
            content = re.sub(r"^```(?:json)?\n?", "", content)
            content = re.sub(r"\n?```$", "", content)
        llm_results = json.loads(content)
        techniques = [
            MITRETechnique(
                technique_id=item["technique_id"],
                technique_name=item["technique_name"],
                tactic=item["tactic"],
                confidence=float(item["confidence"]),
                description=item.get("description"),
            )
            for item in llm_results
            if float(item.get("confidence", 0)) >= 0.5
        ]
        if techniques:
            return sorted(techniques, key=lambda x: x.confidence, reverse=True)
    except Exception:
        pass

    return rule_based
