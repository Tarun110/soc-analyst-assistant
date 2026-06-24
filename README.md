# AI-Powered SOC Analyst Assistant

An intelligent Security Operations Center (SOC) assistant that automates Tier-1 analyst tasks using **Python**, **OpenAI API**, **LangChain**, and the **MITRE ATT&CK** framework.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-REST_API-green)
![LangChain](https://img.shields.io/badge/LangChain-RAG-orange)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)

## Features

- **Alert Analysis** — Analyze SIEM/EDR alerts with AI-powered triage and executive summaries
- **Retrieval-Augmented Generation (RAG)** — Query MITRE ATT&CK, NIST guidance, and threat intelligence
- **IOC Extraction** — Automatically extract IPs, domains, hashes, emails, CVEs, and more
- **Attack Classification** — Map alerts to MITRE ATT&CK techniques with confidence scores
- **Incident Report Generation** — Produce structured markdown reports for escalation
- **Remediation Recommendations** — Prioritized actions mapped to NIST incident response phases
- **Multiple Interfaces** — CLI, REST API (FastAPI), and Streamlit web UI

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│  Alert Input    │────▶│  Alert Analyzer  │────▶│  Incident Report    │
│  (SIEM/EDR)     │     │  (Orchestrator)  │     │  (Markdown)         │
└─────────────────┘     └────────┬─────────┘     └─────────────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
     ┌────────────────┐ ┌───────────────┐ ┌─────────────────┐
     │ IOC Extractor  │ │ Attack        │ │ RAG Engine      │
     │ (Regex)        │ │ Classifier    │ │ (LangChain +    │
     │                │ │ (MITRE ATT&CK)│ │  ChromaDB)      │
     └────────────────┘ └───────────────┘ └────────┬────────┘
                                                   │
                                    ┌──────────────┼──────────────┐
                                    ▼              ▼              ▼
                              MITRE ATT&CK    NIST CSF      Threat Intel
```

## Quick Start

### Prerequisites

- Python 3.10+
- OpenAI API key (optional — offline mode available for IOC/classification)

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/soc-analyst-assistant.git
cd soc-analyst-assistant

python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

### Ingest Knowledge Base (for RAG)

```bash
python scripts/ingest_knowledge_base.py
# or
python main.py ingest
```

### Run Analysis

**CLI:**
```bash
python main.py analyze data/sample_alerts/powershell_emotet_alert.txt
python main.py list-samples
```

**REST API:**
```bash
python main.py serve
# POST http://localhost:8000/analyze
# Docs: http://localhost:8000/docs
```

**Web UI:**
```bash
streamlit run ui/streamlit_app.py
```

## API Usage

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "alert_text": "[ALERT] PowerShell encoded command from WINWORD.EXE...",
    "alert_source": "CrowdStrike",
    "include_report": true
  }'
```

### Response

```json
{
  "summary": "Encoded PowerShell execution from Office application...",
  "severity": "high",
  "iocs": [{"type": "ip", "value": "185.234.72.19", "context": "..."}],
  "attack_classification": [{"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution", "confidence": 0.85}],
  "remediation_actions": [{"priority": "P1 - Immediate", "action": "Isolate affected host...", "rationale": "..."}],
  "incident_report": "# Security Incident Report\n..."
}
```

## Project Structure

```
soc-analyst-assistant/
├── app/
│   ├── api.py                  # FastAPI REST endpoints
│   ├── config.py               # Settings and configuration
│   ├── models/schemas.py       # Pydantic request/response models
│   └── services/
│       ├── alert_analyzer.py   # Main analysis orchestrator
│       ├── attack_classifier.py# MITRE ATT&CK classification
│       ├── ioc_extractor.py    # IOC extraction (regex)
│       ├── incident_reporter.py# Report generation
│       └── rag_engine.py       # LangChain RAG pipeline
├── data/
│   ├── knowledge_base/         # MITRE, NIST, threat intel docs
│   └── sample_alerts/          # Sample alerts for testing
├── scripts/ingest_knowledge_base.py
├── ui/streamlit_app.py         # Web interface
├── tests/                      # Unit tests
├── main.py                     # CLI entry point
└── requirements.txt
```

## Knowledge Base

The RAG knowledge base includes:

| Source | Content |
|--------|---------|
| **MITRE ATT&CK** | T1566.001, T1059.001, T1071.001, T1486, T1110, T1021.001 |
| **NIST** | SP 800-61 Incident Handling, CSF Respond Function |
| **Threat Intel** | Emotet, LockBit, Cobalt Strike campaigns |

Add your own `.md` files to `data/knowledge_base/` and re-run ingest.

## Testing

```bash
pytest tests/ -v
```

## Offline Mode

Without an OpenAI API key, the assistant still provides:
- Regex-based IOC extraction
- Keyword-based MITRE ATT&CK classification
- Rule-based severity and remediation recommendations
- Keyword-matched knowledge base retrieval

Configure `OPENAI_API_KEY` for full AI-powered analysis and RAG embeddings.

## License

MIT License

## Author

Built as a portfolio project demonstrating AI-powered SOC automation with Python, OpenAI, LangChain, and MITRE ATT&CK.
