# GitHub Upload Guide

Follow these steps to publish this project to GitHub.

## Prerequisites

- [Git](https://git-scm.com/download/win) installed
- A [GitHub](https://github.com) account
- (Optional) [OpenAI API key](https://platform.openai.com/api-keys) for full AI mode

## Step 1: Configure environment

```powershell
cd C:\Users\anves\soc-analyst-assistant

# Activate virtual environment
.\venv\Scripts\activate

# Create environment file
copy .env.example .env
# Edit .env and set your OPENAI_API_KEY
```

## Step 2: Verify the project works

```powershell
# Run tests (should show 11 passed)
pytest tests\ -v

# Analyze a sample alert (works without API key)
python main.py analyze data\sample_alerts\powershell_emotet_alert.txt

# Optional: ingest knowledge base for full RAG (requires API key)
python scripts\ingest_knowledge_base.py
```

## Step 3: Initialize Git and push to GitHub

```powershell
cd C:\Users\anves\soc-analyst-assistant

git init
git add .
git commit -m "Initial commit: AI-powered SOC Analyst Assistant with RAG, MITRE ATT&CK, and incident reporting"

# Create a new repo on GitHub (via website or gh CLI), then:
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/soc-analyst-assistant.git
git push -u origin main
```

### Using GitHub CLI (alternative)

```powershell
gh auth login
gh repo create soc-analyst-assistant --public --source=. --remote=origin --push
```

## Step 4: Run the full demo (with OpenAI API key)

```powershell
# 1. Ingest knowledge base (one-time)
python scripts\ingest_knowledge_base.py

# 2. CLI analysis
python main.py analyze data\sample_alerts\cobalt_strike_alert.txt

# 3. Start REST API
python main.py serve
# Open http://localhost:8000/docs

# 4. Start web UI
streamlit run ui\streamlit_app.py
# Open http://localhost:8501
```

## Recommended GitHub repo settings

- **Description:** AI-powered SOC analyst assistant with RAG, MITRE ATT&CK classification, IOC extraction, and incident reporting
- **Topics:** `soc`, `cybersecurity`, `mitre-attack`, `langchain`, `openai`, `rag`, `incident-response`, `python`, `fastapi`
- **README:** Already included at project root

## What gets committed

| Included | Excluded (.gitignore) |
|----------|---------------------|
| Source code, tests, knowledge base | `.env` (secrets) |
| Sample alerts, README, LICENSE | `venv/`, `data/chroma_db/` |
| `.env.example` (template only) | Generated reports in `reports/` |

## Resume bullet alignment

This repo demonstrates:

1. **Alert analysis & summarization** — `app/services/alert_analyzer.py`
2. **RAG (MITRE, NIST, threat intel)** — `app/services/rag_engine.py` + `data/knowledge_base/`
3. **IOC extraction & attack classification** — `ioc_extractor.py`, `attack_classifier.py`
4. **Incident report generation** — `incident_reporter.py`
5. **Tier-1 automation** — CLI, FastAPI, Streamlit interfaces
