"""FastAPI REST API for SOC Analyst Assistant."""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.config import settings
from app.models.schemas import AlertAnalysisRequest, AlertAnalysisResponse, HealthResponse
from app.services.alert_analyzer import alert_analyzer
from app.services.rag_engine import rag_engine

app = FastAPI(
    title="AI-Powered SOC Analyst Assistant",
    description="Analyze security alerts with RAG, MITRE ATT&CK classification, IOC extraction, and incident reporting",
    version=__version__,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
def health_check():
    return HealthResponse(
        status="healthy",
        version=__version__,
        openai_configured=settings.has_openai_key,
        knowledge_base_ready=rag_engine.is_ready,
    )


@app.post("/analyze", response_model=AlertAnalysisResponse)
def analyze_alert(request: AlertAnalysisRequest):
    """Analyze a security alert and return full SOC triage results."""
    try:
        return alert_analyzer.analyze(request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/extract-iocs")
def extract_iocs_endpoint(request: AlertAnalysisRequest):
    """Extract IOCs from alert text only."""
    from app.services.ioc_extractor import extract_iocs

    return {"iocs": extract_iocs(request.alert_text)}


@app.post("/classify")
def classify_attack_endpoint(request: AlertAnalysisRequest):
    """Classify alert against MITRE ATT&CK only."""
    from app.services.attack_classifier import classify_attack_rule_based

    return {"techniques": classify_attack_rule_based(request.alert_text)}
