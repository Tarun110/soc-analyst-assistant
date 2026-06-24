"""Main alert analysis orchestrator."""

from typing import Optional

from langchain_openai import ChatOpenAI

from app.config import settings
from app.models.schemas import AlertAnalysisRequest, AlertAnalysisResponse, SeverityLevel
from app.services.attack_classifier import classify_attack_rule_based, classify_attack_with_llm
from app.services.incident_reporter import (
    determine_severity,
    generate_incident_report,
    generate_remediation_actions,
    save_report,
)
from app.services.ioc_extractor import extract_iocs
from app.services.rag_engine import rag_engine


class AlertAnalyzer:
    """Orchestrates full SOC alert analysis pipeline."""

    def __init__(self):
        self._llm: Optional[ChatOpenAI] = None

    def _get_llm(self) -> Optional[ChatOpenAI]:
        if not settings.has_openai_key:
            return None
        if not self._llm:
            self._llm = ChatOpenAI(
                model=settings.openai_model,
                openai_api_key=settings.openai_api_key,
                temperature=0.1,
            )
        return self._llm

    def analyze(self, request: AlertAnalysisRequest) -> AlertAnalysisResponse:
        """Run complete analysis pipeline on a security alert."""
        alert_text = request.alert_text

        # Step 1: IOC Extraction
        iocs = extract_iocs(alert_text)

        # Step 2: Attack Classification
        rule_based = classify_attack_rule_based(alert_text)
        techniques = classify_attack_with_llm(alert_text, self._get_llm(), rule_based)

        # Step 3: RAG-powered analysis
        rag_analysis, context_snippets = rag_engine.query_with_context(alert_text)

        # Step 4: Determine severity
        severity = determine_severity(alert_text, techniques)

        # Step 5: Generate remediation actions
        remediation = generate_remediation_actions(techniques, iocs, severity)

        # Step 6: Build summary
        summary = self._extract_summary(rag_analysis, alert_text, techniques, iocs)

        # Step 7: Generate incident report
        incident_report = None
        if request.include_report:
            incident_report = generate_incident_report(
                alert_text=alert_text,
                summary=summary,
                severity=severity,
                iocs=iocs,
                techniques=techniques,
                remediation_actions=remediation,
                alert_source=request.alert_source,
            )
            save_report(incident_report)

        return AlertAnalysisResponse(
            summary=summary,
            severity=severity,
            iocs=iocs,
            attack_classification=techniques,
            remediation_actions=remediation,
            rag_context_used=context_snippets,
            incident_report=incident_report,
        )

    def _extract_summary(
        self,
        rag_analysis: str,
        alert_text: str,
        techniques: list,
        iocs: list,
    ) -> str:
        """Extract or build executive summary from RAG analysis."""
        if "##" in rag_analysis or "**Summary" in rag_analysis:
            lines = rag_analysis.split("\n")
            summary_lines = []
            capture = False
            for line in lines:
                if "summary" in line.lower() and ("#" in line or "**" in line):
                    capture = True
                    continue
                if capture:
                    if line.startswith("#") or (line.startswith("**") and "severity" in line.lower()):
                        break
                    if line.strip():
                        summary_lines.append(line.strip())
            if summary_lines:
                return " ".join(summary_lines)

        # Fallback summary
        technique_names = ", ".join(t.technique_name for t in techniques[:3]) or "unknown"
        return (
            f"Security alert analyzed with {len(iocs)} IOC(s) extracted. "
            f"Attack techniques identified: {technique_names}. "
            f"Immediate analyst review recommended."
        )


alert_analyzer = AlertAnalyzer()
