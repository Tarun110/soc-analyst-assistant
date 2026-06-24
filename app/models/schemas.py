"""Pydantic models for API request/response schemas."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"


class IOC(BaseModel):
    type: IOCType
    value: str
    context: Optional[str] = None


class MITRETechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float = Field(ge=0.0, le=1.0)
    description: Optional[str] = None


class RemediationAction(BaseModel):
    priority: str
    action: str
    rationale: str
    mitre_mitigation: Optional[str] = None


class AlertAnalysisRequest(BaseModel):
    alert_text: str = Field(..., min_length=10, description="Raw security alert text or log")
    alert_source: Optional[str] = Field(None, description="SIEM/EDR source name")
    include_report: bool = Field(True, description="Generate full incident report")


class AlertAnalysisResponse(BaseModel):
    summary: str
    severity: SeverityLevel
    iocs: list[IOC]
    attack_classification: list[MITRETechnique]
    remediation_actions: list[RemediationAction]
    rag_context_used: list[str]
    incident_report: Optional[str] = None
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)


class HealthResponse(BaseModel):
    status: str
    version: str
    openai_configured: bool
    knowledge_base_ready: bool
