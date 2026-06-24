"""Streamlit web UI for SOC Analyst Assistant."""

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import SAMPLE_ALERTS_DIR, settings
from app.models.schemas import AlertAnalysisRequest
from app.services.alert_analyzer import alert_analyzer
from app.services.rag_engine import rag_engine

st.set_page_config(
    page_title="SOC Analyst Assistant",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ AI-Powered SOC Analyst Assistant")
st.caption("MITRE ATT&CK | NIST | Threat Intelligence | RAG-Powered Analysis")

# Sidebar
with st.sidebar:
    st.header("Configuration")
    api_status = "✅ Configured" if settings.has_openai_key else "⚠️ Not configured (offline mode)"
    st.write(f"**OpenAI API:** {api_status}")
    kb_status = "✅ Ready" if rag_engine.is_ready else "⚠️ Not ingested"
    st.write(f"**Knowledge Base:** {kb_status}")

    if not rag_engine.is_ready and settings.has_openai_key:
        if st.button("Ingest Knowledge Base"):
            with st.spinner("Ingesting..."):
                count = rag_engine.ingest()
                st.success(f"Ingested {count} chunks")
                st.rerun()

    st.divider()
    st.header("Sample Alerts")
    sample_files = sorted(SAMPLE_ALERTS_DIR.glob("*.txt"))
    selected_sample = st.selectbox("Load sample", [""] + [f.name for f in sample_files])

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("Security Alert Input")
    default_text = ""
    if selected_sample:
        default_text = (SAMPLE_ALERTS_DIR / selected_sample).read_text(encoding="utf-8")

    alert_text = st.text_area(
        "Paste alert text or log",
        value=default_text,
        height=350,
        placeholder="Paste SIEM/EDR alert here...",
    )
    alert_source = st.text_input("Alert Source (optional)", placeholder="CrowdStrike, Splunk, Sentinel...")
    include_report = st.checkbox("Generate incident report", value=True)

with col2:
    st.subheader("Analysis Results")

    if st.button("🔍 Analyze Alert", type="primary", use_container_width=True):
        if len(alert_text.strip()) < 10:
            st.error("Please enter at least 10 characters of alert text.")
        else:
            with st.spinner("Analyzing alert..."):
                request = AlertAnalysisRequest(
                    alert_text=alert_text,
                    alert_source=alert_source or None,
                    include_report=include_report,
                )
                result = alert_analyzer.analyze(request)

            severity_colors = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
                "informational": "🔵",
            }
            icon = severity_colors.get(result.severity.value, "⚪")
            st.markdown(f"### {icon} Severity: **{result.severity.value.upper()}**")
            st.info(result.summary)

            tab1, tab2, tab3, tab4 = st.tabs(["IOCs", "MITRE ATT&CK", "Remediation", "Report"])

            with tab1:
                if result.iocs:
                    for ioc in result.iocs:
                        st.code(f"[{ioc.type.value}] {ioc.value}")
                else:
                    st.write("No IOCs extracted.")

            with tab2:
                if result.attack_classification:
                    for t in result.attack_classification:
                        st.markdown(
                            f"**{t.technique_id}** - {t.technique_name} "
                            f"({t.tactic}) — {t.confidence:.0%} confidence"
                        )
                else:
                    st.write("No techniques classified.")

            with tab3:
                for action in result.remediation_actions:
                    st.markdown(f"**{action.priority}**")
                    st.write(action.action)
                    st.caption(action.rationale)
                    st.divider()

            with tab4:
                if result.incident_report:
                    st.download_button(
                        "Download Report (.md)",
                        result.incident_report,
                        file_name="incident_report.md",
                        mime="text/markdown",
                    )
                    st.markdown(result.incident_report)
                else:
                    st.write("Report not generated.")

st.divider()
st.caption("Built with Python, OpenAI API, LangChain | MITRE ATT&CK Framework | NIST CSF")
