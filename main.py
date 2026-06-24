"""CLI entry point for SOC Analyst Assistant."""

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from app.config import SAMPLE_ALERTS_DIR
from app.models.schemas import AlertAnalysisRequest
from app.services.alert_analyzer import alert_analyzer
from app.services.rag_engine import rag_engine

app = typer.Typer(help="AI-Powered SOC Analyst Assistant CLI")
console = Console()


@app.command()
def analyze(
    alert_file: Optional[Path] = typer.Argument(None, help="Path to alert text file"),
    alert_text: Optional[str] = typer.Option(None, "--text", "-t", help="Alert text directly"),
    source: Optional[str] = typer.Option(None, "--source", "-s", help="Alert source (SIEM/EDR name)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save JSON results to file"),
    no_report: bool = typer.Option(False, "--no-report", help="Skip incident report generation"),
):
    """Analyze a security alert."""
    text = _load_alert(alert_file, alert_text)
    request = AlertAnalysisRequest(
        alert_text=text,
        alert_source=source,
        include_report=not no_report,
    )

    with console.status("[bold green]Analyzing alert..."):
        result = alert_analyzer.analyze(request)

    _print_results(result)

    if output:
        output.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"\n[green]Results saved to {output}[/green]")


@app.command()
def ingest():
    """Ingest knowledge base into vector store (requires OpenAI API key)."""
    from app.config import settings

    if not settings.has_openai_key:
        console.print("[red]Error: OPENAI_API_KEY not configured. Copy .env.example to .env[/red]")
        raise typer.Exit(1)

    with console.status("[bold green]Ingesting knowledge base..."):
        count = rag_engine.ingest()

    console.print(f"[green]Successfully ingested {count} document chunks into vector store.[/green]")


@app.command(name="list-samples")
def list_samples():
    """List available sample alerts."""
    table = Table(title="Sample Alerts")
    table.add_column("File", style="cyan")
    table.add_column("Size", style="green")

    for f in sorted(SAMPLE_ALERTS_DIR.glob("*.txt")):
        table.add_row(f.name, f"{f.stat().st_size} bytes")

    console.print(table)


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host"),
    port: int = typer.Option(8000, "--port"),
):
    """Start the FastAPI server."""
    import uvicorn

    uvicorn.run("app.api:app", host=host, port=port, reload=True)


def _load_alert(alert_file: Optional[Path], alert_text: Optional[str]) -> str:
    if alert_text:
        return alert_text
    if alert_file:
        return alert_file.read_text(encoding="utf-8")
    console.print("[red]Error: Provide alert file or --text[/red]")
    raise typer.Exit(1)


def _print_results(result):
    console.print(Panel(result.summary, title=f"Summary [{result.severity.value.upper()}]", border_style="blue"))

    ioc_table = Table(title="Extracted IOCs")
    ioc_table.add_column("Type", style="cyan")
    ioc_table.add_column("Value", style="yellow")
    for ioc in result.iocs:
        ioc_table.add_row(ioc.type.value, ioc.value)
    console.print(ioc_table)

    mitre_table = Table(title="MITRE ATT&CK Classification")
    mitre_table.add_column("ID", style="cyan")
    mitre_table.add_column("Technique", style="white")
    mitre_table.add_column("Tactic", style="green")
    mitre_table.add_column("Confidence", style="yellow")
    for t in result.attack_classification:
        mitre_table.add_row(t.technique_id, t.technique_name, t.tactic, f"{t.confidence:.0%}")
    console.print(mitre_table)

    rem_table = Table(title="Remediation Actions")
    rem_table.add_column("Priority", style="red")
    rem_table.add_column("Action", style="white")
    for r in result.remediation_actions:
        rem_table.add_row(r.priority, r.action)
    console.print(rem_table)

    if result.incident_report:
        console.print("\n[green]Incident report generated and saved to reports/ directory[/green]")


if __name__ == "__main__":
    app()
