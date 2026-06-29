"""Typer CLI entry-point for the Cloud Cost Optimizer."""
from __future__ import annotations

import csv
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from app.enrichment import aws_provider
from app.enrichment.mock_provider import get_signals as get_mock_signals
from app.ingestion.base import ingest
from app.remediation.generator import write_script
from app.rules.base import Finding, RulesConfig
from app.rules.registry import all_detectors

app = typer.Typer(
    name="cloud-cost-optimizer",
    help="Detect and remediate wasteful cloud resources.",
    add_completion=False,
)

# ── helpers ───────────────────────────────────────────────────────────────────


def _load_config(rules_path: Optional[Path]) -> RulesConfig:
    if rules_path and rules_path.exists():
        return RulesConfig.from_yaml(rules_path)
    default = Path("rules.yaml")
    if default.exists():
        return RulesConfig.from_yaml(default)
    return RulesConfig()


def _gather_signals(resources: list, enrich: bool) -> dict:
    """Return signal dict. If enrich=True, fetches real AWS state via boto3.

    Merge policy under --enrich:
    - AWS resources: real signals from boto3 only (absent = detector skips).
    - Azure resources: mock signals (no Azure SDK in MVP).
    On credential failure, falls back to mock for everything with a warning.
    """
    if not enrich:
        return get_mock_signals(resources)

    console = Console()
    ok, msg = aws_provider.check_credentials()
    if not ok:
        console.print(f"[yellow]Warning:[/yellow] {msg}")
        console.print("[yellow]Falling back to mock signals — "
                      "use without --enrich to silence this.[/yellow]")
        return get_mock_signals(resources)

    console.print(f"[dim]{msg}[/dim]")
    real_aws = aws_provider.get_signals(resources)

    # Azure resources keep mock signals; AWS resources use real-only.
    aws_ids = {r.resource_id for r in resources if r.provider == "aws"}
    mock_all = get_mock_signals(resources)
    merged = {rid: sigs for rid, sigs in mock_all.items() if rid not in aws_ids}
    merged.update(real_aws)
    return merged


def _run_pipeline(
    path: Path,
    rules_path: Optional[Path],
    enrich: bool = False,
) -> tuple[list[Finding], RulesConfig]:
    resources = ingest(path)
    cfg = _load_config(rules_path)
    signals = _gather_signals(resources, enrich)
    findings: list[Finding] = []
    for det in all_detectors(cfg):
        findings.extend(det.detect(resources, signals))
    return findings, cfg


def _display_id(finding: Finding, max_len: int = 30) -> str:
    name = finding.resource_name or finding.resource_id
    if len(name) > max_len:
        return "..." + name[-(max_len - 3):]
    return name


def _print_findings_table(findings: list[Finding], console: Console) -> None:
    table = Table(title="Cloud Cost Findings", show_lines=False, box=None)
    table.add_column("#",          style="dim",    width=3,  no_wrap=True)
    table.add_column("Provider",   style="bold",   width=7,  no_wrap=True)
    table.add_column("Resource",   max_width=30)
    table.add_column("Type",       style="cyan",   width=14, no_wrap=True)
    table.add_column("Category",   style="yellow", max_width=20)
    table.add_column("Reason",     max_width=38)
    table.add_column("Savings/mo", style="green",  width=10, justify="right", no_wrap=True)
    table.add_column("Conf",       style="dim",    width=6,  no_wrap=True)

    for i, f in enumerate(findings, 1):
        reason = f.reason if len(f.reason) <= 38 else f.reason[:35] + "..."
        table.add_row(
            str(i),
            f.provider.upper(),
            _display_id(f),
            f.resource_type.value,
            f.waste_category.value,
            reason,
            f"${f.estimated_monthly_savings:.2f}",
            f.confidence.value,
        )

    console.print(table)


def _print_savings_panel(findings: list[Finding], console: Console) -> None:
    if not findings:
        console.print(Panel("[yellow]No waste detected.[/yellow]", title="Summary"))
        return

    total = sum(f.estimated_monthly_savings for f in findings)
    by_provider: dict[str, float] = {}
    by_provider_count: dict[str, int] = {}
    by_category: dict[str, float] = {}
    by_category_count: dict[str, int] = {}

    for f in findings:
        by_provider[f.provider] = by_provider.get(f.provider, 0.0) + f.estimated_monthly_savings
        by_provider_count[f.provider] = by_provider_count.get(f.provider, 0) + 1
        cat = f.waste_category.value
        by_category[cat] = by_category.get(cat, 0.0) + f.estimated_monthly_savings
        by_category_count[cat] = by_category_count.get(cat, 0) + 1

    provider_lines = [
        f"  {p.upper():<7} ${amt:>8.2f}/mo  ({by_provider_count[p]:>2})"
        for p, amt in sorted(by_provider.items())
    ]
    category_lines = [
        f"  {cat:<22} ${amt:>8.2f}/mo  ({by_category_count[cat]:>2})"
        for cat, amt in sorted(by_category.items(), key=lambda x: -x[1])
    ]

    lines = (
        [
            f"Total findings  : {len(findings)}",
            f"Monthly savings : ${total:.2f}",
            f"Annual estimate : ${total * 12:.2f}",
            "",
            "By Provider",
        ]
        + provider_lines
        + ["", "By Category"]
        + category_lines
    )

    console.print(
        Panel("\n".join(lines), title="[bold green]Savings Summary[/bold green]", border_style="green")
    )


def _build_summary_markdown(findings: list[Finding]) -> str:
    """Generate a three-axis Markdown breakdown: provider, service, waste category."""
    if not findings:
        return "# Cloud Cost Optimizer — Summary Report\n\n_No waste detected._\n"

    total = sum(f.estimated_monthly_savings for f in findings)

    prov_savings: dict[str, float] = {}
    prov_count: dict[str, int] = {}
    svc_savings: dict[str, float] = {}
    svc_provider: dict[str, str] = {}
    svc_count: dict[str, int] = {}
    cat_savings: dict[str, float] = {}
    cat_count: dict[str, int] = {}

    for f in findings:
        prov_savings[f.provider] = prov_savings.get(f.provider, 0.0) + f.estimated_monthly_savings
        prov_count[f.provider] = prov_count.get(f.provider, 0) + 1
        svc = f.service or "unknown"
        svc_savings[svc] = svc_savings.get(svc, 0.0) + f.estimated_monthly_savings
        svc_count[svc] = svc_count.get(svc, 0) + 1
        svc_provider[svc] = f.provider
        cat = f.waste_category.value
        cat_savings[cat] = cat_savings.get(cat, 0.0) + f.estimated_monthly_savings
        cat_count[cat] = cat_count.get(cat, 0) + 1

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows: list[str] = [
        "# Cloud Cost Optimizer — Summary Report",
        f"\nGenerated: {now}",
        "",
        "## Overview",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total findings | {len(findings)} |",
        f"| Monthly savings | ${total:.2f} |",
        f"| Annual estimate | ${total * 12:.2f} |",
        "",
        "## By Provider",
        "",
        "| Provider | Findings | Monthly Savings | Annual Estimate |",
        "|----------|----------|-----------------|-----------------|",
    ]
    for p, amt in sorted(prov_savings.items()):
        rows.append(f"| {p.upper()} | {prov_count[p]} | ${amt:.2f} | ${amt * 12:.2f} |")
    rows.append(
        f"| **Total** | **{len(findings)}** | **${total:.2f}** | **${total * 12:.2f}** |"
    )
    rows += [
        "",
        "## By Service",
        "",
        "| Service | Provider | Findings | Monthly Savings |",
        "|---------|----------|----------|-----------------|",
    ]
    for svc, amt in sorted(svc_savings.items(), key=lambda x: -x[1]):
        prov = svc_provider[svc].upper()
        rows.append(f"| {svc} | {prov} | {svc_count[svc]} | ${amt:.2f} |")
    rows += [
        "",
        "## By Waste Category",
        "",
        "| Category | Findings | Monthly Savings | Annual Estimate |",
        "|----------|----------|-----------------|-----------------|",
    ]
    for cat, amt in sorted(cat_savings.items(), key=lambda x: -x[1]):
        rows.append(f"| {cat} | {cat_count[cat]} | ${amt:.2f} | ${amt * 12:.2f} |")
    rows.append("")
    return "\n".join(rows)


# ── commands ──────────────────────────────────────────────────────────────────


@app.command()
def scan(
    path: Path = typer.Argument(..., help="Billing export (AWS CUR or Azure CSV/JSON)"),
    rules: Optional[Path] = typer.Option(None, "--rules", help="Custom rules.yaml path"),
    enrich: bool = typer.Option(False, "--enrich/--no-enrich",
                                help="Fetch real AWS resource state via boto3."),
) -> None:
    """Ingest billing data, detect waste, and print a findings table."""
    console = Console()
    try:
        findings, _ = _run_pipeline(path, rules, enrich=enrich)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if not findings:
        console.print("[yellow]No waste detected.[/yellow]")
        raise typer.Exit(0)

    _print_findings_table(findings, console)
    _print_savings_panel(findings, console)


@app.command()
def report(
    path: Path = typer.Argument(..., help="Billing export (AWS CUR or Azure CSV/JSON)"),
    format: str = typer.Option("json", "--format", help="Output format: json, csv, or summary"),
    output: Optional[Path] = typer.Option(None, "--output", help="Output file (default: findings.<fmt>)"),
    rules: Optional[Path] = typer.Option(None, "--rules", help="Custom rules.yaml path"),
    enrich: bool = typer.Option(False, "--enrich/--no-enrich",
                                help="Fetch real AWS resource state via boto3."),
) -> None:
    """Write a findings report to disk as JSON, CSV, or Markdown summary."""
    console = Console()
    fmt = format.lower()
    if fmt not in ("json", "csv", "summary"):
        console.print(f"[red]Unknown format '{format}'. Use json, csv, or summary.[/red]")
        raise typer.Exit(1)

    try:
        findings, _ = _run_pipeline(path, rules, enrich=enrich)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    ext = "md" if fmt == "summary" else fmt
    out_path = output or Path(f"findings.{ext}")

    if fmt == "json":
        data = [f.model_dump(mode="json") for f in findings]
        out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    elif fmt == "csv":
        if findings:
            keys = list(findings[0].model_dump(mode="json").keys())
            with out_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=keys)
                writer.writeheader()
                for f in findings:
                    writer.writerow(f.model_dump(mode="json"))
        else:
            out_path.write_text("", encoding="utf-8")
    else:  # summary
        out_path.write_text(_build_summary_markdown(findings), encoding="utf-8")

    console.print(f"[green]Wrote {len(findings)} findings → {out_path}[/green]")


@app.command()
def remediate(
    path: Path = typer.Argument(..., help="Billing export (AWS CUR or Azure CSV/JSON)"),
    output: Path = typer.Option(Path("remediation.sh"), "--output", help="Script output path"),
    rules: Optional[Path] = typer.Option(None, "--rules", help="Custom rules.yaml path"),
    apply: bool = typer.Option(False, "--apply", help="Execute the generated script (requires confirmation)"),
    enrich: bool = typer.Option(False, "--enrich/--no-enrich",
                                help="Fetch real AWS resource state via boto3."),
) -> None:
    """Generate a dry-run bash remediation script. Pass --apply to execute it."""
    console = Console()
    try:
        findings, _ = _run_pipeline(path, rules, enrich=enrich)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if not findings:
        console.print("[yellow]No waste detected — no script generated.[/yellow]")
        raise typer.Exit(0)

    script_path = write_script(findings, output_path=output)
    console.print(f"[green]Wrote {len(findings)} commands → {script_path}[/green]")
    _print_savings_panel(findings, console)

    if apply:
        console.print("[bold yellow]Executing script with --apply …[/bold yellow]")
        result = subprocess.run(["bash", str(script_path), "--apply"], stdin=sys.stdin)
        raise typer.Exit(result.returncode)


if __name__ == "__main__":
    app()
