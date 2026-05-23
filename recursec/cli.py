"""RecurSec CLI — the main entry point."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import structlog
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(name="recursec", help="RecurSec — Recursive Multi-Agent Security Framework")
console = Console()

BANNER = r"""
[bold red]
 ____  ____  ____  _  _  ____  ____  ____  ____
(  _ \( ___)/ ___)( )( )(  _ \/ ___)( ___)/ ___)
 )   / )__)( (__   )()(  )   /\___ \ )__)( (__
(_)\_)(____)\___) (____)((_)\_)(____/(____)\___) [/bold red]
[dim]Recursive Multi-Agent Security Framework[/dim]
[dim]200+ Tools • Unlimited LLMs • Autonomous 24/7[/dim]
"""


def setup_logging(log_level: str = "INFO", log_file: str | None = None) -> None:
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.dev.ConsoleRenderer(colors=True),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
    )


@app.command()
def run(
    config: str = typer.Option("recursec.yaml", "--config", "-c", help="Path to YAML config file"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target to scan"),
    objective: Optional[str] = typer.Option(None, "--objective", "-o", help="Task objective"),
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Run in daemon mode (24/7)"),
    dashboard: bool = typer.Option(True, "--dashboard", help="Start web dashboard"),
    log_level: str = typer.Option("INFO", "--log-level", "-l", help="Log level"),
):
    """Start RecurSec — run a scan or start the daemon."""
    console.print(BANNER)
    setup_logging(log_level)

    from recursec.config.settings import RecurSecConfig

    config_path = Path(config)
    if config_path.exists():
        cfg = RecurSecConfig.from_yaml(config_path)
        console.print(f"[green]Config loaded:[/green] {config_path}")
    else:
        cfg = RecurSecConfig()
        console.print(f"[yellow]No config file found at {config_path}, using defaults[/yellow]")

    cfg.log_level = log_level
    asyncio.run(_run_engine(cfg, target, objective, daemon, dashboard))


async def _run_engine(
    cfg,
    target: str | None,
    objective: str | None,
    daemon: bool,
    dashboard: bool,
) -> None:
    from recursec.daemon.engine import RecurSecEngine

    engine = RecurSecEngine(cfg)
    await engine.initialize()

    status = await engine.get_status()
    console.print(f"[green]Models:[/green] {len(status['models'])} configured")
    console.print(f"[green]Tools:[/green] {status['tools_available']}/{status['tools_total']} available")

    tasks = []

    # Start dashboard
    if dashboard and cfg.dashboard.enabled:
        from recursec.dashboard.app import app as dashboard_app, set_engine
        import uvicorn

        set_engine(engine)
        config = uvicorn.Config(
            dashboard_app,
            host=cfg.dashboard.host,
            port=cfg.dashboard.port,
            log_level="warning",
        )
        server = uvicorn.Server(config)
        tasks.append(asyncio.create_task(server.serve()))
        console.print(f"[green]Dashboard:[/green] http://{cfg.dashboard.host}:{cfg.dashboard.port}")

    if daemon:
        console.print("[bold yellow]Running in daemon mode (24/7)...[/bold yellow]")
        tasks.append(asyncio.create_task(engine.run_daemon()))
    elif target and objective:
        task = await engine.submit_task(objective=objective, target=target)
        result = await engine.run_task(task)
        _print_results(result)
    elif target:
        task = await engine.submit_task(
            objective=f"Full security assessment of {target}",
            target=target,
        )
        result = await engine.run_task(task)
        _print_results(result)
    else:
        if not daemon:
            console.print("[yellow]No target specified. Starting in daemon mode with dashboard only.[/yellow]")
            tasks.append(asyncio.create_task(engine.run_daemon()))

    if tasks:
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            pass
        finally:
            await engine.shutdown()


def _print_results(task) -> None:
    console.print(f"\n[bold]Scan Complete[/bold] — {task.status.value}")
    console.print(f"Steps: {task.step_count} | Children: {len(task.child_task_ids)} | Findings: {len(task.findings)}")

    if task.findings:
        table = Table(title="Findings", show_header=True)
        table.add_column("Severity", style="bold")
        table.add_column("Title")
        table.add_column("Component")
        table.add_column("Confidence")

        for f in sorted(task.findings, key=lambda x: ["critical", "high", "medium", "low", "info"].index(x.severity.value)):
            color = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "blue", "info": "dim"}.get(f.severity.value, "white")
            table.add_row(
                f"[{color}]{f.severity.value}[/{color}]",
                f.title,
                f.affected_component or "-",
                f"{f.confidence:.0%}",
            )
        console.print(table)

    if task.error:
        console.print(f"[red]Error:[/red] {task.error}")


@app.command()
def init(
    output: str = typer.Option("recursec.yaml", "--output", "-o", help="Output config file path"),
):
    """Generate a default configuration file."""
    console.print(BANNER)
    from recursec.config.settings import RecurSecConfig

    cfg = RecurSecConfig(
        models=[
            {
                "name": "deepseek-coder",
                "backend": "vllm",
                "model_id": "deepseek-ai/deepseek-coder-v2",
                "base_url": "http://localhost:8000",
                "task_types": ["code", "security"],
                "priority": 1,
            },
            {
                "name": "qwen-reasoning",
                "backend": "vllm",
                "model_id": "Qwen/Qwen2.5-72B-Instruct",
                "base_url": "http://localhost:8001",
                "task_types": ["reasoning", "general"],
                "priority": 2,
            },
            {
                "name": "llama-general",
                "backend": "llama_cpp",
                "model_id": "llama-3.1-70b",
                "base_url": "http://localhost:8080",
                "task_types": ["general", "writing"],
                "priority": 3,
            },
        ],
    )
    cfg.to_yaml(output)
    console.print(f"[green]Config generated:[/green] {output}")
    console.print("[dim]Edit this file to add your LLM endpoints and customize settings.[/dim]")


@app.command()
def tools():
    """List all available tools and their installation status."""
    console.print(BANNER)
    from recursec.tools.registry import ToolRegistry

    registry = ToolRegistry(sandbox_mode=False)
    registry.load_defaults()

    table = Table(title=f"RecurSec Tools ({registry.count_available()}/{registry.count()} available)")
    table.add_column("Name", style="bold")
    table.add_column("Category")
    table.add_column("Status")
    table.add_column("Description")

    for tool_info in registry.list_available():
        status = "[green]installed[/green]" if tool_info["available"] else "[red]missing[/red]"
        table.add_row(tool_info["name"], tool_info["category"], status, tool_info["description"][:60])

    console.print(table)
    console.print(f"\nTotal: {registry.count()} tools | Available: {registry.count_available()}")


@app.command()
def models():
    """List configured LLM models."""
    console.print(BANNER)
    console.print("[yellow]Run 'recursec run' to see live model status.[/yellow]")


if __name__ == "__main__":
    app()
