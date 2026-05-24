"""RecurSec CLI — conversational autonomous security agent.

DEFAULT: Interactive conversational agent (just run `recursec`)
  You talk, the agent thinks, acts, and reports autonomously.

ALTERNATIVE: Traditional pipeline scan
  recursec scan <target>              Pipeline-based scan
  recursec scan <target> --deep       Deep comprehensive scan

UTILITIES:
  recursec health                     Check LLM server status
  recursec models                     List configured models
  recursec tools                      List available tools
"""

from __future__ import annotations

import argparse

import structlog

from recursec.agents.llm_client import (
    LLMClient,
    MODEL_RAM_GB,
    MODEL_SERVERS,
    TASK_ROUTING,
)
from recursec.agents.runner import AutonomousAgent, Runner, ScanConfig
from recursec.agents.tool_executor import ToolExecutor

logger = structlog.get_logger()


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recursec",
        description="RecurSec — Autonomous Conversational Security Agent",
        epilog=(
            "Default (no arguments): launches interactive agent\n"
            "Example: recursec          → conversational agent\n"
            "Example: recursec scan url → traditional pipeline scan"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    # agent (default — conversational autonomous agent)
    agent_parser = subparsers.add_parser("agent", help="Launch conversational autonomous agent (default)")
    agent_parser.add_argument("target", nargs="?", default="", help="Optional: target to assess immediately")
    agent_parser.add_argument("--goal", "-g", default="", help="Assessment goal in natural language")
    agent_parser.add_argument("--timeout", type=int, default=3600, help="Max time in seconds")
    agent_parser.add_argument("--iterations", type=int, default=200, help="Max autonomous iterations")

    # scan (traditional pipeline)
    scan_parser = subparsers.add_parser("scan", help="Run pipeline-based security assessment")
    scan_parser.add_argument("target", help="Target to scan (URL, IP, domain)")
    scan_parser.add_argument("--goal", "-g", default="", help="Assessment goal")
    scan_parser.add_argument("--deep", action="store_true", help="Deep comprehensive scan")
    scan_parser.add_argument("--stealth", action="store_true", help="Stealth mode (slower, quieter)")
    scan_parser.add_argument("--timeout", type=int, default=3600, help="Max time in seconds")
    scan_parser.add_argument("--output", "-o", default="", help="Output directory")
    scan_parser.add_argument("--tool-timeout", type=int, default=300, help="Per-tool timeout")
    scan_parser.add_argument("--iterations", type=int, default=100, help="Max autonomous iterations")
    scan_parser.add_argument("--no-autonomous", action="store_true", help="Disable autonomous LLM loop")
    scan_parser.add_argument("--no-consensus", action="store_true", help="Disable multi-model consensus voting")

    # models
    subparsers.add_parser("models", help="List configured LLM models")

    # health
    subparsers.add_parser("health", help="Check LLM server health")

    # tools
    subparsers.add_parser("tools", help="List available security tools")

    # version
    subparsers.add_parser("version", help="Show version")

    return parser


def cmd_agent(args: argparse.Namespace) -> None:
    """Launch the conversational autonomous agent."""
    agent = AutonomousAgent(
        max_iterations=args.iterations,
        max_time_s=float(args.timeout),
    )

    if args.target:
        # Direct mode: user specified a target on the command line
        goal = args.goal or f"Find all vulnerabilities in {args.target}"
        agent.chat(goal if args.target in goal else f"{goal} — target: {args.target}")
    else:
        # Interactive mode: conversational REPL
        agent.interactive_loop()


def cmd_scan(args: argparse.Namespace) -> None:
    """Run a pipeline-based security assessment."""
    config = ScanConfig(
        target=args.target,
        goal=args.goal,
        max_time_s=float(args.timeout),
        max_iterations=args.iterations,
        stealth=args.stealth,
        deep_scan=args.deep,
        autonomous=not args.no_autonomous,
        consensus=not args.no_consensus,
        tool_timeout_s=args.tool_timeout,
        output_dir=args.output,
    )

    runner = Runner(config=config)
    runner.run(args.target, goal=args.goal)


def cmd_models(_args: argparse.Namespace) -> None:
    """List configured LLM models and check health."""
    print(f"\n  Configured Models ({len(MODEL_SERVERS)}):")
    print(f"  {'─'*60}")
    print(f"  {'ID':<20} {'Name':<30} {'Port':<8} {'Context':<10}")
    print(f"  {'─'*60}")
    for model_id, info in MODEL_SERVERS.items():
        print(f"  {model_id:<20} {info['name']:<30} {info['port']:<8} {info['ctx']:<10}")
    print()


def cmd_health(_args: argparse.Namespace) -> None:
    """Check which LLM servers are running."""
    client = LLMClient(on_demand=False)
    print("\n  LLM Server Health Check (On-Demand Architecture)")
    print(f"  {'─'*60}")

    healthy = 0
    total_ram = 0.0
    total = len(MODEL_SERVERS)
    for model_id, info in MODEL_SERVERS.items():
        is_healthy = client.check_health(model_id)
        ram = MODEL_RAM_GB.get(model_id, 4.0)
        status = f"ONLINE  ~{ram:.0f}GB RAM" if is_healthy else "on disk"
        icon = "●" if is_healthy else "○"
        print(f"  {icon} {model_id:<20} {info['name']:<28} port:{info['port']:<6} {status}")
        if is_healthy:
            healthy += 1
            total_ram += ram

    print(f"\n  {healthy}/{total} models loaded in RAM ({total_ram:.0f}GB)")
    print(f"  {total - healthy}/{total} models on disk (0GB RAM)")
    if healthy == 0:
        print("\n  Start 1-2 models for on-demand scanning:")
        print("    ./scripts/launch_models.sh whiterabbitneo")
        print("    ./scripts/launch_models.sh whiterabbitneo qwen-coder-14b")
        print("\n  Or just run the agent — it auto-loads models:")
        print("    recursec")
        print("    > Find vulnerabilities in webapp.com")
    elif healthy <= 3:
        print(f"\n  On-demand mode active: {healthy} model(s) loaded, {total - healthy} on disk")
    else:
        print(f"\n  WARNING: {healthy} models loaded — consider using on-demand mode")
        print("  Stop all: ./scripts/launch_models.sh --stop")
    print(f"\n  Smart Routing: {len(TASK_ROUTING)} task types configured")
    print(f"  Consensus voting: {'ready' if healthy >= 2 else 'needs 2+ models'}")
    print("  DynamicModelLoader: max_cached=2, auto-loads from disk")
    print()


def cmd_tools(_args: argparse.Namespace) -> None:
    """List available security tools."""
    executor = ToolExecutor()
    all_tools = executor.get_all_tools()
    available = [t for t in all_tools if t.available]

    print(f"\n  Security Tools ({len(available)}/{len(all_tools)} available):")
    print(f"  {'─'*60}")

    by_cat: dict[str, list] = {}
    for tool in all_tools:
        cat = tool.category.value
        if cat not in by_cat:
            by_cat[cat] = []
        by_cat[cat].append(tool)

    for cat in sorted(by_cat):
        tools = by_cat[cat]
        installed = [t for t in tools if t.available]
        print(f"\n  [{cat.upper()}] ({len(installed)}/{len(tools)})")
        for tool in tools:
            icon = "●" if tool.available else "○"
            print(f"    {icon} {tool.name:<20} {tool.description}")

    print("\n  Install missing tools: sudo apt install <tool> or go install <tool>")
    print()


def main() -> None:
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        # DEFAULT: launch the conversational autonomous agent
        agent = AutonomousAgent()
        agent.interactive_loop()
        return

    handlers = {
        "agent": cmd_agent,
        "scan": cmd_scan,
        "health": cmd_health,
        "models": cmd_models,
        "tools": cmd_tools,
        "version": lambda _: print("RecurSec v1.1.0 — Autonomous Conversational Agent"),
    }

    handler = handlers.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
