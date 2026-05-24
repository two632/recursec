"""RecurSec CLI — command-line interface for the autonomous security agent.

Usage:
    python -m recursec scan <target>                     Quick scan
    python -m recursec scan <target> --deep              Deep comprehensive scan
    python -m recursec scan <target> --stealth           Stealth mode
    python -m recursec models                            List configured models
    python -m recursec tools                             List available tools
    python -m recursec health                            Check LLM server health
"""

from __future__ import annotations

import argparse
import sys
import time

import structlog

from recursec.agents.llm_client import LLMClient, MODEL_SERVERS, TASK_ROUTING
from recursec.agents.runner import Runner, ScanConfig
from recursec.agents.tool_executor import ToolExecutor

logger = structlog.get_logger()


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recursec",
        description="RecurSec — Autonomous Multi-Agent Security Assessment Framework",
    )
    subparsers = parser.add_subparsers(dest="command")

    # scan (the main command)
    scan_parser = subparsers.add_parser("scan", help="Run a security assessment")
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


def cmd_scan(args: argparse.Namespace) -> None:
    """Run a security assessment."""
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
    client = LLMClient()
    print("\n  LLM Server Health Check (On-Demand Architecture)")
    print(f"  {'─'*60}")

    healthy = 0
    total = len(MODEL_SERVERS)
    for model_id, info in MODEL_SERVERS.items():
        start = time.time()
        is_healthy = client.check_health(model_id)
        latency = (time.time() - start) * 1000
        status = "ONLINE" if is_healthy else "OFFLINE"
        icon = "●" if is_healthy else "○"
        print(f"  {icon} {model_id:<20} {info['name']:<28} port:{info['port']:<6} {status} ({latency:.0f}ms)")
        if is_healthy:
            healthy += 1

    print(f"\n  {healthy}/{total} models online")
    if healthy == 0:
        print("  Start 1-2 models for on-demand scanning:")
        print("    ./scripts/launch_models.sh whiterabbitneo")
        print("    ./scripts/launch_models.sh qwen-coder-14b")
    elif healthy < 3:
        print(f"  On-demand mode: {healthy} model(s) loaded, others available on disk")
    print(f"\n  Smart Routing: {len(TASK_ROUTING)} task types configured")
    print("  Consensus voting: available when 2+ models online")
    print()


def cmd_tools(_args: argparse.Namespace) -> None:
    """List available security tools."""
    executor = ToolExecutor()
    all_tools = executor.get_all_tools()
    available = [t for t in all_tools if t.available]

    print(f"\n  Security Tools ({len(available)}/{len(all_tools)} available):")
    print(f"  {'─'*60}")

    # Group by category
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
        parser.print_help()
        print("\nQuick start:")
        print("  python -m recursec scan https://example.com")
        print("  python -m recursec health")
        print("  python -m recursec tools")
        sys.exit(0)

    handlers = {
        "scan": cmd_scan,
        "health": cmd_health,
        "models": cmd_models,
        "tools": cmd_tools,
        "version": lambda _: print("RecurSec v1.0.0"),
    }

    handler = handlers.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
