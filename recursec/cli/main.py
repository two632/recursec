"""RecurSec CLI — command-line interface for the autonomous security agent.

Usage:
    recursec scan <target>              # Quick scan
    recursec assess <target>            # Full assessment
    recursec assess <target> --deep     # Deep comprehensive scan
    recursec config show                # Show current config
    recursec config models              # List configured models
    recursec config add-model <name>    # Add a model
    recursec status                     # Show agent status
    recursec tools                      # List available tools
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

import structlog

logger = structlog.get_logger()


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recursec",
        description="RecurSec — Autonomous Multi-Agent Security Assessment Framework",
    )
    subparsers = parser.add_subparsers(dest="command")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Quick security scan")
    scan_parser.add_argument("target", help="Target to scan (URL, IP, domain)")
    scan_parser.add_argument("--timeout", type=int, default=300, help="Max time in seconds")
    scan_parser.add_argument("--output", "-o", default="", help="Output file")
    scan_parser.add_argument("--format", "-f", default="terminal",
                             choices=["json", "markdown", "terminal", "sarif", "csv"],
                             help="Output format")

    # assess
    assess_parser = subparsers.add_parser("assess", help="Full security assessment")
    assess_parser.add_argument("target", help="Target to assess")
    assess_parser.add_argument("--goal", "-g", default="", help="Assessment goal")
    assess_parser.add_argument("--deep", action="store_true", help="Deep comprehensive scan")
    assess_parser.add_argument("--stealth", action="store_true", help="Stealth mode")
    assess_parser.add_argument("--timeout", type=int, default=1800, help="Max time in seconds")
    assess_parser.add_argument("--max-agents", type=int, default=20, help="Max agents")
    assess_parser.add_argument("--max-depth", type=int, default=3, help="Max recursion depth")
    assess_parser.add_argument("--risk", type=float, default=0.5, help="Risk tolerance 0-1")
    assess_parser.add_argument("--output", "-o", default="", help="Output file")
    assess_parser.add_argument("--format", "-f", default="json",
                             choices=["json", "markdown", "terminal", "sarif", "csv"],
                             help="Output format")
    assess_parser.add_argument("--no-validate", action="store_true", help="Skip validation")
    assess_parser.add_argument("--strategy", default="adaptive",
                             choices=["adaptive", "breadth_first", "depth_first",
                                      "risk_prioritized", "exploitation_focused", "stealth"],
                             help="Assessment strategy")

    # config
    config_parser = subparsers.add_parser("config", help="Configuration management")
    config_sub = config_parser.add_subparsers(dest="config_command")
    config_sub.add_parser("show", help="Show current configuration")
    config_sub.add_parser("models", help="List configured models")
    config_sub.add_parser("init", help="Create default configuration file")

    add_model = config_sub.add_parser("add-model", help="Add a model")
    add_model.add_argument("name", help="Model name")
    add_model.add_argument("--port", type=int, required=True, help="Server port")
    add_model.add_argument("--capabilities", nargs="+", default=[], help="Capabilities")
    add_model.add_argument("--weight", type=float, default=1.0, help="Routing weight")
    add_model.add_argument("--context", type=int, default=4096, help="Context length")
    add_model.add_argument("--prompt", default="", help="System prompt")

    rm_model = config_sub.add_parser("remove-model", help="Remove a model")
    rm_model.add_argument("name", help="Model name")

    # tools
    subparsers.add_parser("tools", help="List available tools")

    # status
    subparsers.add_parser("status", help="Show agent status")

    # version
    subparsers.add_parser("version", help="Show version")

    return parser


def cmd_scan(args: argparse.Namespace) -> None:
    """Run a quick scan."""
    from recursec.agents.recursec_agent import AssessmentConfig, RecurSecAgent

    agent = RecurSecAgent()

    config = AssessmentConfig(
        target=args.target,
        goal=f"Quick security scan of {args.target}",
        max_time_s=float(args.timeout),
        max_agents=10,
    )

    print(f"\n  RecurSec — Scanning {args.target}")
    print(f"  Timeout: {args.timeout}s | Strategy: adaptive")
    print(f"  {'='*50}\n")

    start = time.time()
    result = asyncio.run(agent.assess(config))

    elapsed = time.time() - start
    print(f"\n  Scan complete in {elapsed:.1f}s")
    print(f"  Status: {result.status.value}")
    print(f"  Findings: {len(result.findings)} ({len(result.validated_findings)} validated)")
    print(f"  Agents used: {result.agents_spawned}")
    print(f"  Tools used: {', '.join(result.tools_used) or 'None'}")

    if result.report:
        if args.output:
            Path(args.output).write_text(result.report)
            print(f"  Report saved to: {args.output}")
        else:
            print(f"\n{result.report}")


def cmd_assess(args: argparse.Namespace) -> None:
    """Run a full assessment."""
    from recursec.agents.recursec_agent import AssessmentConfig, RecurSecAgent
    from recursec.agents.strategy_optimizer import AssessmentStrategy

    strategy_map = {
        "adaptive": AssessmentStrategy.ADAPTIVE,
        "breadth_first": AssessmentStrategy.BREADTH_FIRST,
        "depth_first": AssessmentStrategy.DEPTH_FIRST,
        "risk_prioritized": AssessmentStrategy.RISK_PRIORITIZED,
        "exploitation_focused": AssessmentStrategy.EXPLOITATION_FOCUSED,
        "stealth": AssessmentStrategy.STEALTH,
    }

    agent = RecurSecAgent()

    timeout = 3600.0 if args.deep else float(args.timeout)
    max_agents = 30 if args.deep else args.max_agents

    config = AssessmentConfig(
        target=args.target,
        goal=args.goal or f"Security assessment of {args.target}",
        max_depth=args.max_depth,
        max_agents=max_agents,
        max_time_s=timeout,
        risk_tolerance=args.risk,
        strategy=strategy_map.get(args.strategy, AssessmentStrategy.ADAPTIVE),
        validate_findings=not args.no_validate,
        stealth_mode=args.stealth,
    )

    mode = "DEEP" if args.deep else "STANDARD"
    print(f"\n  RecurSec — {mode} Assessment of {args.target}")
    print(f"  Goal: {config.goal}")
    print(f"  Strategy: {args.strategy} | Risk: {args.risk}")
    print(f"  Max agents: {max_agents} | Depth: {args.max_depth}")
    print(f"  Timeout: {timeout:.0f}s | Validate: {not args.no_validate}")
    print(f"  {'='*50}\n")

    start = time.time()
    result = asyncio.run(agent.assess(config))

    elapsed = time.time() - start
    print(f"\n  Assessment complete in {elapsed:.1f}s")
    print(f"  Status: {result.status.value}")
    print(f"  Total findings: {len(result.findings)}")
    print(f"  Validated findings: {len(result.validated_findings)}")
    print(f"  Correlation groups: {len(result.correlation_groups)}")
    print(f"  Agents spawned: {result.agents_spawned}")
    print(f"  Tools used: {', '.join(result.tools_used) or 'None'}")

    if result.errors:
        print(f"  Errors: {len(result.errors)}")

    if result.report:
        if args.output:
            Path(args.output).write_text(result.report)
            print(f"  Report saved to: {args.output}")
        else:
            print(f"\n{result.report}")


def cmd_config(args: argparse.Namespace) -> None:
    """Configuration management."""
    from recursec.config.settings import ModelConfig, Settings

    settings = Settings()

    if args.config_command == "show":
        print(json.dumps(settings.to_dict(), indent=2))

    elif args.config_command == "models":
        print(f"\n  Configured Models ({len(settings.models)}):")
        print(f"  {'─'*50}")
        for name, model in settings.models.items():
            status = "ON" if model.enabled else "OFF"
            caps = ", ".join(model.capabilities[:3])
            print(f"  [{status}] {name:20s} port:{model.port:<6d} "
                  f"ctx:{model.context_length:<8d} w:{model.weight:.1f}  [{caps}]")

    elif args.config_command == "init":
        settings.save("recursec.json")
        print("  Configuration saved to recursec.json")

    elif args.config_command == "add-model":
        model = ModelConfig(
            name=args.name,
            port=args.port,
            capabilities=args.capabilities,
            weight=args.weight,
            context_length=args.context,
            system_prompt=args.prompt,
        )
        settings.add_model(model)
        settings.save()
        print(f"  Model '{args.name}' added (port {args.port})")

    elif args.config_command == "remove-model":
        if settings.remove_model(args.name):
            settings.save()
            print(f"  Model '{args.name}' removed")
        else:
            print(f"  Model '{args.name}' not found")

    else:
        print("  Use: recursec config [show|models|init|add-model|remove-model]")


def cmd_tools(args: argparse.Namespace) -> None:
    """List available tools."""
    from recursec.agents.tool_pipeline import ToolPipeline

    pipeline = ToolPipeline()
    stats = pipeline.get_stats()

    print(f"\n  Available Security Tools ({stats['available']}/{stats['total_tools']}):")
    print(f"  {'─'*50}")

    for category, count in sorted(stats.get("by_category", {}).items()):
        print(f"  [{category:15s}] {count} tools")

    print(f"\n  Total: {stats['available']} available, {stats['total_tools']} registered")


def cmd_status(args: argparse.Namespace) -> None:
    """Show agent status."""
    from recursec.config.settings import Settings

    settings = Settings()
    enabled_models = sum(1 for m in settings.models.values() if m.enabled)

    print("\n  RecurSec Status")
    print(f"  {'─'*40}")
    print(f"  Models: {enabled_models}/{len(settings.models)} enabled")
    print(f"  Strategy: {settings.agent.default_strategy}")
    print(f"  Max depth: {settings.agent.max_recursion_depth}")
    print(f"  Max agents: {settings.agent.max_total_agents}")
    print(f"  Safety model: {'ON' if settings.safety.safety_model_enabled else 'OFF'}")
    print(f"  Output: {settings.output.output_format}")


def main() -> None:
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    handlers = {
        "scan": cmd_scan,
        "assess": cmd_assess,
        "config": cmd_config,
        "tools": cmd_tools,
        "status": cmd_status,
        "version": lambda _: print("RecurSec v1.0.0"),
    }

    handler = handlers.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
