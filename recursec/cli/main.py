"""RecurSec CLI — main entry point for the agent framework.

Commands:
  recursec run         Run an assessment against a target
  recursec init        Generate a default configuration file
  recursec status      Show runtime status
  recursec models      List/manage LLM models
  recursec history     Show assessment history
  recursec knowledge   Query the knowledge graph
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

import structlog

from recursec.agents.goal_decomposer import GoalType
from recursec.agents.runtime import AgentRuntime, RuntimeConfig

logger = structlog.get_logger()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="recursec",
        description="RecurSec — Recursive Multi-Agent Security Framework",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # run
    run_parser = subparsers.add_parser("run", help="Run a security assessment")
    run_parser.add_argument("--target", "-t", required=True, help="Target to assess")
    run_parser.add_argument("--type", "-T", default="full_assessment",
                            choices=[gt.value for gt in GoalType],
                            help="Assessment type")
    run_parser.add_argument("--goal", "-g", default="", help="Custom goal description")
    run_parser.add_argument("--config", "-c", default="recursec.yaml", help="Config file path")
    run_parser.add_argument("--scope", "-s", default="", help="Scope definition (JSON)")
    run_parser.add_argument("--max-time", type=int, default=3600, help="Max time in seconds")
    run_parser.add_argument("--max-tokens", type=int, default=1_000_000, help="Max tokens")
    run_parser.add_argument("--max-agents", type=int, default=50, help="Max concurrent agents")
    run_parser.add_argument("--output", "-o", default="", help="Output file for results")
    run_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # init
    subparsers.add_parser("init", help="Generate default configuration")

    # status
    subparsers.add_parser("status", help="Show runtime status")

    # models
    models_parser = subparsers.add_parser("models", help="Manage LLM models")
    models_parser.add_argument("--list", action="store_true", help="List available models")
    models_parser.add_argument("--dir", default="~/agent/models/gguf/", help="Models directory")

    # history
    history_parser = subparsers.add_parser("history", help="Show assessment history")
    history_parser.add_argument("--limit", type=int, default=10, help="Number of results")

    return parser.parse_args()


def cmd_init() -> None:
    """Generate a default configuration file."""
    config = {
        "recursec": {
            "version": "1.0.0",
            "models": {
                "dir": "~/agent/models/gguf/",
                "backend": "llama-cpp",
                "auto_start": True,
                "instances": [
                    {"name": "whiterabbitneo-7b", "file": "WhiteRabbitNeo-7B-v1.5a-Q4_K_M.gguf",
                     "port": 8100, "tasks": ["security", "exploit"], "priority": 1},
                    {"name": "qwen-coder-14b", "file": "Qwen2.5-Coder-14B-Instruct-Q3_K_M.gguf",
                     "port": 8101, "tasks": ["code", "code_audit"], "priority": 2},
                    {"name": "qwen-coder-7b", "file": "Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf",
                     "port": 8102, "tasks": ["code", "tool_selection"], "priority": 3},
                    {"name": "codellama-13b", "file": "codellama-13b-instruct.Q3_K_M.gguf",
                     "port": 8103, "tasks": ["code", "exploit_dev"], "priority": 4},
                    {"name": "codellama-7b", "file": "codellama-7b.Q4_K_M.gguf",
                     "port": 8104, "tasks": ["code", "fast_code"], "priority": 5},
                    {"name": "deepseek-r1-7b", "file": "DeepSeek-R1-Distill-Qwen-7B-q4_k_m.gguf",
                     "port": 8105, "tasks": ["reasoning", "planning"], "priority": 2},
                    {"name": "deepseek-math-7b", "file": "deepseek-math-7b-instruct-q4_k_m.gguf",
                     "port": 8106, "tasks": ["reasoning", "crypto"], "priority": 4},
                    {"name": "yi-9b-200k", "file": "Yi-9B-200K.Q5_K_M.gguf",
                     "port": 8107, "tasks": ["long_context", "code_audit"], "priority": 3},
                    {"name": "hermes-4-14b", "file": "Hermes-4-14B-IQ2_M.gguf",
                     "port": 8108, "tasks": ["general", "planning", "security"], "priority": 2},
                    {"name": "llama-3.1-8b", "file": "Meta-Llama-3.1-8B-Instruct-Q4_K_S.gguf",
                     "port": 8109, "tasks": ["general", "reasoning"], "priority": 3},
                    {"name": "dolphin-2.9", "file": "dolphin-2.9-llama3-8b.Q4_K_M.gguf",
                     "port": 8110, "tasks": ["general", "uncensored", "security"], "priority": 3},
                    {"name": "mistral-7b", "file": "Mistral-7B-Instruct-v0.3-Q4_K_M.gguf",
                     "port": 8111, "tasks": ["general", "fast"], "priority": 4},
                    {"name": "phi-3.5-mini", "file": "Phi-3.5-mini-instruct-Q4_K_M.gguf",
                     "port": 8112, "tasks": ["fast", "classification"], "priority": 5},
                    {"name": "functiongemma", "file": "functiongemma-270m-it-BF16.gguf",
                     "port": 8113, "tasks": ["function_call", "tool_routing"], "priority": 1},
                    {"name": "llama-guard-3", "file": "llama-guard-3-1b-q4_k_m.gguf",
                     "port": 8114, "tasks": ["safety"], "priority": 1},
                    {"name": "nomic-embed", "file": "nomic-embed-text-v1.5.f32.gguf",
                     "port": 8115, "tasks": ["embedding"], "priority": 1},
                ],
            },
            "agents": {
                "max_agents": 50,
                "max_concurrent": 10,
                "max_recursion_depth": 5,
                "default_timeout_s": 300,
            },
            "budgets": {
                "max_tokens": 1_000_000,
                "max_time_s": 3600,
                "max_steps": 500,
            },
            "memory": {
                "working_capacity": 50,
                "semantic_max_items": 50000,
            },
            "scheduling": {
                "strategy": "adaptive",
                "max_queue_size": 500,
            },
            "features": {
                "reflection": True,
                "learning": True,
                "debate": False,
                "tree_of_thought": False,
                "safety_guard": True,
            },
            "scope": {
                "in_scope_domains": [],
                "out_of_scope_domains": [],
                "in_scope_ips": [],
                "out_of_scope_ips": [],
            },
        },
    }

    output_path = Path("recursec.yaml")
    # Write as JSON since we don't want to add pyyaml dependency
    output_path.write_text(json.dumps(config, indent=2))
    print(f"Configuration written to {output_path}")
    print("Edit the file to customize your setup, then run: recursec run --target <target>")


def cmd_models(args: argparse.Namespace) -> None:
    """List available models."""
    model_dir = Path(args.dir).expanduser()
    if not model_dir.exists():
        print(f"Models directory not found: {model_dir}")
        return

    print(f"\nModels in {model_dir}:\n")
    total_size = 0
    for gguf_file in sorted(model_dir.glob("*.gguf")):
        size_gb = gguf_file.stat().st_size / (1024 ** 3)
        total_size += gguf_file.stat().st_size
        print(f"  {gguf_file.name:<55} {size_gb:>6.2f} GB")

    print(f"\n  Total: {total_size / (1024**3):.2f} GB")


async def cmd_run(args: argparse.Namespace) -> None:
    """Run a security assessment."""
    print(f"\n{'='*60}")
    print(" RecurSec — Recursive Multi-Agent Security Framework")
    print(f"{'='*60}")
    print(f" Target: {args.target}")
    print(f" Type:   {args.type}")
    print(f" Goal:   {args.goal or 'Full assessment'}")
    print(f"{'='*60}\n")

    # Build runtime config
    config = RuntimeConfig(
        max_tokens=args.max_tokens,
        max_time_s=args.max_time,
        max_agents=args.max_agents,
    )

    # Load config file if exists
    config_path = Path(args.config)
    if config_path.exists():
        try:
            file_config = json.loads(config_path.read_text())
            rc = file_config.get("recursec", {})
            budgets = rc.get("budgets", {})
            agents = rc.get("agents", {})
            config.max_tokens = budgets.get("max_tokens", config.max_tokens)
            config.max_time_s = budgets.get("max_time_s", config.max_time_s)
            config.max_agents = agents.get("max_agents", config.max_agents)
            config.max_concurrent = agents.get("max_concurrent", config.max_concurrent)
            config.max_recursion_depth = agents.get("max_recursion_depth", config.max_recursion_depth)
            print(f"[+] Loaded config from {config_path}")
        except (json.JSONDecodeError, OSError) as e:
            print(f"[!] Could not load config: {e}")

    # Parse scope
    scope = None
    if args.scope:
        try:
            scope = json.loads(args.scope)
        except json.JSONDecodeError:
            print(f"[!] Invalid scope JSON: {args.scope}")

    # Create and start runtime
    runtime = AgentRuntime(config=config)

    try:
        print("[*] Initializing runtime...")
        await runtime.start()
        print("[+] Runtime ready\n")

        # Run assessment
        goal_type = GoalType(args.type)
        print(f"[*] Starting assessment of {args.target}...")
        start_time = time.time()

        result = await runtime.run_assessment(
            target=args.target,
            goal=args.goal,
            goal_type=goal_type,
            scope=scope,
        )

        elapsed = time.time() - start_time

        # Print results
        print(f"\n{'='*60}")
        print(" Assessment Complete")
        print(f"{'='*60}")
        print(f" Status:    {result.status}")
        print(f" Duration:  {elapsed:.1f}s")
        print(f" Findings:  {len(result.findings)}")
        print(f" Agents:    {result.agents_spawned}")
        print(f" Phases:    {', '.join(set(result.phases_completed)) or 'N/A'}")
        print()

        if result.findings_by_severity:
            print(" Findings by severity:")
            for severity, count in sorted(result.findings_by_severity.items()):
                print(f"   {severity:<12} {count}")

        # Save output
        if args.output:
            output_path = Path(args.output)
            output_path.write_text(json.dumps(result.to_dict(), indent=2))
            print(f"\n[+] Results saved to {output_path}")

    except KeyboardInterrupt:
        print("\n[!] Interrupted — shutting down...")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
    finally:
        await runtime.stop()
        print("[*] Runtime stopped")


def main() -> None:
    """Main CLI entry point."""
    args = parse_args()

    if not args.command:
        print("RecurSec — Recursive Multi-Agent Security Framework")
        print("Run 'recursec --help' for usage information")
        sys.exit(0)

    if args.command == "init":
        cmd_init()
    elif args.command == "models":
        cmd_models(args)
    elif args.command == "run":
        asyncio.run(cmd_run(args))
    elif args.command == "status":
        print("Status: Not implemented yet (requires running daemon)")
    elif args.command == "history":
        print("History: No assessments found in data/")
    else:
        print(f"Unknown command: {args.command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
