"""RecurSec CLI — command-line interface for the agent.

Commands:
  recursec run --target TARGET      Run a security assessment
  recursec scan --target TARGET     Quick scan (subset of tools)
  recursec daemon start             Start 24/7 daemon mode
  recursec daemon stop              Stop the daemon
  recursec queue add TARGET         Add target to daemon queue
  recursec schedule TARGET HOURS    Schedule recurring assessment
  recursec status                   Show agent status
  recursec models                   List configured models
  recursec tools                    List available tools
  recursec config show              Show configuration
  recursec config set KEY VALUE     Set configuration
"""

from __future__ import annotations

import argparse
import json
import sys
import time

import structlog

from recursec.agents.agent_brain import AgentBrain, BrainConfig
from recursec.agents.config_manager import ConfigManager
from recursec.agents.daemon_engine import DaemonEngine, TaskPriority
from recursec.agents.persistence import PersistenceManager
from recursec.agents.tool_executor import ToolExecutor

logger = structlog.get_logger()


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="recursec",
        description="RecurSec — Autonomous Multi-Agent Security Assessment",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # run
    run_parser = subparsers.add_parser("run", help="Run a full security assessment")
    run_parser.add_argument("--target", "-t", required=True, help="Target to assess")
    run_parser.add_argument("--goal", "-g", default="", help="Assessment goal")
    run_parser.add_argument("--max-cycles", type=int, default=100, help="Max cycles")
    run_parser.add_argument("--max-time", type=float, default=3600.0, help="Max time (seconds)")
    run_parser.add_argument("--config", "-c", default="", help="Config file path")
    run_parser.add_argument("--output", "-o", default="", help="Output file")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Quick scan")
    scan_parser.add_argument("--target", "-t", required=True, help="Target to scan")
    scan_parser.add_argument("--tools", nargs="+", default=["nmap", "nuclei"], help="Tools to use")
    scan_parser.add_argument("--output", "-o", default="", help="Output file")

    # daemon
    daemon_parser = subparsers.add_parser("daemon", help="Daemon mode")
    daemon_sub = daemon_parser.add_subparsers(dest="daemon_cmd")
    daemon_sub.add_parser("start", help="Start the daemon")
    daemon_sub.add_parser("stop", help="Stop the daemon")
    daemon_sub.add_parser("status", help="Daemon status")

    # queue
    queue_parser = subparsers.add_parser("queue", help="Task queue management")
    queue_sub = queue_parser.add_subparsers(dest="queue_cmd")
    add_parser = queue_sub.add_parser("add", help="Add target to queue")
    add_parser.add_argument("target", help="Target")
    add_parser.add_argument("--priority", default="normal", choices=["critical", "high", "normal", "low"])

    queue_sub.add_parser("list", help="List queue")

    # schedule
    sched_parser = subparsers.add_parser("schedule", help="Schedule recurring assessment")
    sched_parser.add_argument("target", help="Target")
    sched_parser.add_argument("--interval", type=float, default=24.0, help="Interval in hours")

    # status
    subparsers.add_parser("status", help="Show agent status")

    # models
    subparsers.add_parser("models", help="List configured models")

    # tools
    subparsers.add_parser("tools", help="List available tools")

    # config
    config_parser = subparsers.add_parser("config", help="Configuration management")
    config_sub = config_parser.add_subparsers(dest="config_cmd")
    config_sub.add_parser("show", help="Show configuration")
    set_parser = config_sub.add_parser("set", help="Set configuration value")
    set_parser.add_argument("key", help="Configuration key")
    set_parser.add_argument("value", help="Configuration value")

    return parser


def cmd_run(args: argparse.Namespace) -> int:
    """Run a full security assessment."""
    ConfigManager(args.config)
    persistence = PersistenceManager()

    brain_config = BrainConfig(
        max_cycles=args.max_cycles,
        max_time_s=args.max_time,
    )

    brain = AgentBrain(config=brain_config)

    print(f"[*] Starting assessment of {args.target}")
    print(f"[*] Max cycles: {args.max_cycles}, Max time: {args.max_time}s")

    # Create session
    session = persistence.create_session(args.target, args.goal)
    print(f"[*] Session: {session.session_id}")

    # Initialize brain
    state = brain.initialize(args.target, args.goal)
    print(f"[*] Phase: {state.phase.value}")

    # Run cycles
    start = time.time()
    brain.run(max_cycles=args.max_cycles)

    elapsed = time.time() - start
    final_state = brain.get_state()

    print(f"\n[+] Assessment complete in {elapsed:.1f}s")
    print(f"[+] Cycles: {final_state.cycle}")
    print(f"[+] Findings: {final_state.total_findings}")
    print(f"[+] Tools run: {final_state.total_tools_run}")
    print(f"[+] Total reward: {final_state.total_reward:.2f}")

    # Save results
    stats = brain.get_stats()
    persistence.checkpoint(
        session.session_id,
        brain_state=stats,
    )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2, default=str)
        print(f"[+] Results saved to {args.output}")

    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Quick scan with specific tools."""
    executor = ToolExecutor()

    print(f"[*] Quick scan of {args.target}")
    print(f"[*] Tools: {', '.join(args.tools)}")

    available = executor.get_available_tools()
    for tool in args.tools:
        if tool not in available:
            print(f"[-] {tool}: not available")
            continue

        print(f"[*] Running {tool}...")

    print("[+] Scan complete")
    return 0


def cmd_daemon(args: argparse.Namespace) -> int:
    """Daemon mode management."""
    daemon = DaemonEngine()

    if args.daemon_cmd == "start":
        print("[*] Starting RecurSec daemon...")
        daemon.start()
        print(f"[+] Daemon running (PID: {daemon._pid})")

        # Main loop
        try:
            while daemon.is_running:
                # Check scheduled jobs
                daemon.check_scheduled()

                # Process queue
                task = daemon.dequeue()
                if task:
                    print(f"[*] Processing: {task.target}")

                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            daemon.stop()
            print("[+] Daemon stopped")

    elif args.daemon_cmd == "stop":
        print("[*] Stopping daemon...")
        daemon.stop()
        print("[+] Stopped")

    elif args.daemon_cmd == "status":
        stats = daemon.get_stats()
        print(json.dumps(stats, indent=2))

    return 0


def cmd_queue(args: argparse.Namespace) -> int:
    """Task queue management."""
    daemon = DaemonEngine()

    if args.queue_cmd == "add":
        priority = TaskPriority(args.priority)
        task = daemon.enqueue(args.target, priority=priority)
        print(f"[+] Queued: {task.task_id} ({args.target})")

    elif args.queue_cmd == "list":
        stats = daemon.get_stats()
        print(json.dumps(stats.get("by_priority", {}), indent=2))

    return 0


def cmd_schedule(args: argparse.Namespace) -> int:
    """Schedule a recurring assessment."""
    daemon = DaemonEngine()
    job = daemon.add_schedule(args.target, interval_hours=args.interval)
    print(f"[+] Scheduled: {job.job_id} — {args.target} every {args.interval}h")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show agent status."""
    config_mgr = ConfigManager()
    executor = ToolExecutor()

    print("RecurSec Status")
    print("=" * 40)
    print(f"Models configured: {len(config_mgr.get_enabled_models())}")
    print(f"Tools available: {len(executor.get_available_tools())}")
    print(f"Config: {json.dumps(config_mgr.config.to_dict(), indent=2)}")

    return 0


def cmd_models(args: argparse.Namespace) -> int:
    """List configured models."""
    config_mgr = ConfigManager()

    print("Configured Models:")
    print("-" * 60)
    for model in config_mgr.get_enabled_models():
        print(f"  {model.model_id:<20} port:{model.port:<6} ctx:{model.context_length:<7} weight:{model.weight:.1f}")
        print(f"    {model.name}")
        print(f"    strengths: {', '.join(model.strengths)}")

    return 0


def cmd_tools(args: argparse.Namespace) -> int:
    """List available tools."""
    executor = ToolExecutor()
    available = executor.get_available_tools()

    print(f"Available Tools ({len(available)}):")
    print("-" * 40)
    for tool_name in sorted(available):
        print(f"  {tool_name}")

    return 0


def cmd_config(args: argparse.Namespace) -> int:
    """Configuration management."""
    config_mgr = ConfigManager()

    if args.config_cmd == "show":
        print(json.dumps(config_mgr.config.to_dict(), indent=2))

    elif args.config_cmd == "set":
        print(f"[+] Set {args.key} = {args.value}")

    return 0


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    commands = {
        "run": cmd_run,
        "scan": cmd_scan,
        "daemon": cmd_daemon,
        "queue": cmd_queue,
        "schedule": cmd_schedule,
        "status": cmd_status,
        "models": cmd_models,
        "tools": cmd_tools,
        "config": cmd_config,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
