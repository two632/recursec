"""RecurSec Engine — the main orchestration engine that ties everything together."""

from __future__ import annotations

import asyncio
import signal
import time
from typing import Any

import structlog

from recursec.agents.factory import AgentFactory
from recursec.config.settings import RecurSecConfig
from recursec.core.models import AgentRole, AgentTask, Target, TaskStatus
from recursec.llm.router import ModelConfig, ModelRouter
from recursec.memory.store import MemoryStore
from recursec.tools.registry import ToolRegistry

logger = structlog.get_logger()


class RecurSecEngine:
    """The main engine that orchestrates everything.

    Flow:
    1. Load config (YAML)
    2. Initialize LLM router with all configured models
    3. Initialize tool registry with 200+ tools
    4. Initialize memory store
    5. Accept tasks and dispatch to the Orchestrator agent
    6. The Orchestrator recursively spawns specialized agents
    7. Results flow back up the tree
    """

    def __init__(self, config: RecurSecConfig):
        self.config = config
        self.router = ModelRouter()
        self.tools = ToolRegistry(
            sandbox_mode=config.tools.sandbox_mode,
            docker_image=config.tools.docker_image,
        )
        self.memory = MemoryStore(
            db_path=config.db_path,
            data_dir=config.data_dir,
        )
        self._running = False
        self._task_queue: asyncio.Queue[AgentTask] = asyncio.Queue()
        self._active_tasks: dict[str, AgentTask] = {}
        self._completed_tasks: list[AgentTask] = []

    async def initialize(self) -> None:
        """Initialize all subsystems."""
        logger.info("engine_initializing")

        # 1. Initialize memory
        await self.memory.initialize()

        # 2. Load tool registry
        self.tools.load_defaults()

        # Add custom tools from config
        for ct in self.config.tools.custom_tools:
            self.tools.add_custom_tool(
                name=ct.get("name", ""),
                binary=ct.get("binary", ""),
                category=ct.get("category", "misc"),
                description=ct.get("description", ""),
                install_cmd=ct.get("install", ""),
            )

        # Auto-install tools if configured
        if self.config.tools.auto_install:
            logger.info("auto_installing_tools")
            results = await self.tools.install_all_available()
            installed = sum(1 for v in results.values() if v)
            logger.info("tools_auto_installed", installed=installed, failed=len(results) - installed)

        # 3. Initialize LLM models
        for model_cfg in self.config.models:
            await self.router.add_model(ModelConfig(
                name=model_cfg.name,
                backend_type=model_cfg.backend,
                model_id=model_cfg.model_id,
                base_url=model_cfg.base_url,
                api_key=model_cfg.api_key,
                task_types=model_cfg.task_types,
                priority=model_cfg.priority,
                max_concurrent=model_cfg.max_concurrent,
                weight=model_cfg.weight,
                **model_cfg.extra,
            ))

        # Health check all models
        health = await self.router.health_check_all()
        healthy = sum(1 for v in health.values() if v)
        logger.info(
            "engine_initialized",
            models=len(self.config.models),
            models_healthy=healthy,
            tools_total=self.tools.count(),
            tools_available=self.tools.count_available(),
        )

    async def submit_task(
        self,
        objective: str,
        target: str | None = None,
        target_type: str = "host",
        agent_role: str = "orchestrator",
        priority: int = 5,
        context: dict[str, Any] | None = None,
    ) -> AgentTask:
        """Submit a new task to the engine."""
        task = AgentTask(
            agent_role=AgentRole(agent_role),
            objective=objective,
            target=Target(name=target or "unknown", value=target or "", target_type=target_type) if target else None,
            priority=priority,
            max_depth=self.config.agent.max_depth,
            max_steps=self.config.agent.max_steps,
            context=context or {},
        )

        await self._task_queue.put(task)
        self._active_tasks[task.id] = task
        logger.info("task_submitted", task_id=task.id, objective=objective[:80], target=target)
        return task

    async def run_task(self, task: AgentTask) -> AgentTask:
        """Run a single task synchronously."""
        agent = AgentFactory.create(
            role=task.agent_role,
            model_router=self.router,
            tool_registry=self.tools,
            memory=self.memory,
        )
        result = await agent.run(task)

        # Store scan record
        scan_id = await self.memory.store_scan(
            target=task.target.value if task.target else "unknown",
            scan_type=task.agent_role.value,
            config={"objective": task.objective},
        )
        await self.memory.complete_scan(scan_id, len(result.findings), result.result)

        return result

    async def run_daemon(self) -> None:
        """Run the engine in daemon mode — processes tasks from the queue 24/7."""
        self._running = True
        logger.info("daemon_started", max_concurrent=self.config.daemon.max_concurrent_tasks)

        # Handle shutdown signals
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._shutdown)

        workers = [
            asyncio.create_task(self._task_worker(i))
            for i in range(self.config.daemon.max_concurrent_tasks)
        ]

        # Scheduled tasks
        if self.config.daemon.schedule:
            workers.append(asyncio.create_task(self._scheduler()))

        try:
            await asyncio.gather(*workers)
        except asyncio.CancelledError:
            pass
        finally:
            logger.info("daemon_stopped")

    async def _task_worker(self, worker_id: int) -> None:
        """Worker that processes tasks from the queue."""
        while self._running:
            try:
                task = await asyncio.wait_for(self._task_queue.get(), timeout=5.0)
            except asyncio.TimeoutError:
                continue

            logger.info("worker_picked_task", worker=worker_id, task_id=task.id)
            try:
                result = await self.run_task(task)
                self._completed_tasks.append(result)
                del self._active_tasks[task.id]
                logger.info(
                    "task_completed",
                    worker=worker_id,
                    task_id=task.id,
                    findings=len(result.findings),
                    status=result.status.value,
                )
            except Exception as e:
                logger.error("task_failed", worker=worker_id, task_id=task.id, error=str(e))
                task.status = TaskStatus.FAILED
                task.error = str(e)

    async def _scheduler(self) -> None:
        """Handle scheduled/recurring tasks."""
        while self._running:
            for sched in self.config.daemon.schedule:
                interval = sched.get("interval_s", 3600)
                last_run = sched.get("_last_run", 0)
                if time.time() - last_run >= interval:
                    await self.submit_task(
                        objective=sched.get("objective", ""),
                        target=sched.get("target"),
                        target_type=sched.get("target_type", "host"),
                        priority=sched.get("priority", 5),
                    )
                    sched["_last_run"] = time.time()
            await asyncio.sleep(self.config.daemon.poll_interval_s)

    def _shutdown(self) -> None:
        logger.info("shutdown_requested")
        self._running = False

    async def get_status(self) -> dict[str, Any]:
        """Get engine status."""
        memory_stats = await self.memory.get_stats()
        return {
            "running": self._running,
            "models": self.router.list_models(),
            "tools_total": self.tools.count(),
            "tools_available": self.tools.count_available(),
            "active_tasks": len(self._active_tasks),
            "queued_tasks": self._task_queue.qsize(),
            "completed_tasks": len(self._completed_tasks),
            "memory": memory_stats,
        }

    async def add_model_runtime(
        self,
        name: str,
        backend: str,
        model_id: str,
        base_url: str,
        api_key: str = "",
        task_types: list[str] | None = None,
        priority: int = 5,
    ) -> None:
        """Hot-add a model at runtime."""
        await self.router.add_model(ModelConfig(
            name=name,
            backend_type=backend,
            model_id=model_id,
            base_url=base_url,
            api_key=api_key,
            task_types=task_types or ["general"],
            priority=priority,
        ))

    async def remove_model_runtime(self, name: str) -> None:
        """Hot-remove a model at runtime."""
        await self.router.remove_model(name)

    async def shutdown(self) -> None:
        """Clean shutdown."""
        self._running = False
        await self.router.close_all()
        await self.memory.close()
        logger.info("engine_shutdown_complete")
