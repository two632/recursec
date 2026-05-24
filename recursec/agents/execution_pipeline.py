"""Execution pipeline — end-to-end agent flow.

Wires together the full intelligence stack:
  Brain → Decomposer → Assembler → LLM → Parser → Memory → Correlation

This is the pipeline that turns a user request into
autonomous security operations. Each step feeds into
the next, creating a continuous reasoning loop.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PipelineStage(str, Enum):
    INTAKE = "intake"                   # Receive task
    UNDERSTANDING = "understanding"     # Classify intent
    PLANNING = "planning"               # Generate plan
    DECOMPOSITION = "decomposition"     # Break into sub-tasks
    KNOWLEDGE_LOAD = "knowledge_load"   # Load relevant KBs
    PROMPT_ASSEMBLY = "prompt_assembly" # Build prompt
    LLM_INFERENCE = "llm_inference"     # Call model
    OUTPUT_PARSE = "output_parse"       # Parse response
    TOOL_EXEC = "tool_exec"             # Execute tools
    RESULT_ANALYZE = "result_analyze"   # Analyze results
    MEMORY_STORE = "memory_store"       # Store in memory
    CORRELATION = "correlation"         # Correlate findings
    VALIDATION = "validation"           # Validate findings
    LEARNING = "learning"              # Update rewards
    REPORTING = "reporting"             # Generate report
    COMPLETE = "complete"               # Pipeline done


class PipelineStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    FAILED = "failed"
    COMPLETED = "completed"


@dataclass
class StageResult:
    """Result of a pipeline stage."""
    stage: PipelineStage = PipelineStage.INTAKE
    success: bool = True
    output: dict[str, Any] = field(default_factory=dict)
    duration_s: float = 0.0
    tokens_used: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage.value[:10],
            "ok": self.success,
            "time": f"{self.duration_s:.1f}s",
        }


@dataclass
class PipelineRun:
    """A single pipeline execution."""
    run_id: str = ""
    task: str = ""
    target: str = ""
    status: PipelineStatus = PipelineStatus.IDLE
    current_stage: PipelineStage = PipelineStage.INTAKE
    stages_completed: list[StageResult] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    total_tokens: int = 0
    total_tool_calls: int = 0
    started_at: float = 0.0
    completed_at: float = 0.0
    error: str = ""

    @property
    def duration_s(self) -> float:
        if self.completed_at:
            return self.completed_at - self.started_at
        if self.started_at:
            return time.time() - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "run": self.run_id[:8],
            "status": self.status.value[:8],
            "stage": self.current_stage.value[:10],
            "findings": len(self.findings),
            "time": f"{self.duration_s:.0f}s",
        }


# Standard pipeline sequences
PIPELINE_SEQUENCES: dict[str, list[PipelineStage]] = {
    "full": [
        PipelineStage.INTAKE,
        PipelineStage.UNDERSTANDING,
        PipelineStage.PLANNING,
        PipelineStage.DECOMPOSITION,
        PipelineStage.KNOWLEDGE_LOAD,
        PipelineStage.PROMPT_ASSEMBLY,
        PipelineStage.LLM_INFERENCE,
        PipelineStage.OUTPUT_PARSE,
        PipelineStage.TOOL_EXEC,
        PipelineStage.RESULT_ANALYZE,
        PipelineStage.MEMORY_STORE,
        PipelineStage.CORRELATION,
        PipelineStage.VALIDATION,
        PipelineStage.LEARNING,
        PipelineStage.REPORTING,
        PipelineStage.COMPLETE,
    ],
    "scan_only": [
        PipelineStage.INTAKE,
        PipelineStage.UNDERSTANDING,
        PipelineStage.KNOWLEDGE_LOAD,
        PipelineStage.PROMPT_ASSEMBLY,
        PipelineStage.LLM_INFERENCE,
        PipelineStage.OUTPUT_PARSE,
        PipelineStage.TOOL_EXEC,
        PipelineStage.RESULT_ANALYZE,
        PipelineStage.MEMORY_STORE,
        PipelineStage.COMPLETE,
    ],
    "analysis_only": [
        PipelineStage.INTAKE,
        PipelineStage.KNOWLEDGE_LOAD,
        PipelineStage.PROMPT_ASSEMBLY,
        PipelineStage.LLM_INFERENCE,
        PipelineStage.OUTPUT_PARSE,
        PipelineStage.CORRELATION,
        PipelineStage.REPORTING,
        PipelineStage.COMPLETE,
    ],
    "validate": [
        PipelineStage.INTAKE,
        PipelineStage.KNOWLEDGE_LOAD,
        PipelineStage.PROMPT_ASSEMBLY,
        PipelineStage.LLM_INFERENCE,
        PipelineStage.TOOL_EXEC,
        PipelineStage.VALIDATION,
        PipelineStage.LEARNING,
        PipelineStage.COMPLETE,
    ],
}

# Stage → required components
STAGE_COMPONENTS: dict[PipelineStage, list[str]] = {
    PipelineStage.UNDERSTANDING: ["unified_brain"],
    PipelineStage.PLANNING: ["planning_heuristics", "unified_brain"],
    PipelineStage.DECOMPOSITION: ["recursive_decomposer"],
    PipelineStage.KNOWLEDGE_LOAD: ["prompt_assembler"],
    PipelineStage.PROMPT_ASSEMBLY: [
        "prompt_assembler", "adaptive_context",
        "context_compression",
    ],
    PipelineStage.LLM_INFERENCE: ["model_selector"],
    PipelineStage.OUTPUT_PARSE: ["output_parser"],
    PipelineStage.TOOL_EXEC: ["tool_executor"],
    PipelineStage.RESULT_ANALYZE: ["chain_of_thought"],
    PipelineStage.MEMORY_STORE: [
        "semantic_memory", "episodic_memory",
    ],
    PipelineStage.CORRELATION: ["finding_correlation"],
    PipelineStage.VALIDATION: ["agent_debate", "adversarial_validator"],
    PipelineStage.LEARNING: ["reward_signal", "experience_replay"],
    PipelineStage.REPORTING: ["report_generator"],
}

# Stage → model preference
STAGE_MODEL_MAP: dict[PipelineStage, str] = {
    PipelineStage.UNDERSTANDING: "DeepSeek-R1",
    PipelineStage.PLANNING: "Hermes-4-14B",
    PipelineStage.LLM_INFERENCE: "WhiteRabbitNeo-7B",
    PipelineStage.RESULT_ANALYZE: "DeepSeek-R1",
    PipelineStage.VALIDATION: "Qwen2.5-Coder-14B",
    PipelineStage.REPORTING: "Mistral-7B",
}


class ExecutionPipeline:
    """End-to-end agent execution pipeline.

    Orchestrates the full flow from task intake
    to report generation, using all intelligence
    modules in sequence.
    """

    def __init__(self) -> None:
        self._runs: dict[str, PipelineRun] = {}
        self._run_counter = 0
        self._log = logger.bind(component="pipeline")

    def create_run(
        self,
        task: str,
        target: str = "",
        pipeline_type: str = "full",
    ) -> PipelineRun:
        """Create a new pipeline run."""
        self._run_counter += 1

        run = PipelineRun(
            run_id=f"run-{self._run_counter}",
            task=task,
            target=target,
            status=PipelineStatus.RUNNING,
            started_at=time.time(),
        )
        self._runs[run.run_id] = run
        return run

    def execute_stage(
        self,
        run_id: str,
        stage: PipelineStage,
    ) -> StageResult:
        """Execute a pipeline stage."""
        run = self._runs.get(run_id)
        if not run:
            return StageResult(stage=stage, success=False, error="Run not found")

        run.current_stage = stage
        start = time.time()

        # Get required components
        components = STAGE_COMPONENTS.get(stage, [])

        # Get model for this stage
        model = STAGE_MODEL_MAP.get(stage, "Mistral-7B")

        result = StageResult(
            stage=stage,
            success=True,
            output={
                "components": components,
                "model": model,
            },
            duration_s=time.time() - start,
        )

        run.stages_completed.append(result)
        return result

    def get_next_stage(self, run_id: str) -> PipelineStage | None:
        """Get the next stage to execute."""
        run = self._runs.get(run_id)
        if not run:
            return None

        sequence = PIPELINE_SEQUENCES.get("full", [])
        completed_stages = {s.stage for s in run.stages_completed}

        for stage in sequence:
            if stage not in completed_stages:
                return stage

        return None

    def add_finding(
        self,
        run_id: str,
        finding: dict[str, Any],
    ) -> None:
        """Add a finding to the run."""
        run = self._runs.get(run_id)
        if run:
            run.findings.append(finding)

    def complete_run(self, run_id: str) -> PipelineRun | None:
        """Complete a pipeline run."""
        run = self._runs.get(run_id)
        if run:
            run.status = PipelineStatus.COMPLETED
            run.completed_at = time.time()
            run.current_stage = PipelineStage.COMPLETE
        return run

    def fail_run(self, run_id: str, error: str = "") -> None:
        """Fail a pipeline run."""
        run = self._runs.get(run_id)
        if run:
            run.status = PipelineStatus.FAILED
            run.error = error
            run.completed_at = time.time()

    def get_pipeline_health(self) -> dict[str, Any]:
        """Get overall pipeline health metrics."""
        total = len(self._runs)
        completed = sum(
            1 for r in self._runs.values()
            if r.status == PipelineStatus.COMPLETED
        )
        failed = sum(
            1 for r in self._runs.values()
            if r.status == PipelineStatus.FAILED
        )
        running = sum(
            1 for r in self._runs.values()
            if r.status == PipelineStatus.RUNNING
        )

        avg_duration = 0.0
        durations = [
            r.duration_s for r in self._runs.values()
            if r.status == PipelineStatus.COMPLETED
        ]
        if durations:
            avg_duration = sum(durations) / len(durations)

        total_findings = sum(
            len(r.findings) for r in self._runs.values()
        )

        return {
            "runs": total,
            "completed": completed,
            "failed": failed,
            "running": running,
            "avg_duration": f"{avg_duration:.0f}s",
            "total_findings": total_findings,
        }

    def build_pipeline_prompt(self, run_id: str = "") -> str:
        """Build pipeline state for LLM."""
        lines = ["## Pipeline\n"]

        if run_id and run_id in self._runs:
            run = self._runs[run_id]
            lines.append(f"Run: {run.run_id[:8]}")
            lines.append(f"Status: {run.status.value}")
            lines.append(f"Stage: {run.current_stage.value}")
            lines.append(f"Findings: {len(run.findings)}")
            lines.append(
                f"Stages done: {len(run.stages_completed)}"
            )
        else:
            health = self.get_pipeline_health()
            lines.append(
                f"Runs: {health['runs']} "
                f"(ok={health['completed']}, fail={health['failed']})"
            )
            lines.append(f"Findings: {health['total_findings']}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return self.get_pipeline_health()
