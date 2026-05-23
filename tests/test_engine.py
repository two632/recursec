"""Test the engine, memory, and router."""


import pytest

from recursec.config.settings import LLMModelConfig, RecurSecConfig
from recursec.llm.backends import BACKEND_REGISTRY, create_backend
from recursec.llm.router import ModelConfig, ModelRouter
from recursec.memory.store import MemoryStore
from recursec.core.models import Severity, Vulnerability


def test_backend_registry():
    """Test all backends are registered."""
    assert "vllm" in BACKEND_REGISTRY
    assert "llama_cpp" in BACKEND_REGISTRY
    assert "sglang" in BACKEND_REGISTRY
    assert "litellm" in BACKEND_REGISTRY
    assert "ollama" in BACKEND_REGISTRY
    assert "openai_compatible" in BACKEND_REGISTRY


def test_create_backend():
    """Test backend creation."""
    backend = create_backend("vllm", model_id="test-model", base_url="http://localhost:8000")
    assert backend.model_id == "test-model"
    assert backend.base_url == "http://localhost:8000"


def test_model_router_init():
    """Test model router initialization."""
    router = ModelRouter()
    assert len(router.list_models()) == 0


@pytest.mark.asyncio
async def test_model_router_add_remove():
    """Test adding and removing models from router."""
    router = ModelRouter()

    await router.add_model(ModelConfig(
        name="test-model",
        backend_type="openai_compatible",
        model_id="test",
        base_url="http://localhost:9999",
        task_types=["general", "code"],
    ))

    models = router.list_models()
    assert len(models) == 1
    assert models[0]["name"] == "test-model"

    await router.remove_model("test-model")
    assert len(router.list_models()) == 0


@pytest.mark.asyncio
async def test_memory_store():
    """Test memory store operations."""
    store = MemoryStore(db_path=":memory:")
    await store.initialize()

    # Store and retrieve context
    await store.store_context("task-1", {"role": "recon", "target": "192.168.1.1"})
    ctx = await store.get_context("task-1")
    assert ctx["role"] == "recon"

    # Store finding
    vuln = Vulnerability(
        title="Open SSH",
        severity=Severity.LOW,
        description="SSH port is open",
        confidence=1.0,
    )
    await store.store_finding("task-1", vuln)

    findings = await store.get_findings(task_id="task-1")
    assert len(findings) == 1
    assert findings[0]["title"] == "Open SSH"

    # Store knowledge
    await store.store_knowledge("ssh-default-port", "22", category="network")
    results = await store.search_knowledge("ssh")
    assert len(results) > 0

    # Stats
    stats = await store.get_stats()
    assert stats["findings_count"] == 1

    await store.close()


@pytest.mark.asyncio
async def test_memory_store_scan_history():
    """Test scan history tracking."""
    store = MemoryStore(db_path=":memory:")
    await store.initialize()

    scan_id = await store.store_scan("192.168.1.1", "recon", {"ports": "1-1000"})
    assert scan_id > 0

    await store.complete_scan(scan_id, findings_count=5, result={"summary": "found 5 issues"})

    await store.close()


def test_config_yaml(tmp_path):
    """Test config save/load to YAML."""
    cfg = RecurSecConfig(
        models=[
            LLMModelConfig(
                name="test-model",
                backend="vllm",
                model_id="test",
                base_url="http://localhost:8000",
                task_types=["code"],
            )
        ],
    )

    yaml_path = tmp_path / "test-config.yaml"
    cfg.to_yaml(yaml_path)

    loaded = RecurSecConfig.from_yaml(yaml_path)
    assert len(loaded.models) == 1
    assert loaded.models[0].name == "test-model"
    assert loaded.models[0].backend == "vllm"
