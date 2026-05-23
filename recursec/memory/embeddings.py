"""RAG / Embedding system — uses nomic-embed-text (or any embedding model) for semantic memory.

This enables agents to:
- Store findings with semantic embeddings for later retrieval
- Search past findings by meaning, not just keywords
- Build a knowledge graph of vulnerability patterns
- Learn from previous scans
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


class EmbeddingClient:
    """Client for embedding model served by llama.cpp --embedding mode."""

    def __init__(self, base_url: str = "http://localhost:8115", model_id: str = "nomic-embed-text"):
        self.base_url = base_url.rstrip("/")
        self.model_id = model_id
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=httpx.Timeout(60.0, connect=10.0),
            )
        return self._client

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Get embeddings for a list of texts."""
        client = await self._get_client()
        try:
            resp = await client.post("/v1/embeddings", json={
                "model": self.model_id,
                "input": texts,
            })
            resp.raise_for_status()
            data = resp.json()
            return [item["embedding"] for item in sorted(data["data"], key=lambda x: x["index"])]
        except httpx.HTTPStatusError:
            # Fallback: try llama.cpp native /embedding endpoint
            try:
                resp = await client.post("/embedding", json={"content": texts[0] if len(texts) == 1 else texts})
                resp.raise_for_status()
                data = resp.json()
                if isinstance(data, list):
                    return [item.get("embedding", []) for item in data]
                return [data.get("embedding", [])]
            except Exception as e:
                logger.error("embedding_error", error=str(e))
                return [[] for _ in texts]
        except Exception as e:
            logger.error("embedding_error", error=str(e))
            return [[] for _ in texts]

    async def embed_one(self, text: str) -> list[float]:
        results = await self.embed([text])
        return results[0] if results else []

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def health_check(self) -> bool:
        try:
            client = await self._get_client()
            resp = await client.get("/health", timeout=5.0)
            return resp.status_code == 200
        except Exception:
            return False


class VectorMemory:
    """In-process vector memory using cosine similarity.

    Avoids external dependencies (no Chroma/Pinecone needed).
    Good for up to ~100K documents. Uses the embedding client.
    """

    def __init__(self, embedding_client: EmbeddingClient):
        self.embedder = embedding_client
        self._documents: list[dict[str, Any]] = []  # {id, text, embedding, metadata}

    async def add(self, doc_id: str, text: str, metadata: dict[str, Any] | None = None) -> None:
        embedding = await self.embedder.embed_one(text)
        if not embedding:
            logger.warning("empty_embedding", doc_id=doc_id)
            return
        self._documents.append({
            "id": doc_id,
            "text": text,
            "embedding": embedding,
            "metadata": metadata or {},
        })

    async def search(self, query: str, top_k: int = 5, min_score: float = 0.3) -> list[dict[str, Any]]:
        """Search by semantic similarity. Returns top_k results."""
        if not self._documents:
            return []

        query_embedding = await self.embedder.embed_one(query)
        if not query_embedding:
            return []

        scored = []
        for doc in self._documents:
            score = _cosine_similarity(query_embedding, doc["embedding"])
            if score >= min_score:
                scored.append({**doc, "score": score})

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:top_k]

    async def add_finding(self, finding: dict[str, Any]) -> None:
        """Add a vulnerability finding to vector memory."""
        text = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('evidence', '')}"
        await self.add(
            doc_id=finding.get("id", ""),
            text=text,
            metadata={"type": "finding", **finding},
        )

    async def add_tool_output(self, tool_name: str, command: str, output: str, task_id: str = "") -> None:
        """Add a tool output for future reference."""
        text = f"Tool: {tool_name}\nCommand: {command}\nOutput: {output[:2000]}"
        await self.add(
            doc_id=f"{task_id}:{tool_name}",
            text=text,
            metadata={"type": "tool_output", "tool": tool_name, "command": command},
        )

    async def search_similar_findings(self, description: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Search for similar past findings."""
        results = await self.search(description, top_k=top_k)
        return [r for r in results if r.get("metadata", {}).get("type") == "finding"]

    def count(self) -> int:
        return len(self._documents)


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)
