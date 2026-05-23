"""Safety guardrail layer — uses Llama-Guard-3 to filter unsafe content.

Intercepts both prompts and responses to ensure:
- No generation of actual malware
- No targeting of unauthorized systems
- No credential exfiltration outside of engagement scope
- Authorization verification before exploit execution
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

# Llama Guard category definitions
UNSAFE_CATEGORIES = """
S1: Violent Crimes
S2: Non-Violent Crimes
S3: Sex-Related Crimes
S4: Child Sexual Exploitation
S5: Defamation
S6: Specialized Advice (ALLOWED for authorized pentesting)
S7: Privacy
S8: Intellectual Property
S9: Indiscriminate Weapons
S10: Hate
S11: Suicide & Self-Harm
S12: Sexual Content
S13: Elections
"""

# Categories that are acceptable in authorized pentesting context
PENTEST_ALLOWED = {"S6"}


class SafetyGuard:
    """Llama-Guard-3 based safety filter for agent outputs.

    Runs as a lightweight classifier (955MB model) to check
    if prompts or responses contain harmful content outside
    the scope of authorized security testing.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8114",
        model_id: str = "llama-guard-3-1b",
        enabled: bool = True,
        authorization_scope: str = "",
    ):
        self.base_url = base_url.rstrip("/")
        self.model_id = model_id
        self.enabled = enabled
        self.authorization_scope = authorization_scope
        self._client: httpx.AsyncClient | None = None
        self._checks_total = 0
        self._checks_blocked = 0

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=httpx.Timeout(30.0, connect=5.0),
            )
        return self._client

    async def check_prompt(self, prompt: str) -> tuple[bool, str]:
        """Check if a prompt is safe. Returns (is_safe, reason)."""
        if not self.enabled:
            return True, ""
        return await self._classify(prompt, role="user")

    async def check_response(self, response: str) -> tuple[bool, str]:
        """Check if a response is safe. Returns (is_safe, reason)."""
        if not self.enabled:
            return True, ""
        return await self._classify(response, role="assistant")

    async def check_tool_command(self, tool_name: str, command: str, target: str = "") -> tuple[bool, str]:
        """Check if a tool command is within scope.

        This is the critical gate before executing any exploit tool.
        """
        if not self.enabled:
            return True, ""

        # Build context for the guard
        context = f"""Security tool execution request:
Tool: {tool_name}
Command: {command}
Target: {target}
Authorization scope: {self.authorization_scope or 'Not specified'}

Is this within the scope of authorized security testing?"""

        return await self._classify(context, role="user")

    async def _classify(self, text: str, role: str = "user") -> tuple[bool, str]:
        """Run Llama Guard classification."""
        self._checks_total += 1

        try:
            client = await self._get_client()
            resp = await client.post("/v1/chat/completions", json={
                "model": self.model_id,
                "messages": [{"role": role, "content": text}],
                "max_tokens": 100,
                "temperature": 0.0,
            })

            if resp.status_code != 200:
                # If safety model is down, default to allowing (fail-open for usability)
                logger.warning("safety_guard_unavailable", status=resp.status_code)
                return True, ""

            data = resp.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()

            # Llama Guard outputs "safe" or "unsafe\nSX" where SX is category
            if content.lower().startswith("safe"):
                return True, ""

            # Parse unsafe category
            parts = content.split("\n")
            categories = [p.strip() for p in parts[1:] if p.strip().startswith("S")]

            # Check if the flagged categories are allowed for pentesting
            flagged = set(categories)
            actually_unsafe = flagged - PENTEST_ALLOWED

            if not actually_unsafe:
                return True, ""

            self._checks_blocked += 1
            reason = f"Blocked by safety guard: {', '.join(actually_unsafe)}"
            logger.warning("safety_blocked", categories=list(actually_unsafe), text=text[:200])
            return False, reason

        except Exception as e:
            # Fail-open: if the guard model is not available, allow the operation
            logger.warning("safety_guard_error", error=str(e))
            return True, ""

    async def health_check(self) -> bool:
        try:
            client = await self._get_client()
            resp = await client.get("/health", timeout=5.0)
            return resp.status_code == 200
        except Exception:
            return False

    def stats(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "total_checks": self._checks_total,
            "blocked": self._checks_blocked,
            "block_rate": self._checks_blocked / max(self._checks_total, 1),
        }

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
