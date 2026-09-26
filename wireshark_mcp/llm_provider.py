"""
LLM Provider abstraction supporting both local Ollama and Sarvam AI (API key-based cloud AI),
as well as a UserDecisionGate for robust human-in-the-loop decision making.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import httpx

ToolLogger = Callable[[str, dict], None]
DecisionCallback = Callable[[str, dict], bool]


@dataclass
class ToolCall:
    """Represents a tool call requested by an LLM model."""
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    """Standardized response from any LLM provider."""
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


@dataclass
class UserDecisionGate:
    """
    Enforces human-in-the-loop decision making for sensitive, destructive,
    or high-impact actions (e.g., file deletion, stopping all captures, long continuous captures).
    """
    require_confirmation: bool = True
    sensitive_tools: set[str] = field(default_factory=lambda: {
        "delete_capture",
        "cleanup_old_captures",
        "stop_all_captures",
        "start_ring_capture",
    })
    confirm_callback: Optional[Callable[[str, dict], bool]] = None
    always_allowed: set[str] = field(default_factory=set)

    def should_confirm(self, tool_name: str) -> bool:
        if not self.require_confirmation:
            return False
        if tool_name in self.always_allowed:
            return False
        return tool_name in self.sensitive_tools

    def request_approval(self, tool_name: str, args: dict) -> tuple[bool, str]:
        """
        Request user decision for executing a sensitive tool.
        Returns:
            (approved: bool, message: str)
        """
        if not self.should_confirm(tool_name):
            return True, "Auto-approved"

        if self.confirm_callback is None:
            # If no interactive callback is configured, allow if confirmation isn't strictly blocking
            return True, "No callback configured, proceeding."

        approved = self.confirm_callback(tool_name, args)
        if approved:
            return True, "User approved action."
        return False, (
            f"[USER_DECISION_DECLINED] Action cancelled by user decision. "
            f"The user chose NOT to execute '{tool_name}' with parameters {args}. "
            f"Please suggest an alternative approach or ask the user for further instructions."
        )


class LLMProvider(ABC):
    """Abstract base class for LLM backends (Ollama, Sarvam AI, etc.)."""

    @abstractmethod
    async def chat(
        self,
        model: str,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]] = None,
        temperature: float = 0.0,
        max_tokens: int = 700,
        keep_alive: str = "30m",
    ) -> LLMResponse:
        """Send a chat turn to the model and return an LLMResponse."""
        pass

    @abstractmethod
    def check_health(self, supervisor_model: str, agent_model: str) -> tuple[bool, str]:
        """Check provider connectivity and model availability."""
        pass


class OllamaProvider(LLMProvider):
    """Local Ollama LLM provider."""

    def __init__(self, host: Optional[str] = None):
        import ollama
        self.host = host
        self._client = ollama.Client(host=host) if host else ollama.Client()

    async def chat(
        self,
        model: str,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]] = None,
        temperature: float = 0.0,
        max_tokens: int = 700,
        keep_alive: str = "30m",
    ) -> LLMResponse:
        clean_messages = []
        for m in messages:
            msg_dict = {"role": m["role"], "content": m.get("content") or ""}
            if "tool_calls" in m and m["tool_calls"]:
                msg_dict["tool_calls"] = m["tool_calls"]
            clean_messages.append(msg_dict)

        options = {"temperature": temperature, "num_predict": max_tokens}
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": clean_messages,
            "options": options,
            "keep_alive": keep_alive,
        }
        if tools:
            kwargs["tools"] = tools

        try:
            # Run in thread pool to avoid blocking async event loop
            response = await asyncio.to_thread(self._client.chat, **kwargs)
        except Exception as e:
            raise RuntimeError(
                f"Could not reach Ollama model '{model}': {e}. "
                f"Is Ollama running (`ollama serve`) and is the model pulled (`ollama pull {model}`)?",
            ) from e

        msg = response.get("message", {})
        content = msg.get("content") or ""
        tool_calls: list[ToolCall] = []

        for idx, call in enumerate(msg.get("tool_calls") or []):
            fn = call.get("function", {})
            name = fn.get("name", "")
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            call_id = call.get("id") or f"call_{name}_{idx}_{int(time.time())}"
            tool_calls.append(ToolCall(id=call_id, name=name, arguments=args))

        return LLMResponse(content=content, tool_calls=tool_calls)

    def check_health(self, supervisor_model: str, agent_model: str) -> tuple[bool, str]:
        try:
            models = self._client.list()
            names = [m.get("model", m.get("name", "?")) for m in models.get("models", [])]
            sup_ok = any(supervisor_model in n for n in names)
            ag_ok = any(agent_model in n for n in names)
            details = f"{len(names)} model(s) pulled. Supervisor ({supervisor_model}): {'pulled' if sup_ok else 'not found'}, Agent ({agent_model}): {'pulled' if ag_ok else 'not found'}"
            return True, details
        except Exception as e:
            return False, f"Ollama not reachable: {e}. Try: ollama serve"


class SarvamProvider(LLMProvider):
    """
    Sarvam AI provider integrating Sarvam's API key-based cloud models
    (such as sarvam-105b, sarvam-105b-conversations, sarvam-2b)
    via their OpenAI-compatible chat completions interface.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://api.sarvam.ai/v1",
        timeout: float = 60.0,
    ):
        self.api_key = (
            api_key
            or os.environ.get("SARVAM_API_KEY")
            or os.environ.get("WSMCP_SARVAM_API_KEY")
        )
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _ensure_api_key(self) -> str:
        if not self.api_key or not self.api_key.strip():
            raise ValueError(
                "Sarvam AI API key is missing. Please set the SARVAM_API_KEY environment variable "
                "(e.g., set SARVAM_API_KEY=your_key), pass --sarvam-api-key, or configure 'sarvam.api_key' "
                "in config.yaml. Get a key at https://dashboard.sarvam.ai"
            )
        return self.api_key.strip()

    def _format_messages_for_api(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        formatted = []
        for m in messages:
            role = m["role"]
            item: dict[str, Any] = {"role": role}

            if role == "tool":
                item["content"] = str(m.get("content", ""))
                # OpenAI standard requires tool_call_id
                item["tool_call_id"] = m.get("tool_call_id") or f"call_{m.get('name', 'tool')}"
                if "name" in m:
                    item["name"] = m["name"]
            elif role == "assistant":
                content = m.get("content")
                item["content"] = content if content is not None else ""
                if "tool_calls" in m and m["tool_calls"]:
                    # Preserve exact tool_calls array format
                    formatted_tool_calls = []
                    for tc in m["tool_calls"]:
                        if isinstance(tc, ToolCall):
                            formatted_tool_calls.append({
                                "id": tc.id,
                                "type": "function",
                                "function": {
                                    "name": tc.name,
                                    "arguments": json.dumps(tc.arguments) if isinstance(tc.arguments, dict) else str(tc.arguments),
                                },
                            })
                        elif isinstance(tc, dict):
                            fn = tc.get("function", {})
                            args = fn.get("arguments", {})
                            formatted_tool_calls.append({
                                "id": tc.get("id", f"call_{fn.get('name', 'tool')}"),
                                "type": "function",
                                "function": {
                                    "name": fn.get("name", ""),
                                    "arguments": json.dumps(args) if isinstance(args, dict) else str(args),
                                },
                            })
                    item["tool_calls"] = formatted_tool_calls
            else:
                item["content"] = str(m.get("content", ""))

            formatted.append(item)
        return formatted

    async def chat(
        self,
        model: str,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]] = None,
        temperature: float = 0.1,
        max_tokens: int = 1000,
        keep_alive: str = "30m",
    ) -> LLMResponse:
        api_key = self._ensure_api_key()
        endpoint = f"{self.base_url}/chat/completions"

        headers = {
            "Content-Type": "application/json",
            "api-subscription-key": api_key,
            "Authorization": f"Bearer {api_key}",
        }

        payload: dict[str, Any] = {
            "model": model,
            "messages": self._format_messages_for_api(messages),
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        # Retry up to 2 times for transient network/rate issues
        last_error = None
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(endpoint, headers=headers, json=payload)

                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if not choices:
                        return LLMResponse(content="(no response choices returned by Sarvam AI)")

                    message = choices[0].get("message", {})
                    content = message.get("content") or ""
                    tool_calls_raw = message.get("tool_calls") or []
                    tool_calls: list[ToolCall] = []

                    for idx, call in enumerate(tool_calls_raw):
                        call_id = call.get("id") or f"call_{idx}_{int(time.time())}"
                        fn = call.get("function", {})
                        name = fn.get("name", "")
                        args = fn.get("arguments", {})
                        if isinstance(args, str):
                            try:
                                args = json.loads(args)
                            except json.JSONDecodeError:
                                args = {"raw_arguments": args}
                        tool_calls.append(ToolCall(id=call_id, name=name, arguments=args))

                    return LLMResponse(content=content, tool_calls=tool_calls)

                # Handle specific HTTP error status codes
                if resp.status_code in (401, 403):
                    try:
                        err_body = resp.json()
                        err_msg = err_body.get("error", {}).get("message", resp.text)
                    except Exception:
                        err_msg = resp.text
                    raise PermissionError(
                        f"Sarvam AI authentication failed (HTTP {resp.status_code}): {err_msg}. "
                        f"Please verify your SARVAM_API_KEY at https://dashboard.sarvam.ai"
                    )

                if resp.status_code == 429:
                    # Rate limit - wait and retry if attempts remain
                    if attempt < 2:
                        await asyncio.sleep(2.0 * (attempt + 1))
                        continue
                    raise RuntimeError(
                        "Sarvam AI rate limit exceeded (HTTP 429). Please wait before making more requests or upgrade quota."
                    )

                # Other HTTP errors
                raise RuntimeError(
                    f"Sarvam AI API error (HTTP {resp.status_code}): {resp.text}"
                )

            except (httpx.ConnectError, httpx.TimeoutException) as e:
                last_error = e
                if attempt < 2:
                    await asyncio.sleep(1.5 * (attempt + 1))
                    continue
                raise RuntimeError(
                    f"Could not connect to Sarvam AI API at {endpoint}: {e}. Check network connection or Sarvam service status."
                ) from e
            except Exception as e:
                raise

        raise RuntimeError(f"Sarvam AI request failed after retries: {last_error}")

    def check_health(self, supervisor_model: str, agent_model: str) -> tuple[bool, str]:
        if not self.api_key or not self.api_key.strip():
            return False, "API key not configured (set SARVAM_API_KEY environment variable or config.yaml)"

        # Lightweight synchronous check against Sarvam endpoint
        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "api-subscription-key": self.api_key.strip(),
            "Authorization": f"Bearer {self.api_key.strip()}",
        }
        # Minimal verification payload
        payload = {
            "model": supervisor_model or "sarvam-105b",
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 5,
        }
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.post(endpoint, headers=headers, json=payload)
            if resp.status_code == 200:
                masked_key = self.api_key[:4] + "..." + self.api_key[-4:] if len(self.api_key) > 8 else "***"
                return True, f"OK — endpoint reachable, key valid ({masked_key})"
            elif resp.status_code in (401, 403):
                return False, f"Authentication error (HTTP {resp.status_code}): invalid or unauthorized key"
            else:
                return False, f"Endpoint responded with HTTP {resp.status_code}: {resp.text[:120]}"
        except Exception as e:
            return False, f"Connection failed: {e}"


def get_llm_provider(
    provider_name: str,
    cfg_ollama: dict[str, Any],
    cfg_sarvam: dict[str, Any],
    sarvam_api_key_override: Optional[str] = None,
) -> LLMProvider:
    """Factory to instantiate the appropriate LLM provider based on configuration."""
    name = (provider_name or "ollama").strip().lower()
    if name in ("sarvam", "sarvamai", "sarvam-ai"):
        api_key = sarvam_api_key_override or cfg_sarvam.get("api_key")
        base_url = cfg_sarvam.get("base_url") or "https://api.sarvam.ai/v1"
        return SarvamProvider(api_key=api_key, base_url=base_url)
    else:
        host = cfg_ollama.get("host")
        return OllamaProvider(host=host)
