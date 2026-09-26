"""
Reusable wrapper around LLM chat APIs (Ollama and Sarvam AI) with MCP tool-calling
and robust human-in-the-loop user decision gating.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from mcp import ClientSession

from .llm_provider import (
    LLMProvider,
    LLMResponse,
    OllamaProvider,
    ToolCall,
    ToolLogger,
    UserDecisionGate,
)


def mcp_tools_to_ollama(tools) -> list[dict]:
    """Convert MCP tools into standard OpenAI/Ollama function calling schema."""
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": t.inputSchema or {"type": "object", "properties": {}},
            },
        }
        for t in tools
    ]


def extract_paths(text: str) -> set[str]:
    """Pull anything that looks like a pcap/pcapng file path out of tool output."""
    return set(re.findall(r"\S+\.pcapn?g", text))


def _sanitize_tool_args(args: dict) -> dict:
    if not isinstance(args, dict):
        return {}
    keys = set(args.keys())
    if keys.issubset({"args", "kwargs"}):
        inner = args.get("args")
        if isinstance(inner, dict):
            return inner
        if isinstance(inner, str) and inner.strip().startswith("{") and inner.strip().endswith("}"):
            try:
                parsed = json.loads(inner)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
        return {}
    return args


async def call_mcp_tool(
    session: ClientSession,
    name: str,
    args: dict,
    decision_gate: Optional[UserDecisionGate] = None,
) -> str:
    """Execute an MCP tool call with optional human-in-the-loop decision gating."""
    args = _sanitize_tool_args(args)
    if decision_gate is not None:
        approved, reason = decision_gate.request_approval(name, args)
        if not approved:
            return reason

    try:
        result = await session.call_tool(name, args)
        text = "\n".join(c.text for c in result.content if hasattr(c, "text")) or "(empty result)"
        if "not authorized yet on this machine" in text:
            # Seamlessly auto-authorize capture on this machine and retry immediately
            try:
                auth_res = await session.call_tool("authorize_capture", {})
                auth_text = "\n".join(c.text for c in auth_res.content if hasattr(c, "text"))
                if "Authorized" in auth_text:
                    retry_res = await session.call_tool(name, args)
                    return "\n".join(c.text for c in retry_res.content if hasattr(c, "text")) or "(empty result)"
            except Exception:
                pass
        return text
    except Exception as e:
        return f"ERROR: tool call failed: {e}"


@dataclass
class ToolAgent:
    """
    Drives a single bounded tool-calling conversation with an LLM provider
    (Ollama or Sarvam AI) against an MCP ClientSession, restricted to a subset
    of tools if `allowed_tools` is given, and gated by `decision_gate`.
    """
    session: ClientSession
    model: str
    system_prompt: str
    all_tools: list  # mcp Tool objects from session.list_tools()
    allowed_tools: Optional[set[str]] = None
    temperature: float = 0
    num_predict: int = 700
    keep_alive: str = "30m"
    max_tool_iterations: int = 8
    on_tool_call: Optional[ToolLogger] = None
    ollama_host: Optional[str] = None
    provider: Optional[LLMProvider] = None
    decision_gate: Optional[UserDecisionGate] = None

    known_paths: set[str] = field(default_factory=set)

    def __post_init__(self):
        tools = self.all_tools
        if self.allowed_tools is not None:
            tools = [t for t in tools if t.name in self.allowed_tools]
        self._tools_schema = mcp_tools_to_ollama(tools)

        if self.provider is None:
            self.provider = OllamaProvider(host=self.ollama_host)

    @property
    def tool_names(self) -> list[str]:
        return [t["function"]["name"] for t in self._tools_schema]

    async def run(self, user_message: str, extra_context: Optional[str] = None) -> str:
        """Run one bounded turn (with internal tool-call loop) and return the final text answer."""
        messages: list[dict] = [{"role": "system", "content": self.system_prompt}]
        if extra_context:
            messages.append({"role": "system", "content": extra_context})
        messages.append({"role": "user", "content": user_message})

        for iteration in range(self.max_tool_iterations):
            is_final_step = (iteration >= self.max_tool_iterations - 1)
            active_tools = None if is_final_step else self._tools_schema
            if is_final_step:
                messages.append({
                    "role": "user",
                    "content": "You have executed all necessary tools. Summarize all your tool findings clearly now without calling any more tools.",
                })

            try:
                response: LLMResponse = await self.provider.chat(
                    model=self.model,
                    messages=messages,
                    tools=active_tools,
                    temperature=self.temperature,
                    max_tokens=self.num_predict,
                    keep_alive=self.keep_alive,
                )
            except Exception as e:
                err_str = str(e).lower()
                if any(w in err_str for w in ("context", "token", "length", "too large", "prompt", "400")):
                    tool_findings = [m["content"] for m in messages if m.get("role") == "tool" and m.get("content")]
                    compact_findings = "\n\n".join(t[:1200] for t in tool_findings[-3:])
                    emergency_messages = [
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": user_message},
                        {"role": "assistant", "content": "I have executed the required network analysis tools."},
                        {"role": "user", "content": f"Based on the following extracted findings, provide your clear, concise final answer to the user:\n\n{compact_findings}"},
                    ]
                    try:
                        comp_resp = await self.provider.chat(
                            model=self.model,
                            messages=emergency_messages,
                            tools=None,
                            temperature=self.temperature,
                            max_tokens=self.num_predict,
                            keep_alive=self.keep_alive,
                        )
                        if comp_resp.content and comp_resp.content.strip():
                            return comp_resp.content
                    except Exception:
                        pass
                    if tool_findings:
                        return f"### Analysis Findings\n\n{compact_findings}"
                return f"ERROR: LLM request failed ({type(self.provider).__name__} / {self.model}): {e}"

            # Append assistant message with content and tool_calls
            tool_calls_raw = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.name, "arguments": tc.arguments},
                }
                for tc in response.tool_calls
            ]
            assistant_msg: dict = {"role": "assistant", "content": response.content}
            if tool_calls_raw:
                assistant_msg["tool_calls"] = tool_calls_raw
            messages.append(assistant_msg)

            if not response.tool_calls:
                return response.content or "(no response)"

            for call in response.tool_calls:
                name = call.name
                args = call.arguments
                if self.on_tool_call:
                    self.on_tool_call(name, args)

                result_text = await call_mcp_tool(
                    self.session, name, args, decision_gate=self.decision_gate
                )
                self.known_paths |= extract_paths(result_text)

                max_tool_chars = 3500
                if len(result_text) > max_tool_chars:
                    head = result_text[:2200]
                    tail = result_text[-1000:]
                    clipped_text = f"{head}\n\n... [output truncated {len(result_text) - 3200} characters to protect LLM context window] ...\n\n{tail}"
                else:
                    clipped_text = result_text

                messages.append({
                    "role": "tool",
                    "content": clipped_text,
                    "name": name,
                    "tool_call_id": call.id,
                })

        # Guaranteed synthesis fallback
        try:
            tool_texts = [m["content"] for m in messages if m.get("role") == "tool" and m.get("content")]
            compact_ctx = "\n\n".join(t[:1200] for t in tool_texts[-3:])
            fallback = await self.provider.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": user_message},
                    {"role": "user", "content": f"Summarize these findings into a clear, complete final answer for the user:\n\n{compact_ctx}"},
                ],
                tools=None,
                temperature=self.temperature,
                max_tokens=self.num_predict,
                keep_alive=self.keep_alive,
            )
            if fallback.content and fallback.content.strip():
                return fallback.content
        except Exception:
            pass

        tool_texts = [m["content"] for m in messages if m.get("role") == "tool" and m.get("content")]
        if tool_texts:
            return "\n\n".join(tool_texts[-3:])
        return "(Tools executed successfully)"


# Backward-compatible alias
OllamaToolAgent = ToolAgent
