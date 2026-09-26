"""
Multi-agent orchestration: a Supervisor model treats each specialist agent
(Capture, Traffic Analyst, Threat Hunter, Report) as a callable "tool".
Supports both local Ollama and Sarvam AI models with human-in-the-loop
user decision gating.

Shared state (known capture file paths) is threaded through every specialist
call so agents don't have to rediscover each other's outputs.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import Callable, Optional

from mcp import ClientSession

from .agents import (
    ALL_AGENTS,
    CAPTURE_AGENT,
    REPORT_AGENT,
    SINGLE_AGENT_SYSTEM_PROMPT,
    THREAT_HUNTER_AGENT,
    TRAFFIC_ANALYST_AGENT,
    AgentSpec,
)
from .jev import JevModule, SubagentLedger
from .memory import MemoryStore, SessionManager
from .llm_provider import (
    LLMProvider,
    LLMResponse,
    OllamaProvider,
    ToolCall,
    ToolLogger,
    UserDecisionGate,
)
from .ollama_client import ToolAgent, call_mcp_tool, extract_paths

SUPERVISOR_SYSTEM_PROMPT = (
    "You are the Supervisor of a small team of network-analysis specialist agents. You do not "
    "call Wireshark tools yourself — you delegate to the right specialist by calling its function:\n"
    "{agent_list}\n\n"
    "RULES:\n"
    "1. Read the user's request and decide which specialist(s) can answer it. You may call more "
    "than one in sequence (e.g. capture_agent to get a file, then traffic_analyst to read it, then "
    "threat_hunter to check it, then report_agent to save a writeup) — pass along file paths and "
    "capture IDs a specialist gives you when calling the next one.\n"
    "2. Give each specialist a clear, self-contained instruction in the 'request' argument, "
    "including any file path or capture_id it needs.\n"
    "3. Never answer a question about interfaces, packets, captures, or traffic yourself without "
    "first delegating — you have no direct access to the network or any files.\n"
    "4. Only use file paths / capture IDs that a specialist actually returned to you. Never invent one.\n"
    "5. If a specialist's reply contains 'ERROR', relay that plainly instead of making up a result.\n"
    "6. Once you have enough information, give the user a clear, concise final answer synthesizing "
    "what the specialists found. Don't call a specialist you don't need.\n"
    "7. Only delegate captures on networks/interfaces the user is authorized to monitor.\n"
    "8. USER DECISIONS & SAFETY: When a user request is ambiguous (e.g. which interface to capture on "
    "when multiple interfaces exist, or which saved pcap file to analyze), do NOT guess. Have the "
    "specialist list the available choices and ask the user to decide. Never instruct an agent to perform "
    "destructive operations (such as delete_capture or stop_all_captures) unless the user explicitly requested "
    "it. In your final synthesis, always provide clear, numbered, actionable decision options for the user's "
    "next steps (e.g. mitigation, stream inspection, export).\n"
    "9. FULL AGENT AUTONOMY & END-TO-END WORKFLOWS:\n"
    "   - 'setup an agent to monitor' or 'monitor all interfaces live' or 'start continuous monitoring': "
    "     take autonomous action immediately! Delegate to capture_agent to call 'start_continuous_monitor' "
    "     (with interface='all' or the specified interface). This spawns an autonomous detached 24/7 background "
    "     subagent with port scan, cleartext cred, ARP spoof, traffic burst, DNS anomaly, and VirusTotal detection! "
    "     Do NOT run 14 individual start_capture jobs!\n"
    "   - 'list all active agents' or 'list subagents': Delegate to capture_agent to call 'list_continuous_monitors'.\n"
    "   - 'monitor <interface>' or 'capture on <interface>': Delegate to capture_agent to capture traffic "
    "     (e.g. capture_live for 15s or start_capture) with standard defaults rather than asking repeated questions.\n"
    "   - 'generate a finding report on <interface>': execute the complete multi-agent workflow autonomously end-to-end:\n"
    "     1. Delegate to capture_agent to capture packets on the interface (15s live capture).\n"
    "     2. Delegate to traffic_analyst to inspect the captured pcap file (protocol hierarchy, conversations, HTTP/DNS/TLS).\n"
    "     3. Delegate to threat_hunter to check for cleartext credentials, scans, or beaconing.\n"
    "     4. Delegate to report_agent to synthesize all findings and save the markdown report to disk.\n"
    "     5. Present the final executive summary with the saved report path and options to open in desktop Wireshark (/wireshark).\n"
    "   Never stall with passive questions or return empty responses when the user gives you a concrete task. Take autonomous initiative through your team!\n"
    "10. JEV DYNAMIC SUBAGENTS: You can call 'spawn_subagent(name, role, task)' to dynamically spin up specialized subagents "
    "    (e.g. for deep DNS forensics, credential tracing, or stream reconstruction). All subagent actions and tool executions "
    "    are automatically audited in the persistent ledger.\n"
    "11. FORENSIC ASSET EXTRACTION & LATENCY INSPECTION: When the user asks to find PDFs, images, documents, "
    "    unique IPs, protocol breakdowns, or calculate time delays / latency / round-trip time (RTT) between "
    "    sent requests and responses in a pcap file:\n"
    "    - Delegate to traffic_analyst to call 'extract_files' (for PDFs, images, documents), 'ip_inventory' (for complete IP breakdown), and 'rtt_latency_stats' (for request-response time delays and TCP RTT).\n"
    "    - Always format your decision options cleanly under a '### Next Steps' heading with clear numbered items (e.g. '1. Open in Wireshark', '2. Follow TCP stream', '3. Export filtered pcap').\n"
    "12. TARGETED EFFICIENCY & PROMPT SYNTHESIS:\n"
    "    - Focus strictly on the specific capture ID, interface, or target requested by the user. If the user asks about "
    "      a specific capture (e.g. 'Check status of c11_35441 and give me full report'), analyze THAT capture only. "
    "      Do NOT wander off into sweeping other unrelated capture files unless explicitly told to do so.\n"
    "    - Once you have gathered sufficient information (typically after 2 to 3 specialist delegations: traffic_analyst "
    "      and threat_hunter), STOP DELEGATING immediately and deliver your final comprehensive executive summary report!\n"
    "13. IP INVESTIGATION, HOST AUDITING & NMAP / PORT SCANNING:\n"
    "    When the user asks to 'find all data on IP <ip>', 'scan IP <ip>', 'run nmap on <ip>', 'investigate host <target>', or similar:\n"
    "    - Take IMMEDIATE autonomous action! Do NOT give an empty response, claim no data exists, or show a passive menu!\n"
    "    - Delegate to threat_hunter with a clear directive to:\n"
    "      1. Query VirusTotal threat intelligence for the IP ('check_ip_virustotal(ip)').\n"
    "      2. Run a port scan / service audit ('port_scan_host(target=ip, ports=\"common\", background=False)' or 'run_nmap_scan(target=ip)'). If the user requested background, set background=True and return the scan ID.\n"
    "      3. Check active host network connections ('powershell_network_connections') to verify if local machine has active connections to this IP.\n"
    "    - If any open ports or risks are found, JEV Decision Engine will automatically score the threat (0-10) and evaluate defensive posture.\n"
    "    - Synthesize all findings into a structured Target Intelligence Dossier with VirusTotal reputation, open ports, JEV risk score, and prioritized defensive next steps.\n"
    "14. OPENING CAPTURES IN WIRESHARK GUI & LIVE REAL-TIME FILTERING:\n"
    "    When the user asks to 'open in wireshark', 'show the analysis live', 'open <file>', or view packets visually:\n"
    "    - Delegate to traffic_analyst to call 'open_in_wireshark(path=<file_path>, display_filter=<filter>)'.\n"
    "    - If the user specified a file path (e.g. 'C:\\Users\\...\\data\\http (1).pcap' or 'http (1).pcap'), pass THAT EXACT PATH!\n"
    "      Do NOT call list_captures first when a file path is already given!\n"
    "    - If the user specified a filter (e.g. http, tcp.port==80, or ip.addr==...), pass it as display_filter so Wireshark GUI opens with live filtering applied.\n"
    "    - Also have traffic_analyst run 'protocol_stats' or 'read_pcap_summary' to provide an executive summary alongside the GUI.\n"
    "15. HTTP REQUEST-RESPONSE LATENCY & ELAPSED TIME DELAYS:\n"
    "    When the user asks about time elapsed from an HTTP request (like HTTP GET) to the reply (HTTP 200 OK / 304), or application round-trip delay:\n"
    "    - Delegate to traffic_analyst to call 'http_rtt_delays(path=<path>)' or 'rtt_latency_stats(path=<path>)'.\n"
    "    - State the exact request frame #, response frame #, HTTP status code, and elapsed time in milliseconds (e.g. 774.77 ms) directly.\n"
)


def agent_spec_to_ollama_tool(spec: AgentSpec) -> dict:
    """Format an agent spec as a callable function tool for the supervisor."""
    return {
        "type": "function",
        "function": {
            "name": f"ask_{spec.key}",
            "description": spec.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "request": {
                        "type": "string",
                        "description": "A clear, self-contained instruction for this specialist, "
                                       "including any file path / capture_id / interface it needs.",
                    }
                },
                "required": ["request"],
            },
        },
    }


def spawn_subagent_tool() -> dict:
    """JEV Dynamic Subagent tool specification for the supervisor."""
    return {
        "type": "function",
        "function": {
            "name": "spawn_subagent",
            "description": (
                "JEV Dynamic Subagent Spawner: dynamically creates, delegates, and executes a dedicated "
                "subagent for an in-depth investigation task (e.g. 'DNS Forensic Subagent', 'TCP Stream Investigator'). "
                "All subagent actions, tool calls, and results are permanently recorded in the ledger."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Descriptive name for the subagent (e.g. 'DNS Investigator')"},
                    "role": {
                        "type": "string",
                        "enum": ["traffic_analyst", "threat_hunter", "capture_agent", "forensic_investigator"],
                        "description": "Role determining available tool preset",
                    },
                    "task": {"type": "string", "description": "Detailed specific task and target pcap file path"},
                },
                "required": ["name", "role", "task"],
            },
        },
    }


@dataclass
class Orchestrator:
    session: ClientSession
    all_tools: list
    supervisor_model: str
    agent_model: str
    temperature: float = 0
    num_predict: int = 700
    keep_alive: str = "30m"
    max_tool_iterations: int = 15
    ollama_host: Optional[str] = None
    provider: Optional[LLMProvider] = None
    decision_gate: Optional[UserDecisionGate] = None
    ledger_dir: Optional[str] = None
    memory_dir: Optional[str] = None
    sessions_dir: Optional[str] = None
    on_delegate: Optional[Callable[[str, str], None]] = None  # (agent_key, request) -> None
    on_tool_call: Optional[ToolLogger] = None

    known_paths: set[str] = field(default_factory=set)
    ledger: SubagentLedger = field(init=False)
    jev: JevModule = field(init=False)
    memory: MemoryStore = field(init=False)
    session_mgr: SessionManager = field(init=False)
    _agents: dict[str, ToolAgent] = field(default_factory=dict, init=False)
    _history: list[dict] = field(default_factory=list, init=False)

    def __post_init__(self):
        if self.provider is None:
            self.provider = OllamaProvider(host=self.ollama_host)

        default_base_dir = os.path.join(tempfile.gettempdir(), "wireshark_mcp_captures")
        default_ledger_dir = self.ledger_dir or os.path.join(default_base_dir, "subagents")
        self.ledger = SubagentLedger(log_dir=default_ledger_dir)
        self.jev = JevModule(provider=self.provider, ledger=self.ledger, model=self.agent_model)
        self.memory = MemoryStore(self.memory_dir or os.path.join(default_base_dir, "memory"))
        self.session_mgr = SessionManager(self.sessions_dir or os.path.join(default_base_dir, "sessions"))

        for spec in ALL_AGENTS:
            self._agents[spec.key] = ToolAgent(
                session=self.session,
                model=self.agent_model,
                system_prompt=spec.system_prompt,
                all_tools=self.all_tools,
                allowed_tools=set(spec.tools),
                temperature=self.temperature,
                num_predict=self.num_predict,
                keep_alive=self.keep_alive,
                max_tool_iterations=self.max_tool_iterations,
                on_tool_call=self.on_tool_call,
                ollama_host=self.ollama_host,
                provider=self.provider,
                decision_gate=self.decision_gate,
            )
        agent_list = "\n".join(f"- ask_{s.key}: {s.description}" for s in ALL_AGENTS)
        self._system_prompt = SUPERVISOR_SYSTEM_PROMPT.format(agent_list=agent_list)
        self._supervisor_tools = [agent_spec_to_ollama_tool(s) for s in ALL_AGENTS] + [spawn_subagent_tool()]
        self._history.append({"role": "system", "content": self._system_prompt})
        mem_summary = self.memory.get_context_summary()
        if mem_summary:
            self._history.append({"role": "system", "content": mem_summary})

    async def _spawn_subagent(self, name: str, role: str, task: str) -> str:
        role_map = {
            "traffic_analyst": (set(TRAFFIC_ANALYST_AGENT.tools), TRAFFIC_ANALYST_AGENT.system_prompt),
            "threat_hunter": (set(THREAT_HUNTER_AGENT.tools), THREAT_HUNTER_AGENT.system_prompt),
            "capture_agent": (set(CAPTURE_AGENT.tools), CAPTURE_AGENT.system_prompt),
            "forensic_investigator": (
                set(TRAFFIC_ANALYST_AGENT.tools) | set(THREAT_HUNTER_AGENT.tools),
                "You are an elite Forensic Investigator subagent. Conduct thorough packet and anomaly inspection.",
            ),
        }
        tools_set, prompt = role_map.get(role, role_map["traffic_analyst"])
        if self.on_delegate:
            self.on_delegate(f"subagent:{name}", task)
        result = await self.jev.spawn_and_execute_subagent(
            name=name,
            role=role,
            task=task,
            tools=self.all_tools,
            session=self.session,
            allowed_tools=tools_set,
            system_prompt=prompt,
            parent="supervisor",
            decision_gate=self.decision_gate,
            on_action=self.on_tool_call,
        )
        self.known_paths |= extract_paths(result)
        return result

    async def _delegate(self, agent_key: str, request: str) -> str:
        spec_key = agent_key[len("ask_"):] if agent_key.startswith("ask_") else agent_key
        agent = self._agents.get(spec_key)
        if agent is None:
            return f"ERROR: no such specialist '{agent_key}'."
        if self.on_delegate:
            self.on_delegate(spec_key, request)
        context = None
        if self.known_paths:
            context = "Known capture file paths so far (reuse these, don't invent others): " + ", ".join(sorted(self.known_paths))
        result = await agent.run(request, extra_context=context)
        self.known_paths |= agent.known_paths | extract_paths(result)
        return result

    async def chat_turn(self, user_message: str) -> str:
        """Run one full user turn (possibly several agent delegations) and return the final answer."""
        self._history.append({"role": "user", "content": user_message})
        if self.known_paths:
            self._history.append({
                "role": "system",
                "content": "Known capture file paths so far: " + ", ".join(sorted(self.known_paths)),
            })

        for iteration in range(self.max_tool_iterations):
            is_final_step = (iteration >= self.max_tool_iterations - 1)
            active_tools = None if is_final_step else self._supervisor_tools
            if is_final_step:
                self._history.append({
                    "role": "user",
                    "content": (
                        "You have gathered all necessary specialist findings. Do not call any more tools. "
                        "Now synthesize all findings into a complete, professional, executive final report for the user."
                    ),
                })

            try:
                response: LLMResponse = await self.provider.chat(
                    model=self.supervisor_model,
                    messages=self._history,
                    tools=active_tools,
                    temperature=self.temperature,
                    max_tokens=self.num_predict,
                    keep_alive=self.keep_alive,
                )
            except Exception as e:
                err_str = str(e).lower()
                if any(w in err_str for w in ("context", "token", "length", "too large", "prompt", "400")):
                    tool_findings = [m["content"] for m in self._history if m.get("role") == "tool" and m.get("content")]
                    compact_evidence = "\n\n".join(t[:1200] for t in tool_findings[-3:])
                    emergency_msgs = [
                        {"role": "system", "content": self._system_prompt},
                        {"role": "user", "content": user_message},
                        {"role": "user", "content": f"Based on the following specialist findings, provide your clear, executive final report to the user:\n\n{compact_evidence}"},
                    ]
                    try:
                        em_resp = await self.provider.chat(
                            model=self.supervisor_model,
                            messages=emergency_msgs,
                            tools=None,
                            temperature=self.temperature,
                            max_tokens=self.num_predict,
                            keep_alive=self.keep_alive,
                        )
                        if em_resp.content and em_resp.content.strip():
                            return em_resp.content
                    except Exception:
                        pass
                    if tool_findings:
                        return f"### Executive Summary\n\n{compact_evidence}"
                return f"ERROR: supervisor request failed ({type(self.provider).__name__} / {self.supervisor_model}): {e}"

            # Append assistant message
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
            self._history.append(assistant_msg)

            if not response.tool_calls:
                if response.content and response.content.strip():
                    self.session_mgr.save_session("latest_session", self._history, self.known_paths)
                    return response.content
                # Avoid (no response) by nudging the model to synthesize findings
                self._history.append({
                    "role": "user",
                    "content": "Please synthesize all findings gathered so far and provide your complete final answer to the user.",
                })
                continue

            for call in response.tool_calls:
                name = call.name
                args = call.arguments
                if name == "spawn_subagent":
                    sub_name = args.get("name", "Subagent") if isinstance(args, dict) else "Subagent"
                    sub_role = args.get("role", "traffic_analyst") if isinstance(args, dict) else "traffic_analyst"
                    sub_task = args.get("task", "") if isinstance(args, dict) else str(args)
                    result_text = await self._spawn_subagent(sub_name, sub_role, sub_task)
                else:
                    request = args.get("request", "") if isinstance(args, dict) else ""
                    result_text = await self._delegate(name, request)

                max_sup_chars = 3800
                if len(result_text) > max_sup_chars:
                    head = result_text[:2400]
                    tail = result_text[-1100:]
                    clipped_res = f"{head}\n\n... [output truncated {len(result_text) - 3500} characters to protect LLM context window] ...\n\n{tail}"
                else:
                    clipped_res = result_text

                self._history.append({
                    "role": "tool",
                    "content": clipped_res,
                    "name": name,
                    "tool_call_id": call.id,
                })

        # Guaranteed fallback: synthesize all evidence gathered without failing
        try:
            fallback_resp = await self.provider.chat(
                model=self.supervisor_model,
                messages=self._history + [{
                    "role": "user",
                    "content": "Synthesize all specialist findings and threat-hunting results above into a complete final report for the user.",
                }],
                tools=None,
                temperature=self.temperature,
                max_tokens=self.num_predict,
                keep_alive=self.keep_alive,
            )
            if fallback_resp.content and fallback_resp.content.strip():
                self.session_mgr.save_session("latest_session", self._history, self.known_paths)
                return fallback_resp.content
        except Exception:
            pass

        # Final safety net: return gathered findings
        tool_findings = [m["content"] for m in self._history if m.get("role") == "tool" and m.get("content")]
        if tool_findings:
            return "### Investigation Summary\n\n" + "\n\n---\n\n".join(tool_findings[-4:])
        return "Investigation completed. All requested data has been captured and analyzed."


@dataclass
class SingleAgent:
    """
    Legacy single-agent mode: one model, the full tool surface, no delegation.
    Keeps full conversation history across turns and respects UserDecisionGate.
    """
    session: ClientSession
    all_tools: list
    model: str
    temperature: float = 0
    num_predict: int = 700
    keep_alive: str = "30m"
    max_tool_iterations: int = 8
    ollama_host: Optional[str] = None
    provider: Optional[LLMProvider] = None
    decision_gate: Optional[UserDecisionGate] = None
    ledger_dir: Optional[str] = None
    memory_dir: Optional[str] = None
    sessions_dir: Optional[str] = None
    on_tool_call: Optional[ToolLogger] = None

    known_paths: set[str] = field(default_factory=set)
    ledger: SubagentLedger = field(init=False)
    jev: JevModule = field(init=False)
    memory: MemoryStore = field(init=False)
    session_mgr: SessionManager = field(init=False)
    _history: list[dict] = field(default_factory=list, init=False)

    def __post_init__(self):
        if self.provider is None:
            self.provider = OllamaProvider(host=self.ollama_host)
        default_base_dir = os.path.join(tempfile.gettempdir(), "wireshark_mcp_captures")
        default_ledger_dir = self.ledger_dir or os.path.join(default_base_dir, "subagents")
        self.ledger = SubagentLedger(log_dir=default_ledger_dir)
        self.jev = JevModule(provider=self.provider, ledger=self.ledger, model=self.model)
        self.memory = MemoryStore(self.memory_dir or os.path.join(default_base_dir, "memory"))
        self.session_mgr = SessionManager(self.sessions_dir or os.path.join(default_base_dir, "sessions"))

        from .ollama_client import mcp_tools_to_ollama
        self._tools_schema = mcp_tools_to_ollama(self.all_tools)
        self._history.append({"role": "system", "content": SINGLE_AGENT_SYSTEM_PROMPT})
        mem_summary = self.memory.get_context_summary()
        if mem_summary:
            self._history.append({"role": "system", "content": mem_summary})

    async def chat_turn(self, user_message: str) -> str:
        self._history.append({"role": "user", "content": user_message})
        if self.known_paths:
            self._history.append({
                "role": "system",
                "content": "Known capture file paths so far (use these, don't invent others): "
                           + ", ".join(sorted(self.known_paths)),
            })

        for iteration in range(self.max_tool_iterations):
            is_final_step = (iteration >= self.max_tool_iterations - 1)
            active_tools = None if is_final_step else self._tools_schema
            if is_final_step:
                self._history.append({
                    "role": "user",
                    "content": "You have gathered all necessary information. Do not call any more tools. Now synthesize all findings into a complete, professional final answer for the user.",
                })

            try:
                response: LLMResponse = await self.provider.chat(
                    model=self.model,
                    messages=self._history,
                    tools=active_tools,
                    temperature=self.temperature,
                    max_tokens=self.num_predict,
                    keep_alive=self.keep_alive,
                )
            except Exception as e:
                return f"ERROR: LLM request failed ({type(self.provider).__name__} / {self.model}): {e}"

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
            self._history.append(assistant_msg)

            if not response.tool_calls:
                if response.content and response.content.strip():
                    return response.content
                self._history.append({
                    "role": "user",
                    "content": "Please synthesize the findings and provide a clear final answer to the user.",
                })
                continue

            for call in response.tool_calls:
                name = call.name
                args = call.arguments
                if self.on_tool_call:
                    self.on_tool_call(name, args)

                result_text = await call_mcp_tool(
                    self.session, name, args, decision_gate=self.decision_gate
                )
                self.known_paths |= extract_paths(result_text)
                self._history.append({
                    "role": "tool",
                    "content": result_text,
                    "name": name,
                    "tool_call_id": call.id,
                })

        # Fallback synthesis
        try:
            fallback_resp = await self.provider.chat(
                model=self.model,
                messages=self._history + [{
                    "role": "user",
                    "content": "Synthesize all tool outputs above into a complete final answer for the user.",
                }],
                tools=None,
                temperature=self.temperature,
                max_tokens=self.num_predict,
                keep_alive=self.keep_alive,
            )
            if fallback_resp.content and fallback_resp.content.strip():
                return fallback_resp.content
        except Exception:
            pass

        tool_findings = [m["content"] for m in self._history if m.get("role") == "tool" and m.get("content")]
        if tool_findings:
            return "### Analysis Summary\n\n" + "\n\n---\n\n".join(tool_findings[-3:])
        return "Scan and analysis completed."
