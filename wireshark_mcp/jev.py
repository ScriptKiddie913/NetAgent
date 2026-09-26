"""
JEV (System-1 Typed Decision & Dynamic Subagent) Module for Wireshark MCP Toolkit.

Provides:
1. Fast Typed Decision Primitives (Noul: Yes/No, Choice: Classification, Score: 1-10)
   operating 100% via existing Sarvam AI or fast local heuristics (NO separate Jev API key needed).
2. Dynamic Subagent Spawner: dynamically creates, delegates, and executes scoped subagents.
3. Subagent Ledger: maintains an audit trail and execution history of what every subagent is doing.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Optional

from mcp import ClientSession

from .llm_provider import LLMProvider, LLMResponse, SarvamProvider, ToolCall, UserDecisionGate
from .ollama_client import ToolAgent, call_mcp_tool


@dataclass
class JevNoul:
    """Yes/No probabilistic decision (e.g., 'Is packet capture required?')."""
    result: bool
    confidence: float
    reason: str


@dataclass
class JevChoice:
    """Discrete classification decision from a set of choices (e.g. routing)."""
    selected: str
    confidence: float
    reason: str


@dataclass
class JevScore:
    """Numerical evaluation (e.g., threat severity 0.0 - 10.0)."""
    score: float
    severity_label: str
    explanation: str


@dataclass
class SubagentAction:
    """Record of a single action taken by a subagent."""
    timestamp: float
    action_type: str  # "tool_call", "thought", "delegation"
    name: str
    arguments: dict[str, Any]
    result_snippet: str


@dataclass
class SubagentRecord:
    """Complete audit record of a spawned subagent's execution lifecycle."""
    subagent_id: str
    name: str
    role: str
    parent: str
    task: str
    status: str  # "active", "completed", "failed"
    started_at: float
    completed_at: Optional[float] = None
    actions: list[SubagentAction] = field(default_factory=list)
    output: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "subagent_id": self.subagent_id,
            "name": self.name,
            "role": self.role,
            "parent": self.parent,
            "task": self.task,
            "status": self.status,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.started_at)),
            "completed_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.completed_at)) if self.completed_at else None,
            "action_count": len(self.actions),
            "actions": [asdict(a) for a in self.actions],
            "output": self.output,
        }


class SubagentLedger:
    """
    Persistent audit ledger keeping track of all spawned subagents,
    what tools they executed, and their outcomes.
    """

    def __init__(self, log_dir: str):
        self.log_dir = log_dir
        self.records: dict[str, SubagentRecord] = {}
        self.ledger_file = os.path.join(log_dir, "subagents_ledger.json")
        os.makedirs(log_dir, exist_ok=True)
        self._load()

    def _load(self):
        if os.path.isfile(self.ledger_file):
            try:
                with open(self.ledger_file, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    for item in data:
                        rec = SubagentRecord(
                            subagent_id=item["subagent_id"],
                            name=item["name"],
                            role=item.get("role", "specialist"),
                            parent=item.get("parent", "supervisor"),
                            task=item["task"],
                            status=item.get("status", "completed"),
                            started_at=time.time(),
                            output=item.get("output"),
                        )
                        self.records[rec.subagent_id] = rec
            except Exception:
                pass

    def _persist(self):
        try:
            with open(self.ledger_file, "w", encoding="utf-8") as fh:
                json.dump([r.to_dict() for r in self.records.values()], fh, indent=2)
        except Exception:
            pass

    def start_subagent(self, name: str, role: str, task: str, parent: str = "supervisor") -> SubagentRecord:
        sub_id = f"sub_{uuid.uuid4().hex[:6]}"
        rec = SubagentRecord(
            subagent_id=sub_id,
            name=name,
            role=role,
            parent=parent,
            task=task,
            status="active",
            started_at=time.time(),
        )
        self.records[sub_id] = rec
        self._persist()
        return rec

    def record_action(self, sub_id: str, action_type: str, name: str, args: dict, result_snippet: str):
        rec = self.records.get(sub_id)
        if rec:
            rec.actions.append(SubagentAction(
                timestamp=time.time(),
                action_type=action_type,
                name=name,
                arguments=args,
                result_snippet=result_snippet[:300],
            ))
            self._persist()

    def complete_subagent(self, sub_id: str, output: str, status: str = "completed"):
        rec = self.records.get(sub_id)
        if rec:
            rec.status = status
            rec.completed_at = time.time()
            rec.output = output
            self._persist()

    def list_all(self) -> list[SubagentRecord]:
        return sorted(self.records.values(), key=lambda r: r.started_at, reverse=True)


class JevModule:
    """
    JEV engine providing fast typed decision-making (Noul, Choice, Score)
    and dynamic subagent lifecycle orchestration using Sarvam AI.
    No separate JEV API key needed — runs via Sarvam or fast heuristics.
    """

    def __init__(self, provider: Optional[LLMProvider] = None, ledger: Optional[SubagentLedger] = None, model: str = "sarvam-105b-conversations"):
        self.provider = provider
        self.ledger = ledger
        self.model = model

    def evaluate_scan(self, target: str, scan_data: dict[str, Any]) -> dict[str, Any]:
        """
        JEV Decision Engine for Host & Port Scans:
        Evaluates open ports, exposed services, and security posture.
        Computes typed JEV score, threat classification, and autonomous defensive decisions.
        """
        open_ports = scan_data.get("open_ports", [])
        risks = scan_data.get("risks", [])
        scanned_count = scan_data.get("scanned_ports", 0)

        # Baseline score calculation
        score = 0.5
        findings = []
        action_options = []

        has_cleartext = any(p in (21, 23) for p, _, _ in open_ports)
        has_remote_admin = any(p in (22, 3389, 445, 139) for p, _, _ in open_ports)
        has_database = any(p in (3306, 5432, 1433, 1521, 27017, 6379) for p, _, _ in open_ports)
        has_web = any(p in (80, 443, 8080, 8443) for p, _, _ in open_ports)

        if not open_ports:
            score = 1.0
            verdict = "HARDENED / FILTERED"
            reason = f"No open ports detected among {scanned_count} audited ports. Host appears stealthy or firewalled."
            action_options = [
                "1. If host should be reachable, verify routing or ICMP ping.",
                "2. Monitor for outbound traffic from this host using a continuous background monitor.",
            ]
        else:
            if has_cleartext:
                score += 4.0
                findings.append("CRITICAL: Unencrypted legacy protocol open (FTP/Telnet transmitting credentials in plaintext).")
                action_options.append("- Immediate remediation: Replace Telnet/FTP with SSH/SFTP or block external access.")
            if has_database:
                score += 3.0
                findings.append("HIGH: Database listening port directly reachable from network.")
                action_options.append("- Secure DB: Bind database listeners strictly to localhost/VPN and enable TLS authentication.")
            if has_remote_admin:
                score += 2.0
                findings.append("WARNING: Remote administration port open (SSH/RDP/SMB).")
                action_options.append("- Access Control: Restrict administrative ports via IP allowlisting or VPN.")
            if has_web:
                score += 0.5
                findings.append("INFO: Web service active (HTTP/HTTPS).")
                action_options.append("- Web Security: Verify SSL/TLS certificates and enforce HTTPS redirect.")

            score = min(10.0, score + 0.3 * len(open_ports))
            if score >= 7.0:
                verdict = "CRITICAL VULNERABILITY EXPOSURE"
            elif score >= 4.0:
                verdict = "MODERATE SECURITY RISK"
            else:
                verdict = "LOW RISK / STANDARD EXPOSURE"

            reason = f"{len(open_ports)} open port(s) detected. " + (" ".join(findings) if findings else "Standard services operational.")

        return {
            "target": target,
            "threat_score": round(score, 1),
            "verdict": verdict,
            "reason": reason,
            "findings": findings,
            "action_options": action_options,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    async def noul(self, question: str, context: str = "") -> JevNoul:
        """
        Fast binary boolean evaluation (Noul):
        Returns True/False with probability/confidence score.
        """
        prompt = (
            f"Context: {context}\n\n"
            f"Question: {question}\n\n"
            "Evaluate this as a strict JEV Noul (Yes/No). Respond ONLY with valid JSON in this exact schema:\n"
            '{"result": true, "confidence": 0.95, "reason": "brief reason"}'
        )
        try:
            resp = await self.provider.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are Jev, a fast typed decision model. Output strict JSON only."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
                max_tokens=150,
            )
            raw = resp.content.strip()
            # Extract JSON block
            m = re.search(r"\{.*\}", raw, re.DOTALL)
            if m:
                data = json.loads(m.group(0))
                return JevNoul(
                    result=bool(data.get("result", False)),
                    confidence=float(data.get("confidence", 0.8)),
                    reason=str(data.get("reason", "Evaluated by JEV")),
                )
        except Exception:
            pass

        # Fast heuristic fallback
        q_lower = question.lower()
        res = any(w in q_lower for w in ("yes", "true", "start", "capture", "threat", "danger", "active"))
        return JevNoul(result=res, confidence=0.7, reason="Heuristic fallback")

    async def choice(self, question: str, choices: list[str], context: str = "") -> JevChoice:
        """
        Fast classification decision (Choice):
        Selects best candidate from given list of options.
        """
        choices_str = ", ".join(f'"{c}"' for c in choices)
        prompt = (
            f"Context: {context}\n\n"
            f"Question: {question}\n"
            f"Available choices: [{choices_str}]\n\n"
            "Select exactly one choice. Respond ONLY with valid JSON:\n"
            '{"selected": "<chosen_choice>", "confidence": 0.9, "reason": "brief rationale"}'
        )
        try:
            resp = await self.provider.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are Jev, a fast typed routing model. Output strict JSON only."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
                max_tokens=150,
            )
            raw = resp.content.strip()
            m = re.search(r"\{.*\}", raw, re.DOTALL)
            if m:
                data = json.loads(m.group(0))
                sel = data.get("selected", choices[0])
                if sel in choices:
                    return JevChoice(
                        selected=sel,
                        confidence=float(data.get("confidence", 0.85)),
                        reason=str(data.get("reason", "Selected by JEV")),
                    )
        except Exception:
            pass

        return JevChoice(selected=choices[0] if choices else "", confidence=0.5, reason="Default choice")

    async def score(self, entity: str, metric: str, context: str = "") -> JevScore:
        """
        Fast numerical scoring (Score):
        Scores a metric from 0.0 to 10.0 (e.g. threat score, urgency).
        """
        prompt = (
            f"Context: {context}\n\n"
            f"Subject: {entity}\n"
            f"Metric to evaluate: {metric} (Scale: 0.0 to 10.0)\n\n"
            "Evaluate and respond ONLY with JSON:\n"
            '{"score": 7.5, "severity_label": "High", "explanation": "brief explanation"}'
        )
        try:
            resp = await self.provider.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are Jev, a fast numerical evaluation model. Output strict JSON only."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
                max_tokens=150,
            )
            raw = resp.content.strip()
            m = re.search(r"\{.*\}", raw, re.DOTALL)
            if m:
                data = json.loads(m.group(0))
                return JevScore(
                    score=float(data.get("score", 5.0)),
                    severity_label=str(data.get("severity_label", "Medium")),
                    explanation=str(data.get("explanation", "Scored by JEV")),
                )
        except Exception:
            pass

        return JevScore(score=5.0, severity_label="Medium", explanation="Standard baseline score")

    async def spawn_and_execute_subagent(
        self,
        name: str,
        role: str,
        task: str,
        tools: list,
        session: ClientSession,
        allowed_tools: set[str],
        system_prompt: str,
        parent: str = "supervisor",
        decision_gate: Optional[UserDecisionGate] = None,
        on_action: Optional[Callable[[str, dict], None]] = None,
    ) -> str:
        """
        Dynamically spawn an autonomous subagent for a scoped task,
        record its execution in the SubagentLedger, and return its output.
        """
        record = self.ledger.start_subagent(name=name, role=role, task=task, parent=parent)

        def logged_tool_call(tool_name: str, args: dict):
            if on_action:
                on_action(tool_name, args)
            self.ledger.record_action(
                sub_id=record.subagent_id,
                action_type="tool_call",
                name=tool_name,
                args=args,
                result_snippet="invoked",
            )

        subagent = ToolAgent(
            session=session,
            model=self.model,
            system_prompt=system_prompt,
            all_tools=tools,
            allowed_tools=allowed_tools,
            temperature=0.1,
            num_predict=700,
            keep_alive="30m",
            max_tool_iterations=8,
            provider=self.provider,
            decision_gate=decision_gate,
            on_tool_call=logged_tool_call,
        )

        try:
            output = await subagent.run(task)
            self.ledger.complete_subagent(record.subagent_id, output=output, status="completed")
            return output
        except Exception as e:
            err_msg = f"ERROR: Subagent '{name}' failed: {e}"
            self.ledger.complete_subagent(record.subagent_id, output=err_msg, status="failed")
            return err_msg
