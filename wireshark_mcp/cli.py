"""
CLI entrypoint: `wireshark-agent`.

Subcommands:
  chat        Interactive chat with Ollama or Sarvam AI models.
              Multi-agent supervisor mode by default (--single for legacy 1-model mode).
              Includes robust user decision gates and in-chat control commands.
  server      Run the MCP server itself on stdio (for use as a tool server, e.g. from Claude Desktop).
  authorize   One-time authorized-use acknowledgment required before any capture tool will run.
  doctor      Check that tshark, Ollama, Sarvam AI, and security/decision gates are operational.
  captures    List / show / clean up saved pcap files.
  config      Show the effective configuration.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
import sys
import time

# Ensure UTF-8 on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import questionary
except ImportError:
    questionary = None

import click
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from .config import Config, load_config
from .llm_provider import (
    OllamaProvider,
    SarvamProvider,
    UserDecisionGate,
    get_llm_provider,
)
from .orchestrator import Orchestrator, SingleAgent

console = Console(legacy_windows=False)


def extract_decision_options(raw_text: str) -> list[tuple[str, str]]:
    """
    Extract decision options specifically from 'Next Steps', 'Available Options', or 'Recommendations'
    sections so the user can navigate and select using arrow keys without false-positive options
    polluting the menu.
    """
    if not raw_text:
        return []

    # Target only explicit next steps / actions / recommendations blocks
    section_patterns = [
        r"(?:Next Steps Available|Next Steps|Next Actions|Available Options|Recommended Next Steps|Recommendations|Actionable Decision Options|What would you like to do next\??)(?:[^\n]*)\n([\s\S]+)$",
    ]
    target_text = ""
    for pat in section_patterns:
        m = re.search(pat, raw_text, re.IGNORECASE)
        if m:
            target_text = m.group(1)
            break

    if not target_text:
        return []

    options = []
    for line in target_text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Stop if we hit a footer, separator, or concluding question
        if any(line.lower().startswith(q) for q in ("what would you", "let me know", "type your", "please select", "---")):
            break
        # Match numbered items: "1 Open in Wireshark", "1. Open in Wireshark", "[1] Open in Wireshark"
        m = re.match(r"^(?:\[\d+\]|\d+[\.\)\s])\s*(.+)$", line)
        if m:
            raw_opt = m.group(1).strip()
            # Strip markdown bold, asterisks, backticks
            clean_opt = re.sub(r"^\*+|\*+$", "", raw_opt).strip()
            clean_opt = clean_opt.replace("**", "").replace("`", "").strip()
            if not clean_opt:
                continue

            # Extract short label and full description
            if " — " in clean_opt:
                label_text = clean_opt.split(" — ")[0].strip()
            elif " - " in clean_opt:
                label_text = clean_opt.split(" - ")[0].strip()
            elif ":" in clean_opt and len(clean_opt.split(":")[0]) < 35:
                label_text = clean_opt.split(":")[0].strip()
            else:
                label_text = clean_opt[:50].strip()

            num = len(options) + 1
            display_label = f"[{num}] {label_text}"
            options.append((display_label, clean_opt))
            if len(options) >= 5:
                break

    return options if len(options) >= 2 else []


AUTHORIZATION_NOTICE = """\
[bold yellow]Authorized use only[/bold yellow]

This tool can capture live network traffic. Only capture traffic on networks and
interfaces you own, or are explicitly authorized to monitor (e.g. your own lab,
your own home network, or with written authorization for the network in question).
Capturing traffic you are not authorized to see may be illegal in your jurisdiction.

Analysis of already-saved pcap files is never gated by this check.
"""


def _server_params() -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=["-m", "wireshark_mcp.server"])


def _format_tool_args(name: str, args: dict) -> str:
    """Format tool parameters into a clean, concise one-liner instead of dumping raw JSON."""
    if not args:
        return ""
    parts = []
    for k, v in args.items():
        if k in ("path", "extract_dir"):
            parts.append(os.path.basename(str(v)))
        elif k in ("display_filter", "bpf_filter"):
            filt = str(v)
            parts.append(f'filter="{filt[:35]}..."' if len(filt) > 35 else f'filter="{filt}"')
        elif k in ("interface", "iface"):
            parts.append(f"iface={v}")
        elif k in ("duration_seconds", "duration"):
            parts.append(f"{v}s")
        elif k in ("protocol", "state", "port", "stream_index"):
            parts.append(f"{k}={v}")
        elif k not in ("max_lines", "resolve_names"):
            val_str = str(v)
            parts.append(f"{k}={val_str[:25]}")
    return f"({', '.join(parts)})" if parts else ""


import random
import threading

# 50+ diverse, catchy, fun & technical 1-line network analysis status phrases
_CYCLING_STATUS_PHRASES = [
    "Mulling over packets...",
    "PCAPing the wire...",
    "Bribing the hamster...",
    "Sniffing TCP flows...",
    "Dissecting frame headers...",
    "Consulting the network oracle...",
    "Greasing the hamster wheel...",
    "Decoding DNS query records...",
    "Hunting rogue beacons...",
    "Feeding the packet shark...",
    "Tracking TCP handshakes...",
    "Filtering broadcast domain noise...",
    "Checking VirusTotal intelligence...",
    "Calibrating network antennas...",
    "Inspecting IPv4/IPv6 headers...",
    "Untangling TCP streams...",
    "Poking the network daemon...",
    "Auditing ARP tables...",
    "Scanning for cleartext credentials...",
    "Tickling the network card...",
    "Reassembling payload streams...",
    "Extracting TLS SNI hostnames...",
    "Hamster is sprinting on the wheel...",
    "Calculating payload entropy...",
    "Listening for suspicious SYN packets...",
    "Checking interface buffer queues...",
    "Correlating endpoint conversations...",
    "Analyzing packet round-trip time...",
    "Carving embedded forensic objects...",
    "Polishing the packet magnifying glass...",
    "Benchmarking latency differentials...",
    "Tracing remote socket endpoints...",
    "Looking for sneaky port scans...",
    "Decoding protocol hierarchies...",
    "Feeding caffeine to the packet engine...",
    "Comparing checksums and hashes...",
    "Checking for duplicate MAC addresses...",
    "Sifting through datagrams...",
    "Synthesizing forensic clues...",
    "Peeking inside payload buffers...",
    "Sniffing unencrypted cookies...",
    "Measuring packet inter-arrival times...",
    "Checking firewall state tables...",
    "Whispering to the network interfaces...",
    "Validating transport layer flags...",
    "Isolating anomalous micro-bursts...",
    "Herding lost packets...",
    "Compiling incident telemetry...",
    "Consulting threat intelligence feeds...",
    "Wrapping up the forensic analysis...",
]


class NetworkStatusIndicator:
    """
    Manages dynamic network-themed working indicators.
    Displays ONE short, punchy phrase at a time (e.g. 'Mulling over packets...',
    'PCAPing the wire...', 'Bribing the hamster...') and smoothly cycles through them.
    Never dumps multiple sentences or long paragraphs all at once.
    """

    def __init__(self, quiet: bool):
        self.quiet = quiet
        self._status = None
        self._ticker_thread = None
        self._stop_ticker = threading.Event()
        self._phrase_idx = 0

    def _rotate_phrases(self):
        while not self._stop_ticker.is_set():
            if self._stop_ticker.wait(timeout=2.2):
                break
            if self._status and not self.quiet:
                self._phrase_idx = (self._phrase_idx + 1) % len(_CYCLING_STATUS_PHRASES)
                phrase = _CYCLING_STATUS_PHRASES[self._phrase_idx]
                try:
                    self._status.update(f"[bold cyan]● {phrase}[/bold cyan]")
                except Exception:
                    pass

    def start(self):
        if not self.quiet:
            self._stop_ticker.clear()
            self._phrase_idx = random.randint(0, len(_CYCLING_STATUS_PHRASES) - 1)
            initial = _CYCLING_STATUS_PHRASES[self._phrase_idx]
            self._status = console.status(f"[bold cyan]● {initial}[/bold cyan]", spinner="dots")
            self._status.start()
            self._ticker_thread = threading.Thread(target=self._rotate_phrases, daemon=True)
            self._ticker_thread.start()

    def update(self, message: str):
        if self._status and not self.quiet:
            self._status.update(f"[bold cyan]● {message}[/bold cyan]")

    def stop(self):
        self._stop_ticker.set()
        if self._status:
            try:
                self._status.stop()
            except Exception:
                pass
            self._status = None

    def log_delegate(self, agent_key: str, request: str):
        if self.quiet:
            return
        short_agent = agent_key.replace("ask_", "").replace("_agent", "")
        status_map = {
            "capture": "PCAPing the wire...",
            "traffic_analyst": "Dissecting packet headers...",
            "threat_hunter": "Hunting rogue threats & beacons...",
            "report": "Compiling final findings...",
        }
        status_msg = status_map.get(short_agent, f"Delegating to {short_agent}...")
        self.update(status_msg)

        first_clause = request.split(".")[0].strip() if "." in request else request.strip()
        first_clause = (first_clause[:65] + "...") if len(first_clause) > 65 else first_clause
        console.print(f" [dim]⚡[/dim] [bold cyan]{short_agent}[/bold cyan] [dim]› {first_clause}[/dim]")

    def log_tool(self, name: str, args: dict):
        if self.quiet:
            return
        if "capture" in name:
            self.update("PCAPing live packets on wire...")
        elif "stream" in name:
            self.update("Reassembling TCP stream...")
        elif "extract" in name or "hash" in name:
            self.update("Carving forensic objects...")
        elif "virustotal" in name or "vt" in name:
            self.update("Checking VirusTotal intelligence...")
        elif "scan" in name or "beacon" in name or "spoof" in name:
            self.update("Threat-hunting heuristics...")
        elif "report" in name or "write" in name:
            self.update("Synthesizing final report...")
        else:
            self.update(f"Running {name}...")

        arg_str = _format_tool_args(name, args)
        console.print(f"   [dim]↳[/dim] [green]{name}[/green] [dim]{arg_str}[/dim]")


def _create_runner(
    session: ClientSession,
    tools: list,
    provider_name: str,
    cfg: Config,
    single: bool,
    quiet: bool,
    supervisor_model: str | None,
    agent_model: str | None,
    sarvam_api_key: str | None,
    decision_gate: UserDecisionGate,
    indicator: NetworkStatusIndicator | None = None,
):
    provider = get_llm_provider(
        provider_name=provider_name,
        cfg_ollama=cfg.ollama,
        cfg_sarvam=cfg.sarvam,
        sarvam_api_key_override=sarvam_api_key,
    )

    is_sarvam = isinstance(provider, SarvamProvider)
    if is_sarvam:
        sup_model = supervisor_model or cfg.sarvam.get("supervisor_model", "sarvam-105b")
        ag_model = agent_model or cfg.sarvam.get("agent_model", "sarvam-105b-conversations")
        temp = float(cfg.sarvam.get("temperature", 0.1))
        num_predict = int(cfg.sarvam.get("max_tokens", 1000))
        max_iters = int(cfg.sarvam.get("max_tool_iterations", 15))
    else:
        sup_model = supervisor_model or cfg.ollama.get("supervisor_model", "llama3.2:1b")
        ag_model = agent_model or cfg.ollama.get("agent_model", "llama3.2:3b")
        temp = float(cfg.ollama.get("temperature", 0))
        num_predict = int(cfg.ollama.get("num_predict", 700))
        max_iters = int(cfg.ollama.get("max_tool_iterations", 15))

    on_tool = indicator.log_tool if indicator else None
    on_del = indicator.log_delegate if indicator else None

    if single:
        runner = SingleAgent(
            session=session,
            all_tools=tools,
            model=ag_model,
            temperature=temp,
            num_predict=num_predict,
            keep_alive=cfg.ollama.get("keep_alive", "30m"),
            max_tool_iterations=max_iters,
            provider=provider,
            decision_gate=decision_gate,
            on_tool_call=on_tool,
        )
    else:
        runner = Orchestrator(
            session=session,
            all_tools=tools,
            supervisor_model=sup_model,
            agent_model=ag_model,
            temperature=temp,
            num_predict=num_predict,
            keep_alive=cfg.ollama.get("keep_alive", "30m"),
            max_tool_iterations=max_iters,
            provider=provider,
            decision_gate=decision_gate,
            on_delegate=on_del,
            on_tool_call=on_tool,
        )

    return runner, provider, sup_model, ag_model


async def _run_chat(
    cfg: Config,
    single: bool,
    quiet: bool,
    supervisor_model: str | None,
    agent_model: str | None,
    provider_name: str | None,
    sarvam_api_key: str | None,
    no_confirm: bool,
):
    current_provider_name = (provider_name or cfg.provider or "ollama").strip().lower()

    # User decision gate configuration
    require_confirm = not no_confirm and cfg.decisions.get("require_confirmation", True)
    sensitive_tools = set(cfg.decisions.get("sensitive_tools") or [
        "delete_capture", "cleanup_old_captures", "stop_all_captures", "start_ring_capture"
    ])

    def confirm_prompt(tool_name: str, args: dict) -> bool:
        console.print()
        descriptions = {
            "delete_capture": "Permanently deletes the specified packet capture file from disk.",
            "cleanup_old_captures": "Deletes older capture files based on the retention window.",
            "stop_all_captures": "Immediately terminates all background network capture jobs.",
            "start_ring_capture": "Initiates a continuous rotating capture writing multiple files to disk.",
        }
        desc = descriptions.get(tool_name, "Modifies system files or terminates active capture processes.")
        args_display = ", ".join(f"{k}='{v}'" for k, v in args.items()) if args else "(no arguments)"

        console.print(Panel(
            f"[bold yellow][!]️  Action Confirmation Gate[/bold yellow]\n\n"
            f"The agent requested execution of: [bold cyan]{tool_name}[/bold cyan]({args_display})\n"
            f"[dim]{desc}[/dim]\n",
            title="[bold red]User Decision Required[/bold red]",
            border_style="yellow",
        ))

        if questionary is not None:
            try:
                choice = questionary.select(
                    "Execute this action? (Use ↑/↓ and Enter)",
                    choices=[
                        "No  (Decline this action)",
                        "Yes (Approve and execute)",
                        "Always allow this tool in session",
                    ],
                ).ask()
            except Exception:
                choice = None
            if choice and choice.startswith("Yes"):
                console.print("[green][OK] Action approved by user.[/green]")
                return True
            elif choice and choice.startswith("Always"):
                decision_gate.always_allowed.add(tool_name)
                console.print(f"[green][OK] Action approved and '{tool_name}' added to session whitelist.[/green]")
                return True
            else:
                console.print("[red]✗ Action declined by user decision.[/red]")
                return False

        try:
            choice = console.input(
                "Execute this action? [bold][y]es / [n]o / [a]lways allow this tool in session[/bold] (default: n): "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False

        if choice in ("y", "yes"):
            console.print("[green][OK] Action approved by user.[/green]")
            return True
        elif choice in ("a", "always"):
            decision_gate.always_allowed.add(tool_name)
            console.print(f"[green][OK] Action approved and '{tool_name}' added to session whitelist.[/green]")
            return True
        else:
            console.print("[red]✗ Action declined by user decision.[/red]")
            return False

    decision_gate = UserDecisionGate(
        require_confirmation=require_confirm,
        sensitive_tools=sensitive_tools,
        confirm_callback=confirm_prompt if require_confirm else None,
    )

    async with stdio_client(_server_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_resp = await session.list_tools()
            tool_names = [t.name for t in tools_resp.tools]
            console.print(f"[green]Connected to MCP server.[/green] {len(tool_names)} tools available.")

            indicator = NetworkStatusIndicator(quiet)
            runner, provider, sup_model, ag_model = _create_runner(
                session=session,
                tools=tools_resp.tools,
                provider_name=current_provider_name,
                cfg=cfg,
                single=single,
                quiet=quiet,
                supervisor_model=supervisor_model,
                agent_model=agent_model,
                sarvam_api_key=sarvam_api_key,
                decision_gate=decision_gate,
                indicator=indicator,
            )

            p_title = "Sarvam AI (Cloud)" if isinstance(provider, SarvamProvider) else "Ollama (Local)"
            if single:
                console.print(f"Provider: [bold cyan]{p_title}[/bold cyan] | Mode: [bold]single-agent[/bold] | Model=[bold]{ag_model}[/bold]")
            else:
                console.print(
                    f"Provider: [bold cyan]{p_title}[/bold cyan] | Mode: [bold]multi-agent[/bold] | "
                    f"Supervisor=[bold]{sup_model}[/bold] | Specialists=[bold]{ag_model}[/bold]"
                )

            gate_status = "[green]ON[/green] (protecting destructive actions)" if decision_gate.require_confirmation else "[yellow]OFF[/yellow]"
            console.print(f"User Decision Gate: {gate_status}")
            console.print("Type your question, slash command ([bold]/help[/bold]), or [bold]quit[/bold] to exit.\n")

            last_answer = ""
            while True:
                detected_options = extract_decision_options(last_answer) if (last_answer and questionary is not None) else []
                user_input = ""

                if detected_options:
                    choices = [label for label, _ in detected_options]
                    choices.append("[>] Type custom instruction / Tell agent what to do...")
                    choices.append("[x] End task / Done for now")
                    try:
                        console.print("[dim]Use ↑/↓ arrow keys and Enter to select an option, or choose custom instruction / end task:[/dim]")
                        selected = await asyncio.to_thread(
                            questionary.select(
                                "Choose an option:",
                                choices=choices,
                                use_shortcuts=False,
                            ).ask
                        )
                    except Exception:
                        selected = None

                    if selected is None:
                        break
                    elif selected.startswith("[x]"):
                        console.print("[dim]Task ended. Ready for your next query.[/dim]\n")
                        last_answer = ""
                        continue
                    elif not selected.startswith("[>]"):
                        for label, full_text in detected_options:
                            if selected == label:
                                user_input = full_text
                                console.print(f"[bold blue]You (selected):[/bold blue] {user_input}")
                                break
                    else:
                        try:
                            user_input = console.input("[bold blue]You (custom instruction):[/bold blue] ").strip()
                        except (EOFError, KeyboardInterrupt):
                            break
                else:
                    try:
                        user_input = console.input("[bold blue]You:[/bold blue] ").strip()
                    except (EOFError, KeyboardInterrupt):
                        break

                if not user_input:
                    continue

                # Built-in exit commands
                if user_input.lower() in ("quit", "exit", "q"):
                    break

                # In-chat one-step authorization
                if user_input.lower().replace("-", " ") in ("wireshark agent authorize", "/authorize", "authorize"):
                    marker = cfg.security.get("ack_marker_file")
                    if marker:
                        os.makedirs(os.path.dirname(marker), exist_ok=True)
                        with open(marker, "w", encoding="utf-8") as fh:
                            fh.write(f"acknowledged {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    console.print(Panel("[green][OK] Packet capture has been AUTHORIZED on this machine![/green]\nYou can now start live captures on any allowed interface.", border_style="green"))
                    last_answer = ""
                    continue

                # Interactive user decision & session control slash commands
                if user_input.startswith("/"):
                    cmd_parts = user_input.split(maxsplit=1)
                    cmd = cmd_parts[0].lower()
                    arg = cmd_parts[1].strip() if len(cmd_parts) > 1 else ""

                    if cmd == "/help":
                        console.print(Panel(
                            "[bold]NetAgent Interactive Commands & Controls:[/bold]\n"
                            "  [cyan]/session [list|save|load][/cyan] - Manage named conversation sessions & checkpoints\n"
                            "  [cyan]/memory [show|add|clear][/cyan]  - View, update, or clear NetAgent's long-term memory\n"
                            "  [cyan]/sandbox [list|import][/cyan]    - Manage isolated sandbox for external untrusted pcaps\n"
                            "  [cyan]/monitor [list|start|stop|stats|delete][/cyan] - Continuous 24/7 background monitoring subagents\n"
                            "  [cyan]/telegram [test|alert][/cyan]   - Telegram BotFather alerts and connectivity\n"
                            "  [cyan]/virustotal [check <ip>|cache][/cyan] - Scan IP reputation against VirusTotal & view cache\n"
                            "  [cyan]/scan <target> [--bg][/cyan]     - Run Nmap/socket port scan with JEV decision engine\n"
                            "  [cyan]/subagents [id][/cyan]          - Inspect spawned JEV subagents and tool execution ledger\n"
                            "  [cyan]/provider [sarvam|ollama][/cyan] - Check or switch AI model provider on the fly\n"
                            "  [cyan]/confirm [on|off][/cyan]        - Toggle human-in-the-loop confirmation for sensitive actions\n"
                            "  [cyan]/interfaces[/cyan]                - Quickly list network interfaces via tshark\n"
                            "  [cyan]/adapters[/cyan]                  - List network adapter statuses & link speeds via PowerShell\n"
                            "  [cyan]/connections[/cyan]               - List active TCP socket connections & processes via PowerShell\n"
                            "  [cyan]/wireshark [path][/cyan]          - Open a saved capture in desktop Wireshark GUI\n"
                            "  [cyan]/captures[/cyan]                  - Quickly list saved captures for analysis decisions\n"
                            "  [cyan]/status[/cyan]                    - Display active provider, models, and decision gate status\n"
                            "  [cyan]/clear[/cyan]                     - Reset conversation history\n"
                            "  [cyan]/help[/cyan]                      - Show this guide\n"
                            "  [cyan]quit / exit[/cyan]                - Exit chat",
                            title="Command Reference",
                            border_style="blue",
                        ))
                        continue

                    elif cmd in ("/subagents", "/ledger"):
                        sub_id = arg.strip()
                        records = runner.ledger.list_all()
                        if not records:
                            console.print("[yellow]No subagents have been spawned in the ledger yet.[/yellow]")
                            continue

                        if sub_id:
                            target = next((r for r in records if r.subagent_id == sub_id), None)
                            if not target:
                                console.print(f"[red]Subagent '{sub_id}' not found in ledger.[/red]")
                                continue
                            table = Table(title=f"Subagent Execution Detail: {target.name} ({target.subagent_id})")
                            table.add_column("Property", style="bold cyan")
                            table.add_column("Value")
                            table.add_row("ID", target.subagent_id)
                            table.add_row("Name", target.name)
                            table.add_row("Role", target.role)
                            table.add_row("Task", target.task)
                            table.add_row("Status", f"[green]{target.status}[/green]" if target.status == "completed" else f"[yellow]{target.status}[/yellow]")
                            table.add_row("Started", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(target.started_at)))
                            table.add_row("Completed", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(target.completed_at)) if target.completed_at else "(active)")
                            table.add_row("Tool Actions Count", str(len(target.actions)))
                            console.print(table)

                            if target.actions:
                                act_table = Table(title=f"Action Log ({len(target.actions)} steps)")
                                act_table.add_column("#", justify="right", style="dim")
                                act_table.add_column("Type", style="magenta")
                                act_table.add_column("Tool", style="cyan")
                                act_table.add_column("Arguments", style="dim")
                                for idx, a in enumerate(target.actions, start=1):
                                    act_table.add_row(str(idx), a.action_type, a.name, str(a.arguments))
                                console.print(act_table)
                            if target.output:
                                console.print(Panel(Markdown(target.output), title="Subagent Final Output", border_style="cyan"))
                            continue

                        table = Table(title=f"Spawned JEV Subagents Ledger ({len(records)} total)")
                        table.add_column("ID", style="cyan")
                        table.add_column("Name", style="bold")
                        table.add_column("Role", style="magenta")
                        table.add_column("Status")
                        table.add_column("Actions", justify="right")
                        table.add_column("Task Preview")
                        for r in records:
                            st_style = "[green]completed[/green]" if r.status == "completed" else f"[yellow]{r.status}[/yellow]"
                            task_prev = r.task[:45] + "..." if len(r.task) > 45 else r.task
                            table.add_row(r.subagent_id, r.name, r.role, st_style, str(len(r.actions)), task_prev)
                        console.print(table)
                        console.print("[dim]Use '/subagents <subagent_id>' to see full step-by-step action history.[/dim]")
                        continue

                    elif cmd == "/session":
                        sub_cmd_parts = arg.split(maxsplit=1)
                        sub_op = sub_cmd_parts[0].lower() if sub_cmd_parts and sub_cmd_parts[0] else "list"
                        session_name = sub_cmd_parts[1].strip() if len(sub_cmd_parts) > 1 else ""

                        if sub_op == "list":
                            sessions = runner.session_mgr.list_sessions()
                            if not sessions:
                                console.print("[yellow]No saved sessions found.[/yellow]")
                            else:
                                t = Table(title="Saved NetAgent Sessions")
                                t.add_column("Session Name", style="bold cyan")
                                t.add_column("Updated At")
                                t.add_column("Messages", justify="right")
                                t.add_column("Notes")
                                for s in sessions:
                                    t.add_row(s["name"], s["updated_at"], str(s["message_count"]), s.get("notes", ""))
                                console.print(t)
                        elif sub_op == "save":
                            if not session_name:
                                session_name = f"session_{time.strftime('%Y%m%d_%H%M%S')}"
                            saved_path = runner.session_mgr.save_session(session_name, runner._history, runner.known_paths)
                            console.print(f"[green][OK] Session saved as '{session_name}' ({saved_path})[/green]")
                        elif sub_op == "load":
                            if not session_name:
                                console.print("[yellow]Usage: /session load <session_name>[/yellow]")
                                continue
                            data = runner.session_mgr.load_session(session_name)
                            if not data:
                                console.print(f"[red]Session '{session_name}' not found.[/red]")
                                continue
                            runner._history = data.get("history", [])
                            runner.known_paths = set(data.get("known_paths", []))
                            console.print(f"[green][OK] Loaded session '{session_name}' with {len(runner._history)} message steps.[/green]")
                        else:
                            console.print("[yellow]Usage: /session [list | save <name> | load <name>][/yellow]")
                        continue

                    elif cmd == "/memory":
                        mem_parts = arg.split(maxsplit=1)
                        mem_op = mem_parts[0].lower() if mem_parts and mem_parts[0] else "show"
                        mem_val = mem_parts[1].strip() if len(mem_parts) > 1 else ""

                        if mem_op == "show":
                            entries = runner.memory.recall()
                            if not entries:
                                console.print("[yellow]NetAgent long-term memory is currently empty.[/yellow]")
                            else:
                                t = Table(title=f"NetAgent Long-Term Memory ({len(entries)} items)")
                                t.add_column("ID", style="dim")
                                t.add_column("Category", style="bold magenta")
                                t.add_column("Content")
                                t.add_column("Created", style="dim")
                                for e in entries:
                                    t.add_row(e.entry_id, e.category.upper(), e.content, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.created_at)))
                                console.print(t)
                        elif mem_op == "add":
                            if not mem_val:
                                console.print("[yellow]Usage: /memory add <note or insight>[/yellow]")
                                continue
                            e = runner.memory.remember("user_note", mem_val, source="user")
                            console.print(f"[green][OK] Saved note to NetAgent memory: {e.content}[/green]")
                        elif mem_op == "clear":
                            runner.memory.clear()
                            console.print("[yellow]Cleared NetAgent long-term memory.[/yellow]")
                        else:
                            console.print("[yellow]Usage: /memory [show | add <note> | clear][/yellow]")
                        continue

                    elif cmd == "/sandbox":
                        sb_parts = arg.split(maxsplit=1)
                        sb_op = sb_parts[0].lower() if sb_parts and sb_parts[0] else "list"
                        sb_path = sb_parts[1].strip() if len(sb_parts) > 1 else ""

                        from .memory import PcapSandbox
                        sb = PcapSandbox(cfg.sandbox_dir)
                        if sb_op == "list":
                            files = sb.list_files()
                            if not files:
                                console.print(f"[yellow]No files in sandbox ({cfg.sandbox_dir}).[/yellow]")
                            else:
                                t = Table(title=f"NetAgent Pcap Sandbox ({len(files)} files)")
                                t.add_column("Filename", style="bold cyan")
                                t.add_column("Size", justify="right")
                                t.add_column("Sandbox Path")
                                for f in files:
                                    t.add_row(f["name"], f"{f['size']:,} B", f["path"])
                                console.print(t)
                        elif sb_op == "import":
                            if not sb_path:
                                console.print("[yellow]Usage: /sandbox import <path_to_pcap>[/yellow]")
                                continue
                            res = sb.import_pcap(sb_path)
                            if res["success"]:
                                runner.known_paths.add(res["sandboxed_path"])
                                console.print(f"[green][OK] Safely imported pcap to sandbox: {res['sandboxed_path']}[/green]")
                            else:
                                console.print(f"[red]Failed to import to sandbox: {res.get('error')}[/red]")
                        elif sb_op == "clean":
                            cnt = sb.clean_sandbox()
                            console.print(f"[yellow]Cleaned sandbox: removed {cnt} file(s).[/yellow]")
                        else:
                            console.print("[yellow]Usage: /sandbox [list | import <path> | clean][/yellow]")
                        continue

                    elif cmd == "/monitor":
                        from .monitor import ContinuousMonitorManager
                        mgr = ContinuousMonitorManager()
                        mon_parts = arg.split(maxsplit=2)
                        mon_op = mon_parts[0].lower() if mon_parts and mon_parts[0] else "list"
                        mon_arg1 = mon_parts[1].strip() if len(mon_parts) > 1 else ""
                        mon_arg2 = mon_parts[2].strip() if len(mon_parts) > 2 else ""

                        if mon_op == "list":
                            monitors = mgr.list_monitors()
                            if not monitors:
                                console.print("[yellow]No continuous monitoring subagents registered.[/yellow]")
                            else:
                                t = Table(title=f"Continuous Monitoring Subagents ({len(monitors)})")
                                t.add_column("ID", style="bold cyan")
                                t.add_column("Name")
                                t.add_column("Interface")
                                t.add_column("PID")
                                t.add_column("Status")
                                t.add_column("Packets", justify="right")
                                t.add_column("Threats", justify="right")
                                t.add_column("Last Run")
                                for m in monitors:
                                    st = m.get("stats", {})
                                    stat_str = f"[green]{m['status']}[/green]" if m.get("status") == "RUNNING" else f"[dim]{m.get('status')}[/dim]"
                                    t.add_row(
                                        m["id"],
                                        m.get("name", ""),
                                        str(m.get("interface", "")),
                                        str(m.get("pid") or "-"),
                                        stat_str,
                                        f"{st.get('total_packets', 0):,}",
                                        str(st.get("threats_detected", 0)),
                                        st.get("last_run") or "Never",
                                    )
                                console.print(t)
                        elif mon_op == "start":
                            name = mon_arg1 or f"monitor_{int(time.time())}"
                            iface = mon_arg2 or "1"
                            res = mgr.start_monitor(name=name, interface=iface)
                            console.print(Panel(
                                f"[green][OK] Started continuous monitoring subagent:[/green]\n"
                                f"  • ID: [bold]{res['id']}[/bold]\n"
                                f"  • Name: {res['name']}\n"
                                f"  • Interface: {res['interface']}\n"
                                f"  • PID: {res['pid']} (Detached background daemon)\n"
                                f"  • Interval: {res['interval_seconds']}s\n\n"
                                f"[dim]This subagent continues running even if this PowerShell window is closed.\n"
                                f"Query statistics anytime with /monitor stats {res['id']}[/dim]",
                                border_style="green",
                            ))
                        elif mon_op == "stop":
                            if not mon_arg1:
                                console.print("[yellow]Usage: /monitor stop <monitor_id>[/yellow]")
                                continue
                            ok = mgr.stop_monitor(mon_arg1)
                            if ok:
                                console.print(f"[green][OK] Stopped monitoring subagent '{mon_arg1}'[/green]")
                            else:
                                console.print(f"[red]Failed to stop subagent '{mon_arg1}'[/red]")
                        elif mon_op == "stats":
                            if not mon_arg1:
                                console.print("[yellow]Usage: /monitor stats <monitor_id>[/yellow]")
                                continue
                            m = mgr.get_monitor(mon_arg1)
                            if not m:
                                console.print(f"[red]Subagent '{mon_arg1}' not found.[/red]")
                                continue
                            st = m.get("stats", {})
                            stat_panel = (
                                f"[bold]Subagent:[/bold] {m.get('name')} ([cyan]{m['id']}[/cyan])\n"
                                f"[bold]Status:[/bold] {m.get('status')} | [bold]PID:[/bold] {m.get('pid') or '-'}\n"
                                f"[bold]Interface:[/bold] {m.get('interface')} | [bold]Interval:[/bold] {m.get('interval_seconds')}s\n"
                                f"[bold]Rules:[/bold] {', '.join(m.get('rules', []))}\n"
                                f"[bold]Total Cycles:[/bold] {st.get('total_cycles', 0)}\n"
                                f"[bold]Packets Inspected:[/bold] {st.get('total_packets', 0):,}\n"
                                f"[bold]Threats Detected:[/bold] {st.get('threats_detected', 0)}\n"
                                f"[bold]Last Active:[/bold] {st.get('last_run') or 'Never'}\n"
                            )
                            recent = st.get("recent_alerts", [])
                            if recent:
                                stat_panel += "\n[bold red]Recent Alerts:[/bold red]\n"
                                for a in recent[-5:]:
                                    stat_panel += f"  • [{a.get('timestamp')}] {a.get('level')} - {a.get('rule')}: {a.get('message')}\n"
                            console.print(Panel(stat_panel, title=f"Statistics: {m['id']}", border_style="cyan"))
                        elif mon_op == "delete":
                            if not mon_arg1:
                                console.print("[yellow]Usage: /monitor delete <monitor_id>[/yellow]")
                                continue
                            ok = mgr.delete_monitor(mon_arg1)
                            if ok:
                                console.print(f"[yellow][OK] Deleted monitoring subagent '{mon_arg1}'[/yellow]")
                            else:
                                console.print(f"[red]Failed to delete subagent '{mon_arg1}'[/red]")
                        else:
                            console.print("[yellow]Usage: /monitor [list | start <name> <iface> | stop <id> | stats <id> | delete <id>][/yellow]")
                        continue

                    elif cmd == "/telegram":
                        from .telegram import TelegramBotService, TelegramNotifier
                        notifier = TelegramNotifier()
                        bot_svc = TelegramBotService()
                        tg_parts = arg.split(maxsplit=1)
                        tg_op = tg_parts[0].lower() if tg_parts and tg_parts[0] else "status"
                        tg_val = tg_parts[1].strip() if len(tg_parts) > 1 else ""

                        if tg_op == "test":
                            console.print("[dim]Testing Telegram bot connection and delivering ping...[/dim]")
                            res = notifier.test_connection()
                            if res.get("success"):
                                console.print(Panel(
                                    f"[green][OK] Telegram Bot Verified![/green]\n"
                                    f"• Bot: @{res.get('bot_username')}\n"
                                    f"• Message: {res.get('message')}",
                                    border_style="green",
                                ))
                            else:
                                console.print(Panel(
                                    f"[red]✗ Telegram Connection Failed[/red]\n"
                                    f"• Error: {res.get('error')}\n\n"
                                    f"[dim]Configure via config.yaml (telegram.bot_token & telegram.chat_id) "
                                    f"or set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.[/dim]",
                                    border_style="red",
                                ))
                        elif tg_op == "start":
                            res = bot_svc.start_daemon()
                            if res.get("success"):
                                console.print(f"[green][OK] {res.get('message')}[/green]")
                            else:
                                console.print(f"[red]Failed to start Telegram daemon: {res.get('error')}[/red]")
                        elif tg_op == "stop":
                            res = bot_svc.stop_daemon()
                            console.print(f"[yellow][OK] {res.get('message')}[/yellow]")
                        elif tg_op == "status":
                            st = bot_svc.get_daemon_status()
                            if st.get("running"):
                                console.print(f"[green]● Telegram Bot Daemon is RUNNING (PID: {st.get('pid')})[/green]")
                                console.print("[dim]You can talk directly to NetAgent via Telegram! Telegram chats are isolated from this console.[/dim]")
                            else:
                                console.print("[yellow]● Telegram Bot Daemon is STOPPED.[/yellow]")
                                console.print("[dim]Start it with: /telegram start or 'netagent telegram start'[/dim]")
                        elif tg_op == "alert":
                            if not tg_val:
                                console.print("[yellow]Usage: /telegram alert <alert_message>[/yellow]")
                                continue
                            res = notifier.send_alert(tg_val, level="CRITICAL")
                            if res.get("success"):
                                console.print(f"[green][OK] Alert dispatched over Telegram (ID: {res.get('message_id')})[/green]")
                            else:
                                console.print(f"[red]Failed to send Telegram alert: {res.get('error')}[/red]")
                        else:
                            console.print("[yellow]Usage: /telegram [start | stop | status | test | alert <message>][/yellow]")
                        continue

                    elif cmd in ("/virustotal", "/vt"):
                        from .virustotal import VirusTotalClient
                        vt = VirusTotalClient()
                        vt_parts = arg.split(maxsplit=1)
                        vt_op = vt_parts[0].lower() if vt_parts and vt_parts[0] else "cache"
                        vt_target = vt_parts[1].strip() if len(vt_parts) > 1 else ""

                        if vt_op == "check":
                            if not vt_target:
                                console.print("[yellow]Usage: /vt check <ip_address>[/yellow]")
                                continue
                            console.print(f"[dim]Checking VirusTotal reputation for {vt_target}...[/dim]")
                            rep = vt.check_ip(vt_target, send_alerts=True)
                            if "error" in rep:
                                console.print(f"[red]Error: {rep['error']}[/red]")
                            else:
                                status_color = "red" if rep.get("is_malicious") else "green"
                                status_title = "MALICIOUS THREAT" if rep.get("is_malicious") else "CLEAN / BENIGN"
                                stats = rep.get("stats", {})
                                cached_str = " (From Cache - No API limit burned)" if rep.get("cached") else " (Fresh VirusTotal Scan)"
                                console.print(Panel(
                                    f"[{status_color} bold]Verdict: {status_title}[/{status_color} bold]{cached_str}\n\n"
                                    f"• IP Address: [bold]{rep.get('ip')}[/bold]\n"
                                    f"• Malicious Score: [bold]{rep.get('malicious_score')}%[/bold]\n"
                                    f"• Security Detections: {stats.get('malicious', 0)}/{stats.get('total_engines', 0)} vendors\n"
                                    f"• Autonomous System / Org: {rep.get('as_owner')}\n"
                                    f"• Country: {rep.get('country')}\n"
                                    f"• Scan Time: {rep.get('scanned_at')}",
                                    title=f"VirusTotal Report: {rep.get('ip')}",
                                    border_style=status_color,
                                ))
                        elif vt_op in ("cache", "list"):
                            entries = vt.cache
                            if not entries:
                                console.print("[yellow]No IPs currently cached in VirusTotal intelligence store.[/yellow]")
                            else:
                                t = Table(title=f"VirusTotal Cached IP Intelligence ({len(entries)} IPs)")
                                t.add_column("IP Address", style="bold cyan")
                                t.add_column("Score", justify="right")
                                t.add_column("Verdict")
                                t.add_column("Organization")
                                t.add_column("Country")
                                t.add_column("Scanned At")
                                for ip_val, data in entries.items():
                                    mal = data.get("is_malicious", False)
                                    verdict_col = "[red]MALICIOUS[/red]" if mal else "[green]CLEAN[/green]"
                                    score_str = f"{data.get('malicious_score', 0)}%"
                                    t.add_row(ip_val, score_str, verdict_col, data.get("as_owner", "Unknown"), data.get("country", "Unknown"), data.get("scanned_at", ""))
                                console.print(t)
                        else:
                            # Direct IP entered
                            ip_cand = vt_op
                            console.print(f"[dim]Checking VirusTotal reputation for {ip_cand}...[/dim]")
                            rep = vt.check_ip(ip_cand, send_alerts=True)
                            if "error" in rep:
                                console.print(f"[red]Error: {rep['error']}[/red]")
                            else:
                                status_color = "red" if rep.get("is_malicious") else "green"
                                status_title = "MALICIOUS THREAT" if rep.get("is_malicious") else "CLEAN / BENIGN"
                                stats = rep.get("stats", {})
                                cached_str = " (From Cache)" if rep.get("cached") else " (Fresh Scan)"
                                console.print(Panel(
                                    f"[{status_color} bold]Verdict: {status_title}[/{status_color} bold]{cached_str}\n\n"
                                    f"• IP Address: [bold]{rep.get('ip')}[/bold]\n"
                                    f"• Malicious Score: [bold]{rep.get('malicious_score')}%[/bold]\n"
                                    f"• Detections: {stats.get('malicious', 0)}/{stats.get('total_engines', 0)} vendors\n"
                                    f"• Org: {rep.get('as_owner')} ({rep.get('country')})\n"
                                    f"• Scan Time: {rep.get('scanned_at')}",
                                    title=f"VirusTotal Report: {rep.get('ip')}",
                                    border_style=status_color,
                                ))
                        continue

                    elif cmd == "/scan":
                        if not arg:
                            console.print("[yellow]Usage: /scan <target> [--ports common|80,443] [--bg] | /scan result <scan_id> | /scan list[/yellow]")
                            continue
                        scan_parts = arg.split()
                        if scan_parts[0].lower() == "result":
                            scan_id = scan_parts[1].strip() if len(scan_parts) > 1 else ""
                            if not scan_id:
                                console.print("[yellow]Usage: /scan result <scan_id>[/yellow]")
                                continue
                            res = await session.call_tool("get_scan_result", {"scan_id": scan_id})
                            text = "\n".join(c.text for c in res.content if hasattr(c, "text"))
                            console.print(Panel(text or "No scan data found", title=f"Scan Result: {scan_id}", border_style="cyan"))
                            continue
                        elif scan_parts[0].lower() == "list":
                            from pathlib import Path
                            scans_dir = Path(cfg.monitors_dir) / "scans"
                            if not scans_dir.is_dir():
                                console.print("[yellow]No scans recorded yet.[/yellow]")
                                continue
                            scan_files = sorted(scans_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
                            if not scan_files:
                                console.print("[yellow]No scans found in cache.[/yellow]")
                                continue
                            t = Table(title=f"Recorded Network Port Scans ({len(scan_files)})")
                            t.add_column("Scan ID", style="bold cyan")
                            t.add_column("Target")
                            t.add_column("Status")
                            t.add_column("Engine")
                            t.add_column("Open Ports", justify="right")
                            t.add_column("JEV Score")
                            t.add_column("Timestamp")
                            for sf in scan_files:
                                try:
                                    with open(sf, "r", encoding="utf-8") as fh:
                                        d = json.load(fh)
                                        jd = d.get("jev_decision", {})
                                        score_str = f"{jd.get('threat_score')}/10" if jd else "-"
                                        t.add_row(
                                            sf.stem,
                                            d.get("target", "Unknown"),
                                            d.get("status", "COMPLETED"),
                                            d.get("engine", "Socket"),
                                            str(len(d.get("open_ports", []))),
                                            score_str,
                                            d.get("timestamp", ""),
                                        )
                                except Exception:
                                    pass
                            console.print(t)
                            continue

                        # Execute port scan
                        target_host = scan_parts[0]
                        is_bg = "--bg" in scan_parts or "bg" in scan_parts
                        ports_val = "common"
                        for idx, p in enumerate(scan_parts):
                            if p in ("--ports", "-p") and idx + 1 < len(scan_parts):
                                ports_val = scan_parts[idx + 1]

                        console.print(f"[dim]Initiating {'background ' if is_bg else ''}scan on {target_host} (ports: {ports_val})...[/dim]")
                        res = await session.call_tool("port_scan_host", {"target": target_host, "ports": ports_val, "background": is_bg})
                        text = "\n".join(c.text for c in res.content if hasattr(c, "text"))
                        console.print(Panel(text or "Scan completed", title=f"Port Scan: {target_host}", border_style="cyan"))
                        continue

                    elif cmd == "/wireshark":
                        args_list = arg.split("-Y", 1)
                        target_path = args_list[0].strip()
                        display_filter = args_list[1].strip() if len(args_list) > 1 else ""
                        if not target_path:
                            from .tshark_utils import TsharkRunner
                            r_tmp = TsharkRunner(cfg)
                            files = r_tmp.list_capture_files()
                            if files:
                                target_path = files[0]
                                console.print(f"[dim]Opening most recent capture: {target_path}[/dim]")
                            else:
                                console.print("[yellow]No captures found in /capture or /data yet to open.[/yellow]")
                                continue
                        call_args = {"path": target_path}
                        if display_filter:
                            call_args["display_filter"] = display_filter
                        res = await session.call_tool("open_in_wireshark", call_args)
                        text = "\n".join(c.text for c in res.content if hasattr(c, "text"))
                        console.print(f"[green]{text}[/green]")
                        continue

                    elif cmd == "/adapters":
                        via = "PowerShell (Get-NetAdapter)" if sys.platform == "win32" else "ip/ifconfig"
                        console.print(f"[dim]Fetching network adapters via {via}...[/dim]")
                        res = await session.call_tool("powershell_adapters", {})
                        text = "\n".join(c.text for c in res.content if hasattr(c, "text"))
                        console.print(Panel(text or "No adapters found", title=f"Network Adapters ({via})", border_style="cyan"))
                        continue

                    elif cmd == "/connections":
                        via = "PowerShell (Get-NetTCPConnection)" if sys.platform == "win32" else "ss"
                        console.print(f"[dim]Fetching established sockets via {via}...[/dim]")
                        res = await session.call_tool("powershell_network_connections", {"state": "Established"})
                        text = "\n".join(c.text for c in res.content if hasattr(c, "text"))
                        console.print(Panel(text or "No active connections", title=f"Live TCP Connections ({via})", border_style="cyan"))
                        continue

                    elif cmd == "/provider":
                        if arg:
                            target_p = arg.lower()
                            if target_p not in ("ollama", "sarvam", "sarvamai"):
                                console.print("[red]Unknown provider. Choose 'ollama' or 'sarvam'.[/red]")
                                continue
                            current_provider_name = target_p
                            runner, provider, sup_model, ag_model = _create_runner(
                                session=session,
                                tools=tools_resp.tools,
                                provider_name=current_provider_name,
                                cfg=cfg,
                                single=single,
                                quiet=quiet,
                                supervisor_model=None,
                                agent_model=None,
                                sarvam_api_key=sarvam_api_key,
                                decision_gate=decision_gate,
                                indicator=indicator,
                            )
                            p_title = "Sarvam AI (Cloud)" if isinstance(provider, SarvamProvider) else "Ollama (Local)"
                            console.print(f"[green]Switched provider to: {p_title}[/green] (supervisor={sup_model}, agent={ag_model})")
                        else:
                            p_title = "Sarvam AI (Cloud)" if isinstance(provider, SarvamProvider) else "Ollama (Local)"
                            console.print(f"Current provider: [bold cyan]{p_title}[/bold cyan]")
                        continue

                    elif cmd == "/confirm":
                        if arg.lower() in ("on", "true", "yes", "1"):
                            decision_gate.require_confirmation = True
                            decision_gate.confirm_callback = confirm_prompt
                            console.print("[green]User decision confirmation gate: ENABLED[/green]")
                        elif arg.lower() in ("off", "false", "no", "0"):
                            decision_gate.require_confirmation = False
                            console.print("[yellow]User decision confirmation gate: DISABLED (auto-approving all actions)[/yellow]")
                        else:
                            state = "ENABLED" if decision_gate.require_confirmation else "DISABLED"
                            console.print(f"User decision confirmation gate is currently: [bold]{state}[/bold]")
                        continue

                    elif cmd == "/interfaces":
                        console.print("[dim]Fetching interfaces directly from tshark...[/dim]")
                        res = await session.call_tool("list_interfaces", {})
                        text = "\n".join(c.text for c in res.content if hasattr(c, "text"))
                        console.print(Panel(text or "No interfaces found", title="Available Interfaces", border_style="cyan"))
                        continue

                    elif cmd == "/captures":
                        console.print("[dim]Fetching capture files...[/dim]")
                        res = await session.call_tool("list_captures", {})
                        text = "\n".join(c.text for c in res.content if hasattr(c, "text"))
                        console.print(Panel(text or "No captures yet", title="Saved Captures", border_style="cyan"))
                        continue

                    elif cmd == "/status":
                        p_title = "Sarvam AI (Cloud)" if isinstance(provider, SarvamProvider) else "Ollama (Local)"
                        table = Table(title="Session Status")
                        table.add_column("Property")
                        table.add_column("Value")
                        table.add_row("Provider", p_title)
                        table.add_row("Supervisor Model", sup_model)
                        table.add_row("Agent Model", ag_model)
                        table.add_row("Decision Confirmation Gate", "ENABLED" if decision_gate.require_confirmation else "DISABLED")
                        table.add_row("Whitelisted in Session", ", ".join(decision_gate.always_allowed) or "(none)")
                        table.add_row("Known Capture Paths", str(len(runner.known_paths)))
                        console.print(table)
                        continue

                    elif cmd == "/clear":
                        runner, provider, sup_model, ag_model = _create_runner(
                            session=session,
                            tools=tools_resp.tools,
                            provider_name=current_provider_name,
                            cfg=cfg,
                            single=single,
                            quiet=quiet,
                            supervisor_model=supervisor_model,
                            agent_model=agent_model,
                            sarvam_api_key=sarvam_api_key,
                            decision_gate=decision_gate,
                            indicator=indicator,
                        )
                        console.print("[green]Conversation history cleared and context reset.[/green]")
                        continue

                    else:
                        console.print(f"[yellow]Unknown command '{cmd}'. Type /help for available commands.[/yellow]")
                        continue

                indicator.start()
                try:
                    answer = await runner.chat_turn(user_input)
                finally:
                    indicator.stop()

                last_answer = answer
                console.print()
                console.print(Panel(Markdown(answer), title="Assistant", border_style="green"))
                console.print()


@click.group(invoke_without_command=True)
@click.option("--config", "config_path", default=None, help="Path to a config.yaml (overrides search order).")
@click.pass_context
def cli(ctx, config_path):
    """NetAgent: Autonomous AI network forensic, packet capture, threat-hunting & analysis agent."""
    ctx.ensure_object(dict)
    ctx.obj["cfg"] = load_config(config_path)
    if ctx.invoked_subcommand is None:
        ctx.invoke(chat)


@cli.command()
@click.option(
    "-p", "--provider", "provider_name",
    type=click.Choice(["ollama", "sarvam"], case_sensitive=False),
    default=None,
    help="AI provider to use: 'ollama' (local) or 'sarvam' (cloud API-key based).",
)
@click.option("--sarvam-api-key", default=None, help="Sarvam AI API key (overrides SARVAM_API_KEY env var).")
@click.option("--single", is_flag=True, help="Use single-agent mode instead of the multi-agent supervisor.")
@click.option("--quiet", is_flag=True, help="Suppress tool-call / delegation logging.")
@click.option("--no-confirm", is_flag=True, help="Disable interactive confirmation gates for sensitive actions.")
@click.option("--supervisor-model", default=None, help="Override the supervisor model.")
@click.option("--agent-model", default=None, help="Override the specialist/single-agent model.")
@click.pass_context
def chat(ctx, provider_name, sarvam_api_key, single, quiet, no_confirm, supervisor_model, agent_model):
    """Start an interactive chat session backed by Wireshark MCP tools and AI agents."""
    cfg: Config = ctx.obj["cfg"]
    try:
        asyncio.run(_run_chat(
            cfg=cfg,
            single=single,
            quiet=quiet,
            supervisor_model=supervisor_model,
            agent_model=agent_model,
            provider_name=provider_name,
            sarvam_api_key=sarvam_api_key,
            no_confirm=no_confirm,
        ))
    except KeyboardInterrupt:
        pass
    console.print("[dim]Session ended.[/dim]")


@cli.command()
@click.pass_context
def server(ctx):
    """Run the MCP server on stdio (for use as a tool server from an MCP client)."""
    from . import server as server_module  # noqa: F401
    server_module.mcp.run()


@cli.command()
@click.pass_context
def authorize(ctx):
    """One-time acknowledgment of authorized-use terms, required before any capture tool will run."""
    cfg: Config = ctx.obj["cfg"]
    console.print(Panel(AUTHORIZATION_NOTICE, title="Authorization required", border_style="yellow"))
    reply = console.input("Type [bold]I AGREE[/bold] to confirm you are authorized: ").strip()
    if reply != "I AGREE":
        console.print("[red]Not confirmed. Capture tools remain disabled.[/red]")
        sys.exit(1)
    marker = cfg.security.get("ack_marker_file")
    os.makedirs(os.path.dirname(marker), exist_ok=True)
    with open(marker, "w", encoding="utf-8") as fh:
        fh.write(f"acknowledged {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    console.print(f"[green]Recorded.[/green] Capture tools are now enabled (marker: {marker}).")


@cli.command()
@click.pass_context
def doctor(ctx):
    """Check that tshark, Ollama, Sarvam AI, and security/decision configurations are operational."""
    cfg: Config = ctx.obj["cfg"]
    table = Table(title="NetAgent Environment & AI Provider Check")
    table.add_column("Component / Check")
    table.add_column("Status")

    # 1. tshark check
    tshark_path = shutil.which(cfg.tshark_path) or (cfg.tshark_path if os.path.isfile(cfg.tshark_path) else None)
    if tshark_path:
        try:
            out = subprocess.run([tshark_path, "-v"], capture_output=True, text=True, timeout=10)
            version = out.stdout.splitlines()[0] if out.stdout else "unknown version"
        except Exception as e:
            version = f"found but failed to run: {e}"
        table.add_row("tshark (CLI)", f"[green]OK[/green] — {tshark_path} ({version})")
    else:
        table.add_row("tshark (CLI)", f"[red]NOT FOUND[/red] — set tshark_path in config or add to PATH")

    # 2. Desktop Wireshark GUI
    gui_path = getattr(cfg, "wireshark_gui_path", "wireshark")
    resolved_gui = shutil.which(gui_path) or (gui_path if os.path.isfile(gui_path) else None)
    if resolved_gui:
        table.add_row("Desktop Wireshark", f"[green]OK[/green] — {resolved_gui}")
    else:
        table.add_row("Desktop Wireshark", "[yellow]NOT FOUND[/yellow] (optional for visual inspection)")

    # 3. Nmap Network Scanner
    nmap_path = shutil.which("nmap")
    if nmap_path:
        table.add_row("Nmap Scanner", f"[green]OK[/green] — {nmap_path}")
    else:
        table.add_row("Nmap Scanner", "[yellow]NOT FOUND[/yellow] (falling back to high-performance socket scanner)")

    # 4. OS Network Inspection Tools & Subagent Engine (psutil)
    if sys.platform == "win32":
        try:
            ps_out = subprocess.run(["powershell", "-NoProfile", "-Command", "Get-Command Get-NetAdapter, Get-NetTCPConnection, Test-NetConnection | Measure-Object | Select-Object -ExpandProperty Count"], capture_output=True, text=True, timeout=5)
            count = ps_out.stdout.strip()
            table.add_row("PowerShell Tools", f"[green]OK[/green] — Get-NetAdapter, Get-NetTCPConnection, Test-NetConnection ({count} found)")
        except Exception:
            table.add_row("PowerShell Tools", "[yellow]Available via powershell.exe[/yellow]")
    else:
        tools_found = []
        for t in ["ip", "ss", "netstat", "tcpdump"]:
            if shutil.which(t):
                tools_found.append(t)
        if tools_found:
            table.add_row("Linux Net Tools", f"[green]OK[/green] — {', '.join(tools_found)}")
        else:
            table.add_row("Linux Net Tools", "[yellow]Basic tools missing (iproute2/net-tools)[/yellow]")

    try:
        import psutil  # type: ignore
        table.add_row("Process Monitor (psutil)", f"[green]OK[/green] — v{psutil.__version__}")
    except ImportError:
        table.add_row("Process Monitor (psutil)", "[red]MISSING[/red] — run `pip install psutil` for background monitors")

    # 4. Configured provider
    active_p = cfg.provider
    table.add_row("Active Provider", f"[bold cyan]{active_p}[/bold cyan]")

    # 5. Sarvam AI provider check
    try:
        sarvam_p = SarvamProvider(
            api_key=cfg.sarvam.get("api_key"),
            base_url=cfg.sarvam.get("base_url", "https://api.sarvam.ai/v1"),
        )
        sup_s = cfg.sarvam.get("supervisor_model", "sarvam-105b")
        ag_s = cfg.sarvam.get("agent_model", "sarvam-105b-conversations")
        ok_s, msg_s = sarvam_p.check_health(sup_s, ag_s)
        if ok_s:
            status_sarvam = f"[green]OK[/green] — {msg_s}"
        elif "API key not configured" in msg_s:
            status_sarvam = "[yellow]API key not configured[/yellow] — set SARVAM_API_KEY environment variable"
        else:
            status_sarvam = f"[red]ERROR[/red] — {msg_s}"
        table.add_row("Sarvam AI (Cloud)", status_sarvam)
    except Exception as e:
        table.add_row("Sarvam AI (Cloud)", f"[red]CHECK FAILED[/red] — {e}")

    # 6. Ollama provider check (optional)
    try:
        ollama_p = OllamaProvider(host=cfg.ollama.get("host"))
        sup = cfg.ollama.get("supervisor_model", "llama3.2:1b")
        ag = cfg.ollama.get("agent_model", "llama3.2:3b")
        ok, msg = ollama_p.check_health(sup, ag)
        status_str = f"[green]OK[/green] — {msg}" if ok else f"[dim]Not running (optional)[/dim]"
        table.add_row("Ollama (Optional)", status_str)
    except Exception:
        table.add_row("Ollama (Optional)", "[dim]Not running (optional — Sarvam AI active)[/dim]")

    # 5. User Decision Gate
    dec = cfg.decisions
    req_confirm = dec.get("require_confirmation", True)
    sens_tools = dec.get("sensitive_tools", [])
    if req_confirm:
        table.add_row(
            "User Decision Gate",
            f"[green]ENABLED[/green] — asks user confirmation for: {', '.join(sens_tools)}",
        )
    else:
        table.add_row("User Decision Gate", "[yellow]DISABLED[/yellow] (auto-approving all actions)")

    # 6. Capture authorization
    marker = cfg.security.get("ack_marker_file")
    table.add_row(
        "Capture authorization",
        "[green]acknowledged[/green]" if marker and os.path.isfile(marker)
        else "[yellow]not yet — run: wireshark-agent authorize[/yellow]",
    )

    # 7. Directories & Sandboxes
    table.add_row("Capture dir", cfg.capture_dir)
    table.add_row("Pcap Sandbox", cfg.sandbox_dir)
    table.add_row("Session Store", cfg.sessions_dir)
    table.add_row("Memory Store", cfg.memory_dir)
    console.print(table)


@cli.group()
def captures():
    """List, inspect, or clean up saved packet captures."""


@captures.command("list")
@click.pass_context
def captures_list(ctx):
    """List saved capture files across /capture and /data folders."""
    cfg: Config = ctx.obj["cfg"]
    from .tshark_utils import TsharkRunner
    runner = TsharkRunner(cfg)
    files = runner.list_capture_files()
    if not files:
        console.print("No captures found in /capture or /data yet.")
        return
    table = Table()
    table.add_column("Location")
    table.add_column("File")
    table.add_column("Size", justify="right")
    table.add_column("Age")
    now = time.time()
    for f in files:
        size = os.path.getsize(f)
        age_min = round((now - os.path.getmtime(f)) / 60, 1)
        folder_tag = "[cyan]capture[/cyan]" if "capture" in f.lower() else "[yellow]data[/yellow]"
        table.add_row(folder_tag, f, f"{size:,} B", f"{age_min} min")
    console.print(table)


@captures.command("clean")
@click.option("--max-age-hours", default=None, type=float, help="Delete captures older than this many hours.")
@click.confirmation_option(prompt="Delete matching capture files?")
@click.pass_context
def captures_clean(ctx, max_age_hours):
    """Delete old capture files (defaults to retention.max_age_hours from config)."""
    cfg: Config = ctx.obj["cfg"]
    threshold = max_age_hours if max_age_hours is not None else cfg.retention["max_age_hours"]
    if not os.path.isdir(cfg.capture_dir):
        console.print("Capture directory doesn't exist yet — nothing to clean.")
        return
    now = time.time()
    removed = 0
    for f in os.listdir(cfg.capture_dir):
        fp = os.path.join(cfg.capture_dir, f)
        if not (os.path.isfile(fp) and f.lower().endswith((".pcap", ".pcapng"))):
            continue
        age_h = (now - os.path.getmtime(fp)) / 3600
        if age_h >= threshold:
            os.remove(fp)
            removed += 1
    console.print(f"Removed {removed} file(s) older than {threshold}h.")


@cli.command("config")
@click.pass_context
def show_config(ctx):
    """Show the effective configuration (defaults + config.yaml + env overrides)."""
    cfg: Config = ctx.obj["cfg"]
    import json as _json
    console.print(Panel(_json.dumps(cfg.raw, indent=2, default=str), title="Effective configuration"))


@cli.group()
def monitor():
    """Manage continuous network monitoring subagents running in the background."""


@monitor.command("list")
def monitor_list():
    """List all running and registered continuous monitoring subagents."""
    from .monitor import ContinuousMonitorManager
    mgr = ContinuousMonitorManager()
    monitors = mgr.list_monitors()
    if not monitors:
        console.print("No continuous monitoring subagents registered.")
        return
    t = Table(title=f"Continuous Monitoring Subagents ({len(monitors)})")
    t.add_column("ID", style="bold cyan")
    t.add_column("Name")
    t.add_column("Interface")
    t.add_column("PID")
    t.add_column("Status")
    t.add_column("Packets", justify="right")
    t.add_column("Threats", justify="right")
    t.add_column("Last Run")
    for m in monitors:
        st = m.get("stats", {})
        stat_str = f"[green]{m['status']}[/green]" if m.get("status") == "RUNNING" else f"[dim]{m.get('status')}[/dim]"
        t.add_row(
            m["id"],
            m.get("name", ""),
            str(m.get("interface", "")),
            str(m.get("pid") or "-"),
            stat_str,
            f"{st.get('total_packets', 0):,}",
            str(st.get("threats_detected", 0)),
            st.get("last_run") or "Never",
        )
    console.print(t)


@monitor.command("start")
@click.option("--name", default=None, help="Descriptive name for the subagent.")
@click.option("--interface", "-i", default="1", help="Network interface index or name.")
@click.option("--interval", default=25, type=int, help="Cycle interval between probes in seconds.")
@click.option("--duration", default=10, type=int, help="Capture probe duration in seconds.")
@click.option("--rules", default=None, help="Comma-separated rules (e.g. port_scan,cleartext_creds,arp_spoof).")
def monitor_start(name, interface, interval, duration, rules):
    """Spawn a detached continuous monitoring subagent."""
    from .monitor import ContinuousMonitorManager
    mgr = ContinuousMonitorManager()
    rule_list = [r.strip() for r in rules.split(",")] if rules else None
    res = mgr.start_monitor(
        name=name,
        interface=interface,
        interval=interval,
        capture_duration=duration,
        rules=rule_list,
    )
    console.print(Panel(
        f"[green][OK] Started continuous monitoring subagent:[/green]\n"
        f"  • ID: [bold]{res['id']}[/bold]\n"
        f"  • Name: {res['name']}\n"
        f"  • Interface: {res['interface']}\n"
        f"  • PID: {res['pid']} (Detached background daemon)\n"
        f"  • Interval: {res['interval_seconds']}s (Capture probe: {res['capture_duration']}s)\n"
        f"  • Rules: {', '.join(res['rules'])}\n\n"
        f"[dim]This subagent continues running even if PowerShell is closed.\n"
        f"Query statistics anytime with: netagent monitor stats {res['id']}[/dim]",
        border_style="green",
    ))


@monitor.command("stop")
@click.argument("monitor_id")
def monitor_stop(monitor_id):
    """Stop a running continuous monitoring subagent."""
    from .monitor import ContinuousMonitorManager
    mgr = ContinuousMonitorManager()
    ok = mgr.stop_monitor(monitor_id)
    if ok:
        console.print(f"[green][OK] Stopped monitoring subagent '{monitor_id}'[/green]")
    else:
        console.print(f"[red]Failed to stop subagent '{monitor_id}'[/red]")


@monitor.command("stats")
@click.argument("monitor_id")
def monitor_stats(monitor_id):
    """View detailed statistics and alerts for a monitoring subagent."""
    from .monitor import ContinuousMonitorManager
    mgr = ContinuousMonitorManager()
    m = mgr.get_monitor(monitor_id)
    if not m:
        console.print(f"[red]Subagent '{monitor_id}' not found.[/red]")
        return
    st = m.get("stats", {})
    stat_panel = (
        f"[bold]Subagent:[/bold] {m.get('name')} ([cyan]{m['id']}[/cyan])\n"
        f"[bold]Status:[/bold] {m.get('status')} | [bold]PID:[/bold] {m.get('pid') or '-'}\n"
        f"[bold]Interface:[/bold] {m.get('interface')} | [bold]Interval:[/bold] {m.get('interval_seconds')}s\n"
        f"[bold]Rules:[/bold] {', '.join(m.get('rules', []))}\n"
        f"[bold]Total Cycles:[/bold] {st.get('total_cycles', 0)}\n"
        f"[bold]Packets Inspected:[/bold] {st.get('total_packets', 0):,}\n"
        f"[bold]Threats Detected:[/bold] {st.get('threats_detected', 0)}\n"
        f"[bold]Last Active:[/bold] {st.get('last_run') or 'Never'}\n"
    )
    recent = st.get("recent_alerts", [])
    if recent:
        stat_panel += "\n[bold red]Recent Alerts:[/bold red]\n"
        for a in recent[-10:]:
            stat_panel += f"  • [{a.get('timestamp')}] {a.get('level')} - {a.get('rule')}: {a.get('message')}\n"
    console.print(Panel(stat_panel, title=f"Subagent Statistics: {m['id']}", border_style="cyan"))


@monitor.command("delete")
@click.argument("monitor_id")
def monitor_delete(monitor_id):
    """Stop and delete a monitoring subagent."""
    from .monitor import ContinuousMonitorManager
    mgr = ContinuousMonitorManager()
    ok = mgr.delete_monitor(monitor_id)
    if ok:
        console.print(f"[yellow][OK] Deleted monitoring subagent '{monitor_id}'[/yellow]")
    else:
        console.print(f"[red]Failed to delete subagent '{monitor_id}'[/red]")


@cli.group()
def telegram():
    """Test and configure Telegram alerts for critical security events."""


@telegram.command("test")
def telegram_test():
    """Test Telegram Bot connection and send a test message."""
    from .telegram import TelegramNotifier
    notifier = TelegramNotifier()
    console.print("Testing Telegram connection...")
    res = notifier.test_connection()
    if res.get("success"):
        console.print(Panel(
            f"[green][OK] Telegram Bot Verified![/green]\n"
            f"• Bot Username: @{res.get('bot_username')}\n"
            f"• Status: {res.get('message')}",
            border_style="green",
        ))
    else:
        console.print(Panel(
            f"[red]✗ Telegram Connection Failed[/red]\n"
            f"• Error: {res.get('error')}",
            border_style="red",
        ))


@telegram.command("alert")
@click.argument("message")
@click.option("--level", default="CRITICAL", help="Alert severity: CRITICAL, HIGH, WARNING, INFO")
def telegram_alert(message, level):
    """Send an immediate manual alert over Telegram."""
    from .telegram import TelegramNotifier
    notifier = TelegramNotifier()
    res = notifier.send_alert(message=message, level=level)
    if res.get("success"):
        console.print(f"[green][OK] Alert sent successfully (message ID: {res.get('message_id')})[/green]")
    else:
        console.print(f"[red]Failed to send alert: {res.get('error')}[/red]")


@telegram.command("start")
def telegram_start():
    """Start the interactive 2-way Telegram bot as a detached background daemon."""
    from .telegram import TelegramBotService
    bot = TelegramBotService()
    res = bot.start_daemon()
    if res.get("success"):
        console.print(f"[green][OK] {res.get('message')}[/green]")
    else:
        console.print(f"[red]Failed to start Telegram daemon: {res.get('error')}[/red]")


@telegram.command("stop")
def telegram_stop():
    """Stop the background Telegram bot daemon."""
    from .telegram import TelegramBotService
    bot = TelegramBotService()
    res = bot.stop_daemon()
    console.print(f"[yellow][OK] {res.get('message')}[/yellow]")


@telegram.command("status")
def telegram_status():
    """Check whether the Telegram bot daemon is active."""
    from .telegram import TelegramBotService
    bot = TelegramBotService()
    st = bot.get_daemon_status()
    if st.get("running"):
        console.print(Panel(
            f"[green]● Telegram Bot Daemon is RUNNING (PID: {st.get('pid')})[/green]\n"
            f"• Logs: {bot.log_file}\n"
            f"• You can message your BotFather bot directly from your phone to talk to NetAgent!",
            border_style="green",
        ))
    else:
        console.print(Panel(
            "[yellow]● Telegram Bot Daemon is STOPPED.[/yellow]\n"
            "• Start it with: [bold]netagent telegram start[/bold]",
            border_style="yellow",
        ))


@telegram.command("bot")
def telegram_bot():
    """Run the 2-way interactive Telegram bot listener in the foreground."""
    from .telegram import TelegramBotService
    bot = TelegramBotService()
    if not bot.bot_token:
        console.print("[red]Telegram bot token not configured. Set TELEGRAM_BOT_TOKEN.[/red]")
        return
    console.print(Panel(
        f"[green]Starting NetAgent Telegram Interactive Bot...[/green]\n"
        f"• Listening for Telegram messages (press Ctrl+C to stop)\n"
        f"• Direct messaging enabled for authorized chat ID: {bot.chat_id or 'Waiting for first message'}",
        border_style="green",
    ))
    try:
        bot.run_polling()
    except KeyboardInterrupt:
        console.print("\n[yellow]Telegram bot stopped.[/yellow]")


@cli.group()
def virustotal():
    """VirusTotal IP address intelligence and threat reputation."""


@virustotal.command("check")
@click.argument("ip")
def vt_check(ip):
    """Check an IP address against VirusTotal (uses cache if already tested)."""
    from .virustotal import VirusTotalClient
    vt = VirusTotalClient()
    rep = vt.check_ip(ip, send_alerts=True)
    if "error" in rep:
        console.print(f"[red]Error: {rep['error']}[/red]")
        return
    status_color = "red" if rep.get("is_malicious") else "green"
    status_title = "MALICIOUS THREAT" if rep.get("is_malicious") else "CLEAN / BENIGN"
    stats = rep.get("stats", {})
    cached_str = " (From Cache - No API token spent)" if rep.get("cached") else " (Fresh Scan)"
    console.print(Panel(
        f"[{status_color} bold]Verdict: {status_title}[/{status_color} bold]{cached_str}\n\n"
        f"• IP Address: [bold]{rep.get('ip')}[/bold]\n"
        f"• Malicious Score: [bold]{rep.get('malicious_score')}%[/bold]\n"
        f"• Detections: {stats.get('malicious', 0)}/{stats.get('total_engines', 0)} vendors\n"
        f"• Org: {rep.get('as_owner')} ({rep.get('country')})\n"
        f"• Scan Time: {rep.get('scanned_at')}",
        title=f"VirusTotal Report: {rep.get('ip')}",
        border_style=status_color,
    ))


@virustotal.command("cache")
def vt_cache():
    """List all cached IP reputation results stored in memory."""
    from .virustotal import VirusTotalClient
    vt = VirusTotalClient()
    entries = vt.cache
    if not entries:
        console.print("No IPs currently cached in VirusTotal intelligence store.")
        return
    t = Table(title=f"VirusTotal Cached IP Intelligence ({len(entries)} IPs)")
    t.add_column("IP Address", style="bold cyan")
    t.add_column("Score", justify="right")
    t.add_column("Verdict")
    t.add_column("Organization")
    t.add_column("Country")
    t.add_column("Scanned At")
    for ip_val, data in entries.items():
        mal = data.get("is_malicious", False)
        verdict_col = "[red]MALICIOUS[/red]" if mal else "[green]CLEAN[/green]"
        score_str = f"{data.get('malicious_score', 0)}%"
        t.add_row(ip_val, score_str, verdict_col, data.get("as_owner", "Unknown"), data.get("country", "Unknown"), data.get("scanned_at", ""))
    console.print(t)


@cli.command("scan")
@click.argument("target")
@click.option("-p", "--ports", default="common", help="Ports to audit: 'common', '80,443,8080', or '1-100'.")
@click.option("--bg", is_flag=True, help="Execute scan asynchronously in background.")
def cli_scan(target, ports, bg):
    """Run an Nmap/socket port scan and JEV security evaluation on an IP or host."""
    from .server import port_scan_host
    console.print(f"[dim]Initiating {'background ' if bg else ''}port scan against [bold]{target}[/bold] (ports: {ports})...[/dim]")
    res = port_scan_host(target=target, ports=ports, background=bg)
    console.print(Panel(res, title=f"Port Scan: {target}", border_style="cyan"))


@cli.command("scan-result")
@click.argument("scan_id")
def cli_scan_result(scan_id):
    """View the results and JEV decision analysis of a background port scan."""
    from .server import get_scan_result
    res = get_scan_result(scan_id)
    console.print(Panel(res, title=f"Scan Result: {scan_id}", border_style="cyan"))


@cli.command("scans")
def cli_scans():
    """List all cached and background port scans."""
    from pathlib import Path
    import json
    from .config import load_config
    cfg = load_config()
    scan_files = []
    seen_ids = set()
    for sdir in [Path(cfg.scans_dir), Path(cfg.monitors_dir) / "scans"]:
        if sdir.is_dir():
            for sf in sorted(sdir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
                if sf.stem not in seen_ids:
                    seen_ids.add(sf.stem)
                    scan_files.append(sf)
    if not scan_files:
        console.print("[yellow]No scans found in cache.[/yellow]")
        return
    scan_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    t = Table(title=f"Recorded Network Port Scans ({len(scan_files)})")
    t.add_column("Scan ID", style="bold cyan")
    t.add_column("Target")
    t.add_column("Status")
    t.add_column("Engine")
    t.add_column("Open Ports", justify="right")
    t.add_column("JEV Score")
    t.add_column("Timestamp")
    for sf in scan_files:
        try:
            with open(sf, "r", encoding="utf-8") as fh:
                d = json.load(fh)
                jd = d.get("jev_decision", {})
                score_str = f"{jd.get('threat_score')}/10" if jd else "-"
                t.add_row(
                    sf.stem,
                    d.get("target", "Unknown"),
                    d.get("status", "COMPLETED"),
                    d.get("engine", "Socket"),
                    str(len(d.get("open_ports", []))),
                    score_str,
                    d.get("timestamp", ""),
                )
        except Exception:
            pass
    console.print(t)


@cli.command("run-scan-worker", hidden=True)
@click.argument("target")
@click.argument("ports")
@click.argument("scan_id")
def cli_run_scan_worker(target, ports, scan_id):
    """Internal detached worker for background port scans."""
    from .server import _run_scan_worker
    _run_scan_worker(target, ports, scan_id)


# =========================================================================
# MCP Server & External Agent Integration Commands
# =========================================================================

@cli.group("mcp")
def cli_mcp():
    """Manage Model Context Protocol (MCP) server configuration and agent integrations."""
    pass


@cli_mcp.command("config")
def cli_mcp_config():
    """Display ready-to-copy MCP configuration for Claude Desktop, Cursor, and AI agents."""
    import json
    python_exe = sys.executable
    sarvam_key = os.environ.get("SARVAM_API_KEY", "YOUR_SARVAM_API_KEY")
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "YOUR_VIRUSTOTAL_API_KEY")
    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "YOUR_TELEGRAM_BOT_TOKEN")
    tg_chat = os.environ.get("TELEGRAM_CHAT_ID", "YOUR_TELEGRAM_CHAT_ID")

    claude_cfg = {
        "mcpServers": {
            "netagent": {
                "command": python_exe,
                "args": ["-m", "wireshark_mcp.server"],
                "env": {
                    "SARVAM_API_KEY": sarvam_key,
                    "VIRUSTOTAL_API_KEY": vt_key,
                    "TELEGRAM_BOT_TOKEN": tg_token,
                    "TELEGRAM_CHAT_ID": tg_chat,
                }
            }
        }
    }

    console.print(Panel(
        "[bold cyan]Claude Desktop Configuration (claude_desktop_config.json)[/bold cyan]\n"
        "[dim]Windows: %APPDATA%\\Claude\\claude_desktop_config.json\n"
        "macOS: ~/Library/Application Support/Claude/claude_desktop_config.json\n"
        "Linux: ~/.config/Claude/claude_desktop_config.json[/dim]\n\n"
        f"[green]{json.dumps(claude_cfg, indent=2)}[/green]",
        title="[bold green]Claude Desktop MCP Integration[/bold green]",
        border_style="cyan"
    ))

    console.print(Panel(
        "[bold cyan]Claude Code CLI Integration One-Liner:[/bold cyan]\n\n"
        f"[yellow]claude mcp add netagent -- \"{python_exe}\" -m wireshark_mcp.server[/yellow]\n\n"
        "[bold cyan]Cursor IDE Integration (.cursor/mcp.json):[/bold cyan]\n\n"
        f"[yellow]A pre-configured .cursor/mcp.json has been created in this repository root.[/yellow]",
        title="[bold green]Developer IDE Integration[/bold green]",
        border_style="cyan"
    ))


@cli_mcp.command("install-claude")
def cli_mcp_install_claude():
    """Automatically register NetAgent into Claude Desktop configuration."""
    import json
    from pathlib import Path
    python_exe = sys.executable
    if sys.platform == "win32":
        cfg_path = Path(os.environ.get("APPDATA", "")) / "Claude" / "claude_desktop_config.json"
    elif sys.platform == "darwin":
        cfg_path = Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    else:
        cfg_path = Path.home() / ".config" / "Claude" / "claude_desktop_config.json"

    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    existing_cfg = {}
    if cfg_path.is_file():
        try:
            with open(cfg_path, "r", encoding="utf-8") as fh:
                existing_cfg = json.load(fh)
        except Exception:
            existing_cfg = {}

    mcp_servers = existing_cfg.setdefault("mcpServers", {})
    mcp_servers["netagent"] = {
        "command": python_exe,
        "args": ["-m", "wireshark_mcp.server"],
        "env": {
            "SARVAM_API_KEY": os.environ.get("SARVAM_API_KEY", ""),
            "VIRUSTOTAL_API_KEY": os.environ.get("VIRUSTOTAL_API_KEY", ""),
            "TELEGRAM_BOT_TOKEN": os.environ.get("TELEGRAM_BOT_TOKEN", ""),
            "TELEGRAM_CHAT_ID": os.environ.get("TELEGRAM_CHAT_ID", ""),
        }
    }

    try:
        with open(cfg_path, "w", encoding="utf-8") as fh:
            json.dump(existing_cfg, fh, indent=2)
        console.print(Panel(
            f"[bold green][OK] NetAgent MCP server successfully registered into Claude Desktop![/bold green]\n\n"
            f"Config file: [cyan]{cfg_path}[/cyan]\n\n"
            f"[yellow]Restart Claude Desktop to immediately access all 58 NetAgent network forensic tools.[/yellow]",
            title="[bold green]Installation Succeeded[/bold green]",
            border_style="green"
        ))
    except Exception as e:
        console.print(f"[bold red]Failed to write Claude Desktop configuration: {e}[/bold red]")


@cli_mcp.command("test")
def cli_mcp_test():
    """Verify MCP server startup, tool listing, prompts, and resources."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    async def _test():
        params = StdioServerParameters(command=sys.executable, args=["-m", "wireshark_mcp.server"])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools_res = await session.list_tools()
                prompts_res = await session.list_prompts()
                resources_res = await session.list_resources()
                console.print(f"[bold green][OK] MCP Server Handshake Successful![/bold green]")
                console.print(f"  • Tools Exposed: [bold cyan]{len(tools_res.tools)}[/bold cyan]")
                console.print(f"  • Prompts Available: [bold cyan]{len(prompts_res.prompts)}[/bold cyan] ({', '.join(p.name for p in prompts_res.prompts)})")
                console.print(f"  • Resources Available: [bold cyan]{len(resources_res.resources)}[/bold cyan] ({', '.join(str(r.uri) for r in resources_res.resources)})")
    try:
        asyncio.run(_test())
    except Exception as e:
        console.print(f"[bold red]MCP Test Failed: {e}[/bold red]")


def main():
    cli(obj={})


if __name__ == "__main__":
    main()
