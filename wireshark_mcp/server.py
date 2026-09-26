"""
MCP server exposing Wireshark (via tshark) as a broad tool surface for LLM agents:
interface/capture management, protocol & conversation stats, filtering, DNS/HTTP/TLS
extraction, and a set of threat-hunting heuristics (port scans, beaconing, ARP spoofing,
cleartext credentials).

Requires: Wireshark + Npcap/libpcap installed, tshark on PATH, `pip install "mcp<2"`.
Run standalone for stdio MCP clients (Claude Desktop, etc.):
    python -m wireshark_mcp.server
or via the CLI:
    wireshark-agent server
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .config import load_config
from .tshark_utils import CaptureError, CaptureHandle, TsharkRunner

SERVER_INSTRUCTIONS = """
NetAgent Autonomous Network Defense, Traffic Sentinel & Packet Forensics MCP Server.

You are interacting with NetAgent via the Model Context Protocol (MCP).
This server provides ~58 enterprise cybersecurity and network analysis tools backed by:
- Wireshark / TShark (deep packet inspection, PCAP dissection, protocol hierarchy, stream extraction)
- Nmap & Native High-Performance Socket Scanner (port auditing, service detection, exposure posture)
- VirusTotal API v3 (automated IP threat scoring, engine consensus, ASN/organization intelligence)
- Continuous 24/7 Subagent Daemons (background packet captures, sentinel rotation, persistent surveillance)
- Telegram BotFather Integration (instant push alerts and two-way SOC telemetry dispatch)
- Persistent Memory & Quarantine Sandbox (isolated analysis of untrusted captures, baseline topology rules)

OPERATIONAL GUIDELINES FOR AI AGENTS (Claude, Cursor, etc.):
1. INVESTIGATION METHODOLOGY:
   - Always scope the capture first using `quick_summary`, `packet_count`, and `protocol_hierarchy`.
   - Identify top talkers and protocols with `analyze_conversations` and `top_endpoints`.
   - Run threat-hunting heuristics (`detect_port_scans`, `detect_beaconing`, `detect_arp_spoof`, `find_credentials`).
   - Cross-reference newly connected public IP addresses against `virustotal_ip_report`.
   - When evaluating open ports, recommend defensive hardening (e.g. disable UPnP, close plaintext services).
2. SAFETY & DESTRUCTIVE ACTIONS:
   - Tools like `delete_capture`, `cleanup_old_captures`, `stop_all_captures`, and `start_ring_capture` modify system files or terminate processes. Exercise caution and verify user intent.
3. CLEAR EVIDENCE REPORTING:
   - State findings with exact metrics (e.g. packet counts, byte volumes, threat percentages, engine ratios).
   - Use `write_report` to save formal markdown incident assessments to disk for SOC operators.
"""

mcp = FastMCP("netagent", instructions=SERVER_INSTRUCTIONS)
CFG = load_config()
RUNNER = TsharkRunner(CFG)


def _err_guard(fn):
    """Decorator: turn CaptureError / unexpected exceptions into ERROR strings, never raise into MCP."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except CaptureError as e:
            return str(e)
        except Exception as e:  # last-resort guard so one bad tool call can't kill the server
            return f"ERROR: unexpected failure in {fn.__name__}: {e}"
    return wrapper


# =========================================================================
# Interfaces & capture file management
# =========================================================================

@mcp.tool()
@_err_guard
def authorize_capture() -> str:
    """Acknowledge authorized-use terms and enable live packet capture tools on this machine."""
    marker = RUNNER.cfg.security.get("ack_marker_file")
    if marker:
        os.makedirs(os.path.dirname(marker), exist_ok=True)
        with open(marker, "w", encoding="utf-8") as fh:
            fh.write(f"acknowledged {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    return "Authorized: live packet capture is now enabled on this machine."


@mcp.tool()
@_err_guard
def list_interfaces() -> str:
    """List available network interfaces that tshark can capture on (numbers/names to use as 'interface')."""
    return RUNNER.run(["-D"], resolve_names=True)


@mcp.tool()
@_err_guard
def list_captures() -> str:
    """List all pcap/pcapng files captured so far, newest first, with size and age. Use these exact paths in other tools."""
    files = RUNNER.list_capture_files()
    if not files:
        return "No captures yet."
    files.sort(key=os.path.getmtime, reverse=True)
    now = time.time()
    lines = []
    for f in files:
        age_min = round((now - os.path.getmtime(f)) / 60, 1)
        lines.append(f"{f}  ({os.path.getsize(f)} bytes, {age_min} min old)")
    return "\n".join(lines)


@mcp.tool()
@_err_guard
def delete_capture(path: str) -> str:
    """Delete a specific saved pcap/pcapng file by path. Irreversible."""
    err = RUNNER.validate_path(path)
    if err:
        return err
    os.remove(path)
    return f"Deleted {path}"


@mcp.tool()
@_err_guard
def cleanup_old_captures(max_age_hours: float = 168) -> str:
    """Delete saved capture files older than max_age_hours (default 168 = 7 days). Returns what was removed."""
    now = time.time()
    removed = []
    for f in RUNNER.list_capture_files():
        age_h = (now - os.path.getmtime(f)) / 3600
        if age_h >= max_age_hours:
            try:
                size = os.path.getsize(f)
                os.remove(f)
                removed.append(f"{f} ({size} bytes, {age_h:.1f}h old)")
            except OSError as e:
                removed.append(f"FAILED to remove {f}: {e}")
    if not removed:
        return f"No captures older than {max_age_hours}h."
    return "Removed:\n" + "\n".join(removed)


@mcp.tool()
@_err_guard
def open_in_wireshark(path: str, display_filter: str = "") -> str:
    """
    Open a saved pcap/pcapng capture file in the desktop Wireshark GUI for visual inspection.
    Optionally supply display_filter (e.g. 'http', 'tcp.port == 80', 'ip.addr == 34.34.34.34')
    to apply live packet filtering in real-time within the desktop Wireshark GUI.
    """
    err = RUNNER.validate_path(path)
    if err:
        return err
    resolved_path = RUNNER.resolve_path(path)
    gui_path = getattr(RUNNER.cfg, "wireshark_gui_path", r"C:\Program Files\Wireshark\Wireshark.exe")
    resolved_bin = shutil.which(gui_path) or (gui_path if os.path.isfile(gui_path) else None)
    if not resolved_bin:
        return f"ERROR: Wireshark desktop application not found at '{gui_path}'. Ensure Wireshark is installed."
    cmd = [resolved_bin, "-r", resolved_path]
    if display_filter and display_filter.strip():
        cmd += ["-Y", display_filter.strip()]
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    filter_note = f" with live display filter '{display_filter}'" if display_filter else ""
    return f"Opened {resolved_path} in desktop Wireshark GUI{filter_note}."


@mcp.tool()
@_err_guard
def powershell_adapters() -> str:
    """Get detailed Windows network adapter status, link speed, MAC address, and status via PowerShell Get-NetAdapter."""
    ps_cmd = "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress | Format-Table -AutoSize | Out-String -Width 120"
    result = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=15)
    return result.stdout.strip() or "No adapters found."


@mcp.tool()
@_err_guard
def powershell_network_connections(state: str = "Established", port: int = 0) -> str:
    """Inspect active TCP/UDP sockets with process IDs using Windows PowerShell (Get-NetTCPConnection)."""
    filter_clause = []
    if state:
        filter_clause.append(f"-State '{state}'")
    if port > 0:
        filter_clause.append(f"-LocalPort {port}")
    clause = " ".join(filter_clause)
    ps_cmd = (
        f"Get-NetTCPConnection {clause} | "
        "Select-Object -First 40 LocalAddress, LocalPort, RemoteAddress, RemotePort, State, "
        "@{Name='Process';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | "
        "Format-Table -AutoSize | Out-String -Width 120"
    )
    result = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=15)
    return result.stdout.strip() or "No connections found matching filter."


@mcp.tool()
@_err_guard
def powershell_test_connection(target: str, port: int = 443) -> str:
    """Test network connectivity, TCP handshake, and ping to target host/IP via PowerShell Test-NetConnection."""
    ps_cmd = f"Test-NetConnection -ComputerName '{target}' -Port {port} -WarningAction SilentlyContinue | Format-List ComputerName, RemoteAddress, RemotePort, TcpTestSucceeded, PingSucceeded, RoundTripTime | Out-String"
    result = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=20)
    return result.stdout.strip() or "No result returned."


# Mapping of standard service ports for native socket scanner
_COMMON_SERVICES = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted CLI)",
    25: "SMTP (Mail)",
    53: "DNS (Domain Name Service)",
    80: "HTTP (Web Server)",
    110: "POP3 (Mail)",
    135: "MS-RPC (Endpoint Mapper)",
    139: "NetBIOS (File/Print)",
    443: "HTTPS (Encrypted Web)",
    445: "SMB (Direct Host / Shares)",
    993: "IMAPS (Secure Mail)",
    995: "POP3S (Secure Mail)",
    1433: "MSSQL (Database)",
    3306: "MySQL (Database)",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL (Database)",
    8080: "HTTP-Alt / Proxy",
    8443: "HTTPS-Alt",
}


def _execute_scan_for_host(target: str, ports: str = "common") -> dict[str, Any]:
    import socket
    from concurrent.futures import ThreadPoolExecutor

    target = target.strip().strip("'").strip('"')
    port_list: list[int] = []
    if ports.strip().lower() in ("common", "default", ""):
        port_list = sorted(_COMMON_SERVICES.keys())
    elif "-" in ports and "," not in ports:
        try:
            start_p, end_p = [int(p.strip()) for p in ports.split("-", 1)]
            port_list = list(range(max(1, start_p), min(65535, end_p) + 1))[:100]
        except Exception:
            port_list = sorted(_COMMON_SERVICES.keys())
    else:
        for p_str in ports.split(","):
            p_clean = p_str.strip()
            if p_clean.isdigit():
                p_num = int(p_clean)
                if 1 <= p_num <= 65535:
                    port_list.append(p_num)
        port_list = sorted(set(port_list))[:100]

    if not port_list:
        port_list = sorted(_COMMON_SERVICES.keys())

    engine = "Native Socket Scanner"
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        for p in [r"C:\Program Files\Nmap\nmap.exe", r"C:\Program Files (x86)\Nmap\nmap.exe"]:
            if os.path.isfile(p):
                nmap_bin = p
                break
    nmap_output = ""

    if nmap_bin:
        try:
            engine = "Nmap Security Scanner"
            p_arg = ",".join(str(p) for p in port_list)
            cmd = [nmap_bin, "-sT", "-T4", "-Pn", "-p", p_arg, target]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            nmap_output = res.stdout.strip()
        except Exception:
            nmap_output = ""

    def _probe(p: int) -> tuple[int, str, float]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.2)
        t0 = time.perf_counter()
        try:
            r = s.connect_ex((target, p))
            ms = (time.perf_counter() - t0) * 1000
            s.close()
            return p, ("OPEN" if r == 0 else "CLOSED"), ms
        except Exception:
            return p, "FILTERED", 0.0

    with ThreadPoolExecutor(max_workers=min(20, len(port_list))) as ex:
        results = list(ex.map(_probe, port_list))

    open_ports = [r for r in results if r[1] == "OPEN"]
    closed_ports = [r for r in results if r[1] == "CLOSED"]
    filtered_ports = [r for r in results if r[1] == "FILTERED"]

    risks = []
    for p, _, _ in open_ports:
        if p in (21, 23):
            risks.append(f"HIGH: Port {p} ({_COMMON_SERVICES.get(p, 'Service')}) transmits unencrypted credentials in cleartext!")
        elif p in (3389, 445, 139):
            risks.append(f"WARNING: Port {p} ({_COMMON_SERVICES.get(p, 'Service')}) exposes remote administration/shares directly to network.")
        elif p in (3306, 5432, 1433):
            risks.append(f"WARNING: Port {p} ({_COMMON_SERVICES.get(p, 'Service')}) exposes database listening port.")

    # JEV Decision Analysis on scan output
    try:
        from .jev import JevModule
        jev_mod = JevModule()
        jev_decision = jev_mod.evaluate_scan(target, {
            "open_ports": open_ports,
            "risks": risks,
            "scanned_ports": len(port_list),
        })
    except Exception:
        jev_decision = None

    return {
        "target": target,
        "engine": engine,
        "scanned_ports": len(port_list),
        "open_ports": open_ports,
        "closed_count": len(closed_ports),
        "filtered_count": len(filtered_ports),
        "risks": risks,
        "jev_decision": jev_decision,
        "nmap_output": nmap_output,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _get_scans_dir() -> Path:
    p = Path(getattr(RUNNER.cfg, "scans_dir", os.path.join(RUNNER.cfg.data_dir, "scans")))
    p.mkdir(parents=True, exist_ok=True)
    return p


def _run_scan_worker(target: str, ports: str, scan_id: str):
    """Entry point for background port scan worker."""
    scans_dir = _get_scans_dir()
    scan_file = scans_dir / f"{scan_id}.json"

    # Avoid duplicate execution if already completed
    if scan_file.is_file():
        try:
            with open(scan_file, "r", encoding="utf-8") as fh:
                existing = json.load(fh)
                if existing.get("status") == "COMPLETED":
                    return
        except Exception:
            pass

    data = _execute_scan_for_host(target, ports)
    data["id"] = scan_id
    data["status"] = "COMPLETED"
    with open(scan_file, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


@mcp.tool()
@_err_guard
def port_scan_host(target: str, ports: str = "common", background: bool = False) -> str:
    """
    Perform a network port scan, service discovery, and vulnerability posture audit on an IP address or hostname.
    Uses Nmap if available on PATH; otherwise falls back to fast concurrent native TCP socket scanning.
    ports: 'common' (audits 19 standard service ports) or comma-separated list like '80,443,8080,3389' or '80-90'.
    background: if True, runs scan in background and returns a task token to check later via get_scan_result.
    """
    target = target.strip().strip("'").strip('"')
    if not target:
        return "ERROR: target host or IP must be specified."

    scans_dir = _get_scans_dir()

    if background:
        import uuid
        scan_id = f"scan_{uuid.uuid4().hex[:6]}"
        scan_file = scans_dir / f"{scan_id}.json"

        # Write initial in-progress record
        init_data = {
            "id": scan_id,
            "target": target,
            "status": "RUNNING",
            "ports": ports,
            "engine": "Native Socket Scanner / Nmap",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        with open(scan_file, "w", encoding="utf-8") as fh:
            json.dump(init_data, fh, indent=2)

        # In-process thread execution (fastest for interactive chat / MCP server)
        t = threading.Thread(target=_run_scan_worker, args=(target, ports, scan_id), daemon=True)
        t.start()

        # Detached background worker process (for CLI invocations that exit immediately)
        python_exe = sys.executable
        if "netagent" in Path(python_exe).name.lower() or "Scripts" in python_exe:
            cand = Path(python_exe).parent.parent / "python.exe"
            if cand.is_file():
                python_exe = str(cand)
            else:
                python_exe = shutil.which("python") or sys.executable

        creationflags = 0
        if sys.platform == "win32":
            # CREATE_NO_WINDOW (0x08000000) | CREATE_NEW_PROCESS_GROUP (0x00000200)
            creationflags = 0x08000000 | 0x00000200

        proj_root = str(Path(__file__).resolve().parent.parent)
        env = dict(os.environ, PYTHONPATH=proj_root)
        cmd = [python_exe, "-m", "wireshark_mcp.cli", "run-scan-worker", target, ports, scan_id]
        try:
            subprocess.Popen(
                cmd,
                cwd=proj_root,
                env=env,
                creationflags=creationflags,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
        except Exception:
            pass

        return (
            f"Background port scan initiated for {target}.\n"
            f"  Scan ID: {scan_id}\n"
            f"  Status: RUNNING (Background process)\n"
            f"  Ports: {ports}\n"
            f"Check status anytime with: get_scan_result('{scan_id}') or /scan result {scan_id}"
        )

    # Synchronous scan
    data = _execute_scan_for_host(target, ports)
    lines = [
        f"--- Port Scan & Service Audit: {target} ---",
        f"Engine: {data['engine']} | Time: {data['timestamp']}",
        f"Ports Audited: {data['scanned_ports']} | Open: {len(data['open_ports'])} | Closed: {data['closed_count']} | Filtered: {data['filtered_count']}\n",
    ]

    if data["open_ports"]:
        lines.append(f"{'PORT':<8} | {'STATE':<8} | {'SERVICE':<28} | {'LATENCY'}")
        lines.append("-" * 60)
        for p, state, ms in data["open_ports"]:
            svc = _COMMON_SERVICES.get(p, "Custom Service")
            lines.append(f"{p:<8} | {state:<8} | {svc:<28} | {ms:.1f}ms")
    else:
        lines.append(f"No open ports detected among the {data['scanned_ports']} ports audited.")

    if data["risks"]:
        lines.append("\n[!] Security Posture Warnings:")
        for r in data["risks"]:
            lines.append(f"  - {r}")
    else:
        lines.append("\n[OK] No high-risk administrative or cleartext protocols detected open.")

    if data.get("jev_decision"):
        jd = data["jev_decision"]
        lines.append(f"\n[JEV] Threat Decision Engine:")
        lines.append(f"  - Verdict: {jd.get('verdict')} (Score: {jd.get('threat_score')}/10)")
        lines.append(f"  - Assessment: {jd.get('reason')}")
        if jd.get("action_options"):
            lines.append("  - Autonomous Recommendations:")
            for opt in jd["action_options"]:
                lines.append(f"    {opt}")

    if data.get("nmap_output"):
        lines.append(f"\nNmap Raw Details:\n{data['nmap_output']}")

    return "\n".join(lines)


@mcp.tool()
@_err_guard
def run_nmap_scan(target: str, arguments: str = "-sT -T4 -Pn -F", background: bool = False) -> str:
    """
    Execute an Nmap security scan against a target IP or hostname with custom arguments (e.g. -sT -T4 -Pn -F).
    If Nmap is installed, runs Nmap directly and passes findings to the JEV decision engine.
    If Nmap is not installed, automatically runs NetAgent's native high-speed TCP socket scanner with JEV evaluation.
    Supports background execution via background=True.
    """
    target = target.strip().strip("'").strip('"')
    if not target:
        return "ERROR: target IP or hostname is required."

    if background:
        return port_scan_host(target=target, ports="common", background=True)

    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        for p in [r"C:\Program Files\Nmap\nmap.exe", r"C:\Program Files (x86)\Nmap\nmap.exe"]:
            if os.path.isfile(p):
                nmap_bin = p
                break

    if nmap_bin:
        try:
            import shlex
            extra_args = shlex.split(arguments)
            cmd = [nmap_bin] + extra_args + [target]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            raw_out = res.stdout.strip()
            from .jev import JevModule
            jev = JevModule()
            parsed_ports = []
            for line in raw_out.splitlines():
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    p_num = int(parts[0].split("/")[0])
                    svc = parts[2] if len(parts) > 2 else "Unknown"
                    parsed_ports.append((p_num, svc, 0.0))
            scan_payload = {
                "target": target,
                "engine": "Nmap Security Scanner",
                "scanned_ports": 100,
                "open_ports": parsed_ports,
                "risks": [],
                "raw_nmap": raw_out,
            }
            jev_eval = jev.evaluate_scan(target, scan_payload)
            report_lines = [
                f"=== Nmap Security Scan Report: {target} ===",
                f"Engine: Nmap Security Scanner ({nmap_bin})",
                f"Command: {nmap_bin} {arguments} {target}",
                "",
                "--- Nmap Raw Findings ---",
                raw_out,
                "",
                "--- JEV Threat Decision ---",
                f"Score: {jev_eval.get('jev_score')}/10.0 ({jev_eval.get('posture')})",
                f"Evaluation: {jev_eval.get('rationale')}",
                "Defensive Recommendations:",
            ]
            for act in jev_eval.get("recommended_actions", []):
                report_lines.append(f"  {act}")
            return "\n".join(report_lines)
        except Exception as e:
            return f"Nmap execution error: {e}. Falling back to native scanner:\n\n" + port_scan_host(target=target, ports="common", background=False)

    notice = "[INFO] Nmap binary not found on system PATH. Automatically executing NetAgent Native Socket Scanner with JEV decision engine:\n\n"
    return notice + port_scan_host(target=target, ports="common", background=False)


@mcp.tool()
@_err_guard
def get_scan_result(scan_id: str) -> str:
    """Retrieve the results and security posture analysis of a background port scan."""
    scans_dir = _get_scans_dir()
    scan_file = scans_dir / f"{scan_id}.json"
    if not scan_file.is_file():
        for alt in [Path(RUNNER.cfg.monitors_dir) / "scans", Path(tempfile.gettempdir()) / "wireshark_mcp_captures" / "monitors" / "scans"]:
            if (alt / f"{scan_id}.json").is_file():
                scan_file = alt / f"{scan_id}.json"
                break
    if not scan_file.is_file():
        return f"Scan ID '{scan_id}' not found. Verify ID or check if scan has completed."

    try:
        with open(scan_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        return f"Error reading scan result: {e}"

    status = data.get("status", "COMPLETED")
    if status == "RUNNING":
        return (
            f"Scan '{scan_id}' for {data.get('target')} is currently RUNNING in background.\n"
            f"Started: {data.get('timestamp')}\n"
            f"Please check again in a few moments."
        )

    lines = [
        f"--- Background Scan Result: {data.get('target')} ({data.get('id')}) ---",
        f"Engine: {data.get('engine')} | Status: {status} | Time: {data.get('timestamp')}",
        f"Audited: {data.get('scanned_ports')} | Open: {len(data.get('open_ports', []))} | Closed: {data.get('closed_count', 0)} | Filtered: {data.get('filtered_count', 0)}\n",
    ]

    open_ports = data.get("open_ports", [])
    if open_ports:
        lines.append(f"{'PORT':<8} | {'STATE':<8} | {'SERVICE':<28} | {'LATENCY'}")
        lines.append("-" * 60)
        for p, state, ms in open_ports:
            svc = _COMMON_SERVICES.get(p, "Custom Service")
            lines.append(f"{p:<8} | {state:<8} | {svc:<28} | {ms:.1f}ms")
    else:
        lines.append("No open ports found.")

    risks = data.get("risks", [])
    if risks:
        lines.append("\n[!] Security Posture Warnings:")
        for r in risks:
            lines.append(f"  - {r}")

    if data.get("jev_decision"):
        jd = data["jev_decision"]
        lines.append(f"\n[JEV] Threat Decision Engine:")
        lines.append(f"  - Verdict: {jd.get('verdict')} (Score: {jd.get('threat_score')}/10)")
        lines.append(f"  - Assessment: {jd.get('reason')}")
        if jd.get("action_options"):
            lines.append("  - Autonomous Recommendations:")
            for opt in jd["action_options"]:
                lines.append(f"    {opt}")

    return "\n".join(lines)


@mcp.tool()
@_err_guard
def jev_evaluate_target(target: str, context: str = "") -> str:
    """
    Query the JEV Threat Decision Engine to evaluate the security risk and posture of an IP or hostname.
    Correlates open port profile, exposure risks, and provides autonomous mitigation decisions.
    """
    from .jev import JevModule
    jev = JevModule()
    scans_dir = _get_scans_dir()
    cached_scan = None
    search_dirs = [scans_dir, Path(RUNNER.cfg.monitors_dir) / "scans", Path(tempfile.gettempdir()) / "wireshark_mcp_captures" / "monitors" / "scans"]
    for sdir in search_dirs:
        if sdir.is_dir() and not cached_scan:
            for sf in sorted(sdir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
                try:
                    with open(sf, "r", encoding="utf-8") as fh:
                        d = json.load(fh)
                        if d.get("target") == target:
                            cached_scan = d
                            break
                except Exception:
                    pass

    scan_info = cached_scan or {"open_ports": [], "risks": [], "scanned_ports": 0}
    decision = jev.evaluate_scan(target, scan_info)

    lines = [
        f"--- JEV Threat Decision: {target} ---",
        f"Verdict: {decision.get('verdict')} (Threat Score: {decision.get('threat_score')}/10)",
        f"Assessment: {decision.get('reason')}",
    ]
    if decision.get("action_options"):
        lines.append("\nRecommended Defensive Actions:")
        for opt in decision["action_options"]:
            lines.append(f"  {opt}")
    return "\n".join(lines)


# =========================================================================
# Capture: blocking (short) and background (long-running, agentic)
# =========================================================================

@mcp.tool()
@_err_guard
def capture_live(interface: str, duration_seconds: int = 10, bpf_filter: str = "", max_packets: int = 200) -> str:
    """
    Capture live packets on an interface for a fixed duration (or until max_packets), blocking until done.
    Use for short captures (a few seconds). For anything longer, use start_capture/stop_capture instead
    so you aren't stuck waiting. interface: as shown by list_interfaces. bpf_filter: e.g. 'tcp port 443'.
    """
    auth_err = RUNNER.check_authorized()
    if auth_err:
        return auth_err
    iface_err = RUNNER.check_interface_allowed(interface)
    if iface_err:
        return iface_err

    path = RUNNER.new_capture_path("live")
    args = ["-i", interface, "-a", f"duration:{duration_seconds}", "-c", str(max_packets), "-w", path]
    if bpf_filter:
        args += ["-f", bpf_filter]
    out = RUNNER.run(args, timeout=duration_seconds + 20, resolve_names=True)
    if out.startswith("ERROR"):
        return out
    summary = RUNNER.run(["-r", path, "-q", "-z", "io,phs"])
    return f"Capture saved to: {path}\n\nProtocol hierarchy:\n{summary}"


@mcp.tool()
@_err_guard
def start_capture(interface: str, bpf_filter: str = "", max_packets: int = 0) -> str:
    """
    Start a live capture in the BACKGROUND and return immediately with a capture_id and file path.
    Use for anything longer than a few seconds. Check progress with capture_status(capture_id) and
    end it with stop_capture(capture_id). max_packets: 0 means unlimited.
    """
    auth_err = RUNNER.check_authorized()
    if auth_err:
        return auth_err
    iface_err = RUNNER.check_interface_allowed(interface)
    if iface_err:
        return iface_err

    path = RUNNER.new_capture_path("bg")
    args = [RUNNER.cfg.tshark_path, "-i", interface, "-w", path]
    if bpf_filter:
        args += ["-f", bpf_filter]
    if max_packets > 0:
        args += ["-c", str(max_packets)]
    kwargs = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    try:
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **kwargs)
    except FileNotFoundError:
        return "ERROR: tshark not found. Install Wireshark and add its install folder to PATH."
    capture_id = f"c{len(RUNNER.captures) + 1}_{int(time.time()) % 100000}"
    RUNNER.captures[capture_id] = CaptureHandle(proc=proc, path=path, interface=interface, bpf_filter=bpf_filter)
    return f"Started capture {capture_id} on interface '{interface}' -> {path}\nCall stop_capture('{capture_id}') when done."


@mcp.tool()
@_err_guard
def start_ring_capture(interface: str, file_duration_seconds: int = 300, num_files: int = 5, bpf_filter: str = "") -> str:
    """
    Start a ROTATING (ring-buffer) background capture: writes a new file every
    file_duration_seconds, keeping only the last num_files (oldest deleted automatically by tshark).
    Good for continuous monitoring without unbounded disk growth. Returns a capture_id;
    use list_captures to see files produced so far, and stop_capture to end it.
    """
    auth_err = RUNNER.check_authorized()
    if auth_err:
        return auth_err
    iface_err = RUNNER.check_interface_allowed(interface)
    if iface_err:
        return iface_err

    base_path = RUNNER.new_capture_path("ring")
    args = [
        RUNNER.cfg.tshark_path, "-i", interface, "-w", base_path,
        "-b", f"duration:{file_duration_seconds}", "-b", f"files:{num_files}",
    ]
    if bpf_filter:
        args += ["-f", bpf_filter]
    kwargs = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    try:
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **kwargs)
    except FileNotFoundError:
        return "ERROR: tshark not found. Install Wireshark and add its install folder to PATH."
    capture_id = f"ring{len(RUNNER.captures) + 1}_{int(time.time()) % 100000}"
    RUNNER.captures[capture_id] = CaptureHandle(proc=proc, path=base_path, interface=interface, bpf_filter=bpf_filter)
    return (f"Started ring capture {capture_id} on '{interface}': {num_files} files x {file_duration_seconds}s, "
            f"base path {base_path}. Use list_captures to see rotated files; stop_capture('{capture_id}') to end.")


@mcp.tool()
@_err_guard
def capture_status(capture_id: str) -> str:
    """Check whether a background capture (start_capture/start_ring_capture) is still running, and for how long."""
    info = RUNNER.captures.get(capture_id)
    if not info:
        return f"ERROR: unknown capture_id '{capture_id}'. Known ids: {list(RUNNER.captures.keys())}"
    elapsed = round(time.time() - info.started, 1)
    if info.proc.poll() is None:
        size = os.path.getsize(info.path) if os.path.exists(info.path) else 0
        return f"RUNNING for {elapsed}s on '{info.interface}', file size so far: {size} bytes"
    return f"STOPPED after {elapsed}s. File ready at: {info.path}"


@mcp.tool()
@_err_guard
def stop_capture(capture_id: str) -> str:
    """Stop a background capture started with start_capture/start_ring_capture, finalizing its file(s)."""
    info = RUNNER.captures.get(capture_id)
    if not info:
        return f"ERROR: unknown capture_id '{capture_id}'. Known ids: {list(RUNNER.captures.keys())}"
    _terminate(info.proc)
    return f"Capture {capture_id} stopped. File ready at: {info.path}"


@mcp.tool()
@_err_guard
def stop_all_captures() -> str:
    """Stop every currently running background capture. Use this to make sure nothing is left running."""
    if not RUNNER.captures:
        return "No captures were running."
    results = []
    for cid, info in RUNNER.captures.items():
        if info.proc.poll() is None:
            _terminate(info.proc)
            results.append(f"{cid}: stopped -> {info.path}")
        else:
            results.append(f"{cid}: was already stopped -> {info.path}")
    return "\n".join(results)


def _terminate(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proc.terminate()
        proc.wait(timeout=10)
    except Exception:
        proc.kill()


# =========================================================================
# Analysis: read-only, works on any saved pcap path
# =========================================================================

@mcp.tool()
@_err_guard
def read_pcap_summary(path: str, max_lines: int = 50) -> str:
    """Read a saved pcap/pcapng file and return a one-line-per-packet summary (like Wireshark's packet list)."""
    err = RUNNER.validate_path(path)
    if err:
        return err
    return RUNNER.truncate(RUNNER.run(["-r", path]), max_lines)


@mcp.tool()
@_err_guard
def protocol_stats(path: str) -> str:
    """Return protocol hierarchy statistics (breakdown by protocol, with byte/packet counts) for a saved pcap file."""
    err = RUNNER.validate_path(path)
    if err:
        return err
    return RUNNER.run(["-r", path, "-q", "-z", "io,phs"])


@mcp.tool()
@_err_guard
def conversation_stats(path: str, protocol: str = "tcp") -> str:
    """
    Return 'top talkers' conversation statistics for a saved pcap file.
    protocol: one of 'tcp', 'udp', 'ip', 'eth'.
    """
    protocol = protocol.lower()
    if protocol not in {"tcp", "udp", "ip", "eth"}:
        return "ERROR: protocol must be one of tcp, udp, ip, eth"
    err = RUNNER.validate_path(path)
    if err:
        return err
    return RUNNER.run(["-r", path, "-q", "-z", f"conv,{protocol}"])


@mcp.tool()
@_err_guard
def endpoint_stats(path: str, protocol: str = "ip") -> str:
    """
    Return per-address endpoint statistics (packets/bytes sent per address) for a saved pcap file.
    protocol: one of 'ip', 'tcp', 'udp', 'eth'.
    """
    protocol = protocol.lower()
    if protocol not in {"ip", "tcp", "udp", "eth"}:
        return "ERROR: protocol must be one of ip, tcp, udp, eth"
    err = RUNNER.validate_path(path)
    if err:
        return err
    return RUNNER.run(["-r", path, "-q", "-z", f"endpoints,{protocol}"])


@mcp.tool()
@_err_guard
def filter_packets(path: str, display_filter: str, max_lines: int = 50) -> str:
    """
    Apply a Wireshark display filter (e.g. 'http', 'dns', 'ip.addr==192.168.1.1', 'tcp.port==443')
    to a saved pcap file and return matching packets.
    """
    err = RUNNER.validate_path(path)
    if err:
        return err
    out = RUNNER.run(["-r", path, "-Y", display_filter])
    if out.startswith("ERROR"):
        return out
    if not out.strip():
        return "No packets matched the filter."
    return RUNNER.truncate(out, max_lines)


@mcp.tool()
@_err_guard
def export_filtered_pcap(path: str, display_filter: str, out_name: str = "") -> str:
    """
    Apply a display filter to a saved pcap and write the MATCHING packets to a new, smaller pcap file.
    Useful to hand a narrowed-down capture to another tool/agent, or to save just the interesting traffic.
    """
    err = RUNNER.validate_path(path)
    if err:
        return err
    out_path = os.path.join(RUNNER.cfg.capture_dir, out_name) if out_name else RUNNER.new_capture_path("filtered")
    result = RUNNER.run(["-r", path, "-Y", display_filter, "-w", out_path])
    if result.startswith("ERROR"):
        return result
    if not os.path.isfile(out_path) or os.path.getsize(out_path) == 0:
        return "No packets matched the filter; no file written."
    return f"Wrote filtered capture to: {out_path} ({os.path.getsize(out_path)} bytes)"


@mcp.tool()
@_err_guard
def packet_detail(path: str, packet_number: int) -> str:
    """Get full field-by-field detail for one specific packet number in a saved pcap file."""
    err = RUNNER.validate_path(path)
    if err:
        return err
    out = RUNNER.run(["-r", path, "-V", f"frame.number=={packet_number}"])
    if out.startswith("ERROR"):
        return out
    return RUNNER.truncate(out, 60) if out.strip() else f"No packet numbered {packet_number} in this file."


@mcp.tool()
@_err_guard
def follow_tcp_stream(path: str, stream_index: int, max_lines: int = 200) -> str:
    """
    Reconstruct and return the full ASCII payload of one TCP stream (like Wireshark's
    'Follow TCP Stream'). stream_index: the tcp.stream number (see filter_packets with
    'tcp.stream==N', or conversation_stats, to find it).
    """
    err = RUNNER.validate_path(path)
    if err:
        return err
    out = RUNNER.run(["-r", path, "-q", "-z", f"follow,tcp,ascii,{stream_index}"])
    if out.startswith("ERROR"):
        return out
    if not out.strip():
        return f"No TCP stream {stream_index} found in this file."
    return RUNNER.truncate(out, max_lines)


@mcp.tool()
@_err_guard
def dns_queries(path: str, max_lines: int = 50) -> str:
    """List DNS queries and answers seen in a saved pcap file (frame #, source IP, query name, resolved address)."""
    err = RUNNER.validate_path(path)
    if err:
        return err
    out = RUNNER.run([
        "-r", path, "-Y", "dns", "-T", "fields",
        "-e", "frame.number", "-e", "ip.src", "-e", "dns.qry.name", "-e", "dns.a",
        "-E", "separator=|",
    ])
    if out.startswith("ERROR"):
        return out
    if not out.strip():
        return "No DNS traffic in this capture."
    return RUNNER.truncate(out, max_lines)


@mcp.tool()
@_err_guard
def http_requests(path: str, max_lines: int = 50) -> str:
    """List HTTP requests seen in a saved pcap file (frame #, source IP, host, method, URI)."""
    err = RUNNER.validate_path(path)
    if err:
        return err
    out = RUNNER.run([
        "-r", path, "-Y", "http.request", "-T", "fields",
        "-e", "frame.number", "-e", "ip.src", "-e", "http.host",
        "-e", "http.request.method", "-e", "http.request.uri",
        "-E", "separator=|",
    ])
    if out.startswith("ERROR"):
        return out
    if not out.strip():
        return "No HTTP requests in this capture (traffic may be HTTPS/TLS — see tls_sni)."
    return RUNNER.truncate(out, max_lines)


@mcp.tool()
@_err_guard
def http_rtt_delays(path: str, max_lines: int = 30) -> str:
    """
    Inspect HTTP request-to-response elapsed times and round-trip delays in a pcap file.
    Shows the exact time taken from when an HTTP GET/POST request was sent until the HTTP OK /
    status response was received, pairing request frame numbers with response frame numbers.
    """
    err = RUNNER.validate_path(path)
    if err:
        return err
    resolved_path = RUNNER.resolve_path(path)
    fields = [
        "frame.number",
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "http.request.method",
        "http.request.uri",
        "http.response.code",
        "http.time",
        "http.request_in",
        "http.response_in",
    ]
    rows = RUNNER.fields(resolved_path, "http", fields)
    if not rows:
        return "No HTTP traffic found in this capture."

    requests = {}
    delays = []
    for r in rows:
        if len(r) < 10:
            continue
        fnum, ftime, src, dst, method, uri, code, resp_time, req_in, resp_in = r
        if method:
            requests[fnum] = {
                "time": ftime,
                "src": src,
                "dst": dst,
                "method": method,
                "uri": uri,
                "resp_in": resp_in,
            }
        elif code and resp_time:
            try:
                ms = float(resp_time) * 1000.0
                req_frame = req_in if req_in else "?"
                req_info = requests.get(req_in, {})
                m = req_info.get("method", "HTTP")
                u = req_info.get("uri", "")
                delays.append({
                    "req_frame": req_frame,
                    "resp_frame": fnum,
                    "src": src,
                    "dst": dst,
                    "method": m,
                    "uri": u,
                    "code": code,
                    "delay_ms": ms,
                    "resp_time_sec": float(resp_time),
                })
            except ValueError:
                pass

    if not delays:
        return "HTTP requests observed, but no completed request-response pairs with timing data were found."

    total_ms = sum(d["delay_ms"] for d in delays)
    avg_ms = total_ms / len(delays)
    min_d = min(delays, key=lambda x: x["delay_ms"])
    max_d = max(delays, key=lambda x: x["delay_ms"])

    lines = [
        "=== HTTP Request-Response Round-Trip Delays ===",
        f"Total Completed Pairs: {len(delays)}",
        f"Average Response Delay: {avg_ms:.2f} ms",
        f"Fastest Response: {min_d['delay_ms']:.2f} ms (Req #{min_d['req_frame']} -> Resp #{min_d['resp_frame']})",
        f"Slowest Response: {max_d['delay_ms']:.2f} ms (Req #{max_d['req_frame']} -> Resp #{max_d['resp_frame']})",
        "",
        "Detailed Request-to-Response Delays:",
        f"{'REQ FRAME':<11} | {'RESP FRAME':<12} | {'CODE':<6} | {'TIME DELAY':<14} | {'METHOD & URI'}",
        "-" * 80,
    ]
    for d in delays[:max_lines]:
        uri_display = d['uri'][:40] if d['uri'] else "/"
        lines.append(
            f"Frame #{d['req_frame']:<5} | Frame #{d['resp_frame']:<6} | {d['code']:<6} | {d['delay_ms']:>8.2f} ms    | {d['method']} {uri_display}"
        )
    if len(delays) > max_lines:
        lines.append(f"... ({len(delays) - max_lines} more pairs truncated)")

    return "\n".join(lines)


@mcp.tool()
@_err_guard
def http_user_agents(path: str, max_lines: int = 50) -> str:
    """List distinct HTTP User-Agent strings seen in a saved pcap file, with a count of requests each made."""
    err = RUNNER.validate_path(path)
    if err:
        return err
    out = RUNNER.run([
        "-r", path, "-Y", "http.user_agent", "-T", "fields", "-e", "http.user_agent",
    ])
    if out.startswith("ERROR"):
        return out
    if not out.strip():
        return "No HTTP User-Agent headers found in this capture."
    counts: dict[str, int] = defaultdict(int)
    for line in out.splitlines():
        line = line.strip()
        if line:
            counts[line] += 1
    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    text = "\n".join(f"{n}x  {ua}" for ua, n in ranked)
    return RUNNER.truncate(text, max_lines)


@mcp.tool()
@_err_guard
def tls_sni(path: str, max_lines: int = 50) -> str:
    """List TLS ClientHello SNI hostnames seen in a saved pcap file — shows which HTTPS sites were contacted."""
    err = RUNNER.validate_path(path)
    if err:
        return err
    out = RUNNER.run([
        "-r", path, "-Y", "tls.handshake.extensions_server_name", "-T", "fields",
        "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
        "-e", "tls.handshake.extensions_server_name",
        "-E", "separator=|",
    ])
    if out.startswith("ERROR"):
        return out
    if not out.strip():
        return "No TLS SNI hostnames found in this capture."
    return RUNNER.truncate(out, max_lines)


@mcp.tool()
@_err_guard
def dhcp_leases(path: str, max_lines: int = 50) -> str:
    """List DHCP transactions in a saved pcap file (client MAC, requested/assigned IP, hostname if present)."""
    err = RUNNER.validate_path(path)
    if err:
        return err
    out = RUNNER.run([
        "-r", path, "-Y", "dhcp", "-T", "fields",
        "-e", "frame.number", "-e", "eth.src", "-e", "dhcp.option.dhcp_server_id",
        "-e", "dhcp.option.requested_ip_address", "-e", "dhcp.option.hostname",
        "-E", "separator=|",
    ])
    if out.startswith("ERROR"):
        return out
    if not out.strip():
        return "No DHCP traffic found in this capture."
    return RUNNER.truncate(out, max_lines)


@mcp.tool()
@_err_guard
def icmp_summary(path: str, max_lines: int = 50) -> str:
    """Summarize ICMP traffic (ping/unreachable/redirect/etc.) in a saved pcap file, by type/code and endpoints."""
    err = RUNNER.validate_path(path)
    if err:
        return err
    out = RUNNER.run([
        "-r", path, "-Y", "icmp", "-T", "fields",
        "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
        "-e", "icmp.type", "-e", "icmp.code",
        "-E", "separator=|",
    ])
    if out.startswith("ERROR"):
        return out
    if not out.strip():
        return "No ICMP traffic found in this capture."
    return RUNNER.truncate(out, max_lines)


@mcp.tool()
@_err_guard
def arp_table(path: str, max_lines: int = 50) -> str:
    """List ARP who-has/is-at exchanges in a saved pcap file (sender/target IP and MAC)."""
    err = RUNNER.validate_path(path)
    if err:
        return err
    out = RUNNER.run([
        "-r", path, "-Y", "arp", "-T", "fields",
        "-e", "frame.number", "-e", "arp.opcode", "-e", "arp.src.hw_mac",
        "-e", "arp.src.proto_ipv4", "-e", "arp.dst.proto_ipv4",
        "-E", "separator=|",
    ])
    if out.startswith("ERROR"):
        return out
    if not out.strip():
        return "No ARP traffic found in this capture."
    return RUNNER.truncate(out, max_lines)


@mcp.tool()
@_err_guard
def extract_http_objects(path: str) -> str:
    """Extract files transferred over HTTP in a saved pcap file (images, downloads, etc.) to a folder, and list them."""
    err = RUNNER.validate_path(path)
    if err:
        return err
    out_dir = os.path.join(RUNNER.cfg.extracted_dir, os.path.splitext(os.path.basename(path))[0])
    os.makedirs(out_dir, exist_ok=True)
    result = RUNNER.run(["-r", path, "-q", "--export-objects", f"http,{out_dir}"])
    if result.startswith("ERROR"):
        return result
    files = os.listdir(out_dir)
    if not files:
        return "No HTTP objects found (traffic may be HTTPS/TLS, which can't be extracted this way)."
    return f"Extracted {len(files)} file(s) to {out_dir}:\n" + "\n".join(files)


@mcp.tool()
@_err_guard
def hash_extracted_objects(extract_dir: str) -> str:
    """
    Compute SHA-256 hashes of every file in a directory produced by extract_http_objects.
    Useful for checking extracted files against known-malware hash databases (offline, local only).
    """
    if not os.path.isdir(extract_dir):
        return f"ERROR: directory not found: {extract_dir}. Run extract_http_objects first."
    lines = []
    for name in sorted(os.listdir(extract_dir)):
        fp = os.path.join(extract_dir, name)
        if not os.path.isfile(fp):
            continue
        h = hashlib.sha256()
        with open(fp, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        lines.append(f"{h.hexdigest()}  {name}  ({os.path.getsize(fp)} bytes)")
    if not lines:
        return "No files found to hash."
    return "\n".join(lines)


@mcp.tool()
@_err_guard
def extract_files(path: str, file_type: str = "all") -> str:
    """
    Extract embedded files (PDFs, images, documents, executables) from HTTP, SMB, or IMF streams in a pcap file.
    file_type can be 'all', 'pdf', 'image', or 'document'.
    Returns a detailed catalog of extracted files including paths, sizes, and SHA-256 hashes.
    """
    err = RUNNER.validate_path(path)
    if err:
        return err
    out_dir = os.path.join(RUNNER.cfg.extracted_dir, os.path.splitext(os.path.basename(path))[0])
    os.makedirs(out_dir, exist_ok=True)

    # Try exporting HTTP, SMB, and IMF objects
    for proto in ("http", "smb", "imf"):
        RUNNER.run(["-r", path, "-q", "--export-objects", f"{proto},{out_dir}"])

    if not os.path.isdir(out_dir):
        return "No files extracted."

    image_exts = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".ico"}
    doc_exts = {".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".csv", ".json", ".xml", ".html"}

    extracted = []
    for name in sorted(os.listdir(out_dir)):
        fp = os.path.join(out_dir, name)
        if not os.path.isfile(fp):
            continue
        ext = os.path.splitext(name)[1].lower()

        # Check magic bytes for PDF if extension is ambiguous
        is_pdf = ext == ".pdf"
        if not is_pdf and os.path.getsize(fp) > 4:
            try:
                with open(fp, "rb") as fh:
                    if fh.read(4) == b"%PDF":
                        is_pdf = True
            except Exception:
                pass

        is_image = ext in image_exts
        is_doc = is_pdf or (ext in doc_exts)

        ftype_lower = file_type.lower()
        if ftype_lower == "pdf" and not is_pdf:
            continue
        elif ftype_lower in ("image", "images") and not is_image:
            continue
        elif ftype_lower in ("document", "documents") and not is_doc:
            continue

        h = hashlib.sha256()
        with open(fp, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        size = os.path.getsize(fp)
        category = "PDF" if is_pdf else ("Image" if is_image else ("Document" if is_doc else "Other"))
        extracted.append((category, name, size, h.hexdigest(), fp))

    if not extracted:
        return f"No matching files found for filter '{file_type}' in {path} (traffic may be encrypted TLS or contain no exported streams)."

    lines = [f"Found {len(extracted)} extracted file(s) in {out_dir}:"]
    for cat, name, size, sha, fp in extracted:
        lines.append(f"  [{cat}] {name} ({size} bytes, sha256:{sha[:12]}...)\n       Path: {fp}")
    return "\n".join(lines)


@mcp.tool()
@_err_guard
def rtt_latency_stats(path: str, max_lines: int = 30) -> str:
    """
    Calculate round-trip time (RTT), latency, and time delay between sent requests and server responses
    across TCP handshakes, HTTP requests, and DNS lookups in a pcap file.
    """
    err = RUNNER.validate_path(path)
    if err:
        return err
    fields = [
        "frame.number",
        "ip.src",
        "ip.dst",
        "tcp.analysis.initial_rtt",
        "tcp.analysis.ack_rtt",
        "http.time",
        "dns.time",
    ]
    filter_expr = "tcp.analysis.initial_rtt || tcp.analysis.ack_rtt || http.time || dns.time"
    rows = RUNNER.fields(path, filter_expr, fields)
    if not rows:
        return "No request-response latency or TCP RTT metrics observed in this capture."

    handshake_rtts = []
    ack_rtts = []
    app_latencies = []

    sample_lines = []
    for row in rows:
        if len(row) < 7:
            continue
        fnum, src, dst, init_rtt, ack_rtt, http_t, dns_t = row
        msg_parts = []
        if init_rtt:
            try:
                v = float(init_rtt)
                handshake_rtts.append(v)
                msg_parts.append(f"TCP Handshake RTT={v*1000:.2f}ms")
            except ValueError:
                pass
        if ack_rtt:
            try:
                v = float(ack_rtt)
                ack_rtts.append(v)
                msg_parts.append(f"TCP ACK RTT={v*1000:.2f}ms")
            except ValueError:
                pass
        if http_t:
            try:
                v = float(http_t)
                app_latencies.append(("HTTP", v))
                msg_parts.append(f"HTTP Response Time={v*1000:.2f}ms")
            except ValueError:
                pass
        if dns_t:
            try:
                v = float(dns_t)
                app_latencies.append(("DNS", v))
                msg_parts.append(f"DNS Resolution Time={v*1000:.2f}ms")
            except ValueError:
                pass
        if msg_parts:
            sample_lines.append(f"Frame #{fnum:<5} {src} -> {dst}: {', '.join(msg_parts)}")

    summary = []
    if handshake_rtts:
        avg_hs = sum(handshake_rtts) / len(handshake_rtts) * 1000
        min_hs = min(handshake_rtts) * 1000
        max_hs = max(handshake_rtts) * 1000
        summary.append(f"TCP Handshake RTT: Avg={avg_hs:.2f}ms, Min={min_hs:.2f}ms, Max={max_hs:.2f}ms (from {len(handshake_rtts)} sessions)")
    if ack_rtts:
        avg_ack = sum(ack_rtts) / len(ack_rtts) * 1000
        min_ack = min(ack_rtts) * 1000
        max_ack = max(ack_rtts) * 1000
        summary.append(f"TCP Ack Latency:   Avg={avg_ack:.2f}ms, Min={min_ack:.2f}ms, Max={max_ack:.2f}ms ({len(ack_rtts)} samples)")
    if app_latencies:
        times = [t for _, t in app_latencies]
        avg_app = sum(times) / len(times) * 1000
        min_app = min(times) * 1000
        max_app = max(times) * 1000
        summary.append(f"App Request-Response Delay: Avg={avg_app:.2f}ms, Min={min_app:.2f}ms, Max={max_app:.2f}ms ({len(app_latencies)} requests)")

    header = "--- Latency & Round-Trip Delay Summary ---\n" + ("\n".join(summary) if summary else "No summary aggregations") + "\n\n--- Sample Request-Response Timings ---\n"
    return header + RUNNER.truncate("\n".join(sample_lines), max_lines)


@mcp.tool()
@_err_guard
def ip_inventory(path: str, max_ips: int = 50) -> str:
    """
    Generate a complete inventory of all IP addresses observed in the capture:
    flags private vs public, protocols used (TCP, UDP, ICMP, DNS, TLS, HTTP),
    and packets sent/received.
    """
    import ipaddress
    err = RUNNER.validate_path(path)
    if err:
        return err

    rows = RUNNER.fields(path, "ip", ["ip.src", "ip.dst", "ip.proto"])
    if not rows:
        return "No IPv4 traffic found in this capture."

    stats: dict[str, dict] = defaultdict(lambda: {"packets": 0, "protos": set()})
    proto_map = {"6": "TCP", "17": "UDP", "1": "ICMP"}
    for src, dst, p in rows:
        p_name = proto_map.get(str(p), f"Proto_{p}")
        if src:
            stats[src]["packets"] += 1
            stats[src]["protos"].add(p_name)
        if dst:
            stats[dst]["packets"] += 1
            stats[dst]["protos"].add(p_name)

    lines = [f"{'IP Address':<18} | {'Type':<8} | {'Packets':<8} | {'Protocols'}"]
    lines.append("-" * 65)
    sorted_ips = sorted(stats.items(), key=lambda kv: kv[1]["packets"], reverse=True)[:max_ips]
    for ip, data in sorted_ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            ip_type = "Private" if ip_obj.is_private else "Public"
        except ValueError:
            ip_type = "Unknown"
        protos_str = ", ".join(sorted(data["protos"]))
        lines.append(f"{ip:<18} | {ip_type:<8} | {data['packets']:<8} | {protos_str}")
    return "\n".join(lines)



# =========================================================================
# Threat-hunting heuristics
# =========================================================================

@mcp.tool()
@_err_guard
def suspicious_scan(path: str) -> str:
    """
    Run a quick heuristic scan of a saved pcap file for common red flags: cleartext credentials
    (HTTP Basic Auth, FTP/Telnet logins), and unusually large DNS TXT responses (possible
    DNS tunneling / exfiltration). Not a substitute for manual review.
    """
    err = RUNNER.validate_path(path)
    if err:
        return err
    findings = []

    basic_auth = RUNNER.run(["-r", path, "-Y", "http.authorization", "-T", "fields",
                              "-e", "frame.number", "-e", "ip.src", "-e", "http.authorization"])
    if basic_auth.strip() and not basic_auth.startswith("ERROR"):
        findings.append("HTTP Basic Auth credentials found (cleartext):\n" + RUNNER.truncate(basic_auth, 20))

    ftp_creds = RUNNER.run(["-r", path, "-Y", "ftp.request.command==\"USER\" or ftp.request.command==\"PASS\"",
                             "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "ftp.request.arg"])
    if ftp_creds.strip() and not ftp_creds.startswith("ERROR"):
        findings.append("FTP USER/PASS sent in cleartext:\n" + RUNNER.truncate(ftp_creds, 20))

    telnet = RUNNER.run(["-r", path, "-Y", "telnet", "-T", "fields",
                          "-e", "frame.number", "-e", "ip.src", "-e", "data.text"])
    if telnet.strip() and not telnet.startswith("ERROR"):
        findings.append("Telnet traffic found (entirely cleartext):\n" + RUNNER.truncate(telnet, 20))

    big_txt = RUNNER.run(["-r", path, "-Y", "dns.txt.length > 100", "-T", "fields",
                           "-e", "frame.number", "-e", "ip.src", "-e", "dns.qry.name", "-e", "dns.txt.length"])
    if big_txt.strip() and not big_txt.startswith("ERROR"):
        findings.append("Unusually large DNS TXT records (possible tunneling):\n" + RUNNER.truncate(big_txt, 20))

    if not findings:
        return "No obvious red flags found by this heuristic scan."
    return "\n\n".join(findings)


@mcp.tool()
@_err_guard
def port_scan_detect(path: str, min_distinct_ports: int = 15, window_seconds: float = 5.0) -> str:
    """
    Heuristic port-scan detector: flags any source IP that touched at least min_distinct_ports
    distinct destination TCP ports within any window_seconds-wide window. Reports each offending
    source IP, the number of distinct ports it touched, and its targets.
    """
    err = RUNNER.validate_path(path)
    if err:
        return err
    rows = RUNNER.fields(path, "tcp", ["frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport"])
    if not rows:
        return "No TCP traffic found in this capture."

    events = []
    for t, src, dst, dport in rows:
        try:
            events.append((float(t), src, dst, dport))
        except ValueError:
            continue
    events.sort(key=lambda e: e[0])

    by_src: dict[str, list[tuple[float, str, str]]] = defaultdict(list)
    for t, src, dst, dport in events:
        by_src[src].append((t, dst, dport))

    findings = []
    for src, hits in by_src.items():
        hits.sort(key=lambda h: h[0])
        n = len(hits)
        left = 0
        best_ports: set[str] = set()
        best_targets: set[str] = set()
        window_ports: set[str] = set()
        window_targets: set[str] = set()
        for right in range(n):
            t_right, dst_r, dport_r = hits[right]
            window_ports.add(dport_r)
            window_targets.add(dst_r)
            while hits[right][0] - hits[left][0] > window_seconds:
                # left pointer no longer contributes; recompute window sets from scratch for correctness
                left += 1
                window_ports = {h[2] for h in hits[left:right + 1]}
                window_targets = {h[1] for h in hits[left:right + 1]}
            if len(window_ports) > len(best_ports):
                best_ports = set(window_ports)
                best_targets = set(window_targets)
        if len(best_ports) >= min_distinct_ports:
            findings.append(
                f"{src}: touched {len(best_ports)} distinct dst ports within {window_seconds}s "
                f"(targets: {', '.join(sorted(best_targets)[:10])}{'...' if len(best_targets) > 10 else ''})"
            )
    if not findings:
        return f"No source touched >= {min_distinct_ports} distinct TCP ports within any {window_seconds}s window."
    return "Possible port scanning detected:\n" + "\n".join(findings)


@mcp.tool()
@_err_guard
def beaconing_detect(path: str, min_occurrences: int = 6, max_jitter_ratio: float = 0.25) -> str:
    """
    Heuristic C2-beaconing detector: for each (src, dst, dst port) with at least min_occurrences
    packets, checks whether the time between consecutive packets is highly regular (low relative
    standard deviation), which is typical of automated periodic check-ins rather than human traffic.
    """
    err = RUNNER.validate_path(path)
    if err:
        return err
    rows = RUNNER.fields(path, "tcp or udp", ["frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport", "udp.dstport"])
    if not rows:
        return "No TCP/UDP traffic found in this capture."

    by_flow: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    for t, src, dst, tport, uport in rows:
        port = tport or uport
        if not (src and dst and port):
            continue
        try:
            by_flow[(src, dst, port)].append(float(t))
        except ValueError:
            continue

    findings = []
    for (src, dst, port), times in by_flow.items():
        if len(times) < min_occurrences:
            continue
        times.sort()
        deltas = [b - a for a, b in zip(times, times[1:]) if b > a]
        if len(deltas) < min_occurrences - 1:
            continue
        mean_delta = statistics.mean(deltas)
        if mean_delta <= 0:
            continue
        stdev_delta = statistics.pstdev(deltas)
        jitter_ratio = stdev_delta / mean_delta
        if jitter_ratio <= max_jitter_ratio:
            findings.append(
                f"{src} -> {dst}:{port}  {len(times)} pkts, avg interval {mean_delta:.1f}s, "
                f"jitter ratio {jitter_ratio:.2f} (regular/periodic — possible beaconing)"
            )
    if not findings:
        return "No highly regular periodic flows found (nothing beaconing-like detected)."
    return "Possible beaconing detected:\n" + "\n".join(sorted(findings))


@mcp.tool()
@_err_guard
def arp_spoof_check(path: str) -> str:
    """
    Check ARP traffic in a saved pcap for signs of ARP spoofing / cache poisoning: the same IP
    address being claimed ('is-at') by more than one MAC address.
    """
    err = RUNNER.validate_path(path)
    if err:
        return err
    rows = RUNNER.fields(path, "arp.opcode == 2", ["arp.src.proto_ipv4", "arp.src.hw_mac"])
    if not rows:
        return "No ARP 'is-at' replies found in this capture."
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    for ip, mac in rows:
        if ip and mac:
            ip_to_macs[ip].add(mac)
    offenders = {ip: macs for ip, macs in ip_to_macs.items() if len(macs) > 1}
    if not offenders:
        return "No IP address was claimed by more than one MAC — no ARP spoofing indicators found."
    lines = [f"{ip} claimed by {len(macs)} different MACs: {', '.join(sorted(macs))}" for ip, macs in offenders.items()]
    return "Possible ARP spoofing detected:\n" + "\n".join(lines)


@mcp.tool()
@_err_guard
def long_lived_connections(path: str, min_seconds: float = 300.0, max_lines: int = 30) -> str:
    """
    List TCP conversations that lasted at least min_seconds — useful for spotting persistent
    connections such as reverse shells, tunnels, or long-poll/beaconing channels.
    """
    err = RUNNER.validate_path(path)
    if err:
        return err
    out = RUNNER.run(["-r", path, "-q", "-z", "conv,tcp"])
    if out.startswith("ERROR"):
        return out
    lines = out.splitlines()
    result_lines = []
    for line in lines:
        parts = line.split()
        # tshark conv,tcp table rows end with a duration column like "12.3456"
        if len(parts) >= 2:
            try:
                duration = float(parts[-1])
            except ValueError:
                continue
            if duration >= min_seconds:
                result_lines.append(line)
    if not result_lines:
        return f"No TCP conversations lasted >= {min_seconds}s."
    return RUNNER.truncate("\n".join(result_lines), max_lines)


# =========================================================================
# Reporting
# =========================================================================

@mcp.tool()
@_err_guard
def write_report(title: str, content_markdown: str, filename: str = "") -> str:
    """
    Save a markdown report (e.g. a findings summary from analysis) to disk under the reports
    directory, and return its path. Use this to produce a durable artifact of an investigation.
    """
    safe_name = filename.strip() or (title.strip().lower().replace(" ", "_")[:60] or "report")
    safe_name = "".join(c for c in safe_name if c.isalnum() or c in ("_", "-")) or "report"
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(RUNNER.cfg.reports_dir, f"{safe_name}_{ts}.md")
    body = f"# {title}\n\n_Generated {time.strftime('%Y-%m-%d %H:%M:%S')}_\n\n{content_markdown}\n"
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return f"Report written to: {out_path}"


# =========================================================================
# Subagent Audit & Ledger
# =========================================================================

@mcp.tool()
@_err_guard
def list_subagents(subagent_id: str = "") -> str:
    """
    Query the JEV subagent audit ledger to inspect spawned subagents, their execution status,
    number of tool calls, and output summaries. If subagent_id is provided, returns detailed
    step-by-step action history.
    """
    candidates = [
        os.path.join(RUNNER.cfg.capture_dir, "subagents", "subagents_ledger.json"),
        os.path.join(tempfile.gettempdir(), "wireshark_mcp_captures", "subagents", "subagents_ledger.json"),
    ]
    ledger_path = next((p for p in candidates if os.path.isfile(p)), candidates[0])
    if not os.path.isfile(ledger_path):
        return "No subagents have been spawned yet."

    try:
        with open(ledger_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        return f"ERROR reading subagent ledger: {e}"

    if not data:
        return "Subagent ledger is currently empty."

    if subagent_id:
        target = next((item for item in data if item.get("subagent_id") == subagent_id), None)
        if not target:
            return f"Subagent '{subagent_id}' not found in ledger."
        lines = [
            f"Subagent ID: {target.get('subagent_id')}",
            f"Name: {target.get('name')}",
            f"Role: {target.get('role')}",
            f"Task: {target.get('task')}",
            f"Status: {target.get('status')}",
            f"Started: {target.get('started_at')}",
            f"Completed: {target.get('completed_at') or 'in-progress'}",
            f"Actions ({len(target.get('actions', []))} total):",
        ]
        for idx, act in enumerate(target.get("actions", []), start=1):
            lines.append(f"  {idx}. [{act.get('action_type')}] {act.get('name')}({act.get('arguments')})")
        if target.get("output"):
            lines.append(f"\nFinal Output:\n{target.get('output')}")
        return "\n".join(lines)

    lines = [f"{'ID':<12} | {'ROLE':<18} | {'STATUS':<10} | {'ACTIONS':<7} | {'NAME / TASK'}"]
    lines.append("-" * 75)
    for item in data:
        sid = item.get("subagent_id", "")
        role = item.get("role", "")
        status = item.get("status", "")
        actions = len(item.get("actions", []))
        name = item.get("name", "")
        task = item.get("task", "")
        task_preview = f"{name}: {task[:40]}..." if len(task) > 40 else f"{name}: {task}"
        lines.append(f"{sid:<12} | {role:<18} | {status:<10} | {actions:<7} | {task_preview}")

    return "\n".join(lines)


# =========================================================================
# Sandbox & Memory
# =========================================================================

@mcp.tool()
@_err_guard
def sandbox_import_pcap(path: str, custom_name: str = "") -> str:
    """
    Safely import an external or untrusted pcap/pcapng file into NetAgent's isolated sandbox directory.
    Validates PCAP magic bytes, prevents path traversal, and returns the sandboxed path ready for analysis.
    """
    from .memory import PcapSandbox
    sb = PcapSandbox(RUNNER.cfg.sandbox_dir)
    res = sb.import_pcap(path, custom_name=custom_name)
    if not res["success"]:
        return f"ERROR importing to sandbox: {res.get('error', 'unknown error')}"
    return (
        f"Safely staged in sandbox:\n"
        f"  Path: {res['sandboxed_path']}\n"
        f"  Size: {res['size_bytes']:,} bytes\n"
        f"  Integrity: {res['validation']}"
    )


@mcp.tool()
@_err_guard
def sandbox_list() -> str:
    """List all pcap files currently stored inside NetAgent's isolated sandbox."""
    from .memory import PcapSandbox
    sb = PcapSandbox(RUNNER.cfg.sandbox_dir)
    files = sb.list_files()
    if not files:
        return "No pcap files currently in the sandbox."
    lines = [f"{'FILENAME':<35} | {'SIZE':<12} | {'PATH'}"]
    lines.append("-" * 75)
    for f in files:
        lines.append(f"{f['name']:<35} | {f['size']:,} B{'':<4} | {f['path']}")
    return "\n".join(lines)


@mcp.tool()
@_err_guard
def remember_insight(category: str, note: str) -> str:
    """
    Save an important network finding, device profile, suspicious IP, or preference into
    NetAgent's persistent long-term memory across sessions.
    Categories: 'topology', 'ioc', 'device', 'preference', 'incident'.
    """
    from .memory import MemoryStore
    mem = MemoryStore(RUNNER.cfg.memory_dir)
    entry = mem.remember(category=category, content=note)
    return f"Saved to NetAgent long-term memory [{entry.category.upper()}]: {entry.content}"


@mcp.tool()
@_err_guard
def recall_memory(query: str = "") -> str:
    """Recall stored network facts, device notes, or past threat findings from NetAgent's long-term memory."""
    from .memory import MemoryStore
    mem = MemoryStore(RUNNER.cfg.memory_dir)
    entries = mem.recall(query=query)
    if not entries:
        return f"No memories found matching query '{query}'." if query else "NetAgent long-term memory is currently empty."
    lines = [f"Recalled {len(entries)} memory item(s):"]
    for e in entries:
        lines.append(f"  • [{e.category.upper()}] {e.content} (id: {e.entry_id})")
    return "\n".join(lines)


@mcp.tool()
@_err_guard
def send_telegram_alert(message: str, level: str = "CRITICAL") -> str:
    """
    Send an urgent network security alert directly to Telegram via the configured Telegram Bot.
    Levels: 'CRITICAL', 'HIGH', 'WARNING', 'INFO'.
    """
    from .telegram import TelegramNotifier
    notifier = TelegramNotifier()
    if not notifier.is_configured():
        return "Telegram is not configured. Set telegram.bot_token and telegram.chat_id in config.yaml or via /telegram setup."
    res = notifier.send_alert(message=message, level=level)
    if res.get("success"):
        return f"Telegram alert delivered successfully (msg_id: {res.get('message_id')})."
    return f"Failed to send Telegram alert: {res.get('error')}"


@mcp.tool()
@_err_guard
def list_continuous_monitors() -> str:
    """
    List all background continuous network monitoring subagents, their running status,
    packet counts, and threat detection statistics.
    """
    from .monitor import ContinuousMonitorManager
    mgr = ContinuousMonitorManager()
    monitors = mgr.list_monitors()
    if not monitors:
        return "No continuous monitoring subagents registered."
    lines = [f"{'ID':<12} | {'NAME':<16} | {'STATUS':<8} | {'PID':<8} | {'PACKETS':<10} | {'THREATS':<8} | {'LAST RUN'}"]
    lines.append("-" * 80)
    for m in monitors:
        st = m.get("stats", {})
        pid_str = str(m.get("pid") or "-")
        lines.append(
            f"{m['id']:<12} | {m.get('name', ''):<16} | {m.get('status', 'STOPPED'):<8} | "
            f"{pid_str:<8} | {st.get('total_packets', 0):<10} | {st.get('threats_detected', 0):<8} | {st.get('last_run') or 'Never'}"
        )
    return "\n".join(lines)


@mcp.tool()
@_err_guard
def start_continuous_monitor(
    name: str = "",
    interface: str = "1",
    interval: int = 25,
    capture_duration: int = 10,
    rules: str = "port_scan,cleartext_creds,arp_spoof,traffic_burst,dns_anomalies",
) -> str:
    """
    Spawn a detached continuous monitoring subagent that runs independently in the background.
    Continues operating even when PowerShell windows are closed.
    Does NOT require LLM API keys — runs autonomous local heuristic checks and sends Telegram alerts.
    """
    from .monitor import ContinuousMonitorManager
    mgr = ContinuousMonitorManager()
    rule_list = [r.strip() for r in rules.split(",") if r.strip()]
    res = mgr.start_monitor(
        name=name or None,
        interface=interface,
        interval=interval,
        capture_duration=capture_duration,
        rules=rule_list,
    )
    return (
        f"Continuous monitoring subagent spawned successfully!\n"
        f"  ID: {res['id']}\n"
        f"  Name: {res['name']}\n"
        f"  Interface: {res['interface']}\n"
        f"  PID: {res.get('pid')}\n"
        f"  Cycle Interval: {res['interval_seconds']}s (Captures: {res['capture_duration']}s)\n"
        f"  Active Rules: {', '.join(res['rules'])}\n"
        f"  Status: {res['status']} (Detached background process)"
    )


@mcp.tool()
@_err_guard
def stop_continuous_monitor(monitor_id: str) -> str:
    """Stop a running continuous network monitoring subagent by ID or name."""
    from .monitor import ContinuousMonitorManager
    mgr = ContinuousMonitorManager()
    ok = mgr.stop_monitor(monitor_id)
    if ok:
        return f"Successfully stopped monitoring subagent '{monitor_id}'."
    return f"Failed to stop subagent '{monitor_id}'. Verify the ID with list_continuous_monitors."


@mcp.tool()
@_err_guard
def get_continuous_monitor_stats(monitor_id: str) -> str:
    """Get full performance statistics, cycle history, and recent security alerts for a monitoring subagent."""
    from .monitor import ContinuousMonitorManager
    mgr = ContinuousMonitorManager()
    m = mgr.get_monitor(monitor_id)
    if not m:
        return f"Monitor subagent '{monitor_id}' not found."
    st = m.get("stats", {})
    alerts = st.get("recent_alerts", [])
    out = [
        f"--- Monitor: {m.get('name')} ({m['id']}) ---",
        f"Status: {m.get('status')} (PID: {m.get('pid') or 'None'})",
        f"Interface: {m.get('interface')} | Interval: {m.get('interval_seconds')}s",
        f"Rules: {', '.join(m.get('rules', []))}",
        f"Total Cycles: {st.get('total_cycles', 0)}",
        f"Total Packets Inspected: {st.get('total_packets', 0):,}",
        f"Threats Detected: {st.get('threats_detected', 0)}",
        f"Last Run: {st.get('last_run') or 'Never'}",
    ]
    if alerts:
        out.append("\nRecent Alerts:")
        for a in alerts[-5:]:
            out.append(f"  • [{a.get('timestamp')}] {a.get('level')} - {a.get('rule')}: {a.get('message')}")
    else:
        out.append("\nNo security threats detected so far.")
    return "\n".join(out)


@mcp.tool()
@_err_guard
def check_ip_virustotal(ip: str) -> str:
    """
    Check the reputation and threat intelligence of an IP address via VirusTotal v3 API.
    Caches results so already-scanned IPs are never re-queried redundantly.
    Flags malicious IPs with detection score >= 70% and sends a Telegram alert if configured.
    """
    from .virustotal import VirusTotalClient
    vt = VirusTotalClient()
    res = vt.check_ip(ip, send_alerts=True)
    if "error" in res:
        return f"VirusTotal Error for {ip}: {res['error']}"
    if not res.get("is_public", True):
        return f"{ip}: {res.get('message', 'Private/Internal IP - skipped VT check.')}"

    cache_str = "[CACHED]" if res.get("cached") else "[FRESH SCAN]"
    status_str = "MALICIOUS THREAT" if res.get("is_malicious") else "CLEAN / BENIGN"
    stats = res.get("stats", {})
    return (
        f"VirusTotal IP Report for {ip} {cache_str}:\n"
        f"  • Verdict: {status_str}\n"
        f"  • Malicious Score: {res.get('malicious_score')}%\n"
        f"  • Detections: {stats.get('malicious', 0)}/{stats.get('total_engines', 0)} security vendors\n"
        f"  • Autonomous System / Org: {res.get('as_owner')}\n"
        f"  • Country: {res.get('country')}\n"
        f"  • Timestamp: {res.get('scanned_at')}"
    )


@mcp.tool()
@_err_guard
def scan_pcap_virustotal(path: str) -> str:
    """
    Extract all unique public IP addresses connected in a pcap/pcapng capture and evaluate them
    against VirusTotal. Skips already-tested IPs (cached) and alerts on high-risk malicious IPs.
    """
    err = RUNNER.validate_path(path)
    if err:
        return err

    from .virustotal import VirusTotalClient, is_public_ip
    vt = VirusTotalClient()

    # Extract src and dst IPs
    try:
        rows = RUNNER.fields(path, "", ["ip.src", "ip.dst"])
    except Exception as e:
        return f"Error extracting IPs: {e}"

    public_ips = set()
    for row in rows:
        for val in row:
            for item in val.split(","):
                ip = item.strip()
                if ip and is_public_ip(ip):
                    public_ips.add(ip)

    if not public_ips:
        return f"No public Internet IP addresses found in {os.path.basename(path)}."

    lines = [f"Scanning {len(public_ips)} public IP(s) from {os.path.basename(path)} against VirusTotal:"]
    threat_count = 0

    for ip in sorted(public_ips):
        rep = vt.check_ip(ip, send_alerts=True)
        if "error" in rep:
            lines.append(f"  • {ip}: Error - {rep['error']}")
            continue
        cached = "(cached)" if rep.get("cached") else "(scanned)"
        score = rep.get("malicious_score", 0)
        stats = rep.get("stats", {})
        mal = stats.get("malicious", 0)
        tot = stats.get("total_engines", 0)
        org = rep.get("as_owner", "Unknown")

        if rep.get("is_malicious"):
            threat_count += 1
            lines.append(f"  • [ALERT] [MALICIOUS {score}%] {ip} ({mal}/{tot} engines) - Org: {org} {cached}")
        else:
            lines.append(f"  • [OK] [CLEAN {score}%] {ip} ({mal}/{tot} engines) - Org: {org} {cached}")

    lines.append(f"\nSummary: {len(public_ips)} IPs evaluated. {threat_count} high-risk threat(s) flagged (>= 70%).")
    return "\n".join(lines)



# =========================================================================
# MCP Prompts & Resources for External AI Agents (Claude, Cursor, etc.)
# =========================================================================

@mcp.prompt()
def network_triage_guide(incident_description: str = "", capture_id: str = "") -> str:
    """Standard Operating Procedure for AI agents triaging an active network incident or capture file."""
    return f"""Incident Triage Request: {incident_description or 'General network traffic inspection'}
Target Capture ID: {capture_id or 'Latest capture in capture directory'}

Step-by-Step Triage Instructions for AI Agent:
1. Identify the capture: Call `list_captures` or verify `{capture_id}`.
2. High-level telemetry: Run `quick_summary` and `protocol_hierarchy` to identify dominant traffic protocols.
3. Conversation flow: Run `analyze_conversations` to isolate high-volume IP pairs and unusual port communications.
4. Threat screening: Execute `detect_beaconing`, `detect_port_scans`, and `find_credentials`.
5. Threat intelligence: Extract external IP addresses from conversations and query `virustotal_ip_report` for any public endpoints.
6. Documentation: Synthesize all findings into a structured report using `write_report`.
"""


@mcp.prompt()
def threat_hunting_playbook(suspected_threat: str = "", target_ip: str = "") -> str:
    """Forensic threat hunting playbook for identifying C2 beaconing, data exfiltration, and lateral movement."""
    return f"""Suspected Threat: {suspected_threat or 'Beaconing / Malware C2 / Data Exfiltration'}
Target Indicator: {target_ip or 'All external endpoints'}

Hunting Methodology:
1. Call `detect_beaconing` to measure connection interval regularity and calculate delta timestamps.
2. Call `http_requests` and `tls_handshakes` to examine SNI hostnames, user-agent anomalies, and abnormal HTTP methods.
3. Call `dns_queries` to identify potential DNS tunneling (high-entropy subdomains, TXT record exfiltration).
4. Run `virustotal_ip_report` on any suspicious endpoints to get engine detection consensus.
5. If cleartext protocols (FTP, Telnet, HTTP) are present, call `find_credentials` to verify credential exposure.
"""


@mcp.prompt()
def host_security_audit(target_host: str = "127.0.0.1") -> str:
    """Methodology for conducting an authorized port audit and service exposure assessment."""
    return f"""Target Host: {target_host}

Audit Workflow:
1. Call `port_scan_host(target='{target_host}', ports='common')` to discover open TCP ports and identify services.
2. Evaluate each exposed service:
   - Are plaintext protocols (HTTP, Telnet, FTP) exposed where encrypted variants should be used?
   - Are administrative interfaces or UPnP exposed?
3. Synthesize risk levels (LOW, MEDIUM, HIGH, CRITICAL) for each open port.
4. Recommend concrete defensive remediation steps (firewall rules, binding to localhost, TLS termination).
"""


@mcp.resource("netagent://system/status")
def system_status_resource() -> str:
    """Real-time NetAgent system status: capture permissions, interface counts, and active monitors."""
    from .monitor import ContinuousMonitorManager
    mon_dir = getattr(getattr(RUNNER, "cfg", None), "monitors_dir", None)
    if not mon_dir:
        mon_dir = os.path.join(tempfile.gettempdir(), "wireshark_mcp_captures", "monitors")
    mgr = ContinuousMonitorManager(mon_dir)
    monitors = mgr.list_monitors()
    active_monitors = [m for m in monitors if m.get("status") == "RUNNING"]

    captures = RUNNER.list_captures() if RUNNER else []
    
    status_data = {
        "server_name": "netagent",
        "version": "2.5.0",
        "capture_authorized": RUNNER.is_capture_authorized() if RUNNER else False,
        "capture_directory": RUNNER.capture_dir if RUNNER else "",
        "total_saved_captures": len(captures),
        "active_background_monitors": len(active_monitors),
        "total_registered_monitors": len(monitors),
        "timestamp": datetime.now().isoformat(),
    }
    return json.dumps(status_data, indent=2)


@mcp.resource("netagent://memory/long-term")
def memory_resource() -> str:
    """Persistent long-term network topology and cybersecurity rules stored in NetAgent memory."""
    from .memory import MemoryStore
    mem_dir = getattr(getattr(RUNNER, "cfg", None), "memory_dir", None)
    if not mem_dir:
        mem_dir = os.path.join(tempfile.gettempdir(), "wireshark_mcp_captures", "memory")
    mem = MemoryStore(mem_dir)
    notes = [e.to_dict() for e in mem.recall()]
    return json.dumps({
        "total_notes": len(notes),
        "notes": notes,
    }, indent=2)


@mcp.resource("netagent://threats/virustotal-cache")
def virustotal_cache_resource() -> str:
    """Summary of all cached VirusTotal threat intelligence reports."""
    from .virustotal import VirusTotalClient
    vt = VirusTotalClient()
    cached = vt._load_cache()
    return json.dumps({
        "total_cached_ips": len(cached),
        "reports": cached,
    }, indent=2)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--scan-worker":
        # Argument schema: --scan-worker <target> <ports> <scan_id>
        _t = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
        _p = sys.argv[3] if len(sys.argv) > 3 else "common"
        _sid = sys.argv[4] if len(sys.argv) > 4 else "scan_tmp"
        _run_scan_worker(_t, _p, _sid)
    else:
        mcp.run()

