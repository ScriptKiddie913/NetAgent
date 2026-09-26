"""
Continuous Network Monitoring Subagents for NetAgent.
Enables spawning detached background monitoring daemons that survive terminal closures.
These agents inspect interfaces continuously using fast local heuristics and JEV rules
WITHOUT burning LLM tokens or requiring external API keys.
If critical security threats are detected, alerts are dispatched directly via Telegram.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import psutil

from .config import load_config
from .telegram import TelegramNotifier
from .virustotal import VirusTotalClient, is_public_ip


def _get_monitors_dir() -> Path:
    cfg = load_config()
    d = Path(cfg.monitors_dir)
    d.mkdir(parents=True, exist_ok=True)
    return d


@dataclass
class MonitorAlert:
    timestamp: str
    level: str  # "CRITICAL", "HIGH", "WARNING", "INFO"
    rule: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)


class ContinuousMonitorManager:
    """Manages lifecycle of continuous detached monitoring subagents."""

    def __init__(self) -> None:
        self.monitors_dir = _get_monitors_dir()

    def _monitor_path(self, monitor_id: str) -> Path:
        return self.monitors_dir / f"{monitor_id}.json"

    def _log_path(self, monitor_id: str) -> Path:
        return self.monitors_dir / f"{monitor_id}.log"

    def list_monitors(self) -> list[dict[str, Any]]:
        """List all registered continuous monitoring subagents and verify alive state."""
        monitors = []
        for file in self.monitors_dir.glob("*.json"):
            try:
                with open(file, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                
                # Check if process is still running
                pid = data.get("pid")
                is_alive = False
                if pid:
                    try:
                        if psutil.pid_exists(pid):
                            p = psutil.Process(pid)
                            if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                                is_alive = True
                    except Exception:
                        is_alive = False

                if not is_alive and data.get("status") == "RUNNING":
                    data["status"] = "STOPPED"
                    data["pid"] = None
                    # Update file
                    try:
                        with open(file, "w", encoding="utf-8") as fh:
                            json.dump(data, fh, indent=2)
                    except Exception:
                        pass

                monitors.append(data)
            except Exception:
                continue

        return sorted(monitors, key=lambda m: m.get("created_at", ""), reverse=True)

    def get_monitor(self, monitor_id: str) -> Optional[dict[str, Any]]:
        p = self._monitor_path(monitor_id)
        if not p.is_file():
            # Try fuzzy match by name
            for m in self.list_monitors():
                if m.get("name") == monitor_id or m.get("id") == monitor_id:
                    return m
            return None
        try:
            with open(p, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return None

    def start_monitor(
        self,
        name: str | None = None,
        interface: str = "1",
        interval: int = 25,
        capture_duration: int = 10,
        rules: list[str] | None = None,
    ) -> dict[str, Any]:
        """Spawn a detached continuous monitoring subagent that runs independently of PowerShell."""
        monitor_id = f"mon_{uuid.uuid4().hex[:6]}"
        agent_name = name or f"agent-{monitor_id}"

        default_rules = [
            "port_scan",
            "cleartext_creds",
            "arp_spoof",
            "traffic_burst",
            "dns_anomalies",
            "virustotal",
        ]
        active_rules = rules or default_rules

        # Auto-detect active interface (e.g. Wi-Fi) if default "1" requested
        if str(interface).strip().lower() in ("all", "*"):
            interface = "all"
        elif str(interface) == "1":
            try:
                tshark_bin = load_config().tshark_path
                res = subprocess.run([tshark_bin, "-D"], capture_output=True, text=True, timeout=5)
                for line in res.stdout.splitlines():
                    if "wi-fi" in line.lower():
                        # Extract interface number
                        idx = line.split(".")[0].strip()
                        if idx.isdigit():
                            interface = idx
                            break
            except Exception:
                pass

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        definition: dict[str, Any] = {
            "id": monitor_id,
            "name": agent_name,
            "interface": str(interface),
            "interval_seconds": max(5, int(interval)),
            "capture_duration": max(3, int(capture_duration)),
            "rules": active_rules,
            "status": "RUNNING",
            "pid": None,
            "created_at": now_str,
            "stats": {
                "total_cycles": 0,
                "total_packets": 0,
                "threats_detected": 0,
                "started_at": now_str,
                "last_run": None,
                "recent_alerts": [],
            },
        }

        # Save initial json
        json_path = self._monitor_path(monitor_id)
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(definition, fh, indent=2)

        # Resolve real python interpreter even if running under netagent.exe wrapper
        python_exe = sys.executable
        if "netagent" in Path(python_exe).name.lower() or "Scripts" in python_exe:
            cand = Path(python_exe).parent.parent / "python.exe"
            if cand.is_file():
                python_exe = str(cand)
            else:
                python_exe = shutil.which("python") or sys.executable

        cmd = [python_exe, "-m", "wireshark_mcp.monitor", "worker", monitor_id]

        creationflags = 0
        if sys.platform == "win32":
            # CREATE_NO_WINDOW (0x08000000) + CREATE_NEW_PROCESS_GROUP (0x00000200)
            creationflags = 0x08000000 | 0x00000200

        proj_root = str(Path(__file__).resolve().parent.parent)
        env = dict(os.environ, PYTHONPATH=proj_root)

        proc = subprocess.Popen(
            cmd,
            cwd=proj_root,
            env=env,
            creationflags=creationflags,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )

        definition["pid"] = proc.pid
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(definition, fh, indent=2)

        return definition

    def stop_monitor(self, monitor_id: str) -> bool:
        """Stop a running monitor subagent process."""
        mon = self.get_monitor(monitor_id)
        if not mon:
            return False

        actual_id = mon["id"]
        json_path = self._monitor_path(actual_id)
        mon["status"] = "STOPPED"

        pid = mon.get("pid")
        if pid:
            try:
                if psutil.pid_exists(pid):
                    p = psutil.Process(pid)
                    p.terminate()
                    try:
                        p.wait(timeout=3)
                    except psutil.TimeoutExpired:
                        p.kill()
            except Exception:
                pass

        mon["pid"] = None
        try:
            with open(json_path, "w", encoding="utf-8") as fh:
                json.dump(mon, fh, indent=2)
            return True
        except Exception:
            return False

    def edit_monitor(
        self,
        monitor_id: str,
        name: str | None = None,
        interval: int | None = None,
        rules: list[str] | None = None,
    ) -> Optional[dict[str, Any]]:
        """Modify an existing subagent's configuration on the fly."""
        mon = self.get_monitor(monitor_id)
        if not mon:
            return None

        actual_id = mon["id"]
        if name:
            mon["name"] = name
        if interval is not None:
            mon["interval_seconds"] = max(5, int(interval))
        if rules is not None:
            mon["rules"] = rules

        json_path = self._monitor_path(actual_id)
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(mon, fh, indent=2)

        return mon

    def delete_monitor(self, monitor_id: str) -> bool:
        """Stop and completely delete a monitor subagent and its logs."""
        mon = self.get_monitor(monitor_id)
        if not mon:
            return False

        actual_id = mon["id"]
        self.stop_monitor(actual_id)

        json_path = self._monitor_path(actual_id)
        log_path = self._log_path(actual_id)

        try:
            if json_path.is_file():
                json_path.unlink()
            if log_path.is_file():
                log_path.unlink()
            return True
        except Exception:
            return False


# =========================================================================
# Background Daemon Worker (Runs independently, 0 API keys required)
# =========================================================================

class ContinuousMonitorWorker:
    """
    Autonomous inspection engine that runs cyclic captures and local heuristics.
    Requires ZERO LLM tokens. Operates 24/7 in detached background process.
    """

    def __init__(self, monitor_id: str) -> None:
        self.monitor_id = monitor_id
        self.manager = ContinuousMonitorManager()
        self.cfg = load_config()
        self.telegram = TelegramNotifier()
        self.vt = VirusTotalClient()
        self.seen_arp: dict[str, str] = {}  # IP -> MAC tracker for ARP spoofing

    def run(self) -> None:
        log_path = self.manager._log_path(self.monitor_id)
        try:
            self._log_fh = open(log_path, "a", encoding="utf-8", buffering=1)
            sys.stdout = self._log_fh
            sys.stderr = self._log_fh
        except Exception:
            pass

        print(f"[{datetime.now()}] NetAgent Continuous Monitoring Worker started for {self.monitor_id}", flush=True)
        tshark_bin = self.cfg.tshark_path

        while True:
            # Re-read monitor state
            data = self.manager.get_monitor(self.monitor_id)
            if not data or data.get("status") == "STOPPED":
                print(f"[{datetime.now()}] Stop requested or record deleted. Terminating.", flush=True)
                break

            interface = data.get("interface", "1")
            duration = int(data.get("capture_duration", 10))
            interval = int(data.get("interval_seconds", 25))
            rules = set(data.get("rules", []))
            stats = data.setdefault("stats", {})

            # Temp capture file
            temp_pcap = self.manager.monitors_dir / f"tmp_{self.monitor_id}.pcapng"

            # Execute capture probe
            captured = False
            packet_count = 0
            alerts: list[dict[str, Any]] = []

            try:
                # Run tshark capture across specified or all interfaces
                iface_args: list[str] = []
                if str(interface).strip().lower() in ("all", "*"):
                    try:
                        res_d = subprocess.run([tshark_bin, "-D"], capture_output=True, text=True, timeout=5)
                        for line in res_d.stdout.splitlines():
                            if not line.strip() or "etwdump" in line.lower():
                                continue
                            idx = line.split(".")[0].strip()
                            if idx.isdigit():
                                iface_args.extend(["-i", idx])
                    except Exception:
                        iface_args = ["-i", "1"]
                elif "," in str(interface):
                    for item in str(interface).split(","):
                        if item.strip():
                            iface_args.extend(["-i", item.strip()])
                else:
                    iface_args = ["-i", str(interface)]

                if not iface_args:
                    iface_args = ["-i", "1"]

                cmd = [tshark_bin] + iface_args + [
                    "-a", f"duration:{duration}",
                    "-w", str(temp_pcap),
                    "-q",
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 15)
                if temp_pcap.is_file() and temp_pcap.stat().st_size > 0:
                    captured = True
            except Exception as e:
                print(f"[{datetime.now()}] Capture warning on iface {interface}: {e}")

            if captured:
                # Count packets
                try:
                    count_out = subprocess.run(
                        [tshark_bin, "-r", str(temp_pcap), "-T", "fields", "-e", "frame.number"],
                        capture_output=True, text=True, timeout=15,
                    )
                    lines = [ln for ln in count_out.stdout.splitlines() if ln.strip()]
                    packet_count = len(lines)
                except Exception:
                    packet_count = 1

                # 1. Port Scan Check
                if "port_scan" in rules and packet_count > 5:
                    alert = self._check_port_scan(temp_pcap, tshark_bin)
                    if alert:
                        alerts.append(alert)

                # 2. Cleartext Credential Check
                if "cleartext_creds" in rules and packet_count > 0:
                    alert = self._check_cleartext_creds(temp_pcap, tshark_bin)
                    if alert:
                        alerts.append(alert)

                # 3. ARP Spoof Check
                if "arp_spoof" in rules and packet_count > 0:
                    alert = self._check_arp_spoof(temp_pcap, tshark_bin)
                    if alert:
                        alerts.append(alert)

                # 4. Traffic Burst Spike Check
                if "traffic_burst" in rules:
                    alert = self._check_traffic_burst(packet_count, duration)
                    if alert:
                        alerts.append(alert)

                # 5. DNS Anomalies Check
                if "dns_anomalies" in rules and packet_count > 0:
                    alert = self._check_dns_anomalies(temp_pcap, tshark_bin)
                    if alert:
                        alerts.append(alert)

                # 6. VirusTotal IP Reputation Check (New connected public IPs)
                if ("virustotal" in rules or self.vt.is_configured()) and packet_count > 0:
                    vt_alerts = self._check_virustotal_ips(temp_pcap, tshark_bin)
                    if vt_alerts:
                        alerts.extend(vt_alerts)

            # Process any alerts
            if alerts:
                stats["threats_detected"] = stats.get("threats_detected", 0) + len(alerts)
                recent = stats.setdefault("recent_alerts", [])
                for alt in alerts:
                    recent.append(alt)
                    # Dispatch to Telegram if configured
                    if self.telegram.is_configured():
                        try:
                            self.telegram.send_alert(
                                message=f"*{alt['rule'].upper()} DETECTED*\n{alt['message']}",
                                level=alt.get("level", "CRITICAL"),
                                category=alt["rule"],
                                details=alt.get("details"),
                            )
                        except Exception as e:
                            print(f"[{datetime.now()}] Telegram dispatch error: {e}")

                # Trim recent alerts to 30
                if len(recent) > 30:
                    stats["recent_alerts"] = recent[-30:]

                # Preserve pcap if threat found
                saved_threat_pcap = (
                    Path(self.cfg.capture_dir)
                    / f"threat_{self.monitor_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcapng"
                )
                try:
                    if temp_pcap.is_file():
                        shutil.copyfile(temp_pcap, saved_threat_pcap)
                except Exception:
                    pass

            # Clean up temp pcap
            try:
                if temp_pcap.is_file():
                    temp_pcap.unlink()
            except Exception:
                pass

            # Update stats
            stats["total_cycles"] = stats.get("total_cycles", 0) + 1
            stats["total_packets"] = stats.get("total_packets", 0) + packet_count
            stats["last_run"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            json_p = self.manager._monitor_path(self.monitor_id)
            try:
                with open(json_p, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, indent=2)
            except Exception:
                pass

            # Sleep in 1-second chunks to be responsive to stop signals
            for _ in range(interval):
                time.sleep(1)
                if not json_p.is_file():
                    break
                try:
                    with open(json_p, "r", encoding="utf-8") as fh:
                        cur = json.load(fh)
                    if cur.get("status") == "STOPPED":
                        return
                except Exception:
                    pass

    def _check_port_scan(self, pcap: Path, tshark: str) -> Optional[dict[str, Any]]:
        try:
            cmd = [
                tshark, "-r", str(pcap),
                "-Y", "tcp.flags.syn==1 and tcp.flags.ack==0",
                "-T", "fields", "-e", "ip.src", "-e", "tcp.dstport",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            syn_map: dict[str, set[str]] = {}
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    ip, port = parts[0], parts[1]
                    syn_map.setdefault(ip, set()).add(port)

            for ip, ports in syn_map.items():
                if len(ports) >= 8:
                    return {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "level": "CRITICAL",
                        "rule": "port_scan",
                        "message": f"High-velocity TCP port scan detected from `{ip}` hitting {len(ports)} distinct ports.",
                        "details": {"source_ip": ip, "unique_ports_scanned": len(ports)},
                    }
        except Exception:
            pass
        return None

    def _check_cleartext_creds(self, pcap: Path, tshark: str) -> Optional[dict[str, Any]]:
        try:
            cmd = [
                tshark, "-r", str(pcap),
                "-Y", "http.authorization or ftp or telnet",
                "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol", "-e", "_ws.col.Info",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            for line in res.stdout.splitlines():
                if "Basic " in line or "USER " in line or "PASS " in line:
                    return {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "level": "HIGH",
                        "rule": "cleartext_creds",
                        "message": f"Cleartext authentication credential or Basic Auth header observed in transit.",
                        "details": {"snippet": line[:120]},
                    }
        except Exception:
            pass
        return None

    def _check_arp_spoof(self, pcap: Path, tshark: str) -> Optional[dict[str, Any]]:
        try:
            cmd = [
                tshark, "-r", str(pcap),
                "-Y", "arp.opcode == 2",
                "-T", "fields", "-e", "arp.src.proto_ipv4", "-e", "arp.src.hw_mac",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    ip, mac = parts[0], parts[1]
                    if ip in self.seen_arp and self.seen_arp[ip] != mac:
                        old_mac = self.seen_arp[ip]
                        return {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "level": "CRITICAL",
                            "rule": "arp_spoof",
                            "message": f"Possible ARP spoofing/poisoning! IP `{ip}` previously mapped to `{old_mac}` now claimed by `{mac}`.",
                            "details": {"ip": ip, "prior_mac": old_mac, "new_mac": mac},
                        }
                    self.seen_arp[ip] = mac
        except Exception:
            pass
        return None

    def _check_traffic_burst(self, packet_count: int, duration: int) -> Optional[dict[str, Any]]:
        rate = packet_count / max(1, duration)
        if rate > 300:  # >300 packets per second
            return {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "level": "WARNING",
                "rule": "traffic_burst",
                "message": f"Unusual traffic burst detected: {rate:.1f} packets/second on monitored interface.",
                "details": {"packet_count": packet_count, "rate_per_sec": f"{rate:.1f}"},
            }
        return None

    def _check_dns_anomalies(self, pcap: Path, tshark: str) -> Optional[dict[str, Any]]:
        try:
            cmd = [
                tshark, "-r", str(pcap),
                "-Y", "dns.flags.response == 0",
                "-T", "fields", "-e", "dns.qry.name",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            queries = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
            for q in queries:
                if len(q) > 50:
                    return {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "level": "HIGH",
                        "rule": "dns_anomalies",
                        "message": f"Suspicious high-entropy/long DNS query observed (possible DNS tunneling/exfiltration).",
                        "details": {"query": q[:100]},
                    }
            if len(queries) > 80:
                return {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "level": "WARNING",
                    "rule": "dns_anomalies",
                    "message": f"Excessive DNS query volume: {len(queries)} queries in {pcap.name} sample.",
                    "details": {"query_count": len(queries)},
                }
        except Exception:
            pass
        return None

    def _check_virustotal_ips(self, pcap: Path, tshark: str) -> list[dict[str, Any]]:
        alerts = []
        try:
            cmd = [
                tshark, "-r", str(pcap),
                "-T", "fields",
                "-e", "ip.src", "-e", "ip.dst",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            seen_ips: set[str] = set()
            for line in res.stdout.splitlines():
                for part in line.split():
                    for sub in part.split(","):
                        ip = sub.strip()
                        if ip and is_public_ip(ip):
                            seen_ips.add(ip)

            for ip in seen_ips:
                # If already tested, check_ip returns cached report without re-querying!
                # If not tested, scans via VirusTotal, caches report in memory and sends alert if >= 70%.
                report = self.vt.check_ip(ip, send_alerts=True)
                if report.get("is_malicious"):
                    stats = report.get("stats", {})
                    alerts.append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "level": "CRITICAL",
                        "rule": "virustotal",
                        "message": (
                            f"VirusTotal detected malicious connected IP: {ip} "
                            f"(Malicious Score: {report.get('malicious_score')}%, "
                            f"{stats.get('malicious', 0)}/{stats.get('total_engines', 0)} security vendors). "
                            f"Org: {report.get('as_owner')}, Country: {report.get('country')}."
                        ),
                        "details": {
                            "ip": ip,
                            "malicious_score": f"{report.get('malicious_score')}%",
                            "engines_flagged": f"{stats.get('malicious', 0)}/{stats.get('total_engines', 0)}",
                            "as_owner": report.get("as_owner"),
                            "country": report.get("country"),
                        },
                    })
        except Exception as e:
            print(f"[{datetime.now()}] VirusTotal inspection error: {e}", flush=True)
        return alerts


# =========================================================================
# CLI Entrypoint for the Detached Worker Process
# =========================================================================

def main():
    parser = argparse.ArgumentParser(description="NetAgent Continuous Monitor Worker")
    parser.add_argument("action", choices=["worker"], help="Action to execute")
    parser.add_argument("monitor_id", help="Monitor ID to run")
    args = parser.parse_args()

    if args.action == "worker":
        worker = ContinuousMonitorWorker(args.monitor_id)
        worker.run()


if __name__ == "__main__":
    main()
