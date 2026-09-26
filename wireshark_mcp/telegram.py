"""
Telegram Bot Notification Integration for NetAgent.
Allows sending critical network security alerts directly to a designated Telegram chat
via a BotFather Telegram bot token.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime
from typing import Any

import httpx

from .config import load_config


class TelegramNotifier:
    """Manages Telegram bot alerts and notifications."""

    def __init__(self, bot_token: str | None = None, chat_id: str | None = None) -> None:
        cfg = load_config()
        tg_cfg = cfg.telegram if hasattr(cfg, "telegram") else {}
        self.bot_token = (
            bot_token
            or os.environ.get("TELEGRAM_BOT_TOKEN")
            or os.environ.get("WSMCP_TELEGRAM_BOT_TOKEN")
            or tg_cfg.get("bot_token")
        )
        self.chat_id = (
            chat_id
            or os.environ.get("TELEGRAM_CHAT_ID")
            or os.environ.get("WSMCP_TELEGRAM_CHAT_ID")
            or tg_cfg.get("chat_id")
        )
        if self.chat_id:
            self.chat_id = str(self.chat_id).strip()
        if self.bot_token:
            self.bot_token = str(self.bot_token).strip()

    def is_configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def test_connection(self) -> dict[str, Any]:
        """Test the bot token and attempt to send a ping message."""
        if not self.bot_token:
            return {"success": False, "error": "Bot token is missing or not configured."}

        # Step 1: getMe
        try:
            r = httpx.get(
                f"https://api.telegram.org/bot{self.bot_token}/getMe",
                timeout=10.0,
            )
            data = r.json()
            if not data.get("ok"):
                return {"success": False, "error": f"Invalid bot token: {data.get('description', 'Unknown error')}"}
            bot_user = data.get("result", {}).get("username", "UnknownBot")
        except Exception as e:
            return {"success": False, "error": f"Connection error testing Telegram bot token: {e}"}

        # Step 2: send test message if chat_id is present
        if not self.chat_id:
            return {
                "success": True,
                "bot_username": bot_user,
                "message": f"Token valid (@{bot_user}). However, chat_id is not set yet.",
            }

        hostname = socket.gethostname()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        text = (
            f"[OK] *NetAgent Telegram Alert System Online*\n\n"
            f"• *Host:* `{hostname}`\n"
            f"• *Time:* `{now}`\n"
            f"• *Status:* Connected & Verified\n\n"
            f"Continuous subagent monitors and critical security alerts will be dispatched here."
        )

        try:
            r2 = httpx.post(
                f"https://api.telegram.org/bot{self.bot_token}/sendMessage",
                json={
                    "chat_id": self.chat_id,
                    "text": text,
                    "parse_mode": "Markdown",
                },
                timeout=10.0,
            )
            res2 = r2.json()
            if res2.get("ok"):
                return {
                    "success": True,
                    "bot_username": bot_user,
                    "chat_id": self.chat_id,
                    "message": f"Test message delivered successfully to chat {self.chat_id} via @{bot_user}.",
                }
            return {
                "success": False,
                "bot_username": bot_user,
                "error": f"Failed to deliver message to chat {self.chat_id}: {res2.get('description')}",
            }
        except Exception as e:
            return {"success": False, "bot_username": bot_user, "error": f"Failed to send test message: {e}"}

    def send_alert(
        self,
        message: str,
        level: str = "CRITICAL",
        category: str = "Network Threat",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Dispatch a security alert to the configured Telegram chat."""
        if not self.is_configured():
            return {
                "success": False,
                "error": "Telegram notifications not configured. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.",
            }

        level_emoji = {
            "CRITICAL": "[ALERT]",
            "HIGH": "[!]️",
            "WARNING": "⚡",
            "INFO": "ℹ️",
        }.get(level.upper(), "[ALERT]")

        hostname = socket.gethostname()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        formatted_text = (
            f"{level_emoji} *[NetAgent Alert - {level.upper()}]*\n"
            f"*Category:* {category}\n"
            f"*Host:* `{hostname}` | *Time:* `{now}`\n\n"
            f"{message}\n"
        )

        if details:
            formatted_text += "\n*Details:*\n"
            for k, v in details.items():
                formatted_text += f"• *{k}:* `{v}`\n"

        try:
            r = httpx.post(
                f"https://api.telegram.org/bot{self.bot_token}/sendMessage",
                json={
                    "chat_id": self.chat_id,
                    "text": formatted_text,
                    "parse_mode": "Markdown",
                },
                timeout=10.0,
            )
            res = r.json()
            if res.get("ok"):
                return {"success": True, "message_id": res["result"]["message_id"]}
            return {"success": False, "error": res.get("description", "Failed to send message")}
        except Exception as e:
            return {"success": False, "error": str(e)}


_default_notifier: TelegramNotifier | None = None


def get_telegram_notifier() -> TelegramNotifier:
    global _default_notifier
    if _default_notifier is None:
        _default_notifier = TelegramNotifier()
    return _default_notifier


class TelegramBotService:
    """
    Two-way interactive Telegram bot service for NetAgent.
    Allows user to directly talk to NetAgent via Telegram:
      - Query host status and active monitors
      - Start and stop continuous background monitoring subagents
      - Check VirusTotal IP reputation
      - Receive security alerts
      - Chat with NetAgent (Sarvam AI / local) directly from Telegram
    All logging is directed to telegram_bot.log and completely isolated from the CLI interface.
    """

    def __init__(self, bot_token: str | None = None, chat_id: str | None = None) -> None:
        self.notifier = TelegramNotifier(bot_token=bot_token, chat_id=chat_id)
        self.bot_token = self.notifier.bot_token
        self.chat_id = self.notifier.chat_id
        cfg = load_config()
        self.log_file = Path(cfg.monitors_dir) / "telegram_bot.log"
        self.pid_file = Path(cfg.monitors_dir) / "telegram_bot.pid"
        self._sarvam_api_key = (
            os.environ.get("SARVAM_API_KEY")
            or os.environ.get("WSMCP_SARVAM_API_KEY")
            or (cfg.sarvam.get("api_key") if hasattr(cfg, "sarvam") else None)
        )

    def _log(self, msg: str) -> None:
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
        except Exception:
            pass

    def send_reply(self, chat_id: str, text: str) -> bool:
        if not self.bot_token:
            return False
        # Try Markdown first; fallback to plain text if markdown parsing fails
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        try:
            r = httpx.post(
                url,
                json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
                timeout=12.0,
            )
            if r.json().get("ok"):
                return True
        except Exception:
            pass

        try:
            r2 = httpx.post(
                url,
                json={"chat_id": chat_id, "text": text},
                timeout=12.0,
            )
            return bool(r2.json().get("ok"))
        except Exception as e:
            self._log(f"Failed to send reply to {chat_id}: {e}")
            return False

    def handle_command(self, chat_id: str, text: str) -> str:
        """Process incoming command and return response string."""
        cmd = text.strip()
        cmd_lower = cmd.lower()

        if cmd_lower in ("/start", "/help", "help"):
            return (
                "[DEFENSE] *NetAgent Network Defense Telegram Interface*\n\n"
                "Available Commands:\n"
                "• `/status` - Host telemetry & active monitors count\n"
                "• `/monitors` or `/agents` - List running continuous subagents\n"
                "• `/start_monitor [iface]` - Spawn a 24/7 background monitor subagent (e.g. `/start_monitor all`)\n"
                "• `/stop_monitor <id>` - Stop a monitoring subagent\n"
                "• `/stats <id>` - In-depth metrics, cycle counts, & alerts\n"
                "• `/check <ip>` or `/vt <ip>` - VirusTotal IP reputation lookup\n"
                "• `/alerts` - Latest detected threat alerts\n"
                "• `/captures` - List recent capture files on disk\n\n"
                "[TIP] *Natural Conversation:* You can also send any cybersecurity question or network query to chat directly with NetAgent!"
            )

        if cmd_lower in ("/status", "status"):
            from .monitor import ContinuousMonitorManager
            from .memory import MemoryStore
            from .virustotal import VirusTotalClient
            hostname = socket.gethostname()
            mgr = ContinuousMonitorManager()
            monitors = mgr.list_monitors()
            running = sum(1 for m in monitors if m.get("status") == "RUNNING")
            mem = MemoryStore().recall()
            vt_cache = VirusTotalClient().cache

            return (
                f"[SENTINEL] *NetAgent System Status*\n\n"
                f"• *Host:* `{hostname}`\n"
                f"• *Continuous Monitors:* `{running}/{len(monitors)} active`\n"
                f"• *Long-term Memory Insights:* `{len(mem)} items`\n"
                f"• *VirusTotal Cached IPs:* `{len(vt_cache)} scanned`\n"
                f"• *Status:* Operational & Active"
            )

        if cmd_lower in ("/monitors", "/agents", "agents", "list agents", "list monitors"):
            from .monitor import ContinuousMonitorManager
            mgr = ContinuousMonitorManager()
            monitors = mgr.list_monitors()
            if not monitors:
                return "ℹ️ No continuous monitoring subagents are currently registered. Use `/start_monitor all` to spawn one."
            lines = ["[DEFENSE] *Continuous Monitoring Subagents:*"]
            for m in monitors:
                status_icon = "[RUNNING]" if m.get("status") == "RUNNING" else "[STOPPED]"
                st = m.get("stats", {})
                lines.append(
                    f"\n{status_icon} *{m.get('name')}* (`{m['id']}`)\n"
                    f"  • Status: `{m.get('status')}` (PID: `{m.get('pid') or 'None'}`)\n"
                    f"  • Interface: `{m.get('interface')}` | Interval: `{m.get('interval_seconds')}s`\n"
                    f"  • Packets Inspected: `{st.get('total_packets', 0):,}`\n"
                    f"  • Threats Detected: `{st.get('threats_detected', 0)}`"
                )
            return "\n".join(lines)

        if cmd_lower.startswith("/start_monitor") or cmd_lower.startswith("start monitor"):
            parts = cmd.split(maxsplit=2)
            iface = parts[1] if len(parts) > 1 else "all"
            name = parts[2] if len(parts) > 2 else f"agent-{iface}"
            from .monitor import ContinuousMonitorManager
            mgr = ContinuousMonitorManager()
            res = mgr.start_monitor(name=name, interface=iface)
            return (
                f"[OK] *Continuous Monitor Subagent Spawned!*\n\n"
                f"• *ID:* `{res['id']}`\n"
                f"• *Name:* `{res['name']}`\n"
                f"• *Interface:* `{res['interface']}`\n"
                f"• *PID:* `{res.get('pid')}`\n"
                f"• *Cycle Interval:* `{res['interval_seconds']}s` (Probe: `{res['capture_duration']}s`)\n"
                f"• *Status:* Running in background (independent of terminal)\n"
                f"• *Rules:* `{', '.join(res['rules'])}`"
            )

        if cmd_lower.startswith("/stop_monitor") or cmd_lower.startswith("stop monitor"):
            parts = cmd.split(maxsplit=1)
            if len(parts) < 2:
                return "[!]️ Please specify the subagent ID to stop, e.g. `/stop_monitor mon_123456`."
            target_id = parts[1].strip()
            from .monitor import ContinuousMonitorManager
            mgr = ContinuousMonitorManager()
            ok = mgr.stop_monitor(target_id)
            if ok:
                return f"[STOPPED] Successfully stopped monitoring subagent `{target_id}`."
            return f"[FAIL] Could not stop subagent `{target_id}`. Check ID with `/monitors`."

        if cmd_lower.startswith("/stats") or cmd_lower.startswith("stats"):
            parts = cmd.split(maxsplit=1)
            if len(parts) < 2:
                return "[!]️ Please specify the subagent ID, e.g. `/stats mon_123456`."
            target_id = parts[1].strip()
            from .monitor import ContinuousMonitorManager
            mgr = ContinuousMonitorManager()
            m = mgr.get_monitor(target_id)
            if not m:
                return f"[FAIL] Subagent `{target_id}` not found."
            st = m.get("stats", {})
            alerts = st.get("recent_alerts", [])
            txt = (
                f"[METRICS] *Metrics for {m.get('name')}* (`{m['id']}`)\n"
                f"• *Status:* `{m.get('status')}` (PID: `{m.get('pid') or 'None'}`)\n"
                f"• *Interface:* `{m.get('interface')}`\n"
                f"• *Total Cycles:* `{st.get('total_cycles', 0)}`\n"
                f"• *Total Packets:* `{st.get('total_packets', 0):,}`\n"
                f"• *Threats Detected:* `{st.get('threats_detected', 0)}`\n"
                f"• *Last Run:* `{st.get('last_run') or 'Never'}`\n"
            )
            if alerts:
                txt += "\n[ALERT] *Recent Alerts:*\n"
                for a in alerts[-3:]:
                    txt += f"• [{a.get('level')}] *{a.get('rule')}:* {a.get('message')}\n"
            else:
                txt += "\n[OK] No security threats detected by this agent."
            return txt

        if cmd_lower.startswith("/check") or cmd_lower.startswith("/vt") or cmd_lower.startswith("check ip"):
            parts = cmd.split(maxsplit=1)
            if len(parts) < 2:
                return "[!]️ Please provide an IP address to scan, e.g. `/check 1.1.1.1`."
            target_ip = parts[1].strip().strip("`").strip("'")
            from .virustotal import VirusTotalClient
            vt = VirusTotalClient()
            rep = vt.check_ip(target_ip, send_alerts=False)
            if "error" in rep:
                return f"[FAIL] VirusTotal Error: {rep['error']}"
            if not rep.get("is_public", True):
                return f"ℹ️ `{target_ip}` is a private/internal IP address. VirusTotal checks apply to public Internet IPs."
            cached = "_(cached in memory)_" if rep.get("cached") else "_(fresh scan)_"
            status_emoji = "[ALERT] *MALICIOUS THREAT*" if rep.get("is_malicious") else "[OK] *CLEAN / BENIGN*"
            stats = rep.get("stats", {})
            return (
                f"[DEFENSE] *VirusTotal Intelligence Report* {cached}\n\n"
                f"• *IP:* `{target_ip}`\n"
                f"• *Verdict:* {status_emoji}\n"
                f"• *Malicious Score:* `{rep.get('malicious_score')}%`\n"
                f"• *Vendor Detections:* `{stats.get('malicious', 0)}/{stats.get('total_engines', 0)}`\n"
                f"• *Autonomous System / Org:* `{rep.get('as_owner')}`\n"
                f"• *Country:* `{rep.get('country')}`\n"
                f"• *Scanned At:* `{rep.get('scanned_at')}`"
            )

        if cmd_lower in ("/alerts", "alerts"):
            from .monitor import ContinuousMonitorManager
            mgr = ContinuousMonitorManager()
            all_alerts = []
            for m in mgr.list_monitors():
                for alt in m.get("stats", {}).get("recent_alerts", []):
                    all_alerts.append((m.get("name"), alt))
            if not all_alerts:
                return "[OK] No threat alerts recorded across any continuous monitor agents."
            lines = ["[ALERT] *Latest Security Alerts Across All Subagents:*"]
            for agent_name, alt in all_alerts[-8:]:
                lines.append(
                    f"• *[{alt.get('level')}]* `{agent_name}` ({alt.get('rule')}):\n"
                    f"  {alt.get('message')} _({alt.get('timestamp')})_"
                )
            return "\n".join(lines)

        if cmd_lower in ("/captures", "captures"):
            cfg = load_config()
            cap_dir = Path(cfg.capture_dir)
            files = sorted(cap_dir.glob("*.pcap*"), key=lambda f: f.stat().st_mtime, reverse=True)
            if not files:
                return "[FILE] No packet captures saved in local capture directory yet."
            lines = [f"[FILE] *Recent Packet Captures ({len(files)} total):*"]
            for f in files[:8]:
                size_mb = f.stat().st_size / (1024 * 1024)
                lines.append(f"• `{f.name}` ({size_mb:.2f} MB)")
            return "\n".join(lines)

        # Natural Language / Chat with NetAgent via Sarvam AI
        if self._sarvam_api_key:
            try:
                sys_prompt = (
                    "You are NetAgent, an elite cybersecurity and network traffic analysis assistant. "
                    "You are replying to the user over Telegram. Provide concise, direct, technically accurate, "
                    "and professional network security responses. Do not hallucinate packet numbers or IPs. "
                    "Format responses using clean Telegram Markdown."
                )
                r = httpx.post(
                    "https://api.sarvam.ai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self._sarvam_api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "sarvam-105b",
                        "messages": [
                            {"role": "system", "content": sys_prompt},
                            {"role": "user", "content": cmd},
                        ],
                        "max_tokens": 800,
                        "temperature": 0.2,
                    },
                    timeout=25.0,
                )
                data = r.json()
                reply = data.get("choices", [{}])[0].get("message", {}).get("content")
                if reply:
                    return reply
            except Exception as e:
                self._log(f"Sarvam AI query error: {e}")

        # Fallback if no LLM configured
        return (
            f"NetAgent received: \"{cmd}\"\n\n"
            f"Use `/help` to view all available commands, or `/monitors` to check subagents."
        )

    def run_polling(self) -> None:
        """Continuous long-polling loop for Telegram updates."""
        if not self.bot_token:
            self._log("Cannot run Telegram bot: bot token not configured.")
            return

        # Save PID
        try:
            self.pid_file.write_text(str(os.getpid()), encoding="utf-8")
        except Exception:
            pass

        self._log(f"Telegram bot polling service started (PID: {os.getpid()}).")
        offset = 0

        while True:
            try:
                url = f"https://api.telegram.org/bot{self.bot_token}/getUpdates"
                params: dict[str, Any] = {"timeout": 20}
                if offset:
                    params["offset"] = offset

                r = httpx.get(url, params=params, timeout=30.0)
                data = r.json()

                if not data.get("ok"):
                    self._log(f"getUpdates error: {data.get('description')}")
                    time.sleep(5)
                    continue

                updates = data.get("result", [])
                for update in updates:
                    update_id = update.get("update_id", 0)
                    offset = max(offset, update_id + 1)

                    message = update.get("message", {})
                    text = message.get("text", "")
                    sender_chat = message.get("chat", {})
                    chat_id = str(sender_chat.get("id", ""))

                    if not text or not chat_id:
                        continue

                    # If chat_id whitelist configured, enforce it
                    if self.chat_id and str(self.chat_id) != chat_id:
                        self._log(f"Ignored message from unauthorized chat_id: {chat_id}")
                        continue
                    elif not self.chat_id:
                        # Auto-pair first chat_id if not yet configured
                        self.chat_id = chat_id
                        self.notifier.chat_id = chat_id
                        self._log(f"Paired with Telegram chat_id: {chat_id}")

                    # Process command / message
                    self._log(f"Received message from {chat_id}: {text[:60]}")
                    response = self.handle_command(chat_id, text)
                    self.send_reply(chat_id, response)

            except httpx.TimeoutException:
                continue
            except Exception as e:
                self._log(f"Telegram polling loop exception: {e}")
                time.sleep(3)

    def start_daemon(self) -> dict[str, Any]:
        """Spawn the Telegram bot listener as a detached background daemon."""
        if not self.bot_token:
            return {"success": False, "error": "Bot token not configured. Set TELEGRAM_BOT_TOKEN."}

        # Check if already running
        status = self.get_daemon_status()
        if status.get("running"):
            return {"success": True, "pid": status.get("pid"), "message": "Telegram bot daemon is already running."}

        python_exe = sys.executable
        if "netagent" in Path(python_exe).name.lower() or "Scripts" in python_exe:
            cand = Path(python_exe).parent.parent / "python.exe"
            if cand.is_file():
                python_exe = str(cand)
            else:
                python_exe = shutil.which("python") or sys.executable

        proj_root = str(Path(__file__).resolve().parent.parent)
        cmd = [python_exe, "-m", "wireshark_mcp.telegram", "daemon"]

        creationflags = 0
        if sys.platform == "win32":
            creationflags = 0x08000000 | 0x00000200

        proc = subprocess.Popen(
            cmd,
            cwd=proj_root,
            env=dict(os.environ, PYTHONPATH=proj_root),
            creationflags=creationflags,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )

        try:
            self.pid_file.write_text(str(proc.pid), encoding="utf-8")
        except Exception:
            pass

        return {
            "success": True,
            "pid": proc.pid,
            "message": f"Telegram bot daemon started in background (PID: {proc.pid}). Logs: {self.log_file}",
        }

    def stop_daemon(self) -> dict[str, Any]:
        """Stop running Telegram bot daemon."""
        status = self.get_daemon_status()
        pid = status.get("pid")
        if not status.get("running") or not pid:
            return {"success": True, "message": "Telegram bot daemon is not running."}

        try:
            import psutil
            if psutil.pid_exists(pid):
                p = psutil.Process(pid)
                p.terminate()
                try:
                    p.wait(timeout=3)
                except psutil.TimeoutExpired:
                    p.kill()
        except Exception as e:
            self._log(f"Error terminating daemon PID {pid}: {e}")

        try:
            if self.pid_file.is_file():
                self.pid_file.unlink()
        except Exception:
            pass

        return {"success": True, "message": f"Telegram bot daemon (PID {pid}) stopped."}

    def get_daemon_status(self) -> dict[str, Any]:
        """Check if Telegram bot daemon is active."""
        if not self.pid_file.is_file():
            return {"running": False, "pid": None}
        try:
            pid_str = self.pid_file.read_text(encoding="utf-8").strip()
            if pid_str.isdigit():
                pid = int(pid_str)
                import psutil
                if psutil.pid_exists(pid):
                    p = psutil.Process(pid)
                    if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                        return {"running": True, "pid": pid}
        except Exception:
            pass
        return {"running": False, "pid": None}


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "daemon":
        bot = TelegramBotService()
        bot.run_polling()

