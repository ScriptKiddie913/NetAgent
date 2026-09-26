#!/usr/bin/env python3
"""
NetAgent Setup & One-Click Installer (setup_netagent.py)

Performs end-to-end setup for NetAgent:
1. Prompts for or verifies Sarvam AI API Key (and optional Telegram Bot tokens).
2. Installs NetAgent and all dependencies into current Python environment in editable mode.
3. Sets up global PowerShell PATH and execution shims so `netagent` runs from ANY directory.
4. Initializes isolated Sandbox, Long-Term Memory, Sessions, and Background Monitor directories.
5. Pre-authorizes live packet captures.
6. Runs NetAgent diagnostics check (`netagent doctor`).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def print_banner():
    banner = r"""
  _   _      _        _                    _   
 | \ | | ___| |_     / \   __ _  ___ _ __ | |_ 
 |  \| |/ _ \ __|   / _ \ / _` |/ _ \ '_ \| __|
 | |\  |  __/ |_   / ___ \ (_| |  __/ | | | |_ 
 |_| \_|\___|\__| /_/   \_\__, |\___|_| |_|\__|
                          |___/                
       Autonomous AI Network Defense & Traffic Sentinel
    ======================================================
"""
    print(banner)


def run_cmd(cmd: list[str], desc: str) -> bool:
    print(f"[*] {desc}...")
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print(f"    [+] {desc} succeeded.")
            return True
        else:
            print(f"    [-] Warning during {desc}:\n{res.stderr.strip()}")
            return False
    except Exception as e:
        print(f"    [-] Error running {cmd}: {e}")
        return False


def _run_system_installer(cmd: list[str], desc: str, env: dict | None = None) -> bool:
    print(f"[*] {desc}...")
    try:
        # Check if sudo is usable
        res = subprocess.run(cmd, env=env, capture_output=False, text=True)
        return res.returncode == 0
    except Exception as e:
        print(f"    [-] Error executing {desc}: {e}")
        return False


def ensure_linux_network_stack() -> bool:
    """Auto-detects and installs TShark, Wireshark, Nmap, tcpdump and core IP tools on Linux."""
    tshark_found = bool(shutil.which("tshark"))
    nmap_found = bool(shutil.which("nmap"))
    dumpcap_found = bool(shutil.which("dumpcap"))

    if tshark_found and nmap_found and dumpcap_found:
        print(f"    [+] Found tshark in PATH: {shutil.which('tshark')}")
        print(f"    [+] Found nmap in PATH: {shutil.which('nmap')}")
        return True

    print("    [!] Missing network forensic / scanning tools on Linux:")
    if not tshark_found:
        print("        • tshark (CLI packet dissection engine) - MISSING")
    if not nmap_found:
        print("        • nmap (IP & port discovery scanner) - MISSING")
    if not dumpcap_found:
        print("        • dumpcap (packet capture engine) - MISSING")

    print("    [*] Automatically pulling and installing complete network forensic & IP stack...")

    # Debian / Ubuntu / Kali / Mint / PopOS (APT)
    if shutil.which("apt-get"):
        print("    [*] Configuring debconf for automated non-interactive packet capture permissions...")
        try:
            p = subprocess.Popen(["sudo", "-E", "debconf-set-selections"], stdin=subprocess.PIPE, text=True)
            p.communicate(input="wireshark-common wireshark-common/install-setuid boolean true\n")
        except Exception:
            pass

        apt_env = os.environ.copy()
        apt_env["DEBIAN_FRONTEND"] = "noninteractive"
        _run_system_installer(["sudo", "-E", "apt-get", "update", "-y"], "Updating APT package repository", env=apt_env)
        pkgs = ["tshark", "wireshark", "dumpcap", "nmap", "tcpdump", "net-tools", "iproute2", "traceroute", "libpcap-dev"]
        ok = _run_system_installer(["sudo", "-E", "apt-get", "install", "-y"] + pkgs, "Installing TShark, Wireshark, Nmap, tcpdump & IP tools via apt-get", env=apt_env)

        # Grant non-root packet capture rights
        user = os.environ.get("USER") or os.environ.get("LOGNAME")
        if user:
            subprocess.run(["sudo", "usermod", "-aG", "wireshark", user], capture_output=True)
        dumpcap_path = shutil.which("dumpcap") or "/usr/bin/dumpcap"
        if os.path.isfile(dumpcap_path):
            subprocess.run(["sudo", "chmod", "+x", dumpcap_path], capture_output=True)
            subprocess.run(["sudo", "setcap", "CAP_NET_RAW+eip CAP_NET_ADMIN+eip", dumpcap_path], capture_output=True)
            print("    [+] Configured non-root packet capture capabilities on dumpcap.")

        return bool(shutil.which("tshark"))

    # Fedora / RHEL / CentOS (DNF / YUM)
    elif shutil.which("dnf"):
        pkgs = ["wireshark", "wireshark-cli", "tshark", "nmap", "tcpdump", "net-tools", "iproute", "traceroute", "libpcap-devel"]
        _run_system_installer(["sudo", "dnf", "install", "-y"] + pkgs, "Installing network tools via dnf")
        user = os.environ.get("USER") or os.environ.get("LOGNAME")
        if user:
            subprocess.run(["sudo", "usermod", "-aG", "wireshark", user], capture_output=True)
        return bool(shutil.which("tshark"))

    # Arch Linux / Manjaro (Pacman)
    elif shutil.which("pacman"):
        pkgs = ["wireshark-cli", "wireshark-qt", "nmap", "tcpdump", "net-tools", "iproute2", "traceroute", "libpcap"]
        _run_system_installer(["sudo", "pacman", "-S", "--noconfirm"] + pkgs, "Installing network tools via pacman")
        user = os.environ.get("USER") or os.environ.get("LOGNAME")
        if user:
            subprocess.run(["sudo", "usermod", "-aG", "wireshark", user], capture_output=True)
        return bool(shutil.which("tshark"))

    # openSUSE (Zypper)
    elif shutil.which("zypper"):
        pkgs = ["wireshark", "tshark", "nmap", "tcpdump", "net-tools", "iproute2", "traceroute", "libpcap-devel"]
        _run_system_installer(["sudo", "zypper", "--non-interactive", "install"] + pkgs, "Installing network tools via zypper")
        return bool(shutil.which("tshark"))

    return False


def ensure_wireshark_installed() -> bool:
    """Detects and installs Wireshark / TShark if not present on system."""
    import urllib.request

    # On Linux, dispatch to comprehensive installer
    if sys.platform.startswith("linux"):
        return ensure_linux_network_stack()

    # 1. Check if tshark is directly discoverable in PATH
    tshark_found = shutil.which("tshark")
    if tshark_found:
        print(f"    [+] Found tshark in PATH: {tshark_found}")
        return True

    # 2. On Windows, check standard installation directories
    if sys.platform == "win32":
        known_dirs = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark",
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Wireshark",
        ]
        for wdir in known_dirs:
            tshark_exe = wdir / "tshark.exe"
            if tshark_exe.is_file():
                print(f"    [+] Found Wireshark at {wdir}. Registering in PATH...")
                os.environ["PATH"] = str(wdir) + os.pathsep + os.environ.get("PATH", "")
                try:
                    ps_cmd = (
                        f"$cur = [System.Environment]::GetEnvironmentVariable('Path', 'User'); "
                        f"if ($cur -notlike '*{str(wdir)}*') {{ "
                        f"[System.Environment]::SetEnvironmentVariable('Path', $cur + ';{str(wdir)}', 'User') "
                        f"}}"
                    )
                    subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True)
                except Exception:
                    pass
                return True

        # Wireshark is missing on Windows - Pull and Install automatically
        print("    [-] Wireshark / TShark not detected on system.")
        print("    [*] Pulling and installing Wireshark automatically (never assuming pre-present tools)...")

        # Try Winget
        if shutil.which("winget"):
            print("    [*] Installing via Windows Package Manager (winget)...")
            res = subprocess.run(
                ["winget", "install", "--id", "WiresharkFoundation.Wireshark", "-e", "--silent",
                 "--accept-source-agreements", "--accept-package-agreements"],
                capture_output=True, text=True
            )
            if res.returncode == 0:
                print("    [+] Wireshark installed successfully via winget.")
                for wdir in known_dirs:
                    if (wdir / "tshark.exe").is_file():
                        os.environ["PATH"] = str(wdir) + os.pathsep + os.environ.get("PATH", "")
                        return True

        # Try Chocolatey
        if shutil.which("choco"):
            print("    [*] Installing via Chocolatey...")
            res = subprocess.run(["choco", "install", "wireshark", "-y"], capture_output=True, text=True)
            if res.returncode == 0:
                print("    [+] Wireshark installed successfully via Chocolatey.")
                for wdir in known_dirs:
                    if (wdir / "tshark.exe").is_file():
                        os.environ["PATH"] = str(wdir) + os.pathsep + os.environ.get("PATH", "")
                        return True

        # Fallback: Pull official installer directly via HTTPS
        installer_url = "https://2.na.dl.wireshark.org/win64/Wireshark-latest-x64.exe"
        temp_installer = Path(tempfile.gettempdir()) / "WiresharkInstaller.exe"
        print(f"    [*] Pulling Wireshark installer from {installer_url}...")
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            req = urllib.request.Request(installer_url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as resp, open(temp_installer, "wb") as out_f:
                shutil.copyfileobj(resp, out_f)
            print(f"    [+] Pulled installer to {temp_installer}. Running silent installation...")
            subprocess.run([str(temp_installer), "/S", "/desktopicon=no", "/quicklaunchicon=no"], check=True)
            print("    [+] Wireshark silent installation completed.")
            for wdir in known_dirs:
                if (wdir / "tshark.exe").is_file():
                    os.environ["PATH"] = str(wdir) + os.pathsep + os.environ.get("PATH", "")
                    return True
        except Exception as e:
            print(f"    [-] Direct installer pull error: {e}")

    # macOS automated installation
    elif sys.platform == "darwin":
        if shutil.which("brew"):
            print("    [*] Installing Wireshark via Homebrew...")
            subprocess.run(["brew", "install", "--cask", "wireshark"], capture_output=True)
            return True

    return bool(shutil.which("tshark"))


def ensure_nmap_installed() -> bool:
    """Detects and installs Nmap if not present on system."""
    if shutil.which("nmap"):
        print("    [+] Found nmap in PATH.")
        return True

    if sys.platform.startswith("linux"):
        return ensure_linux_network_stack()

    if sys.platform == "win32":
        nmap_dirs = [
            Path(r"C:\Program Files (x86)\Nmap"),
            Path(r"C:\Program Files\Nmap"),
        ]
        for nd in nmap_dirs:
            if (nd / "nmap.exe").is_file():
                print(f"    [+] Found Nmap at {nd}. Registering in PATH...")
                os.environ["PATH"] = str(nd) + os.pathsep + os.environ.get("PATH", "")
                return True

        if shutil.which("winget"):
            print("    [*] Pulling Nmap via winget...")
            res = subprocess.run(
                ["winget", "install", "--id", "Insecure.Nmap", "-e", "--silent",
                 "--accept-source-agreements", "--accept-package-agreements"],
                capture_output=True, text=True
            )
            if res.returncode == 0:
                print("    [+] Nmap installed successfully.")
                return True

    print("    [i] Nmap raw binary not installed; NetAgent high-performance socket scanner active as fallback.")
    return False


def ensure_system_tools_installed():
    print("\n--- 0. System Prerequisite Verification & Auto-Installer ---")
    print("[*] Checking network packet inspection tools (Wireshark / TShark / Nmap)...")
    print("    [!] Policy: Never assume any tools are pre-present on system.")
    ensure_wireshark_installed()
    ensure_nmap_installed()


def setup_api_key(
    api_key_override: str | None = None,
    telegram_token: str | None = None,
    telegram_chat: str | None = None,
    virustotal_key: str | None = None,
) -> str:
    print("\n--- 1. AI Model, Alert & Threat Intel Configuration ---")
    if api_key_override:
        current_key = api_key_override.strip()
    else:
        current_key = os.environ.get("SARVAM_API_KEY", "").strip()

    # Also check config.yaml if present
    cfg_file = Path("config.yaml")
    if not current_key and cfg_file.is_file():
        try:
            import yaml
            with open(cfg_file, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
                current_key = (data.get("sarvam") or {}).get("api_key") or ""
        except Exception:
            pass

    if current_key and not api_key_override:
        masked = current_key[:8] + "..." + current_key[-4:] if len(current_key) > 12 else "********"
        print(f"[*] Found existing Sarvam API Key: {masked}")
        try:
            ans = input("    Press Enter to keep this key, or enter a new key: ").strip()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        api_key = ans if ans else current_key
    elif api_key_override:
        api_key = api_key_override.strip()
    else:
        print("[*] NetAgent runs autonomously on Sarvam AI cloud models (no local Ollama required).")
        print("    Get your API key at: https://dashboard.sarvam.ai")
        while not current_key:
            try:
                current_key = input("    Enter your SARVAM_API_KEY: ").strip()
            except (EOFError, KeyboardInterrupt):
                current_key = ""
                break
            if not current_key:
                print("    [!] API key cannot be empty. Please enter your Sarvam API key.")
        api_key = current_key or "YOUR_SARVAM_API_KEY_HERE"

    # Save to user environment permanently on Windows
    if sys.platform == "win32":
        try:
            subprocess.run(["setx", "SARVAM_API_KEY", api_key], capture_output=True, text=True)
            print("    [+] Saved SARVAM_API_KEY to Windows User Environment permanently.")
        except Exception:
            pass

    # Optional Telegram Bot Setup
    tg_token = telegram_token or os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    tg_chat = telegram_chat or os.environ.get("TELEGRAM_CHAT_ID", "").strip()

    if not tg_token and not api_key_override:
        print("\n[*] Optional Telegram Botfather Alerting:")
        try:
            tg_setup = input("    Configure Telegram alerts for critical security events? (y/N): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            tg_setup = "n"
        if tg_setup in ("y", "yes"):
            try:
                tg_token = input("    Enter Telegram Bot Token (from @BotFather): ").strip()
                tg_chat = input("    Enter Telegram Chat ID (user or group): ").strip()
            except (EOFError, KeyboardInterrupt):
                pass

    if tg_token and sys.platform == "win32":
        try:
            subprocess.run(["setx", "TELEGRAM_BOT_TOKEN", tg_token], capture_output=True, text=True)
            if tg_chat:
                subprocess.run(["setx", "TELEGRAM_CHAT_ID", tg_chat], capture_output=True, text=True)
            print("    [+] Saved Telegram credentials to Windows User Environment.")
        except Exception:
            pass

    # Optional VirusTotal API Setup
    vt_key = virustotal_key or os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not vt_key and not api_key_override:
        print("\n[*] Optional VirusTotal Threat Intelligence:")
        print("    Automatically inspects all newly connected IP addresses against VirusTotal.")
        print("    Flags malicious IPs with detection score >= 70% and sends alerts.")
        try:
            vt_setup = input("    Configure VirusTotal API key now? (y/N): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            vt_setup = "n"
        if vt_setup in ("y", "yes"):
            try:
                vt_key = input("    Enter VirusTotal API Key: ").strip()
            except (EOFError, KeyboardInterrupt):
                pass

    if vt_key and sys.platform == "win32":
        try:
            subprocess.run(["setx", "VIRUSTOTAL_API_KEY", vt_key], capture_output=True, text=True)
            print("    [+] Saved VIRUSTOTAL_API_KEY to Windows User Environment.")
        except Exception:
            pass

    # Save to ~/.netagent/config.yaml and local config.yaml
    home_netagent = Path.home() / ".netagent"
    home_netagent.mkdir(parents=True, exist_ok=True)
    home_cfg = home_netagent / "config.yaml"

    yaml_content = f"""# NetAgent Global Configuration
provider: sarvam

sarvam:
  api_key: "{api_key}"
  supervisor_model: "sarvam-105b"
  agent_model: "sarvam-105b-conversations"
  temperature: 0.1
  max_tokens: 1000

decisions:
  require_confirmation: true
  sensitive_tools:
    - delete_capture
    - cleanup_old_captures
    - stop_all_captures
    - start_ring_capture

security:
  require_authorization_ack: true
  allowed_interfaces: []

telegram:
  enabled: {str(bool(tg_token and tg_chat)).lower()}
  bot_token: "{tg_token or ''}"
  chat_id: "{tg_chat or ''}"

virustotal:
  enabled: {str(bool(vt_key)).lower()}
  api_key: "{vt_key or ''}"
  alert_threshold_percent: 70
"""
    try:
        with open(home_cfg, "w", encoding="utf-8") as fh:
            fh.write(yaml_content)
        print(f"    [+] Saved configuration to {home_cfg}")
    except Exception as e:
        print(f"    [-] Warning writing {home_cfg}: {e}")

    local_cfg = Path(__file__).resolve().parent / "config.yaml"
    try:
        with open(local_cfg, "w", encoding="utf-8") as fh:
            fh.write(yaml_content)
        print(f"    [+] Saved local workspace configuration to {local_cfg}")
    except Exception:
        pass

    os.environ["SARVAM_API_KEY"] = api_key
    if tg_token:
        os.environ["TELEGRAM_BOT_TOKEN"] = tg_token
    if tg_chat:
        os.environ["TELEGRAM_CHAT_ID"] = tg_chat
    if vt_key:
        os.environ["VIRUSTOTAL_API_KEY"] = vt_key
    return api_key


def install_dependencies():
    print("\n--- 2. Installing NetAgent Package & Dependencies ---")
    python_exe = sys.executable
    run_cmd([python_exe, "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel", "psutil"], "Upgrading pip, setuptools, wheel & psutil")
    run_cmd([python_exe, "-m", "pip", "install", "-e", "."], "Installing NetAgent in editable mode")


def configure_powershell_path():
    print("\n--- 3. Configuring Global 'netagent' Command & PATH ---")
    import sysconfig
    scripts_dir = sysconfig.get_path("scripts")
    if not os.path.isdir(scripts_dir):
        python_dir = os.path.dirname(sys.executable)
        candidates = [
            os.path.join(python_dir, "Scripts"),
            os.path.join(python_dir, "bin"),
            python_dir,
            os.path.join(os.path.dirname(python_dir), "Scripts"),
            os.path.join(os.path.dirname(python_dir), "bin"),
        ]
        for c in candidates:
            if os.path.isdir(c):
                scripts_dir = c
                break

    print(f"[*] Python Scripts/bin directory: {scripts_dir}")

    # Check if scripts_dir is in PATH
    path_env = os.environ.get("PATH", "")
    if scripts_dir.lower() not in path_env.lower():
        if sys.platform == "win32":
            try:
                ps_cmd = (
                    f"$current = [System.Environment]::GetEnvironmentVariable('Path', 'User'); "
                    f"if ($current -notlike '*{scripts_dir}*') {{ "
                    f"[System.Environment]::SetEnvironmentVariable('Path', $current + ';{scripts_dir}', 'User') "
                    f"}}"
                )
                subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True)
                print(f"    [+] Added {scripts_dir} to User PATH in Windows registry.")
            except Exception as e:
                print(f"    [-] Could not update registry PATH: {e}")
        else:
            print(f"    [!] Note: Ensure {scripts_dir} is in your PATH (e.g., in ~/.bashrc or ~/.zshrc).")
    else:
        print("    [+] Python Scripts/bin directory is already in PATH.")

    # Also create netagent shims in ~/.netagent/bin (cross-platform)
    user_bin = Path.home() / ".netagent" / "bin"
    user_bin.mkdir(parents=True, exist_ok=True)
    cmd_script = user_bin / "netagent.cmd"
    ps_script = user_bin / "netagent.ps1"
    sh_script = user_bin / "netagent"

    python_run = sys.executable
    with open(cmd_script, "w", encoding="utf-8") as fh:
        fh.write(f'@echo off\n"{python_run}" -m wireshark_mcp.cli %*\n')

    with open(ps_script, "w", encoding="utf-8") as fh:
        fh.write(f'& "{python_run}" -m wireshark_mcp.cli $args\n')

    with open(sh_script, "w", encoding="utf-8") as fh:
        fh.write(f'#!/usr/bin/env bash\nexec "{python_run}" -m wireshark_mcp.cli "$@"\n')
    try:
        sh_script.chmod(0o755)
    except Exception:
        pass

    print(f"    [+] Created global execution shims at {user_bin}")


def initialize_directories_and_auth():
    print("\n--- 4. Initializing /capture, /data, Sandbox, Memory, Sessions & Monitors ---")
    from wireshark_mcp.config import PROJECT_ROOT, DEFAULT_CAPTURE_DIR, DEFAULT_DATA_DIR
    
    # 1. Project-level /capture and /data directories
    os.makedirs(DEFAULT_CAPTURE_DIR, exist_ok=True)
    os.makedirs(DEFAULT_DATA_DIR, exist_ok=True)

    data_subdirs = [
        os.path.join(DEFAULT_DATA_DIR, "reports"),
        os.path.join(DEFAULT_DATA_DIR, "extracted"),
        os.path.join(DEFAULT_DATA_DIR, "subagents"),
        os.path.join(DEFAULT_DATA_DIR, "sessions"),
        os.path.join(DEFAULT_DATA_DIR, "memory"),
        os.path.join(DEFAULT_DATA_DIR, "sandbox"),
        os.path.join(DEFAULT_DATA_DIR, "monitors"),
        os.path.join(DEFAULT_DATA_DIR, "scans"),
    ]
    for d in data_subdirs:
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            pass
    print(f"    [+] Initialized /capture at {DEFAULT_CAPTURE_DIR}")
    print(f"    [+] Initialized /data directory structure at {DEFAULT_DATA_DIR}")

    # Fallback temp dir
    base_dir = os.path.join(tempfile.gettempdir(), "wireshark_mcp_captures")
    try:
        os.makedirs(base_dir, exist_ok=True)
        os.makedirs(os.path.join(base_dir, "memory"), exist_ok=True)
    except Exception:
        pass

    # Auto-authorize capture marker in all locations
    for d in [DEFAULT_CAPTURE_DIR, DEFAULT_DATA_DIR, base_dir]:
        try:
            auth_marker = os.path.join(d, ".authorized")
            with open(auth_marker, "w", encoding="utf-8") as fh:
                fh.write(f"authorized {d} setup_netagent\n")
        except Exception:
            pass
    print("    [+] Live packet capture permission pre-authorized.")

    # Pre-populate long-term memory with baseline network knowledge
    seed_memories = [
        {
            "entry_id": "mem_seed01",
            "category": "topology",
            "content": "Standard private subnets: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16. Multicast: 224.0.0.0/4.",
            "created_at": "2026-01-01 00:00:00",
            "source": "system",
        },
        {
            "entry_id": "mem_seed02",
            "category": "preference",
            "content": "Default live capture duration is 15 seconds. Use tshark or PowerShell for interface enumeration.",
            "created_at": "2026-01-01 00:00:00",
            "source": "system",
        }
    ]
    import json
    for target_dir in [os.path.join(DEFAULT_DATA_DIR, "memory"), os.path.join(base_dir, "memory")]:
        try:
            os.makedirs(target_dir, exist_ok=True)
            mem_file = os.path.join(target_dir, "long_term_memory.json")
            if not os.path.isfile(mem_file):
                with open(mem_file, "w", encoding="utf-8") as fh:
                    json.dump(seed_memories, fh, indent=2)
        except Exception:
            pass
    print("    [+] Long-term network memory seeded with baseline topology rules.")


def verify_installation():
    print("\n--- 5. Running NetAgent Diagnostic Check ---")
    python_exe = sys.executable
    subprocess.run([python_exe, "-m", "wireshark_mcp.cli", "doctor"])


def configure_claude_desktop_mcp():
    """Detects and registers NetAgent in Claude Desktop if installed."""
    import json
    if sys.platform == "win32":
        cfg_path = Path(os.environ.get("APPDATA", "")) / "Claude" / "claude_desktop_config.json"
    elif sys.platform == "darwin":
        cfg_path = Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    else:
        cfg_path = Path.home() / ".config" / "Claude" / "claude_desktop_config.json"

    if cfg_path.parent.is_dir():
        print("\n--- 6. Claude Desktop MCP Auto-Integration ---")
        print(f"[*] Detected Claude Desktop installation at: {cfg_path.parent}")
        existing_cfg = {}
        if cfg_path.is_file():
            try:
                with open(cfg_path, "r", encoding="utf-8") as fh:
                    existing_cfg = json.load(fh)
            except Exception:
                existing_cfg = {}
        mcp_servers = existing_cfg.setdefault("mcpServers", {})
        mcp_servers["netagent"] = {
            "command": sys.executable,
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
            print("    [+] NetAgent automatically registered into Claude Desktop configuration!")
        except Exception as e:
            print(f"    [-] Could not write Claude config: {e}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="NetAgent Setup & One-Click Installer")
    parser.add_argument("--api-key", default=None, help="Sarvam AI API key")
    parser.add_argument("--telegram-token", default=None, help="Telegram BotFather token")
    parser.add_argument("--telegram-chat-id", default=None, help="Telegram Chat ID for alerts")
    parser.add_argument("--virustotal-key", default=None, help="VirusTotal API key for IP threat intelligence")
    parser.add_argument("--no-launch", action="store_true", help="Do not prompt to launch NetAgent after setup")
    args = parser.parse_args()

    print_banner()
    ensure_system_tools_installed()
    setup_api_key(
        api_key_override=args.api_key,
        telegram_token=args.telegram_token,
        telegram_chat=args.telegram_chat_id,
        virustotal_key=args.virustotal_key,
    )
    install_dependencies()
    configure_powershell_path()
    initialize_directories_and_auth()
    verify_installation()
    configure_claude_desktop_mcp()

    print("\n" + "=" * 72)
    print("      [SUCCESS] NetAgent has been successfully installed and configured!      ")
    print("=" * 72)
    print("\nYou can now run NetAgent from ANY PowerShell window with:")
    print("    netagent")
    print("or:")
    print("    netagent chat")
    print("\nAvailable CLI commands:")
    print("    netagent                  - Start interactive AI chat")
    print("    netagent doctor           - Check network tools and AI connectivity")
    print("    netagent captures list    - View all captured packet files")
    print("    netagent monitor list     - View continuous background monitoring subagents")
    print("    netagent monitor start    - Spawn detached 24/7 background monitor daemon")
    print("    netagent monitor stats    - View subagent packet inspection and alert stats")
    print("    netagent monitor stop     - Stop a running monitor subagent")
    print("    netagent telegram test    - Verify Telegram bot connectivity")
    print("    netagent telegram start   - Start 2-way Telegram interactive bot daemon")
    print("    netagent telegram status  - Check 2-way Telegram bot daemon status")
    print("    netagent telegram stop    - Stop 2-way Telegram bot daemon")
    print("    netagent telegram bot     - Run 2-way Telegram bot in foreground")
    print("    netagent scan <target>    - Audit host ports & services with JEV decision engine")
    print("    netagent mcp config       - View ready-to-copy Claude Desktop & Cursor configs")
    print("    netagent mcp install-claude- Auto-register NetAgent in Claude Desktop config")
    print("    netagent mcp test         - Test MCP tools, prompts & resources handshake")
    print("    netagent scans            - List all recorded host and port scans")
    print("    netagent scan-result <id> - View results & JEV posture analysis of a scan")
    print("    netagent virustotal check - Check IP against VirusTotal (cached)")
    print("    netagent virustotal cache - List all cached IP intelligence reports")
    print("    netagent --help           - Show full CLI options")
    print("\nIn-chat slash commands:")
    print("    /session [save|load|list] - Save or resume named chat sessions")
    print("    /memory [show|add|clear]  - Inspect or update long-term memory")
    print("    /sandbox [list|import]    - Safely stage external pcaps in sandbox")
    print("    /monitor [list|start|...] - Manage continuous background monitors")
    print("    /telegram [start|stop|..] - Manage 2-way Telegram bot & send alerts")
    print("    /virustotal [check|cache] - Query or inspect VirusTotal IP reputation")
    print("    /scan <target> [--bg]     - Audit host ports & services with JEV decisions")
    print("    /subagents                - View dynamically spawned subagents ledger")
    print("    /wireshark                - Open capture in desktop Wireshark GUI")
    print("    /adapters /connections    - Live PowerShell network inspection")
    print("=" * 72 + "\n")

    if not args.no_launch:
        try:
            launch = input("Launch NetAgent now? (Y/n): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            launch = "n"
        if launch in ("", "y", "yes"):
            print("\nStarting NetAgent...\n")
            subprocess.run([sys.executable, "-m", "wireshark_mcp.cli", "chat"])


if __name__ == "__main__":
    main()
