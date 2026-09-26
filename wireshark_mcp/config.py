"""
Central configuration for the toolkit. Loads defaults, then overlays
config.yaml (if present) and environment variables (WSMCP_*).

Precedence, low -> high: DEFAULTS  <  config.yaml  <  environment variables.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - yaml is a required dep, but fail soft
    yaml = None

def get_project_root() -> str:
    """Find the root directory for NetAgent data and capture files."""
    if os.environ.get("NETAGENT_DIR"):
        return os.environ["NETAGENT_DIR"]
    for candidate in [
        r"C:\Users\KIIT\ollama-wireshark-mcp-v2",
        r"C:\Users\KIIT\Downloads\ollama-wireshark-mcp-v2",
    ]:
        if os.path.isdir(candidate):
            return candidate
    cwd = os.getcwd()
    if os.path.isdir(os.path.join(cwd, "wireshark_mcp")) or os.path.isfile(os.path.join(cwd, "pyproject.toml")) or os.path.isdir(os.path.join(cwd, "data")):
        return cwd
    return os.path.expanduser("~")


PROJECT_ROOT = get_project_root()
DEFAULT_CAPTURE_DIR = os.path.join(PROJECT_ROOT, "capture")
DEFAULT_DATA_DIR = os.path.join(PROJECT_ROOT, "data")
try:
    os.makedirs(DEFAULT_CAPTURE_DIR, exist_ok=True)
except Exception:
    pass
try:
    os.makedirs(DEFAULT_DATA_DIR, exist_ok=True)
except Exception:
    pass


def _detect_default_tshark() -> str:
    """Find tshark on PATH or fall back to standard Windows install path if present."""
    if shutil.which("tshark"):
        return "tshark"
    if sys.platform == "win32":
        win_path = r"C:\Program Files\Wireshark\tshark.exe"
        if os.path.isfile(win_path):
            return win_path
    return "tshark"


def _detect_default_wireshark_gui() -> str:
    """Find Wireshark desktop GUI executable."""
    if sys.platform == "win32":
        win_path = r"C:\Program Files\Wireshark\Wireshark.exe"
        if os.path.isfile(win_path):
            return win_path
    return "wireshark"


DEFAULTS: dict[str, Any] = {
    "provider": "sarvam",  # Default to Sarvam AI (no local Ollama required)
    "tshark_path": _detect_default_tshark(),
    "wireshark_gui_path": _detect_default_wireshark_gui(),
    "capture_dir": DEFAULT_CAPTURE_DIR,
    "data_dir": DEFAULT_DATA_DIR,
    "max_output_lines": 80,
    "default_capture_timeout": 60,
    "ollama": {
        "host": None,  # None -> ollama library default (http://localhost:11434)
        "supervisor_model": "llama3.2:1b",
        "agent_model": "llama3.2:3b",
        "temperature": 0,
        "num_predict": 700,
        "keep_alive": "30m",
        "max_tool_iterations": 15,
    },
    "sarvam": {
        "api_key": None,  # None -> read from SARVAM_API_KEY env var
        "base_url": "https://api.sarvam.ai/v1",
        "supervisor_model": "sarvam-105b",
        "agent_model": "sarvam-105b-conversations",
        "temperature": 0.1,
        "max_tokens": 1000,
        "max_tool_iterations": 15,
    },
    "decisions": {
        # Require user confirmation before running destructive or high-impact actions
        "require_confirmation": True,
        "sensitive_tools": [
            "delete_capture",
            "cleanup_old_captures",
            "stop_all_captures",
            "start_ring_capture",
        ],
    },
    "security": {
        # Empty list = no restriction (any interface tshark can see is allowed).
        # Populate with interface names/numbers to hard-restrict what can be captured on.
        "allowed_interfaces": [],
        # If true, the CLI prints an authorized-use banner and requires typing
        # "I AGREE" once per machine (recorded in a marker file) before any
        # capture tool can run. Analysis-only tools are never gated.
        "require_authorization_ack": True,
        "ack_marker_file": os.path.join(DEFAULT_CAPTURE_DIR, ".authorized"),
    },
    "retention": {
        # Auto-delete captured files older than this many hours on `captures clean`
        # (never run automatically/silently — only when the command is invoked).
        "max_age_hours": 168,
    },
    "telegram": {
        "enabled": False,
        "bot_token": None,
        "chat_id": None,
    },
    "virustotal": {
        "enabled": True,
        "api_key": None,
        "alert_threshold_percent": 70.0,
    },
}

CONFIG_SEARCH_PATHS = [
    Path.cwd() / "config.yaml",
    Path.cwd() / "netagent.yaml",
    Path.cwd() / "wireshark_mcp.yaml",
    Path.home() / ".netagent" / "config.yaml",
    Path.home() / ".config" / "wireshark_mcp" / "config.yaml",
]


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge override into base. A `null`/None value in override means "use the
    default" (so config.example.yaml can list every key with null placeholders)
    rather than clobbering the default with None — except for keys whose default
    genuinely is None (e.g. ollama.host or sarvam.api_key)."""
    out = dict(base)
    for k, v in override.items():
        if v is None and k in out and out[k] is not None:
            continue
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _load_yaml_file(path: Path) -> dict:
    if not path.is_file() or yaml is None:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _apply_env_overrides(cfg: dict) -> dict:
    # env var -> (key path tuple, caster)
    env_map = {
        "WSMCP_PROVIDER": (("provider",), str),
        "WSMCP_AI_PROVIDER": (("provider",), str),
        "WSMCP_TSHARK_PATH": (("tshark_path",), str),
        "WSMCP_CAPTURE_DIR": (("capture_dir",), str),
        "WSMCP_MAX_OUTPUT_LINES": (("max_output_lines",), int),
        "WSMCP_OLLAMA_HOST": (("ollama", "host"), str),
        "WSMCP_SUPERVISOR_MODEL": (("ollama", "supervisor_model"), str),
        "WSMCP_AGENT_MODEL": (("ollama", "agent_model"), str),
        "WSMCP_MAX_TOOL_ITERATIONS": (("ollama", "max_tool_iterations"), int),
        "SARVAM_API_KEY": (("sarvam", "api_key"), str),
        "WSMCP_SARVAM_API_KEY": (("sarvam", "api_key"), str),
        "WSMCP_SARVAM_BASE_URL": (("sarvam", "base_url"), str),
        "WSMCP_SARVAM_SUPERVISOR_MODEL": (("sarvam", "supervisor_model"), str),
        "WSMCP_SARVAM_AGENT_MODEL": (("sarvam", "agent_model"), str),
        "WSMCP_REQUIRE_CONFIRMATION": (
            ("decisions", "require_confirmation"),
            lambda v: str(v).lower() in ("1", "true", "yes", "on"),
        ),
        "TELEGRAM_BOT_TOKEN": (("telegram", "bot_token"), str),
        "WSMCP_TELEGRAM_BOT_TOKEN": (("telegram", "bot_token"), str),
        "TELEGRAM_CHAT_ID": (("telegram", "chat_id"), str),
        "WSMCP_TELEGRAM_CHAT_ID": (("telegram", "chat_id"), str),
        "VIRUSTOTAL_API_KEY": (("virustotal", "api_key"), str),
        "WSMCP_VIRUSTOTAL_API_KEY": (("virustotal", "api_key"), str),
        "VT_API_KEY": (("virustotal", "api_key"), str),
    }
    for env_key, (keys, caster) in env_map.items():
        val = os.environ.get(env_key)
        if val is None:
            continue
        try:
            typed_val = caster(val)
        except (TypeError, ValueError):
            typed_val = val
        node = cfg
        for k in keys[:-1]:
            node = node.setdefault(k, {})
        node[keys[-1]] = typed_val
    return cfg


@dataclass
class Config:
    raw: dict = field(default_factory=dict)

    @property
    def provider(self) -> str:
        return str(self.raw.get("provider", "ollama")).lower()

    @property
    def tshark_path(self) -> str:
        return self.raw["tshark_path"]

    @property
    def wireshark_gui_path(self) -> str:
        return self.raw.get("wireshark_gui_path", "wireshark")

    @property
    def capture_dir(self) -> str:
        return self.raw.get("capture_dir", DEFAULT_CAPTURE_DIR)

    @property
    def data_dir(self) -> str:
        return self.raw.get("data_dir", DEFAULT_DATA_DIR)

    @property
    def reports_dir(self) -> str:
        return os.path.join(self.data_dir, "reports")

    @property
    def extracted_dir(self) -> str:
        return os.path.join(self.data_dir, "extracted")

    @property
    def max_output_lines(self) -> int:
        return int(self.raw["max_output_lines"])

    @property
    def default_capture_timeout(self) -> int:
        return int(self.raw["default_capture_timeout"])

    @property
    def ollama(self) -> dict:
        return self.raw.get("ollama", {})

    @property
    def sarvam(self) -> dict:
        return self.raw.get("sarvam", {})

    @property
    def decisions(self) -> dict:
        return self.raw.get("decisions", {})

    @property
    def security(self) -> dict:
        return self.raw.get("security", {})

    @property
    def retention(self) -> dict:
        return self.raw.get("retention", {})

    @property
    def sandbox_dir(self) -> str:
        return os.path.join(self.data_dir, "sandbox")

    @property
    def sessions_dir(self) -> str:
        return os.path.join(self.data_dir, "sessions")

    @property
    def memory_dir(self) -> str:
        return os.path.join(self.data_dir, "memory")

    @property
    def monitors_dir(self) -> str:
        return os.path.join(self.data_dir, "monitors")

    @property
    def scans_dir(self) -> str:
        return os.path.join(self.data_dir, "scans")

    @property
    def subagents_dir(self) -> str:
        return os.path.join(self.data_dir, "subagents")

    @property
    def telegram(self) -> dict:
        return self.raw.get("telegram", {})

    @property
    def virustotal(self) -> dict:
        return self.raw.get("virustotal", {})

    def ensure_dirs(self) -> None:
        for d in (
            self.capture_dir,
            self.reports_dir,
            self.extracted_dir,
            self.sandbox_dir,
            self.sessions_dir,
            self.memory_dir,
            self.monitors_dir,
        ):
            os.makedirs(d, exist_ok=True)


def load_config(explicit_path: str | None = None) -> Config:
    cfg = dict(DEFAULTS)
    cfg["ollama"] = dict(DEFAULTS["ollama"])
    cfg["sarvam"] = dict(DEFAULTS["sarvam"])
    cfg["decisions"] = dict(DEFAULTS["decisions"])
    cfg["security"] = dict(DEFAULTS["security"])
    cfg["retention"] = dict(DEFAULTS["retention"])
    cfg["telegram"] = dict(DEFAULTS["telegram"])
    cfg["virustotal"] = dict(DEFAULTS["virustotal"])

    paths = [Path(explicit_path)] if explicit_path else CONFIG_SEARCH_PATHS
    for p in paths:
        file_cfg = _load_yaml_file(p)
        if file_cfg:
            cfg = _deep_merge(cfg, file_cfg)
            break

    cfg = _apply_env_overrides(cfg)
    config = Config(raw=cfg)
    config.ensure_dirs()
    return config
