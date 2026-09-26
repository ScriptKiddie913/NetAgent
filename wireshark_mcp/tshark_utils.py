"""
Low-level helpers for shelling out to tshark and managing capture files.
Kept separate from server.py so both the MCP server and any future
non-MCP caller (tests, CLI utilities) can reuse them without importing FastMCP.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from .config import Config


class CaptureError(Exception):
    """Raised for user-facing capture/analysis errors (caught and stringified by tools)."""


@dataclass
class CaptureHandle:
    proc: subprocess.Popen
    path: str
    interface: str
    bpf_filter: str
    started: float = field(default_factory=time.time)


class TsharkRunner:
    """Wraps tshark invocation, capture file bookkeeping, and authorization gating."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.captures: dict[str, CaptureHandle] = {}
        cfg.ensure_dirs()

    # ---------- authorization ----------

    def check_authorized(self) -> Optional[str]:
        """Returns an error string if capture is not authorized on this machine, else None."""
        sec = self.cfg.security
        if not sec.get("require_authorization_ack", True):
            return None
        marker = sec.get("ack_marker_file")
        if marker and os.path.isfile(marker):
            return None
        return (
            "ERROR: packet capture is not authorized yet on this machine. "
            "Run `wireshark-agent authorize` in a terminal first (one-time), "
            "confirming you are only capturing traffic you own or are authorized to monitor."
        )

    def check_interface_allowed(self, interface: str) -> Optional[str]:
        allowed = self.cfg.security.get("allowed_interfaces") or []
        if allowed and interface not in allowed:
            return (
                f"ERROR: interface '{interface}' is not in the configured allowlist "
                f"({allowed}). Update security.allowed_interfaces in config.yaml to permit it."
            )
        return None

    # ---------- file helpers & resolution ----------

    def resolve_path(self, path: str) -> str:
        """Resolve a pcap/pcapng path from user input, data/, capture/, sandbox/, or workspace."""
        if not path:
            return path
        clean = path.strip().strip("'").strip('"')
        if os.path.isfile(clean):
            return clean

        candidate_dirs = [
            getattr(self.cfg, "data_dir", ""),
            getattr(self.cfg, "capture_dir", ""),
            getattr(self.cfg, "sandbox_dir", ""),
            r"C:\Users\KIIT\ollama-wireshark-mcp-v2\data",
            r"C:\Users\KIIT\Downloads\ollama-wireshark-mcp-v2\data",
            r"C:\Users\KIIT\ollama-wireshark-mcp-v2\capture",
            r"C:\Users\KIIT\Downloads\ollama-wireshark-mcp-v2\capture",
            os.path.join(tempfile.gettempdir(), "wireshark_mcp_captures"),
        ]

        # 1. Direct join in candidate dirs
        for cd in candidate_dirs:
            if cd and os.path.isdir(cd):
                target = os.path.join(cd, clean)
                if os.path.isfile(target):
                    return target

        # 2. Check by basename in candidate dirs
        base = os.path.basename(clean)
        for cd in candidate_dirs:
            if cd and os.path.isdir(cd):
                target = os.path.join(cd, base)
                if os.path.isfile(target):
                    return target
                try:
                    for fname in os.listdir(cd):
                        if fname.lower() == base.lower():
                            match_path = os.path.join(cd, fname)
                            if os.path.isfile(match_path):
                                return match_path
                except OSError:
                    pass

        return clean

    # ---------- core exec ----------

    def run(self, args: list[str], timeout: int = 60, resolve_names: bool = False) -> str:
        resolved_args = list(args)
        for i, a in enumerate(resolved_args):
            if a == "-r" and i + 1 < len(resolved_args):
                resolved_args[i + 1] = self.resolve_path(resolved_args[i + 1])
        full_args = ([] if resolve_names else ["-n"]) + resolved_args
        try:
            result = subprocess.run(
                [self.cfg.tshark_path] + full_args,
                capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode != 0:
                return f"ERROR: {result.stderr.strip() or 'tshark exited with code ' + str(result.returncode)}"
            return result.stdout
        except FileNotFoundError:
            return "ERROR: tshark not found. Install Wireshark/tshark and ensure it's on PATH (see `wireshark-agent doctor`)."
        except subprocess.TimeoutExpired:
            return f"ERROR: tshark timed out after {timeout}s."

    # ---------- file helpers ----------

    def new_capture_path(self, prefix: str = "cap", ext: str = "pcapng") -> str:
        name = f"{prefix}_{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}.{ext}"
        return os.path.join(self.cfg.capture_dir, name)

    def list_capture_files(self) -> list[str]:
        found = []
        dirs = [
            getattr(self.cfg, "capture_dir", ""),
            getattr(self.cfg, "data_dir", ""),
            getattr(self.cfg, "sandbox_dir", ""),
            r"C:\Users\KIIT\ollama-wireshark-mcp-v2\data",
            r"C:\Users\KIIT\Downloads\ollama-wireshark-mcp-v2\data",
            r"C:\Users\KIIT\ollama-wireshark-mcp-v2\capture",
            r"C:\Users\KIIT\Downloads\ollama-wireshark-mcp-v2\capture",
        ]
        seen_paths = set()
        for d in dirs:
            if d and os.path.isdir(d):
                try:
                    for f in os.listdir(d):
                        if f.lower().endswith((".pcap", ".pcapng")):
                            full = os.path.normpath(os.path.join(d, f))
                            if os.path.isfile(full) and full not in seen_paths:
                                seen_paths.add(full)
                                found.append(full)
                except OSError:
                    pass
        return sorted(found, key=lambda p: os.path.getmtime(p), reverse=True)

    def validate_path(self, path: str) -> Optional[str]:
        resolved = self.resolve_path(path)
        if os.path.isfile(resolved):
            return None
        known = self.list_capture_files()
        hint = ("Known captures:\n" + "\n".join(known)) if known else "No captures exist yet — run start_capture or capture_live first."
        return f"ERROR: file not found: {path}\n{hint}"

    @staticmethod
    def truncate(text: str, max_lines: int) -> str:
        lines = text.splitlines()
        if len(lines) > max_lines:
            return "\n".join(lines[:max_lines]) + f"\n... ({len(lines) - max_lines} more lines truncated, raise max_lines to see more)"
        return text

    def fields(self, path: str, display_filter: str, field_names: list[str], timeout: int = 60) -> list[list[str]]:
        """Run `-T fields` and return rows as lists of strings (empty string for missing field)."""
        resolved_path = self.resolve_path(path)
        args = ["-r", resolved_path]
        if display_filter:
            args += ["-Y", display_filter]
        args += ["-T", "fields"]
        for f in field_names:
            args += ["-e", f]
        args += ["-E", "separator=\t", "-E", "occurrence=f"]
        out = self.run(args, timeout=timeout)
        if out.startswith("ERROR"):
            raise CaptureError(out)
        rows = []
        for line in out.splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            parts += [""] * (len(field_names) - len(parts))
            rows.append(parts[: len(field_names)])
        return rows
