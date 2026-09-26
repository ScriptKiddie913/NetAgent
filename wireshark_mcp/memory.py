"""
Memory, Context Memory, Sessions & Pcap Sandboxing for NetAgent.

Provides:
1. MemoryStore: Long-term persistent memory for network insights, host profiles,
   flagged IOCs, and user preferences across sessions.
2. SessionManager: Named and auto-saved chat sessions (conversation state,
   delegation history, and discovered capture paths).
3. PcapSandbox: Isolated sandbox for safely importing, validating (magic bytes & size),
   and analyzing external or untrusted pcap files.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Optional


# =========================================================================
# 1. Long-Term Memory
# =========================================================================

@dataclass
class MemoryEntry:
    entry_id: str
    category: str  # e.g., "topology", "ioc", "device", "preference", "incident"
    content: str
    created_at: float
    source: str = "assistant"

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "category": self.category,
            "content": self.content,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.created_at)),
            "source": self.source,
        }


class MemoryStore:
    """Persistent long-term memory for NetAgent."""

    def __init__(self, memory_dir: str):
        self.memory_dir = memory_dir
        os.makedirs(memory_dir, exist_ok=True)
        self.memory_file = os.path.join(memory_dir, "long_term_memory.json")
        self.entries: list[MemoryEntry] = []
        self._load()

    def _load(self):
        if os.path.isfile(self.memory_file):
            try:
                with open(self.memory_file, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)
                    for item in raw:
                        self.entries.append(MemoryEntry(
                            entry_id=item.get("entry_id", uuid.uuid4().hex[:8]),
                            category=item.get("category", "general"),
                            content=item.get("content", ""),
                            created_at=time.time(),
                            source=item.get("source", "assistant"),
                        ))
            except Exception:
                pass

    def _save(self):
        try:
            with open(self.memory_file, "w", encoding="utf-8") as fh:
                json.dump([e.to_dict() for e in self.entries], fh, indent=2)
        except Exception:
            pass

    def remember(self, category: str, content: str, source: str = "assistant") -> MemoryEntry:
        """Add a new insight or fact to long-term memory."""
        entry = MemoryEntry(
            entry_id=f"mem_{uuid.uuid4().hex[:6]}",
            category=category.strip().lower() or "general",
            content=content.strip(),
            created_at=time.time(),
            source=source,
        )
        self.entries.append(entry)
        self._save()
        return entry

    def recall(self, query: str = "") -> list[MemoryEntry]:
        """Search memory by category or keyword."""
        if not query:
            return list(self.entries)
        q = query.lower()
        return [
            e for e in self.entries
            if q in e.category.lower() or q in e.content.lower()
        ]

    def get_context_summary(self, max_items: int = 8) -> str:
        """Format recent memories for injection into system context."""
        if not self.entries:
            return ""
        recent = self.entries[-max_items:]
        lines = ["--- NetAgent Long-Term Memory & Network Context ---"]
        for e in recent:
            lines.append(f"• [{e.category.upper()}] {e.content}")
        return "\n".join(lines)

    def clear(self):
        """Clear all stored long-term memories."""
        self.entries.clear()
        if os.path.isfile(self.memory_file):
            try:
                os.remove(self.memory_file)
            except Exception:
                pass


# =========================================================================
# 2. Session Manager
# =========================================================================

@dataclass
class SessionRecord:
    session_id: str
    name: str
    updated_at: float
    message_count: int
    known_paths: list[str]
    history: list[dict]
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "name": self.name,
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.updated_at)),
            "message_count": self.message_count,
            "known_paths": self.known_paths,
            "notes": self.notes,
            "history": self.history,
        }


class SessionManager:
    """Manages persistent and named chat sessions for NetAgent."""

    def __init__(self, sessions_dir: str):
        self.sessions_dir = sessions_dir
        os.makedirs(sessions_dir, exist_ok=True)

    def _file_for(self, name: str) -> str:
        safe_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", name.strip().lower()) or "session"
        return os.path.join(self.sessions_dir, f"{safe_name}.json")

    def save_session(
        self,
        name: str,
        history: list[dict],
        known_paths: set[str],
        notes: str = "",
    ) -> str:
        filepath = self._file_for(name)
        rec = SessionRecord(
            session_id=uuid.uuid4().hex[:8],
            name=name,
            updated_at=time.time(),
            message_count=len(history),
            known_paths=sorted(list(known_paths)),
            history=history,
            notes=notes,
        )
        try:
            with open(filepath, "w", encoding="utf-8") as fh:
                json.dump(rec.to_dict(), fh, indent=2)
            return filepath
        except Exception as e:
            return f"ERROR saving session: {e}"

    def load_session(self, name: str) -> Optional[dict]:
        filepath = self._file_for(name)
        if not os.path.isfile(filepath):
            return None
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return None

    def list_sessions(self) -> list[dict]:
        if not os.path.isdir(self.sessions_dir):
            return []
        out = []
        for f in os.listdir(self.sessions_dir):
            if f.endswith(".json"):
                fp = os.path.join(self.sessions_dir, f)
                try:
                    with open(fp, "r", encoding="utf-8") as fh:
                        data = json.load(fh)
                        out.append({
                            "file": f,
                            "name": data.get("name", f[:-5]),
                            "updated_at": data.get("updated_at", ""),
                            "message_count": data.get("message_count", 0),
                            "notes": data.get("notes", ""),
                        })
                except Exception:
                    continue
        return sorted(out, key=lambda x: x["updated_at"], reverse=True)

    def delete_session(self, name: str) -> bool:
        fp = self._file_for(name)
        if os.path.isfile(fp):
            try:
                os.remove(fp)
                return True
            except Exception:
                return False
        return False


# =========================================================================
# 3. Pcap Sandbox
# =========================================================================

# PCAP / PCAPNG Magic Numbers
PCAP_MAGIC_NUMBERS = (
    b"\xa1\xb2\xc3\xd4",  # standard pcap, same endian
    b"\xd4\xc3\xb2\xa1",  # standard pcap, swapped endian
    b"\xa1\xb2\x3c\x4d",  # nanosecond pcap, same endian
    b"\x4d\x3c\xb2\xa1",  # nanosecond pcap, swapped endian
    b"\x0a\x0d\x0d\x0a",  # pcapng section header block
)


class PcapSandbox:
    """
    Secure isolated sandbox for safely importing, validating, and staging
    untrusted or external packet captures before analysis.
    """

    def __init__(self, sandbox_dir: str):
        self.sandbox_dir = sandbox_dir
        os.makedirs(sandbox_dir, exist_ok=True)

    def validate_pcap_header(self, filepath: str) -> tuple[bool, str]:
        """Verify file existence and valid PCAP/PCAPNG magic bytes."""
        if not os.path.isfile(filepath):
            return False, f"File does not exist: {filepath}"
        size = os.path.getsize(filepath)
        if size < 24:
            return False, f"File is too small to be a valid pcap ({size} bytes)"

        try:
            with open(filepath, "rb") as fh:
                magic = fh.read(4)
                if magic in PCAP_MAGIC_NUMBERS:
                    return True, "Valid PCAP/PCAPNG header verified"
                return False, f"Invalid pcap magic bytes ({magic.hex()}) — file may be corrupted or not a pcap"
        except Exception as e:
            return False, f"Failed to read file header: {e}"

    def import_pcap(self, source_path: str, custom_name: str = "") -> dict[str, Any]:
        """
        Validate and safely import an external pcap file into the sandbox directory.
        Returns metadata and sandboxed file path.
        """
        source_path = os.path.abspath(source_path.strip().strip("'\""))
        is_valid, msg = self.validate_pcap_header(source_path)
        if not is_valid:
            return {
                "success": False,
                "error": msg,
                "sandboxed_path": "",
            }

        base = custom_name.strip() or os.path.basename(source_path)
        # Sanitize filename
        safe_base = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", base)
        if not safe_base.lower().endswith((".pcap", ".pcapng")):
            safe_base += ".pcap"

        dest_path = os.path.join(self.sandbox_dir, safe_base)
        # Avoid clobbering existing file with same name
        if os.path.exists(dest_path) and os.path.abspath(dest_path) != source_path:
            name_part, ext = os.path.splitext(safe_base)
            dest_path = os.path.join(self.sandbox_dir, f"{name_part}_{uuid.uuid4().hex[:4]}{ext}")

        try:
            if os.path.abspath(dest_path) != source_path:
                shutil.copy2(source_path, dest_path)
            size = os.path.getsize(dest_path)
            return {
                "success": True,
                "sandboxed_path": dest_path,
                "filename": os.path.basename(dest_path),
                "size_bytes": size,
                "validation": msg,
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to stage file in sandbox: {e}",
                "sandboxed_path": "",
            }

    def list_files(self) -> list[dict[str, Any]]:
        """List all pcap files currently stored inside the sandbox."""
        if not os.path.isdir(self.sandbox_dir):
            return []
        out = []
        for name in sorted(os.listdir(self.sandbox_dir)):
            if name.lower().endswith((".pcap", ".pcapng")):
                fp = os.path.join(self.sandbox_dir, name)
                if os.path.isfile(fp):
                    out.append({
                        "name": name,
                        "path": fp,
                        "size": os.path.getsize(fp),
                        "mtime": os.path.getmtime(fp),
                    })
        return out

    def clean_sandbox(self) -> int:
        """Remove all files inside the sandbox directory."""
        if not os.path.isdir(self.sandbox_dir):
            return 0
        removed = 0
        for name in os.listdir(self.sandbox_dir):
            fp = os.path.join(self.sandbox_dir, name)
            try:
                if os.path.isfile(fp) or os.path.islink(fp):
                    os.remove(fp)
                    removed += 1
                elif os.path.isdir(fp):
                    shutil.rmtree(fp)
                    removed += 1
            except Exception:
                pass
        return removed
