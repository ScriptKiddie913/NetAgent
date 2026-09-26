"""
VirusTotal IP Intelligence and Reputation Module for NetAgent.
Continuously scans connected IP addresses, caches results persistently in memory,
and alerts if an IP is flagged as malicious (threshold >= 70%).
"""
from __future__ import annotations

import ipaddress
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import httpx

from .config import load_config
from .memory import MemoryStore
from .telegram import TelegramNotifier


def is_public_ip(ip_str: str) -> bool:
    """Check if an IP string is a valid public IPv4/IPv6 address (not private, loopback, or multicast)."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_multicast
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


class VirusTotalClient:
    """Manages VirusTotal v3 IP lookups, caching, and threat evaluation."""

    def __init__(self, api_key: str | None = None) -> None:
        cfg = load_config()
        vt_cfg = cfg.raw.get("virustotal", {})
        self.api_key = (
            api_key
            or os.environ.get("VIRUSTOTAL_API_KEY")
            or os.environ.get("WSMCP_VIRUSTOTAL_API_KEY")
            or os.environ.get("VT_API_KEY")
            or vt_cfg.get("api_key")
        )
        if self.api_key:
            self.api_key = str(self.api_key).strip()

        self.threshold_percent = float(vt_cfg.get("alert_threshold_percent", 70.0))
        self.cache_dir = Path(cfg.memory_dir)
        self.cache_file = self.cache_dir / "virustotal_cache.json"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache = self._load_cache()
        self.mem_store = MemoryStore(cfg.memory_dir)
        self.telegram = TelegramNotifier()

    def _load_cache(self) -> dict[str, Any]:
        if self.cache_file.is_file():
            try:
                with open(self.cache_file, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except Exception:
                return {}
        return {}

    def _save_cache(self) -> None:
        try:
            with open(self.cache_file, "w", encoding="utf-8") as fh:
                json.dump(self.cache, fh, indent=2)
        except Exception:
            pass

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def is_tested(self, ip: str) -> bool:
        """Check if an IP has already been scanned and stored in cache."""
        return ip.strip() in self.cache

    def get_cached(self, ip: str) -> Optional[dict[str, Any]]:
        """Retrieve stored analysis for an already-tested IP."""
        return self.cache.get(ip.strip())

    def check_ip(self, ip: str, send_alerts: bool = True) -> dict[str, Any]:
        """
        Check an IP address against VirusTotal.
        If already tested, returns the cached report without re-querying.
        If new, queries VirusTotal v3 endpoint, stores the report, and sends an alert if malicious >= 70%.
        """
        ip = ip.strip()
        if not is_public_ip(ip):
            return {
                "ip": ip,
                "is_public": False,
                "tested": False,
                "message": "Private, loopback, or non-routable IP address. Skipped VT lookup.",
            }

        # Check existing cache
        if self.is_tested(ip):
            cached = self.get_cached(ip)
            cached["cached"] = True
            return cached

        if not self.is_configured():
            return {
                "ip": ip,
                "is_public": True,
                "tested": False,
                "error": "VirusTotal API key is not configured. Set VIRUSTOTAL_API_KEY environment variable or in config.yaml.",
            }

        # Query VirusTotal API v3
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

        try:
            with httpx.Client(timeout=15.0) as client:
                res = client.get(url, headers=headers)
                if res.status_code == 404:
                    result = {
                        "ip": ip,
                        "is_public": True,
                        "tested": True,
                        "cached": False,
                        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "malicious_score": 0.0,
                        "is_malicious": False,
                        "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                        "as_owner": "Unknown",
                        "country": "Unknown",
                        "message": "IP address not found in VirusTotal database (clean / unflagged).",
                    }
                    self.cache[ip] = result
                    self._save_cache()
                    return result

                if res.status_code != 200:
                    return {
                        "ip": ip,
                        "is_public": True,
                        "tested": False,
                        "error": f"VirusTotal API HTTP {res.status_code}: {res.text[:200]}",
                    }

                data = res.json().get("data", {})
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total_engines = malicious + suspicious + harmless + undetected

                # Calculate malicious percentage
                if total_engines > 0:
                    malicious_score = round(((malicious + (0.5 * suspicious)) / total_engines) * 100, 2)
                else:
                    malicious_score = 0.0

                as_owner = attrs.get("as_owner") or attrs.get("network") or "Unknown"
                country = attrs.get("country") or "Unknown"
                reputation = attrs.get("reputation", 0)

                is_threat = malicious_score >= self.threshold_percent

                result = {
                    "ip": ip,
                    "is_public": True,
                    "tested": True,
                    "cached": False,
                    "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "malicious_score": malicious_score,
                    "is_malicious": is_threat,
                    "threshold_percent": self.threshold_percent,
                    "as_owner": as_owner,
                    "country": country,
                    "reputation": reputation,
                    "stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": undetected,
                        "total_engines": total_engines,
                    },
                }

                # Store in persistent cache and long-term memory
                self.cache[ip] = result
                self._save_cache()

                threat_tag = "MALICIOUS" if is_threat else "CLEAN"
                self.mem_store.remember(
                    category="ioc" if is_threat else "topology",
                    content=f"VirusTotal report for IP {ip}: {threat_tag} (Score: {malicious_score}%, {malicious}/{total_engines} engines, Org: {as_owner}, Country: {country})",
                    source="virustotal",
                )

                # Dispatch Telegram alert if malicious score exceeds threshold
                if is_threat and send_alerts:
                    alert_text = (
                        f"[!]️ *HIGH-RISK MALICIOUS IP CONNECTED*\n\n"
                        f"• *IP:* `{ip}`\n"
                        f"• *Detection Score:* `{malicious_score}%` ({malicious}/{total_engines} security vendors)\n"
                        f"• *Organization:* `{as_owner}`\n"
                        f"• *Country:* `{country}`\n"
                        f"• *Threshold:* `>= {self.threshold_percent}%`"
                    )
                    self.telegram.send_alert(
                        message=alert_text,
                        level="CRITICAL",
                        category="VirusTotal Threat",
                        details={
                            "ip": ip,
                            "malicious_vendors": f"{malicious}/{total_engines}",
                            "score": f"{malicious_score}%",
                            "as_owner": as_owner,
                            "country": country,
                        },
                    )

                return result

        except Exception as e:
            return {
                "ip": ip,
                "is_public": True,
                "tested": False,
                "error": f"Error querying VirusTotal: {e}",
            }

    def scan_ip_list(self, ip_list: list[str], send_alerts: bool = True) -> list[dict[str, Any]]:
        """Scan a list of IPs, automatically skipping already-tested IPs and private IPs."""
        results = []
        for ip in set(ip_list):
            if is_public_ip(ip):
                res = self.check_ip(ip, send_alerts=send_alerts)
                results.append(res)
        return results
