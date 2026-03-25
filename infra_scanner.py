"""Infrastructure Scanner - $100K bug methodology for Project Triage v4.

Implements infrastructure-class vulnerability detection targeting the patterns
that produce $25K-$100K+ bug bounty payouts. Based on research into:
- Assetnote's methodology for pre-auth RCE on edge devices
- Orange Tsai's SSRF/deserialization chain methodology
- HackerOne 2024-2025 payout tier analysis

Key insight: every $100K+ finding shares one or more of:
pre-auth access, infrastructure-layer impact, chained exploit sequences,
or mass data exposure affecting all users.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Payout tier classification
# ---------------------------------------------------------------------------

@dataclass
class PayoutTier:
    """Classification of vulnerability by expected bounty range."""
    tier: str  # "100k", "25k", "5k", "commodity"
    min_bounty: int
    max_bounty: int
    characteristics: list[str]
    priority_multiplier: float  # Boost for hypothesis scoring


PAYOUT_TIERS: dict[str, PayoutTier] = {
    "100k": PayoutTier(
        tier="100k", min_bounty=50000, max_bounty=500000,
        characteristics=[
            "pre-auth_rce", "zero_click", "auth_bypass_infrastructure",
            "novel_memory_corruption", "supply_chain_rce",
        ],
        priority_multiplier=3.0,
    ),
    "25k": PayoutTier(
        tier="25k", min_bounty=10000, max_bounty=100000,
        characteristics=[
            "ssrf_cloud_creds", "chained_path_traversal_rce",
            "saml_sso_bypass", "mass_account_takeover",
            "payment_manipulation", "pre_auth_admin_access",
        ],
        priority_multiplier=2.5,
    ),
    "5k": PayoutTier(
        tier="5k", min_bounty=2000, max_bounty=25000,
        characteristics=[
            "ssrf_internal", "idor_mass_data", "race_condition_payment",
            "jwt_algorithm_confusion", "oauth_redirect_bypass",
            "stored_xss_admin", "business_logic_financial",
        ],
        priority_multiplier=1.8,
    ),
    "commodity": PayoutTier(
        tier="commodity", min_bounty=100, max_bounty=5000,
        characteristics=[
            "reflected_xss", "individual_idor", "standard_sqli",
            "csrf_limited", "info_disclosure_no_exploit",
        ],
        priority_multiplier=1.0,
    ),
}


# ---------------------------------------------------------------------------
# Infrastructure target identification
# ---------------------------------------------------------------------------

@dataclass
class InfraTarget:
    """An identified infrastructure component with attack priority."""
    category: str  # vpn, sso, api_gateway, backup, admin, cloud_meta
    name: str
    url: str
    priority: int  # 1=highest, 6=lowest
    attack_techniques: list[str]
    payout_potential: str  # tier name


# Infrastructure patterns to detect from recon data
INFRA_PATTERNS: list[dict[str, Any]] = [
    {
        "category": "vpn",
        "priority": 1,
        "payout_potential": "100k",
        "signals": [
            r"fortinet|fortigate|fortios",
            r"pulse.?secure|ivanti.?connect",
            r"palo.?alto.?global.?protect",
            r"cisco.?asa|anyconnect",
            r"citrix.?gateway|netscaler",
            r"sonicwall",
            r"checkpoint|mobile.?access",
        ],
        "attack_techniques": [
            "pre_auth_rce_fuzzing", "chunked_encoding_overflow",
            "path_traversal_config_read", "session_fixation",
            "default_credentials", "cve_known_exploit",
        ],
    },
    {
        "category": "sso",
        "priority": 2,
        "payout_potential": "25k",
        "signals": [
            r"saml|sso|single.?sign",
            r"okta|auth0|onelogin|ping.?identity",
            r"azure.?ad|entra",
            r"keycloak|cas.?server",
            r"shibboleth|adfs",
            r"/saml/|/sso/|/oauth/|/oidc/",
        ],
        "attack_techniques": [
            "saml_signature_wrapping", "saml_signature_removal",
            "xml_parser_differential", "saml_comment_injection",
            "oauth_redirect_uri_bypass", "oidc_nonce_replay",
            "jwt_algorithm_confusion",
        ],
    },
    {
        "category": "api_gateway",
        "priority": 3,
        "payout_potential": "25k",
        "signals": [
            r"kong|apigee|mulesoft",
            r"aws.?api.?gateway|azure.?api.?management",
            r"tyk|gravitee|wso2",
            r"x-kong-|x-apigee-|x-gateway-",
        ],
        "attack_techniques": [
            "path_normalization_bypass", "rate_limit_bypass",
            "auth_header_injection", "request_smuggling",
            "api_key_enumeration",
        ],
    },
    {
        "category": "backup_sync",
        "priority": 4,
        "payout_potential": "100k",
        "signals": [
            r"/backup|/restore|/sync|/cluster",
            r"/replication|/migration|/import",
            r"veeam|commvault|rubrik",
            r"serialized|pickle|marshal",
        ],
        "attack_techniques": [
            "deserialization_java", "deserialization_python_pickle",
            "deserialization_dotnet_viewstate", "deserialization_yaml",
            "unauthenticated_endpoint_access",
        ],
    },
    {
        "category": "admin_panel",
        "priority": 5,
        "payout_potential": "25k",
        "signals": [
            r"jenkins|grafana|kibana|prometheus",
            r"jupyter|notebook|phpmyadmin",
            r"kubernetes.?dashboard|rancher",
            r"spring.?boot.?actuator|/actuator/",
            r"admin|manage|console|dashboard",
            r":8080|:8443|:9090|:3000|:5601",
        ],
        "attack_techniques": [
            "default_credentials", "unauthenticated_access",
            "ssrf_via_webhook", "rce_via_script_console",
            "info_disclosure_debug_endpoint",
        ],
    },
    {
        "category": "cloud_metadata",
        "priority": 6,
        "payout_potential": "25k",
        "signals": [
            r"169\.254\.169\.254",
            r"metadata\.google\.internal",
            r"100\.100\.100\.200",  # Alibaba Cloud
        ],
        "attack_techniques": [
            "ssrf_aws_imds_v1", "ssrf_aws_imds_v2",
            "ssrf_gcp_metadata", "ssrf_azure_metadata",
            "dns_rebinding_metadata",
        ],
    },
]


# ---------------------------------------------------------------------------
# Deserialization endpoint detection
# ---------------------------------------------------------------------------

DESER_SIGNALS: list[dict[str, Any]] = [
    {
        "name": "java_serialization",
        "content_types": ["application/x-java-serialized-object", "application/octet-stream"],
        "url_patterns": [r"/invoke|/jmx|/cluster|/sync|/agent"],
        "header_signals": [r"x-java-|aced0005"],  # Java magic bytes
        "payout_potential": "100k",
    },
    {
        "name": "python_pickle",
        "content_types": ["application/octet-stream", "application/pickle"],
        "url_patterns": [r"/model|/predict|/inference|/pipeline|/serialize"],
        "header_signals": [r"\x80\x04\x95"],  # Pickle protocol 4
        "payout_potential": "100k",
    },
    {
        "name": "dotnet_viewstate",
        "content_types": ["application/x-www-form-urlencoded"],
        "url_patterns": [r"\.aspx|\.ashx|\.asmx"],
        "header_signals": [r"__viewstate|machinekey"],
        "payout_potential": "25k",
    },
    {
        "name": "yaml_unsafe",
        "content_types": ["application/yaml", "application/x-yaml", "text/yaml"],
        "url_patterns": [r"/config|/import|/upload|/parse"],
        "header_signals": [],
        "payout_potential": "100k",
    },
    {
        "name": "xml_entity",
        "content_types": ["application/xml", "text/xml", "application/soap+xml"],
        "url_patterns": [r"/soap|/wsdl|/xmlrpc|/rss|/feed|/import"],
        "header_signals": [r"<!DOCTYPE|<!ENTITY"],
        "payout_potential": "25k",
    },
]


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class InfraScanner:
    """Infrastructure-class vulnerability scanner.

    Identifies high-value infrastructure targets from recon data and
    generates hypotheses prioritized by payout tier.
    """

    def identify_infra_targets(
        self,
        hosts: list[str],
        tech_stack: dict[str, Any],
        headers: dict[str, str],
        endpoints: list[str],
        observations: list[str],
    ) -> list[InfraTarget]:
        """Identify infrastructure targets from recon data.

        Scans all available recon data for signals indicating
        high-value infrastructure components.
        """
        targets: list[InfraTarget] = []
        # Combine all text for pattern matching
        all_text = " ".join([
            " ".join(hosts),
            str(tech_stack),
            " ".join(f"{k}: {v}" for k, v in headers.items()),
            " ".join(endpoints),
            " ".join(observations),
        ]).lower()

        for pattern in INFRA_PATTERNS:
            for signal_re in pattern["signals"]:
                if re.search(signal_re, all_text, re.IGNORECASE):
                    # Find the specific URL/host that matched
                    matched_host = ""
                    for host in hosts:
                        if re.search(signal_re, host, re.IGNORECASE):
                            matched_host = host
                            break
                    if not matched_host and hosts:
                        matched_host = hosts[0]

                    target = InfraTarget(
                        category=pattern["category"],
                        name=f"{pattern['category']}_{signal_re[:20]}",
                        url=matched_host,
                        priority=pattern["priority"],
                        attack_techniques=pattern["attack_techniques"],
                        payout_potential=pattern["payout_potential"],
                    )
                    targets.append(target)
                    break  # One match per category is enough

        return sorted(targets, key=lambda t: t.priority)

    def detect_deserialization_surfaces(
        self,
        endpoints: list[str],
        content_types: list[str],
        headers: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Detect potential deserialization attack surfaces.

        Returns list of endpoints likely vulnerable to deserialization attacks.
        """
        surfaces: list[dict[str, Any]] = []
        all_text = " ".join(endpoints + content_types + list(headers.values())).lower()

        for deser in DESER_SIGNALS:
            # Check content types
            ct_match = any(
                ct.lower() in all_text for ct in deser["content_types"]
            )
            # Check URL patterns
            url_match = any(
                re.search(pat, all_text, re.IGNORECASE)
                for pat in deser["url_patterns"]
            )
            # Check header signals
            header_match = any(
                re.search(sig, all_text, re.IGNORECASE)
                for sig in deser["header_signals"]
            ) if deser["header_signals"] else False

            if ct_match or url_match or header_match:
                # Find matching endpoints
                matched_eps = []
                for ep in endpoints:
                    if any(re.search(p, ep, re.IGNORECASE) for p in deser["url_patterns"]):
                        matched_eps.append(ep)

                surfaces.append({
                    "type": deser["name"],
                    "endpoints": matched_eps or endpoints[:3],
                    "payout_potential": deser["payout_potential"],
                    "confidence": 0.8 if (ct_match and url_match) else 0.5,
                })

        return surfaces

    def classify_payout_tier(self, technique: str) -> PayoutTier:
        """Classify a technique by its expected payout tier."""
        technique_lower = technique.lower()
        for tier_name, tier in PAYOUT_TIERS.items():
            for char in tier.characteristics:
                if char in technique_lower or technique_lower in char:
                    return tier
        return PAYOUT_TIERS["commodity"]

    def generate_infra_hypotheses(
        self,
        targets: list[InfraTarget],
        base_url: str,
    ) -> list[dict[str, Any]]:
        """Convert infrastructure targets to hypothesis dicts for the attack graph.

        Returns hypothesis dicts ready to feed to HypothesisEngine.create().
        """
        hypotheses: list[dict[str, Any]] = []

        for target in targets:
            tier = PAYOUT_TIERS.get(target.payout_potential, PAYOUT_TIERS["commodity"])

            for technique in target.attack_techniques[:3]:
                hyp = {
                    "endpoint": target.url or base_url,
                    "technique": f"infra_{technique}",
                    "description": (
                        f"[{tier.tier} tier] Infrastructure {target.category}: "
                        f"{technique} on {target.name}"
                    ),
                    "novelty": 8,
                    "exploitability": 7,
                    "impact": 10 if tier.tier == "100k" else 9,
                    "effort": 5,
                    "priority_multiplier": tier.priority_multiplier,
                }
                hypotheses.append(hyp)

        return hypotheses

    def generate_deser_hypotheses(
        self,
        surfaces: list[dict[str, Any]],
        base_url: str,
    ) -> list[dict[str, Any]]:
        """Convert deserialization surfaces to hypothesis dicts."""
        hypotheses: list[dict[str, Any]] = []

        for surface in surfaces:
            tier = PAYOUT_TIERS.get(surface["payout_potential"], PAYOUT_TIERS["5k"])
            for ep in surface["endpoints"][:2]:
                hyp = {
                    "endpoint": ep if ep.startswith("http") else f"{base_url.rstrip('/')}/{ep.lstrip('/')}",
                    "technique": f"deser_{surface['type']}",
                    "description": (
                        f"[{tier.tier} tier] Deserialization: {surface['type']} "
                        f"on {ep} (confidence={surface['confidence']:.0%})"
                    ),
                    "novelty": 9,
                    "exploitability": 8,
                    "impact": 10 if tier.tier == "100k" else 9,
                    "effort": 5,
                }
                hypotheses.append(hyp)

        return hypotheses

    @staticmethod
    def get_emerging_categories() -> list[dict[str, Any]]:
        """Return emerging high-value vulnerability categories for 2025+."""
        return [
            {
                "category": "ai_llm",
                "description": "AI/LLM vulnerabilities - 210% increase in valid reports, 540% surge in prompt injection",
                "techniques": [
                    "prompt_injection_direct", "prompt_injection_indirect",
                    "tool_abuse_data_exfil", "rag_poisoning",
                    "output_manipulation", "training_data_extraction",
                ],
                "payout_potential": "5k",
            },
            {
                "category": "mcp_server",
                "description": "MCP (Model Context Protocol) infrastructure - emerging attack surface",
                "techniques": [
                    "mcp_unauthenticated_rce", "mcp_ssrf",
                    "mcp_tool_injection", "mcp_prompt_leak",
                ],
                "payout_potential": "25k",
            },
            {
                "category": "supply_chain",
                "description": "Supply chain attacks via CI/CD, package registries, build pipelines",
                "techniques": [
                    "ci_pipeline_injection", "dependency_confusion",
                    "typosquatting", "build_artifact_poisoning",
                ],
                "payout_potential": "100k",
            },
        ]
