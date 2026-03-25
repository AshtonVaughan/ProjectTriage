"""OSINT Engine - Deep reconnaissance for Project Triage v4.

Enhanced OSINT capabilities beyond basic subdomain enumeration:
- Cloud asset enumeration (S3/Azure/GCP bucket permutations)
- Source map exploitation (extract original source from .js.map)
- 20+ JS secret patterns (AWS keys, Stripe, GitHub tokens, JWTs)
- Dev/staging environment discovery
- ASN/WHOIS pivoting for acquired company domains

Research basis: R3.2 deep research into 2024-2025 bug bounty recon methodology.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from utils.utils import run_cmd


# ---------------------------------------------------------------------------
# Cloud asset enumeration
# ---------------------------------------------------------------------------

CLOUD_PERMUTATIONS: list[str] = [
    "{name}", "{name}-prod", "{name}-dev", "{name}-staging",
    "{name}-backup", "{name}-assets", "{name}-static", "{name}-media",
    "{name}-uploads", "{name}-data", "{name}-logs", "{name}-config",
    "{name}-test", "{name}-qa", "{name}-uat", "{name}-sandbox",
    "prod-{name}", "dev-{name}", "staging-{name}", "backup-{name}",
    "{name}-public", "{name}-private", "{name}-internal",
    "{name}-cdn", "{name}-images", "{name}-files", "{name}-docs",
]

@dataclass
class CloudAsset:
    """A discovered cloud storage asset."""
    provider: str  # aws, azure, gcp
    bucket_name: str
    url: str
    status: str  # public_read, exists_private, not_found
    contents_sample: list[str] = field(default_factory=list)


class CloudEnumerator:
    """Enumerate cloud storage assets using naming permutations."""

    def generate_bucket_names(self, company_name: str) -> list[str]:
        """Generate potential bucket names from company name."""
        # Clean the name
        name = company_name.lower().strip()
        name = re.sub(r'[^a-z0-9-]', '', name.replace(' ', '-'))

        names = set()
        for pattern in CLOUD_PERMUTATIONS:
            names.add(pattern.format(name=name))

        # Also try without hyphens and with dots
        name_nodash = name.replace('-', '')
        if name_nodash != name:
            for pattern in CLOUD_PERMUTATIONS[:10]:
                names.add(pattern.format(name=name_nodash))

        return sorted(names)

    def check_s3_bucket(self, bucket_name: str) -> CloudAsset:
        """Check if an S3 bucket exists and its access level."""
        url = f"https://{bucket_name}.s3.amazonaws.com/"
        try:
            result = run_cmd(f"curl -s -o /dev/null -w '%{{http_code}}' '{url}' --max-time 5")
            code = result.strip().strip("'")
            if code == "200":
                status = "public_read"
            elif code == "403":
                status = "exists_private"
            elif code == "404":
                status = "not_found"
            else:
                status = f"http_{code}"
            return CloudAsset(
                provider="aws", bucket_name=bucket_name,
                url=url, status=status,
            )
        except Exception:
            return CloudAsset(
                provider="aws", bucket_name=bucket_name,
                url=url, status="error",
            )

    def check_azure_blob(self, container_name: str) -> CloudAsset:
        """Check if an Azure blob container exists."""
        url = f"https://{container_name}.blob.core.windows.net/?comp=list"
        try:
            result = run_cmd(f"curl -s -o /dev/null -w '%{{http_code}}' '{url}' --max-time 5")
            code = result.strip().strip("'")
            status = "public_read" if code == "200" else "exists_private" if code == "403" else "not_found"
            return CloudAsset(
                provider="azure", bucket_name=container_name,
                url=url, status=status,
            )
        except Exception:
            return CloudAsset(
                provider="azure", bucket_name=container_name,
                url=url, status="error",
            )

    def check_gcp_bucket(self, bucket_name: str) -> CloudAsset:
        """Check if a GCP storage bucket exists."""
        url = f"https://storage.googleapis.com/{bucket_name}"
        try:
            result = run_cmd(f"curl -s -o /dev/null -w '%{{http_code}}' '{url}' --max-time 5")
            code = result.strip().strip("'")
            status = "public_read" if code == "200" else "exists_private" if code == "403" else "not_found"
            return CloudAsset(
                provider="gcp", bucket_name=bucket_name,
                url=url, status=status,
            )
        except Exception:
            return CloudAsset(
                provider="gcp", bucket_name=bucket_name,
                url=url, status="error",
            )

    def enumerate_all(self, company_name: str, max_checks: int = 30) -> list[CloudAsset]:
        """Enumerate cloud assets across AWS, Azure, and GCP."""
        names = self.generate_bucket_names(company_name)[:max_checks]
        found: list[CloudAsset] = []

        for name in names:
            # Check S3
            s3 = self.check_s3_bucket(name)
            if s3.status in ("public_read", "exists_private"):
                found.append(s3)

            # Check Azure (only for top candidates to save time)
            if len(found) < 10:
                azure = self.check_azure_blob(name)
                if azure.status in ("public_read", "exists_private"):
                    found.append(azure)

            # Check GCP
            if len(found) < 10:
                gcp = self.check_gcp_bucket(name)
                if gcp.status in ("public_read", "exists_private"):
                    found.append(gcp)

        return found


# ---------------------------------------------------------------------------
# Source map exploitation
# ---------------------------------------------------------------------------

@dataclass
class SourceMapResult:
    """Result of source map extraction."""
    js_url: str
    map_url: str
    source_files: list[str]  # Original file paths from sources array
    secrets_found: list[dict[str, str]]
    endpoints_found: list[str]
    has_source_content: bool


class SourceMapExtractor:
    """Extract and analyze JavaScript source maps."""

    def check_source_map(self, js_url: str) -> SourceMapResult | None:
        """Check if a JS file has an accessible source map."""
        try:
            # Fetch JS file and look for sourceMappingURL
            js_content = run_cmd(f"curl -s '{js_url}' --max-time 10")
            match = re.search(r'//[#@]\s*sourceMappingURL=(.+?)[\s\n"\']', js_content)
            if not match:
                return None

            map_ref = match.group(1).strip()

            # Resolve map URL
            if map_ref.startswith('http'):
                map_url = map_ref
            elif map_ref.startswith('//'):
                parsed = urlparse(js_url)
                map_url = f"{parsed.scheme}:{map_ref}"
            elif map_ref.startswith('/'):
                parsed = urlparse(js_url)
                map_url = f"{parsed.scheme}://{parsed.netloc}{map_ref}"
            else:
                base = js_url.rsplit('/', 1)[0]
                map_url = f"{base}/{map_ref}"

            # Fetch the map
            map_content = run_cmd(f"curl -s '{map_url}' --max-time 10")
            if not map_content or map_content.startswith('<!'):
                return None  # Got HTML error page, not JSON

            map_data = json.loads(map_content)

            sources = map_data.get("sources", [])
            has_content = bool(map_data.get("sourcesContent"))

            # Extract secrets from source content
            secrets: list[dict[str, str]] = []
            endpoints: list[str] = []

            source_text = " ".join(map_data.get("sourcesContent", []))
            if source_text:
                for name, pattern in JS_SECRET_PATTERNS.items():
                    for m in re.finditer(pattern, source_text):
                        secrets.append({"type": name, "value": m.group(0)[:80]})

                for m in re.finditer(r"['\"](/api/v\d+/[a-zA-Z0-9/_-]+)['\"]", source_text):
                    endpoints.append(m.group(1))

            return SourceMapResult(
                js_url=js_url,
                map_url=map_url,
                source_files=sources[:50],
                secrets_found=secrets,
                endpoints_found=list(set(endpoints)),
                has_source_content=has_content,
            )
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Enhanced JS secret patterns
# ---------------------------------------------------------------------------

JS_SECRET_PATTERNS: dict[str, str] = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
    "google_oauth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "stripe_live_key": r"sk_live_[0-9a-zA-Z]{24,}",
    "stripe_test_key": r"sk_test_[0-9a-zA-Z]{24,}",
    "stripe_publishable": r"pk_(live|test)_[0-9a-zA-Z]{24,}",
    "github_token": r"ghp_[0-9a-zA-Z]{36}",
    "github_oauth": r"gho_[0-9a-zA-Z]{36}",
    "slack_token": r"xox[baprs]-[0-9a-zA-Z-]{10,48}",
    "slack_webhook": r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{24}",
    "twilio_sid": r"AC[0-9a-f]{32}",
    "twilio_token": r"(?i)twilio.{0,20}['\"][0-9a-f]{32}['\"]",
    "mailgun_key": r"key-[0-9a-zA-Z]{32}",
    "sendgrid_key": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "jwt_token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
    "private_key": r"-----BEGIN (RSA|EC|PGP|DSA|OPENSSH) PRIVATE KEY-----",
    "heroku_api": r"(?i)heroku.{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]",
    "firebase_url": r"https://[a-z0-9-]+\.firebaseio\.com",
    "firebase_key": r"(?i)firebase.{0,20}['\"][A-Za-z0-9_-]{39}['\"]",
    "graphql_endpoint": r"['\"](?:/graphql|/gql|/graphiql|/api/graphql)['\"]",
    "internal_url": r"https?://[a-z0-9.-]+\.(internal|corp|local|intranet|dev\.)[a-z.]*",
    "api_path": r"['\"](?:/api/v[0-9]+/[a-zA-Z0-9/_-]+)['\"]",
    "basic_auth": r"(?i)authorization['\"]?\s*[:=]\s*['\"]Basic\s+[A-Za-z0-9+/=]{10,}",
    "bearer_token": r"(?i)authorization['\"]?\s*[:=]\s*['\"]Bearer\s+[A-Za-z0-9._-]{20,}",
}


# ---------------------------------------------------------------------------
# Dev/staging environment discovery
# ---------------------------------------------------------------------------

STAGING_PATTERNS: list[str] = [
    "staging", "stage", "dev", "development", "test", "testing",
    "uat", "qa", "preprod", "pre-prod", "sandbox", "demo",
    "beta", "alpha", "rc", "internal", "debug",
    "admin-staging", "api-dev", "api-staging", "api-test",
    "app-staging", "app-dev", "app-test",
    "v2", "next", "canary", "preview",
]

NON_STANDARD_PORTS: list[int] = [
    3000, 4000, 5000, 8000, 8080, 8443, 8888,
    9000, 9090, 9200, 9300, 15672, 27017,
]


class StagingDiscovery:
    """Discover dev/staging environments that may have weaker security."""

    def generate_staging_subdomains(self, base_domain: str) -> list[str]:
        """Generate potential staging subdomain variations."""
        subs = []
        for pattern in STAGING_PATTERNS:
            subs.append(f"{pattern}.{base_domain}")
        return subs

    def check_non_standard_ports(self, host: str, ports: list[int] | None = None) -> list[dict[str, Any]]:
        """Check for services on non-standard ports."""
        ports = ports or NON_STANDARD_PORTS
        found: list[dict[str, Any]] = []

        for port in ports:
            try:
                result = run_cmd(
                    f"curl -s -o /dev/null -w '%{{http_code}}' "
                    f"'https://{host}:{port}/' --max-time 3 -k 2>/dev/null || "
                    f"curl -s -o /dev/null -w '%{{http_code}}' "
                    f"'http://{host}:{port}/' --max-time 3"
                )
                code = result.strip().strip("'")
                if code and code not in ("000", ""):
                    found.append({
                        "host": host,
                        "port": port,
                        "status_code": code,
                        "url": f"http://{host}:{port}/",
                    })
            except Exception:
                pass

        return found


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class OSINTEngine:
    """Orchestrates all OSINT capabilities."""

    def __init__(self) -> None:
        self.cloud_enum = CloudEnumerator()
        self.source_map = SourceMapExtractor()
        self.staging = StagingDiscovery()

    def run_cloud_enum(self, company_name: str, max_checks: int = 30) -> list[CloudAsset]:
        """Run cloud asset enumeration."""
        return self.cloud_enum.enumerate_all(company_name, max_checks)

    def run_source_map_check(self, js_urls: list[str]) -> list[SourceMapResult]:
        """Check multiple JS URLs for source maps."""
        results = []
        for url in js_urls[:20]:
            result = self.source_map.check_source_map(url)
            if result:
                results.append(result)
        return results

    def scan_js_secrets(self, js_content: str) -> list[dict[str, str]]:
        """Scan JS content for secrets using enhanced patterns."""
        secrets = []
        for name, pattern in JS_SECRET_PATTERNS.items():
            for match in re.finditer(pattern, js_content):
                value = match.group(0)
                # Skip obviously fake/example values
                if any(fake in value.lower() for fake in ["example", "xxx", "your_", "placeholder"]):
                    continue
                secrets.append({"type": name, "value": value[:100]})
        return secrets

    def discover_staging(self, base_domain: str) -> list[dict[str, Any]]:
        """Discover staging/dev environments."""
        subs = self.staging.generate_staging_subdomains(base_domain)
        found = []
        for sub in subs[:15]:
            try:
                result = run_cmd(
                    f"curl -s -o /dev/null -w '%{{http_code}}' "
                    f"'https://{sub}/' --max-time 3 -k"
                )
                code = result.strip().strip("'")
                if code and code not in ("000", "404", ""):
                    found.append({
                        "subdomain": sub,
                        "status_code": code,
                        "url": f"https://{sub}/",
                    })
            except Exception:
                pass
        return found

    def generate_hypotheses(
        self,
        cloud_assets: list[CloudAsset],
        source_maps: list[SourceMapResult],
        staging_envs: list[dict[str, Any]],
        js_secrets: list[dict[str, str]],
        base_url: str,
    ) -> list[dict[str, Any]]:
        """Convert all OSINT findings to hypothesis dicts."""
        hypotheses: list[dict[str, Any]] = []

        # Cloud asset hypotheses
        for asset in cloud_assets:
            if asset.status == "public_read":
                hypotheses.append({
                    "endpoint": asset.url,
                    "technique": f"cloud_{asset.provider}_public_read",
                    "description": f"Public {asset.provider} bucket: {asset.bucket_name}",
                    "novelty": 6, "exploitability": 9, "impact": 8, "effort": 1,
                })
            elif asset.status == "exists_private":
                hypotheses.append({
                    "endpoint": asset.url,
                    "technique": f"cloud_{asset.provider}_acl_bypass",
                    "description": f"Private {asset.provider} bucket exists: {asset.bucket_name} - test ACL bypass",
                    "novelty": 7, "exploitability": 6, "impact": 8, "effort": 3,
                })

        # Source map hypotheses
        for sm in source_maps:
            if sm.secrets_found:
                hypotheses.append({
                    "endpoint": sm.js_url,
                    "technique": "source_map_secret_exposure",
                    "description": f"Source map exposes {len(sm.secrets_found)} secrets from {sm.js_url}",
                    "novelty": 8, "exploitability": 9, "impact": 9, "effort": 1,
                })
            if sm.has_source_content:
                hypotheses.append({
                    "endpoint": sm.map_url,
                    "technique": "source_map_source_code_exposure",
                    "description": f"Full source code exposed via source map: {len(sm.source_files)} files",
                    "novelty": 7, "exploitability": 7, "impact": 7, "effort": 2,
                })

        # Staging environment hypotheses
        for env in staging_envs:
            hypotheses.append({
                "endpoint": env["url"],
                "technique": "staging_env_exposed",
                "description": f"Staging/dev environment found: {env['subdomain']} (HTTP {env['status_code']})",
                "novelty": 6, "exploitability": 7, "impact": 7, "effort": 2,
            })

        # JS secret hypotheses
        for secret in js_secrets[:10]:
            hypotheses.append({
                "endpoint": base_url,
                "technique": f"js_secret_{secret['type']}",
                "description": f"JS secret found: {secret['type']} = {secret['value'][:30]}...",
                "novelty": 7, "exploitability": 9, "impact": 8, "effort": 1,
            })

        return hypotheses
