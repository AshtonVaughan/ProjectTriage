"""Fetch and parse web page content, certificate data, WHOIS, and DNS records."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from core.config import Config
from core.tool_registry import Tool
from utils.utils import run_cmd, sanitize_subprocess_arg


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _http_get(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
) -> tuple[int, dict[str, str], str]:
    """Perform a GET request. Returns (status_code, response_headers, body)."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, resp_headers, body
    except urllib.error.HTTPError as exc:
        body = exc.read(4096).decode("utf-8", errors="replace") if exc.fp else ""
        resp_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return exc.code, resp_headers, body
    except Exception as exc:
        return 0, {}, str(exc)


# ---------------------------------------------------------------------------
# Content extraction helpers
# ---------------------------------------------------------------------------

def _extract_text(html: str) -> str:
    """Strip HTML tags and collapse whitespace into readable text."""
    # Remove script and style blocks entirely
    html = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.IGNORECASE | re.DOTALL)
    # Strip all remaining tags
    text = re.sub(r"<[^>]+>", " ", html)
    # Collapse whitespace
    text = re.sub(r"\s{2,}", "\n", text)
    return text.strip()[:8000]


def _extract_links(html: str, base_url: str = "") -> list[str]:
    """Extract all href/src/action links from HTML."""
    pattern = re.compile(
        r'(?:href|src|action|data-src)\s*=\s*["\']([^"\'<>\s]{4,})["\']',
        re.IGNORECASE,
    )
    found = pattern.findall(html)
    links: list[str] = []
    seen: set[str] = set()
    for link in found:
        link = link.strip()
        if link.startswith("//"):
            link = "https:" + link
        elif link.startswith("/") and base_url:
            parsed = urllib.parse.urlparse(base_url)
            link = f"{parsed.scheme}://{parsed.netloc}{link}"
        if link not in seen and len(link) < 500:
            seen.add(link)
            links.append(link)
    return links[:200]


def _extract_forms(html: str) -> list[dict[str, Any]]:
    """Extract form elements and their input fields from HTML."""
    forms: list[dict[str, Any]] = []
    form_pattern = re.compile(
        r"<form([^>]*)>(.*?)</form>",
        re.IGNORECASE | re.DOTALL,
    )
    input_pattern = re.compile(
        r"<input([^>]*)>",
        re.IGNORECASE,
    )
    attr_pattern = re.compile(r'(\w[\w-]*)\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)

    for form_match in form_pattern.finditer(html):
        form_attrs_str = form_match.group(1)
        form_body = form_match.group(2)

        form_attrs = dict(attr_pattern.findall(form_attrs_str))
        inputs: list[dict[str, str]] = []

        for input_match in input_pattern.finditer(form_body):
            input_attrs = dict(attr_pattern.findall(input_match.group(1)))
            inputs.append({
                "name": input_attrs.get("name", ""),
                "type": input_attrs.get("type", "text"),
                "value": input_attrs.get("value", ""),
                "placeholder": input_attrs.get("placeholder", ""),
            })

        forms.append({
            "action": form_attrs.get("action", ""),
            "method": form_attrs.get("method", "GET").upper(),
            "enctype": form_attrs.get("enctype", ""),
            "inputs": inputs,
        })
    return forms


# ---------------------------------------------------------------------------
# Public tool functions
# ---------------------------------------------------------------------------

def fetch_page(
    url: str,
    method: str = "auto",
    extract: str = "text",
) -> dict[str, Any]:
    """Fetch a web page and extract content for analysis.

    Use this to read a specific page's content, discover forms, or collect
    links. Distinct from the crawler (which follows links recursively) -
    fetch_page retrieves a single URL. Use Jina Reader for JS-heavy pages,
    or raw/curl for static HTML or when you need exact response headers.

    method options:
    - auto: tries Jina Reader first (handles JS rendering), falls back to curl
    - jina: prepends https://r.jina.ai/ for clean markdown extraction
    - curl: raw HTTP via system curl command
    - raw: direct urllib request, no processing

    extract options:
    - text: readable text content (strips HTML)
    - links: list of all URLs found on the page
    - forms: all forms with their input fields
    - headers: HTTP response headers only (skips body download)
    """
    url = sanitize_subprocess_arg(url, "url")
    method = sanitize_subprocess_arg(method, "generic").lower()
    extract = sanitize_subprocess_arg(extract, "generic").lower()

    if not url.startswith("http"):
        url = "https://" + url

    status_code = 0
    content_type = ""
    resp_headers: dict[str, str] = {}
    raw_content = ""
    method_used = "none"
    error = ""

    # --- headers-only shortcut ---
    if extract == "headers":
        status_code, resp_headers, _ = _http_get(
            url,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10,
        )
        return {
            "content": "",
            "status_code": status_code,
            "method_used": "raw",
            "content_type": resp_headers.get("content-type", ""),
            "headers": resp_headers,
            "stdout": "\n".join(f"{k}: {v}" for k, v in resp_headers.items()),
            "stderr": "",
            "returncode": 0 if status_code > 0 else 1,
        }

    methods_to_try: list[str] = []
    if method == "auto":
        methods_to_try = ["jina", "curl"]
    else:
        methods_to_try = [method]

    for m in methods_to_try:
        try:
            if m == "jina":
                jina_url = f"https://r.jina.ai/{url}"
                status_code, resp_headers, raw_content = _http_get(
                    jina_url,
                    headers={
                        "Accept": "text/markdown,text/plain,*/*",
                        "X-Retain-Images": "none",
                        "User-Agent": "Mozilla/5.0",
                    },
                    timeout=25,
                )
                if status_code in (200, 201) and raw_content:
                    method_used = "jina"
                    content_type = resp_headers.get("content-type", "text/markdown")
                    break
                else:
                    error = f"Jina Reader HTTP {status_code}"

            elif m == "curl":
                curl_result = run_cmd(
                    ["curl", "-s", "-L", "--max-time", "20",
                     "-A", "Mozilla/5.0",
                     "-D", "-",  # Include headers in output
                     url],
                    timeout=30,
                )
                raw_output = curl_result.get("stdout", "")
                if raw_output:
                    # Split headers from body on blank line
                    parts = raw_output.split("\r\n\r\n", 1)
                    if len(parts) == 2:
                        header_block, raw_content = parts
                        # Parse status from first header line
                        status_match = re.search(r"HTTP/[\d.]+\s+(\d+)", header_block)
                        status_code = int(status_match.group(1)) if status_match else 200
                        ct_match = re.search(r"content-type:\s*([^\r\n]+)", header_block, re.IGNORECASE)
                        content_type = ct_match.group(1).strip() if ct_match else ""
                    else:
                        raw_content = raw_output
                        status_code = 200
                    method_used = "curl"
                    break
                else:
                    error = f"curl returned no content (rc={curl_result.get('returncode', -1)})"

            elif m == "raw":
                status_code, resp_headers, raw_content = _http_get(
                    url,
                    headers={"User-Agent": "Mozilla/5.0"},
                    timeout=20,
                )
                content_type = resp_headers.get("content-type", "")
                if raw_content:
                    method_used = "raw"
                    break
                else:
                    error = f"Raw HTTP {status_code} - no content"

        except Exception as exc:
            error = f"{m}: {exc}"
            continue

    if not raw_content:
        return {
            "content": "",
            "status_code": status_code,
            "method_used": method_used,
            "content_type": content_type,
            "error": error,
            "stdout": f"Failed to fetch {url}: {error}",
            "stderr": error,
            "returncode": 1,
        }

    # --- Apply extraction ---
    content: Any = ""
    if extract == "text":
        if method_used == "jina":
            # Jina already returns markdown/text
            content = raw_content[:8000]
        else:
            content = _extract_text(raw_content)

    elif extract == "links":
        links = _extract_links(raw_content, base_url=url)
        content = "\n".join(links)

    elif extract == "forms":
        forms = _extract_forms(raw_content)
        content = json.dumps(forms, indent=2)

    else:
        # Fallback: return raw
        content = raw_content[:8000]

    return {
        "content": content,
        "status_code": status_code,
        "method_used": method_used,
        "content_type": content_type,
        "url": url,
        "stdout": str(content)[:4000],
        "stderr": "",
        "returncode": 0 if status_code in range(200, 400) else 1,
    }


def fetch_certificate_info(domain: str) -> dict[str, Any]:
    """Query crt.sh certificate transparency logs for a domain.

    Use this during recon to discover subdomains via certificate logs -
    often reveals internal, staging, and API subdomains not visible in DNS.
    More passive than active subdomain enumeration.
    """
    domain = sanitize_subprocess_arg(domain, "target")
    domain = domain.split("//")[-1].split("/")[0].strip()

    if not domain:
        return {
            "certificates": [],
            "subdomains": [],
            "stdout": "",
            "stderr": "Empty domain",
            "returncode": 1,
        }

    encoded = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={encoded}&output=json"

    output_parts: list[str] = [f"=== Certificate Transparency: {domain} ===", ""]

    status, _, body = _http_get(
        url,
        headers={"User-Agent": "Mozilla/5.0"},
        timeout=30,
    )

    if status != 200 or not body:
        return {
            "certificates": [],
            "subdomains": [],
            "stdout": f"crt.sh returned HTTP {status}",
            "stderr": f"HTTP {status}",
            "returncode": 1,
        }

    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        return {
            "certificates": [],
            "subdomains": [],
            "stdout": f"Failed to parse crt.sh response: {exc}",
            "stderr": str(exc),
            "returncode": 1,
        }

    # Collect unique subdomains
    subdomains: set[str] = set()
    certificates: list[dict[str, Any]] = []

    for entry in data:
        name_value = entry.get("name_value", "")
        issuer = entry.get("issuer_name", "")
        not_before = entry.get("not_before", "")
        not_after = entry.get("not_after", "")

        # name_value may contain newline-separated names
        names = [n.strip().lstrip("*.") for n in name_value.split("\n") if n.strip()]
        for name in names:
            if name.endswith(f".{domain}") or name == domain:
                subdomains.add(name)

        certificates.append({
            "name_value": name_value,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
        })

    sorted_subs = sorted(subdomains)

    output_parts.append(f"Total certificates: {len(certificates)}")
    output_parts.append(f"Unique subdomains: {len(sorted_subs)}")
    output_parts.append("")
    output_parts.append("--- Subdomains ---")
    for sub in sorted_subs[:100]:
        output_parts.append(f"  {sub}")

    if len(sorted_subs) > 100:
        output_parts.append(f"  ... and {len(sorted_subs) - 100} more")

    output_parts.append("")
    output_parts.append("--- Recent Certificates (latest 10) ---")
    for cert in certificates[:10]:
        output_parts.append(f"  Name: {cert['name_value'][:80]}")
        output_parts.append(f"  Issuer: {cert['issuer'][:80]}")
        output_parts.append(f"  Valid: {cert['not_before']} - {cert['not_after']}")
        output_parts.append("")

    return {
        "certificates": certificates[:50],
        "subdomains": sorted_subs,
        "subdomain_count": len(sorted_subs),
        "domain": domain,
        "stdout": "\n".join(output_parts),
        "stderr": "",
        "returncode": 0,
    }


def fetch_whois(domain: str) -> dict[str, Any]:
    """Perform a WHOIS lookup on a domain.

    Use during initial recon to identify registrar, creation date,
    expiry date, and nameservers. Useful for target profiling and
    detecting recently registered domains (phishing indicators).
    """
    domain = sanitize_subprocess_arg(domain, "target")
    domain = domain.split("//")[-1].split("/")[0].strip()

    if not domain:
        return {
            "parsed": {},
            "raw": "",
            "stdout": "",
            "stderr": "Empty domain",
            "returncode": 1,
        }

    result = run_cmd(["whois", domain], timeout=30)
    raw = result.get("stdout", "")
    stderr = result.get("stderr", "")
    rc = result.get("returncode", -1)

    if not raw:
        # Fallback: try python-whois or report unavailability
        return {
            "parsed": {},
            "raw": "",
            "stdout": f"whois command not available or no data for {domain}",
            "stderr": stderr,
            "returncode": rc,
        }

    # Parse common WHOIS fields
    def _extract_field(pattern: str, text: str) -> str:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        return match.group(1).strip() if match else ""

    def _extract_list(pattern: str, text: str) -> list[str]:
        return [m.group(1).strip() for m in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)]

    parsed: dict[str, Any] = {
        "domain": domain,
        "registrar": _extract_field(r"Registrar:\s*(.+)", raw),
        "registrar_url": _extract_field(r"Registrar URL:\s*(.+)", raw),
        "whois_server": _extract_field(r"Registrar WHOIS Server:\s*(.+)", raw),
        "creation_date": _extract_field(
            r"Creation Date:\s*(.+)|Created On:\s*(.+)|created:\s*(.+)", raw
        ),
        "updated_date": _extract_field(
            r"Updated Date:\s*(.+)|Last Updated On:\s*(.+)|last-modified:\s*(.+)", raw
        ),
        "expiry_date": _extract_field(
            r"Registrar Registration Expiration Date:\s*(.+)|Expiry Date:\s*(.+)|Expiration Date:\s*(.+)", raw
        ),
        "status": _extract_list(r"Domain Status:\s*(.+)", raw),
        "nameservers": _extract_list(r"Name Server:\s*(.+)|nserver:\s*(.+)", raw),
        "registrant_org": _extract_field(r"Registrant Organization:\s*(.+)", raw),
        "registrant_country": _extract_field(r"Registrant Country:\s*(.+)", raw),
        "admin_email": _extract_field(r"Admin Email:\s*(.+)", raw),
        "tech_email": _extract_field(r"Tech Email:\s*(.+)", raw),
        "dnssec": _extract_field(r"DNSSEC:\s*(.+)", raw),
    }

    # Remove empty fields for cleanliness
    parsed = {k: v for k, v in parsed.items() if v}

    output_parts = [f"=== WHOIS: {domain} ===", ""]
    for key, value in parsed.items():
        if isinstance(value, list):
            output_parts.append(f"{key}:")
            for item in value:
                output_parts.append(f"  {item}")
        else:
            output_parts.append(f"{key}: {value}")

    return {
        "parsed": parsed,
        "raw": raw[:3000],
        "domain": domain,
        "stdout": "\n".join(output_parts),
        "stderr": stderr,
        "returncode": 0,
    }


def fetch_dns_records(domain: str, record_type: str = "ANY") -> dict[str, Any]:
    """Enumerate DNS records for a domain using dig or nslookup.

    Use during recon to map domain infrastructure - A records reveal IPs,
    MX reveals mail servers, TXT may contain SPF/DKIM config or verification
    tokens, NS reveals the DNS provider. Prefer this over manual DNS lookups.
    More targeted than subfinder - use when you want specific record types.

    Supported record_type values: A, AAAA, MX, NS, TXT, CNAME, SOA, ANY
    """
    domain = sanitize_subprocess_arg(domain, "target")
    record_type = sanitize_subprocess_arg(record_type, "generic").upper()
    domain = domain.split("//")[-1].split("/")[0].strip()

    if not domain:
        return {
            "records": {},
            "stdout": "",
            "stderr": "Empty domain",
            "returncode": 1,
        }

    valid_types = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "ANY"}
    if record_type not in valid_types:
        record_type = "ANY"

    output_parts: list[str] = [f"=== DNS Records: {domain} (type={record_type}) ===", ""]
    records: dict[str, list[str]] = {}
    errors: list[str] = []

    # Determine which record types to query
    if record_type == "ANY":
        types_to_query = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    else:
        types_to_query = [record_type]

    # Try dig first, fall back to nslookup
    for rtype in types_to_query:
        result = run_cmd(["dig", "+short", domain, rtype], timeout=15)
        if result.get("returncode") == 0 and result.get("stdout", "").strip():
            values = [ln.strip() for ln in result["stdout"].splitlines() if ln.strip()]
            records[rtype] = values
            output_parts.append(f"--- {rtype} ---")
            for v in values:
                output_parts.append(f"  {v}")
            output_parts.append("")
            continue

        # dig failed or not installed - try nslookup
        ns_result = run_cmd(["nslookup", "-type=" + rtype, domain], timeout=15)
        ns_stdout = ns_result.get("stdout", "")
        if ns_stdout:
            # Parse nslookup output: extract answer section lines
            values = []
            in_answer = False
            for line in ns_stdout.splitlines():
                line = line.strip()
                if "answer" in line.lower() or "non-authoritative" in line.lower():
                    in_answer = True
                    continue
                if in_answer and line and not line.startswith(";"):
                    # Extract value from "domain  type  value" lines
                    parts = line.split()
                    if len(parts) >= 2:
                        values.append(line)
            if values:
                records[rtype] = values
                output_parts.append(f"--- {rtype} (via nslookup) ---")
                for v in values:
                    output_parts.append(f"  {v}")
                output_parts.append("")
            else:
                errors.append(f"{rtype}: no records found")
        else:
            errors.append(f"{rtype}: dig/nslookup unavailable or no data")

    if not records:
        output_parts.append("No DNS records retrieved.")
        output_parts.append("Ensure dig or nslookup is installed.")

    # Extract key data points for structured output
    summary: dict[str, Any] = {
        "domain": domain,
        "record_type_queried": record_type,
        "a_records": records.get("A", []),
        "aaaa_records": records.get("AAAA", []),
        "mx_records": records.get("MX", []),
        "ns_records": records.get("NS", []),
        "txt_records": records.get("TXT", []),
        "cname_records": records.get("CNAME", []),
        "soa_records": records.get("SOA", []),
    }
    # Remove empty lists from summary
    summary = {k: v for k, v in summary.items() if v or k in ("domain", "record_type_queried")}

    return {
        "records": records,
        "summary": summary,
        "domain": domain,
        "errors": errors,
        "stdout": "\n".join(output_parts),
        "stderr": "; ".join(errors) if errors else "",
        "returncode": 0 if records else 1,
    }


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

def register_fetch_tools(config: Config) -> list[Tool]:
    """Register page fetching and passive recon tools."""
    tools: list[Tool] = []

    tools.append(Tool(
        name="fetch_page",
        description=(
            "Fetch a single web page and return its content, links, or forms. "
            "Use Jina Reader (method=auto) for JS-rendered pages. Use extract=forms "
            "to find injection points, extract=links to map endpoints, extract=headers "
            "to check security headers. Complements the crawler - use for individual "
            "URLs rather than recursive crawling."
        ),
        parameters={
            "url": "Full URL to fetch (e.g. https://example.com/login)",
            "method": "Fetch method: auto (Jina then curl), jina, curl, raw (default: auto)",
            "extract": "What to extract: text, links, forms, headers (default: text)",
        },
        example='fetch_page(url="https://example.com/login", extract="forms")',
        phase_tags=["recon", "discovery", "vulnerability_scan"],
        execute=fetch_page,
    ))

    tools.append(Tool(
        name="fetch_certificate_info",
        description=(
            "Query crt.sh certificate transparency logs to discover subdomains. "
            "Passive recon - reveals internal, staging, dev, and API subdomains "
            "registered in TLS certificates. Use before active subdomain brute-forcing "
            "to build a seed list. Complements subfinder."
        ),
        parameters={
            "domain": "Root domain to query certificates for (e.g. example.com)",
        },
        example='fetch_certificate_info(domain="example.com")',
        phase_tags=["recon", "osint"],
        execute=fetch_certificate_info,
    ))

    tools.append(Tool(
        name="fetch_whois",
        description=(
            "WHOIS lookup for a domain. Returns registrar, creation date, expiry, "
            "nameservers, and registrant info. Use for target profiling - identifies "
            "ownership, hosting provider via NS records, and domain age. "
            "Requires whois to be installed on the system."
        ),
        parameters={
            "domain": "Domain to look up (e.g. example.com)",
        },
        example='fetch_whois(domain="example.com")',
        phase_tags=["recon", "osint"],
        execute=fetch_whois,
    ))

    tools.append(Tool(
        name="fetch_dns_records",
        description=(
            "Enumerate DNS records using dig/nslookup. Returns A, AAAA, MX, NS, TXT, "
            "CNAME, and SOA records. Use to map infrastructure: A records find IPs, "
            "MX finds mail servers (often separate scope), TXT reveals SPF/DKIM config "
            "or service verification tokens, NS reveals DNS provider. More targeted "
            "than subfinder when specific record types are needed."
        ),
        parameters={
            "domain": "Domain to query (e.g. example.com or sub.example.com)",
            "record_type": "DNS record type: A, AAAA, MX, NS, TXT, CNAME, SOA, or ANY (default: ANY)",
        },
        example='fetch_dns_records(domain="example.com", record_type="TXT")',
        phase_tags=["recon", "discovery"],
        execute=fetch_dns_records,
    ))

    return tools
