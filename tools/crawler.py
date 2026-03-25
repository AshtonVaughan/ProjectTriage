"""Active web crawler tool wrapping katana/gospider."""
from __future__ import annotations
from typing import Any
from utils import run_cmd

def crawl(target: str, depth: int = 3, headless: bool = False, timeout: int = 60) -> dict[str, Any]:
    """Crawl a target to discover endpoints, forms, and API calls."""
    url = target if target.startswith("http") else f"https://{target}"
    # Try katana first
    try:
        hl = "-hl" if headless else ""
        cmd = f"katana -u '{url}' -d {depth} -jc -kf all {hl} -silent -timeout {timeout} 2>/dev/null | head -500"
        result = run_cmd(cmd)
        if result and result.strip():
            lines = [l.strip() for l in result.split("\n") if l.strip()]
            return {"stdout": "\n".join(lines), "returncode": 0, "endpoints_found": len(lines)}
    except Exception:
        pass
    # Try gospider
    try:
        cmd = f"gospider -s '{url}' -d {depth} --js -t 5 --sitemap --robots -q 2>/dev/null | head -500"
        result = run_cmd(cmd)
        if result and result.strip():
            return {"stdout": result, "returncode": 0}
    except Exception:
        pass
    # Fallback: basic curl + grep for links
    try:
        result = run_cmd(f"curl -s '{url}' --max-time 15 | grep -oP '(?:href|src|action)=[\"\\x27]([^\"\\x27]+)' | head -100")
        return {"stdout": result or "No endpoints found", "returncode": 0}
    except Exception:
        return {"stdout": "Crawl failed - no crawler available", "returncode": 1}
