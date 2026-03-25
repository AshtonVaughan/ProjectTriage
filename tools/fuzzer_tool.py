"""Directory and content fuzzer tool wrapping ffuf/feroxbuster."""
from __future__ import annotations
from typing import Any
from utils import run_cmd

BUILTIN_PATHS: list[str] = [
    "admin", "api", "api/v1", "api/v2", "api/v3", "api/internal",
    "console", "dashboard", "debug", "dev", "docs", "env",
    ".env", ".git", ".git/config", ".git/HEAD",
    "backup", "config", "database", "db", "dump",
    "graphql", "graphiql", "swagger", "swagger.json", "openapi.json",
    "actuator", "actuator/env", "actuator/health", "actuator/heapdump",
    "server-status", "server-info", "phpinfo.php", "info.php",
    "wp-admin", "wp-login.php", "wp-content",
    "login", "register", "signup", "reset", "forgot",
    "upload", "uploads", "files", "static", "assets", "media",
    "test", "testing", "staging", "internal", "private",
    "robots.txt", "sitemap.xml", ".well-known", "crossdomain.xml",
    "cgi-bin", "bin", "scripts", "includes",
    "status", "health", "healthcheck", "ping", "version",
    "metrics", "prometheus", "grafana",
    ".DS_Store", ".htaccess", ".htpasswd", "web.config",
    "trace.axd", "elmah.axd",
]

def fuzz_directories(target: str, wordlist: str = "", extensions: str = "", threads: int = 20, match_codes: str = "200,301,302,403") -> dict[str, Any]:
    """Fuzz directories on the target. Uses ffuf if available, falls back to built-in."""
    url = target.rstrip("/")
    found: list[dict[str, str]] = []
    # Try ffuf first
    try:
        ext_flag = f"-e {extensions}" if extensions else ""
        wl = wordlist or "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
        cmd = f"ffuf -u '{url}/FUZZ' -w {wl} {ext_flag} -mc {match_codes} -t {threads} -timeout 10 -json 2>/dev/null | head -200"
        result = run_cmd(cmd)
        if result and '"status"' in result:
            import json, re
            for line in result.strip().split("\n"):
                try:
                    data = json.loads(line)
                    if "results" in data:
                        for r in data["results"]:
                            found.append({"path": r.get("input", {}).get("FUZZ", ""), "status": str(r.get("status", "")), "length": str(r.get("length", ""))})
                except Exception:
                    pass
            if found:
                return {"stdout": "\n".join(f"{f['status']} {f['path']} [{f['length']}]" for f in found), "returncode": 0}
    except Exception:
        pass
    # Fallback: built-in path list with curl
    codes = set(match_codes.split(","))
    for path in BUILTIN_PATHS:
        try:
            result = run_cmd(f"curl -s -o /dev/null -w '%{{http_code}}' '{url}/{path}' --max-time 3")
            code = result.strip().strip("'")
            if code in codes:
                found.append({"path": path, "status": code, "length": ""})
        except Exception:
            pass
    output = "\n".join(f"{f['status']} /{f['path']}" for f in found) if found else "No results found"
    return {"stdout": output, "returncode": 0}

def fuzz_params(target: str, params: str = "", method: str = "GET") -> dict[str, Any]:
    """Fuzz for hidden parameters on an endpoint."""
    from fuzzer import SmartFuzzer
    fuzzer = SmartFuzzer()
    configs = fuzzer.discover_params(target)
    found = []
    for config in configs[:5]:
        try:
            result = run_cmd(f"curl -s -o /dev/null -w '%{{http_code}} %{{size_download}}' '{config['url']}' --max-time 5")
            parts = result.strip().split()
            if parts and parts[0] not in ("404", "000"):
                found.append(f"{parts[0]} {config['url'][:100]}")
        except Exception:
            pass
    return {"stdout": "\n".join(found) if found else "No hidden params found", "returncode": 0}
