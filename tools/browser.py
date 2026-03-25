"""Playwright-based browser automation for JavaScript-heavy targets, SPAs, and OAuth flows."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from core.config import Config
from core.tool_registry import Tool
from utils.utils import sanitize_subprocess_arg

# ---------------------------------------------------------------------------
# Module-level browser lifecycle state
# ---------------------------------------------------------------------------

_browser = None
_playwright = None

PLAYWRIGHT_INSTALL_MSG = (
    "Playwright is not installed. Run: pip install playwright && playwright install chromium"
)

CHROMIUM_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
]


def _get_browser() -> Any:
    """Lazily initialize Playwright and a headless Chromium browser instance.

    Re-creates the browser if it has crashed or been disconnected.
    """
    global _browser, _playwright
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        raise ImportError(PLAYWRIGHT_INSTALL_MSG)

    # Re-create if browser has been closed or crashed
    if _browser is not None:
        try:
            # A live browser responds to this; a crashed one raises
            _ = _browser.contexts
        except Exception:
            _browser = None
            _playwright = None

    if _browser is None:
        _playwright = sync_playwright().start()
        _browser = _playwright.chromium.launch(
            headless=True,
            args=CHROMIUM_ARGS,
        )
    return _browser


def _new_context(session_file: str = "") -> Any:
    """Create a new isolated browser context, optionally loading saved auth state."""
    browser = _get_browser()
    if session_file:
        sp = Path(session_file)
        if sp.exists():
            return browser.new_context(storage_state=str(sp))
    return browser.new_context()


def _save_screenshot(page: Any, findings_dir: Path, prefix: str = "screenshot") -> str:
    """Capture a full-page screenshot and return the saved file path."""
    findings_dir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    path = findings_dir / f"{prefix}_{ts}.png"
    page.screenshot(path=str(path), full_page=True)
    return str(path)


def _extract_content(page: Any, response: Any, extract: str) -> Any:
    """Extract the requested content type from the page after navigation."""
    if extract == "html":
        return page.content()
    if extract == "links":
        hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        return hrefs
    if extract == "forms":
        forms = page.eval_on_selector_all(
            "form",
            """forms => forms.map(f => ({
                action: f.action,
                method: f.method,
                inputs: Array.from(f.querySelectorAll('input,select,textarea')).map(i => ({
                    name: i.name, type: i.type, id: i.id, placeholder: i.placeholder
                }))
            }))""",
        )
        return forms
    if extract == "cookies":
        ctx = page.context
        cookies = ctx.cookies()
        return cookies
    if extract == "headers":
        if response is not None:
            return dict(response.headers)
        return {}
    # Default: "text"
    return page.inner_text("body") if page.query_selector("body") else page.content()


# ---------------------------------------------------------------------------
# Public tool functions
# ---------------------------------------------------------------------------


def browser_navigate(
    url: str,
    wait_for: str = "load",
    screenshot: bool = False,
    extract: str = "text",
    session_file: str = "",
) -> dict[str, Any]:
    """Navigate to a URL and extract content.

    Parameters
    ----------
    url:
        Target URL to navigate to.
    wait_for:
        "load", "networkidle", "domcontentloaded", or a CSS selector to wait for.
    screenshot:
        Save a screenshot to the findings directory and include the path in the result.
    extract:
        What to return - "text", "html", "links", "forms", "cookies", "headers".
    session_file:
        Optional path to a saved auth state JSON file.
    """
    try:
        url = sanitize_subprocess_arg(url, "url")
    except Exception:
        pass

    try:
        context = _new_context(session_file)
    except ImportError as e:
        return {"error": str(e), "content": None, "url": url, "status": None}

    try:
        page = context.new_page()
        response = None

        # Determine wait condition
        playwright_wait_events = {"load", "networkidle", "domcontentloaded"}
        if wait_for in playwright_wait_events:
            response = page.goto(url, wait_until=wait_for, timeout=30000)
        else:
            # wait_for is a CSS selector
            response = page.goto(url, wait_until="load", timeout=30000)
            try:
                page.wait_for_selector(wait_for, timeout=10000)
            except Exception:
                pass

        status = response.status if response else None
        final_url = page.url
        title = page.title()

        content = _extract_content(page, response, extract)

        screenshot_path = None
        if screenshot:
            findings_dir = Path("findings")
            try:
                from core.config import Config as _Cfg  # noqa: F401
            except Exception:
                pass
            screenshot_path = _save_screenshot(page, findings_dir, "navigate")

        return {
            "content": content,
            "url": final_url,
            "status": status,
            "title": title,
            "screenshot": screenshot_path,
        }
    except Exception as exc:
        return {"error": str(exc), "content": None, "url": url, "status": None, "screenshot": None}
    finally:
        try:
            context.close()
        except Exception:
            pass


def browser_click(
    url: str,
    selector: str,
    wait_after: str = "networkidle",
    session_file: str = "",
) -> dict[str, Any]:
    """Navigate to a URL and click an element matching a CSS selector.

    Parameters
    ----------
    url:
        Target URL.
    selector:
        CSS selector of the element to click.
    wait_after:
        Network/load state to wait for after the click ("load", "networkidle", "domcontentloaded").
    session_file:
        Optional path to a saved auth state JSON file.
    """
    try:
        url = sanitize_subprocess_arg(url, "url")
    except Exception:
        pass

    try:
        context = _new_context(session_file)
    except ImportError as e:
        return {"error": str(e), "content": None, "url": url}

    try:
        page = context.new_page()
        page.goto(url, wait_until="load", timeout=30000)

        page.wait_for_selector(selector, timeout=10000)
        page.click(selector)

        playwright_wait_events = {"load", "networkidle", "domcontentloaded"}
        if wait_after in playwright_wait_events:
            page.wait_for_load_state(wait_after, timeout=15000)

        final_url = page.url
        title = page.title()
        text = page.inner_text("body") if page.query_selector("body") else page.content()

        return {
            "content": text,
            "url": final_url,
            "title": title,
            "clicked_selector": selector,
        }
    except Exception as exc:
        return {"error": str(exc), "content": None, "url": url, "clicked_selector": selector}
    finally:
        try:
            context.close()
        except Exception:
            pass


def browser_fill_form(
    url: str,
    form_data: dict[str, str] | str,
    submit_selector: str = "",
    session_file: str = "",
) -> dict[str, Any]:
    """Fill a form on a page and optionally submit it.

    Parameters
    ----------
    url:
        Target URL containing the form.
    form_data:
        Dict mapping CSS selectors to values, e.g. {"#username": "admin", "#password": "pass"}.
        Accepts a JSON string if the agent passes a serialized dict.
    submit_selector:
        CSS selector of the submit button. If empty, no submit action is taken.
    session_file:
        Optional path to a saved auth state JSON file.
    """
    try:
        url = sanitize_subprocess_arg(url, "url")
    except Exception:
        pass

    # Accept JSON string from agent
    if isinstance(form_data, str):
        try:
            form_data = json.loads(form_data)
        except Exception:
            return {"error": "form_data must be a dict or JSON string mapping selector -> value", "url": url}

    try:
        context = _new_context(session_file)
    except ImportError as e:
        return {"error": str(e), "content": None, "url": url}

    try:
        page = context.new_page()
        page.goto(url, wait_until="load", timeout=30000)

        for selector, value in form_data.items():
            try:
                page.wait_for_selector(selector, timeout=5000)
                page.fill(selector, str(value))
            except Exception as field_err:
                pass  # Continue with other fields even if one fails

        if submit_selector:
            page.wait_for_selector(submit_selector, timeout=5000)
            page.click(submit_selector)
            try:
                page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass

        final_url = page.url
        title = page.title()
        text = page.inner_text("body") if page.query_selector("body") else page.content()

        return {
            "content": text,
            "url": final_url,
            "title": title,
            "fields_filled": list(form_data.keys()),
            "submitted": bool(submit_selector),
        }
    except Exception as exc:
        return {"error": str(exc), "content": None, "url": url}
    finally:
        try:
            context.close()
        except Exception:
            pass


def browser_execute_js(
    url: str,
    script: str,
    session_file: str = "",
) -> dict[str, Any]:
    """Navigate to a URL and execute arbitrary JavaScript on the page.

    Useful for testing DOM XSS sinks, extracting JS variables, checking
    postMessage handlers, and probing client-side security controls.

    Parameters
    ----------
    url:
        Target URL to load before executing the script.
    script:
        JavaScript to execute. The return value of the last expression is captured.
    session_file:
        Optional path to a saved auth state JSON file.
    """
    try:
        url = sanitize_subprocess_arg(url, "url")
    except Exception:
        pass

    try:
        context = _new_context(session_file)
    except ImportError as e:
        return {"error": str(e), "result": None, "url": url}

    try:
        page = context.new_page()
        page.goto(url, wait_until="load", timeout=30000)

        result = page.evaluate(script)

        # Capture any console errors as bonus context
        final_url = page.url
        title = page.title()

        return {
            "result": result,
            "url": final_url,
            "title": title,
            "script_length": len(script),
        }
    except Exception as exc:
        return {"error": str(exc), "result": None, "url": url}
    finally:
        try:
            context.close()
        except Exception:
            pass


def browser_capture_auth(
    url: str,
    username_selector: str,
    password_selector: str,
    username: str,
    password: str,
    submit_selector: str,
    session_file: str = "",
) -> dict[str, Any]:
    """Perform a login flow and capture the resulting session state.

    Navigates to the login page, fills credentials, submits the form, waits
    for the post-login redirect, then captures cookies, localStorage,
    sessionStorage, and any Authorization headers seen during the flow.
    The full session state is saved to a JSON file for reuse by other functions.

    Parameters
    ----------
    url:
        Login page URL.
    username_selector:
        CSS selector for the username/email input field.
    password_selector:
        CSS selector for the password input field.
    username:
        Credential - username or email.
    password:
        Credential - password.
    submit_selector:
        CSS selector for the login submit button.
    session_file:
        Output path for the saved session JSON. Defaults to findings/session_<ts>.json.
    """
    try:
        url = sanitize_subprocess_arg(url, "url")
    except Exception:
        pass

    try:
        context = _new_context()
    except ImportError as e:
        return {"error": str(e), "session_file": None, "url": url}

    captured_auth_headers: list[str] = []

    try:
        page = context.new_page()

        # Intercept responses to capture auth tokens in headers
        def on_response(response: Any) -> None:
            try:
                auth = response.headers.get("authorization", "")
                www_auth = response.headers.get("www-authenticate", "")
                set_cookie = response.headers.get("set-cookie", "")
                if auth:
                    captured_auth_headers.append(f"Authorization: {auth}")
                if www_auth:
                    captured_auth_headers.append(f"WWW-Authenticate: {www_auth}")
                if set_cookie:
                    captured_auth_headers.append(f"Set-Cookie: {set_cookie[:200]}")
            except Exception:
                pass

        page.on("response", on_response)

        page.goto(url, wait_until="load", timeout=30000)

        # Fill credentials
        page.wait_for_selector(username_selector, timeout=10000)
        page.fill(username_selector, username)

        page.wait_for_selector(password_selector, timeout=5000)
        page.fill(password_selector, password)

        page.wait_for_selector(submit_selector, timeout=5000)
        page.click(submit_selector)

        # Wait for post-login redirect
        try:
            page.wait_for_load_state("networkidle", timeout=20000)
        except Exception:
            pass

        final_url = page.url
        title = page.title()

        # Extract client-side storage
        local_storage: dict[str, str] = {}
        session_storage: dict[str, str] = {}
        try:
            local_storage = page.evaluate(
                "() => Object.fromEntries(Object.entries(localStorage))"
            )
        except Exception:
            pass
        try:
            session_storage = page.evaluate(
                "() => Object.fromEntries(Object.entries(sessionStorage))"
            )
        except Exception:
            pass

        cookies = context.cookies()

        # Save session state for reuse
        ts = int(time.time())
        if not session_file:
            findings_dir = Path("findings")
            findings_dir.mkdir(parents=True, exist_ok=True)
            session_file = str(findings_dir / f"session_{ts}.json")

        context.storage_state(path=session_file)

        return {
            "session_file": session_file,
            "url": final_url,
            "title": title,
            "cookies": cookies,
            "local_storage": local_storage,
            "session_storage": session_storage,
            "captured_auth_headers": captured_auth_headers,
            "login_successful": final_url != url,
        }
    except Exception as exc:
        return {"error": str(exc), "session_file": None, "url": url}
    finally:
        try:
            context.close()
        except Exception:
            pass


def browser_screenshot(
    url: str,
    full_page: bool = True,
    output_path: str = "",
    session_file: str = "",
) -> dict[str, Any]:
    """Navigate to a URL and capture a screenshot.

    Parameters
    ----------
    url:
        Target URL to screenshot.
    full_page:
        Capture the full scrollable page (True) or just the visible viewport (False).
    output_path:
        Optional explicit output file path. If empty, auto-generated in findings/.
    session_file:
        Optional path to a saved auth state JSON file.
    """
    try:
        url = sanitize_subprocess_arg(url, "url")
    except Exception:
        pass

    try:
        context = _new_context(session_file)
    except ImportError as e:
        return {"error": str(e), "screenshot": None, "url": url}

    try:
        page = context.new_page()
        page.goto(url, wait_until="networkidle", timeout=30000)

        title = page.title()
        final_url = page.url

        if not output_path:
            findings_dir = Path("findings")
            findings_dir.mkdir(parents=True, exist_ok=True)
            ts = int(time.time())
            output_path = str(findings_dir / f"screenshot_{ts}.png")

        page.screenshot(path=output_path, full_page=full_page)

        return {
            "screenshot": output_path,
            "url": final_url,
            "title": title,
            "full_page": full_page,
        }
    except Exception as exc:
        return {"error": str(exc), "screenshot": None, "url": url}
    finally:
        try:
            context.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_browser_tools(config: Config) -> list[Tool]:
    """Register all browser automation tools with the tool registry."""
    return [
        Tool(
            name="browser_navigate",
            description=(
                "Navigate a URL with a real headless Chromium browser and extract content. "
                "Handles SPAs, JavaScript-rendered pages, and OAuth redirects. "
                "Can extract text, HTML, links, forms, cookies, or response headers. "
                "Optionally saves a screenshot."
            ),
            parameters={
                "url": "Target URL to navigate to",
                "wait_for": "Wait condition: 'load', 'networkidle', 'domcontentloaded', or a CSS selector (default: load)",
                "screenshot": "Save screenshot to findings/ and return path (default: false)",
                "extract": "What to return: 'text', 'html', 'links', 'forms', 'cookies', 'headers' (default: text)",
                "session_file": "Optional path to saved auth state JSON from browser_capture_auth",
            },
            example='browser_navigate(url="https://app.example.com/dashboard", wait_for="networkidle", extract="links")',
            phase_tags=["recon", "enumeration", "exploitation", "analysis"],
            execute=lambda **kw: browser_navigate(**kw),
        ),
        Tool(
            name="browser_click",
            description=(
                "Navigate to a URL and click an element matching a CSS selector. "
                "Returns page state after the click and any resulting navigation. "
                "Use this for testing buttons, links, and UI interactions that trigger JS."
            ),
            parameters={
                "url": "Target URL",
                "selector": "CSS selector of element to click (e.g. '#submit-btn', 'button[type=submit]')",
                "wait_after": "State to wait for after click: 'load', 'networkidle', 'domcontentloaded' (default: networkidle)",
                "session_file": "Optional path to saved auth state JSON",
            },
            example='browser_click(url="https://app.example.com/admin", selector="#delete-user-btn")',
            phase_tags=["exploitation", "analysis"],
            execute=lambda **kw: browser_click(**kw),
        ),
        Tool(
            name="browser_fill_form",
            description=(
                "Fill a web form with provided field values and optionally submit it. "
                "Use for testing login forms, search inputs, registration pages, and any "
                "user-controlled input that a curl/httpx request cannot replicate."
            ),
            parameters={
                "url": "Target URL containing the form",
                "form_data": "JSON dict mapping CSS selectors to values, e.g. {\"#user\": \"admin\", \"#pass\": \"test\"}",
                "submit_selector": "CSS selector of submit button. Omit to fill without submitting",
                "session_file": "Optional path to saved auth state JSON",
            },
            example='browser_fill_form(url="https://app.example.com/login", form_data={"#email":"admin@test.com","#password":"password123"}, submit_selector="button[type=submit]")',
            phase_tags=["exploitation", "analysis"],
            execute=lambda **kw: browser_fill_form(**kw),
        ),
        Tool(
            name="browser_execute_js",
            description=(
                "Load a URL in a real browser and execute arbitrary JavaScript on the page. "
                "Use for: testing DOM XSS sinks, extracting JS variables and API keys from memory, "
                "checking postMessage handlers, probing prototype chains, and reading hidden DOM state."
            ),
            parameters={
                "url": "Target URL to load",
                "script": "JavaScript expression or function body to execute. Return value is captured.",
                "session_file": "Optional path to saved auth state JSON",
            },
            example='browser_execute_js(url="https://app.example.com", script="Object.keys(window.__REDUX_STATE__ || {})")',
            phase_tags=["exploitation", "analysis", "recon"],
            execute=lambda **kw: browser_execute_js(**kw),
        ),
        Tool(
            name="browser_capture_auth",
            description=(
                "Perform a full login flow in a real browser and capture the resulting session. "
                "Returns cookies, localStorage, sessionStorage, and any auth tokens observed. "
                "Saves a session JSON file that can be passed to other browser_* tools as session_file."
            ),
            parameters={
                "url": "Login page URL",
                "username_selector": "CSS selector for the username/email input",
                "password_selector": "CSS selector for the password input",
                "username": "Username or email to log in with",
                "password": "Password to use",
                "submit_selector": "CSS selector for the submit/login button",
                "session_file": "Output path for saved session JSON (default: findings/session_<ts>.json)",
            },
            example='browser_capture_auth(url="https://app.example.com/login", username_selector="#email", password_selector="#password", username="admin@test.com", password="hunter2", submit_selector="button[type=submit]")',
            phase_tags=["exploitation", "analysis"],
            execute=lambda **kw: browser_capture_auth(**kw),
        ),
        Tool(
            name="browser_screenshot",
            description=(
                "Navigate to a URL and capture a screenshot for evidence or visual analysis. "
                "Returns the saved file path. Use for documenting vulnerabilities or capturing "
                "pages that require JavaScript to render properly."
            ),
            parameters={
                "url": "Target URL to screenshot",
                "full_page": "Capture full scrollable page vs visible viewport only (default: true)",
                "output_path": "Optional explicit output file path. Auto-generated in findings/ if omitted",
                "session_file": "Optional path to saved auth state JSON",
            },
            example='browser_screenshot(url="https://app.example.com/admin/users", full_page=True)',
            phase_tags=["exploitation", "analysis", "reporting"],
            execute=lambda **kw: browser_screenshot(**kw),
        ),
    ]
