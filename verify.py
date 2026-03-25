#!/usr/bin/env python3
"""Project Triage - Full module verification.

Imports every module, instantiates every class, calls key methods with
test data, and reports all errors. Run this before any hunt to catch bugs.

Usage: python verify.py
"""

import importlib
import sys
import traceback
from pathlib import Path

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
WARN = "\033[93mWARN\033[0m"

errors: list[str] = []
warnings: list[str] = []
passed = 0


def check(name: str, fn):
    """Run a check function, report pass/fail."""
    global passed
    try:
        fn()
        print(f"  [{PASS}] {name}")
        passed += 1
    except Exception as e:
        msg = f"{name}: {e}"
        errors.append(msg)
        print(f"  [{FAIL}] {msg}")


def warn_check(name: str, fn):
    """Run a check, warn on failure but don't count as error."""
    global passed
    try:
        fn()
        print(f"  [{PASS}] {name}")
        passed += 1
    except Exception as e:
        warnings.append(f"{name}: {e}")
        print(f"  [{WARN}] {name}: {e}")


# ── 1. Import every module ──────────────────────────────────────────────

print("\n=== MODULE IMPORTS ===")

MODULES = {
    "core": ["agent", "config", "context", "cost_tracker", "orchestrator",
             "parallel", "planner", "prompts", "provider", "scope",
             "session", "tool_registry"],
    "brain": ["agot_reasoner", "arch_analyzer", "assumption_engine",
              "chain_analyzer", "chain_engine", "client_analyzer",
              "confusion_engine", "coverage_asymmetry", "curriculum",
              "data_manager", "dom_analyzer", "domain_knowledge",
              "edge_analyzer", "escalation_router", "idor_engine",
              "intent_model", "lats_explorer", "mcts_explorer",
              "perceptor", "procedural_memory", "self_reflect",
              "state_machine", "tech_fingerprint", "websocket_tester",
              "workflow_tester", "world_model", "scale_model"],
    "intel": ["callback_server", "campaign_manager", "differential_engine",
              "fuzzer", "h2_desync", "hackerone", "infra_scanner",
              "interactsh_client", "js_analyzer", "mcp_tester",
              "monitor_mode", "nuclei_scan", "osint_engine",
              "program_intel", "source_analyzer", "source_intel",
              "supply_chain"],
    "models": ["attack_graph", "auth_context", "auth_manager", "cvss",
               "disclosures", "evidence", "hypothesis", "knowledge",
               "memory", "models_db", "patterns", "profiles",
               "target_model"],
    "ui": ["live_display", "report", "report_generator", "tui"],
    "utils": ["db", "evidence_collector", "quality_gate", "sanitizer",
              "utils", "validator", "wordlists"],
    "tools": ["analyzer", "browser", "cache_poison", "cloud_meta",
              "cors", "crawler", "crlf", "desync", "discovery",
              "dns_rebind", "exploit", "fetch_page", "fuzzer_tool",
              "graphql", "jwt", "llm_attacks", "oauth", "prompt_inject",
              "proto_pollution", "race", "recon", "register_discovery",
              "register_new", "saml", "scanner", "ssti",
              "subdomain_takeover", "web_search", "xss"],
}

imported = {}
for pkg, modules in MODULES.items():
    for mod in modules:
        full = f"{pkg}.{mod}"
        check(full, lambda f=full: importlib.import_module(f))


# ── 2. Instantiate brain modules ────────────────────────────────────────

print("\n=== BRAIN MODULE INSTANTIATION ===")

def _test_brain():
    from brain.confusion_engine import ConfusionEngine
    from brain.idor_engine import IDOREngine
    from brain.client_analyzer import ClientAnalyzer
    from brain.assumption_engine import AssumptionEngine
    from brain.intent_model import IntentModel
    from brain.edge_analyzer import EdgeAnalyzer
    from brain.coverage_asymmetry import CoverageAsymmetryDetector
    from brain.domain_knowledge import DomainKnowledge
    from brain.arch_analyzer import ArchAnalyzer
    from brain.chain_analyzer import ChainAnalyzer
    from brain.chain_engine import ChainEngine
    from brain.dom_analyzer import DOMAnalyzer
    from brain.websocket_tester import WebSocketTester
    from brain.state_machine import StateMachineExtractor
    from brain.workflow_tester import WorkflowTester
    from brain.tech_fingerprint import TechFingerprinter
    from brain.data_manager import DataManager
    from brain.scale_model import ScaleModel
    return {
        "confusion": ConfusionEngine(),
        "idor": IDOREngine(),
        "client": ClientAnalyzer(),
        "assumption": AssumptionEngine(),
        "intent": IntentModel(),
        "edge": EdgeAnalyzer(),
        "coverage": CoverageAsymmetryDetector(),
        "domain": DomainKnowledge(),
        "arch": ArchAnalyzer(),
        "chain_analyzer": ChainAnalyzer(),
        "chain_engine": ChainEngine(),
        "dom": DOMAnalyzer(),
        "websocket": WebSocketTester(),
        "state_machine": StateMachineExtractor(),
        "workflow": WorkflowTester(),
        "fingerprint": TechFingerprinter(),
        "data_mgr": DataManager(Path("data")),
        "scale": ScaleModel(),
    }

brain_modules = {}
check("instantiate all brain modules", lambda: brain_modules.update(_test_brain()))


# ── 3. Test brain module methods with sample data ───────────────────────

print("\n=== BRAIN MODULE METHOD TESTS ===")

test_url = "https://example.com"
test_tech = {"framework": "nextjs", "cdn": "cloudflare", "waf": "cloudflare", "auth": "jwt"}
test_endpoints = [{"url": "https://example.com/api/users", "method": "GET"}]
test_js = "var socket = new WebSocket('wss://example.com/ws'); addEventListener('message', function(e) { console.log(e.data); });"

if brain_modules:
    bm = brain_modules

    check("confusion_engine.generate_confusion_hypotheses",
          lambda: bm["confusion"].generate_confusion_hypotheses(test_url, test_tech, test_endpoints))

    check("confusion_engine.identify_component_stack",
          lambda: bm["confusion"].identify_component_stack({}, test_url, test_tech))

    check("idor_engine.generate_idor_tests",
          lambda: bm["idor"].generate_idor_tests(test_endpoints, {}))

    check("idor_engine.generate_bola_tests",
          lambda: bm["idor"].generate_bola_tests(test_endpoints, test_tech))

    check("client_analyzer.generate_client_hypotheses",
          lambda: bm["client"].generate_client_hypotheses(test_url, test_js, test_tech))

    check("assumption_engine.generate_assumptions",
          lambda: bm["assumption"].generate_assumptions(test_url, "GET", ["id", "user"], test_tech))

    check("intent_model.generate_violation_tests",
          lambda: bm["intent"].generate_violation_tests(test_url, "GET", ["id"], test_tech))

    check("edge_analyzer.identify_components",
          lambda: bm["edge"].identify_components(test_url, {}, test_tech))

    check("coverage_asymmetry.assess_surface",
          lambda: bm["coverage"].assess_surface(test_url))

    check("domain_knowledge.detect_domain",
          lambda: bm["domain"].detect_domain(test_url, [test_url], test_tech))

    check("arch_analyzer.detect_patterns",
          lambda: bm["arch"].detect_patterns(test_url, {}, test_tech))

    check("chain_analyzer.analyze (empty)",
          lambda: bm["chain_analyzer"].analyze([]))

    check("dom_analyzer.generate_hypotheses",
          lambda: bm["dom"].generate_hypotheses(test_url, test_tech))

    check("websocket_tester.discover_ws_endpoints (no evidence)",
          lambda: bm["websocket"].discover_ws_endpoints(test_url))

    check("websocket_tester.discover_ws_endpoints (with JS evidence)",
          lambda: bm["websocket"].discover_ws_endpoints(test_url, js_content=test_js))

    check("scale_model.estimate_scale",
          lambda: bm["scale"].estimate_scale(test_tech, subdomain_count=10, endpoint_count=50))

    check("scale_model.get_scale_hypotheses",
          lambda: bm["scale"].get_scale_hypotheses(test_tech, 10, 50))

    check("scale_model.get_environment_hypotheses",
          lambda: bm["scale"].get_environment_hypotheses("example.com"))

    check("data_manager.get_routes_for_tech",
          lambda: bm["data_mgr"].get_routes_for_tech(test_tech))

    check("data_manager.get_sensitive_paths",
          lambda: bm["data_mgr"].get_sensitive_paths())


# ── 4. Test hypothesis score normalization ──────────────────────────────

print("\n=== HYPOTHESIS SCORE NORMALIZATION ===")

def _test_scores():
    from core.agent import _to_int_score
    assert _to_int_score(8) == 8, f"int 8 -> {_to_int_score(8)}"
    assert _to_int_score(0.75) == 7, f"float 0.75 -> {_to_int_score(0.75)}"
    assert _to_int_score(0.5) == 5, f"float 0.5 -> {_to_int_score(0.5)}"
    assert _to_int_score("high") == 8, f"str 'high' -> {_to_int_score('high')}"
    assert _to_int_score("low") == 4, f"str 'low' -> {_to_int_score('low')}"
    assert _to_int_score("critical") == 10, f"str 'critical' -> {_to_int_score('critical')}"
    assert _to_int_score("medium") == 6, f"str 'medium' -> {_to_int_score('medium')}"
    assert _to_int_score(None) == 5, f"None -> {_to_int_score(None)}"

check("_to_int_score all types", _test_scores)


# ── 5. Test intel modules ──────────────────────────────────────────────

print("\n=== INTEL MODULE TESTS ===")

check("HackerOneImporter instantiation",
      lambda: __import__("intel.hackerone", fromlist=["HackerOneImporter"]).HackerOneImporter())

check("ProgramIntelligence instantiation",
      lambda: __import__("intel.program_intel", fromlist=["ProgramIntelligence"]).ProgramIntelligence())

check("InfraScanner instantiation",
      lambda: __import__("intel.infra_scanner", fromlist=["InfraScanner"]).InfraScanner())

check("CampaignManager instantiation",
      lambda: __import__("intel.campaign_manager", fromlist=["CampaignManager"]).CampaignManager(Path("data")))

check("SmartFuzzer instantiation",
      lambda: __import__("intel.fuzzer", fromlist=["SmartFuzzer"]).SmartFuzzer())


# ── 6. Test models ─────────────────────────────────────────────────────

print("\n=== MODEL TESTS ===")

check("AuthContext instantiation",
      lambda: __import__("models.auth_context", fromlist=["AuthContext"]).AuthContext())

def _test_auth_context():
    from models.auth_context import AuthContext
    ac = AuthContext()
    ac.add_session("user", "user", cookies={"session": "abc123"})
    roles = [s.role for s in ac.sessions.values()]
    assert roles == ["user"], f"Expected ['user'], got {roles}"
    tokens = {n: bool(s.jwt_token) for n, s in ac.sessions.items()}
    assert tokens == {"user": False}, f"Expected {{'user': False}}, got {tokens}"

check("AuthContext.add_session + role/token extraction", _test_auth_context)

check("QualityGate instantiation",
      lambda: __import__("utils.quality_gate", fromlist=["QualityGate"]).QualityGate())


# ── 7. Test tool registrations ─────────────────────────────────────────

print("\n=== TOOL REGISTRATION TESTS ===")

def _test_tool_reg(reg_module, reg_func, needs_config=True):
    mod = __import__(reg_module, fromlist=[reg_func])
    fn = getattr(mod, reg_func)
    if needs_config:
        from core.config import Config
        try:
            config = Config.from_env()
        except RuntimeError:
            # No tools on PATH (e.g., Windows dev machine)
            return
        tools = fn(config)
    else:
        tools = fn()
    assert isinstance(tools, list), f"Expected list, got {type(tools)}"
    for t in tools:
        assert hasattr(t, "name"), f"Tool missing 'name': {t}"
        assert hasattr(t, "execute"), f"Tool missing 'execute': {t}"

warn_check("register_recon_tools", lambda: _test_tool_reg("tools.recon", "register_recon_tools"))
warn_check("register_scanner_tools", lambda: _test_tool_reg("tools.scanner", "register_scanner_tools"))
warn_check("register_exploit_tools", lambda: _test_tool_reg("tools.exploit", "register_exploit_tools"))
warn_check("register_analyzer_tools", lambda: _test_tool_reg("tools.analyzer", "register_analyzer_tools", False))
warn_check("register_race_tools", lambda: _test_tool_reg("tools.race", "register_race_tools"))
warn_check("register_graphql_tools", lambda: _test_tool_reg("tools.graphql", "register_graphql_tools"))
warn_check("register_jwt_tools", lambda: _test_tool_reg("tools.jwt", "register_jwt_tools"))
warn_check("register_saml_tools", lambda: _test_tool_reg("tools.saml", "register_saml_tools"))
warn_check("register_oauth_tools", lambda: _test_tool_reg("tools.oauth", "register_oauth_tools"))
warn_check("register_llm_attack_tools", lambda: _test_tool_reg("tools.llm_attacks", "register_llm_attack_tools"))
warn_check("register_dns_rebind_tools", lambda: _test_tool_reg("tools.dns_rebind", "register_dns_rebind_tools"))
warn_check("register_discovery_tools", lambda: _test_tool_reg("tools.register_discovery", "register_discovery_tools"))
warn_check("register_web_search_tools", lambda: _test_tool_reg("tools.web_search", "register_web_search_tools"))
warn_check("register_fetch_tools", lambda: _test_tool_reg("tools.fetch_page", "register_fetch_tools"))
warn_check("register_browser_tools", lambda: _test_tool_reg("tools.browser", "register_browser_tools"))


# ── 8. Test procedural memory ──────────────────────────────────────────

print("\n=== PROCEDURAL MEMORY TESTS ===")

def _test_procedural_memory():
    from brain.procedural_memory import ProceduralMemory
    import tempfile
    td = tempfile.mkdtemp()
    try:
        pm = ProceduralMemory(Path(td))
        skills = pm.find_applicable_skills({"framework": "express", "auth": "jwt"}, test_url)
        assert isinstance(skills, list)
        hyps = pm.get_skill_hypotheses(skills, "example.com")
        assert isinstance(hyps, list)
    finally:
        try:
            import shutil
            shutil.rmtree(td, ignore_errors=True)
        except Exception:
            pass

check("ProceduralMemory find_applicable_skills + get_skill_hypotheses", _test_procedural_memory)


# ── 9. Test curriculum ─────────────────────────────────────────────────

print("\n=== CURRICULUM TESTS ===")

def _test_curriculum():
    from brain.curriculum import CurriculumManager
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        cm = CurriculumManager(Path(td))
        profile = cm.assess_target_difficulty(test_tech, "cloudflare", "jwt")
        assert hasattr(profile, "level"), f"Missing level: {profile}"
        assert hasattr(profile, "name"), f"Missing name: {profile}"
        hyps = cm.get_curriculum_hypotheses(profile.level, test_tech)
        assert isinstance(hyps, list)

check("CurriculumManager assess + hypotheses", _test_curriculum)


# ── 10. Test HackerOne importer ────────────────────────────────────────

print("\n=== HACKERONE IMPORTER TESTS ===")

def _test_h1_importer():
    from intel.hackerone import HackerOneImporter
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        h1 = HackerOneImporter(Path(td))
        # Test BountyHound bridge
        profile = h1.import_from_bountyhound("shopify")
        if profile:
            assert len(profile.in_scope) > 0, "Shopify should have in-scope assets"
            ctx = h1.generate_scope_context(profile)
            assert "In-Scope" in ctx, f"Missing In-Scope section: {ctx[:200]}"
        # Test parse_input
        handle, platform = h1._parse_input("https://hackerone.com/shopify")
        assert handle == "shopify", f"Expected 'shopify', got '{handle}'"
        assert platform == "hackerone", f"Expected 'hackerone', got '{platform}'"

check("HackerOneImporter parse + BountyHound bridge", _test_h1_importer)


# ── 11. Test the full agent import chain ───────────────────────────────

print("\n=== FULL AGENT IMPORT CHAIN ===")

check("from core.agent import Agent", lambda: __import__("core.agent", fromlist=["Agent"]))
check("from main import build_registry", lambda: __import__("main", fromlist=["build_registry"]))


# ── Results ─────────────────────────────────────────────────────────────

print("\n" + "=" * 60)
print(f"  PASSED: {passed}")
print(f"  FAILED: {len(errors)}")
print(f"  WARNINGS: {len(warnings)}")
print("=" * 60)

if errors:
    print(f"\n\033[91mFAILURES:\033[0m")
    for e in errors:
        print(f"  - {e}")

if warnings:
    print(f"\n\033[93mWARNINGS (non-critical):\033[0m")
    for w in warnings:
        print(f"  - {w}")

if not errors:
    print(f"\n\033[92mAll critical checks passed. Safe to hunt.\033[0m")
else:
    print(f"\n\033[91mFix {len(errors)} error(s) before hunting.\033[0m")

sys.exit(1 if errors else 0)
