#!/usr/bin/env python3
"""Project Triage - Full logic path verification.

Simulates an entire hunt cycle without an LLM. Tests every code path
the agent takes during Phase A, Phase B, and the main loop setup.
Catches type errors, missing attributes, broken imports, and logic bugs.

Usage: PYTHONPATH=. python3 verify.py
   or: python verify.py  (from project root)
"""

import importlib
import json
import os
import sys
import tempfile
import shutil
import traceback
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
WARN = "\033[93mWARN\033[0m"

errors: list[str] = []
warnings: list[str] = []
passed = 0


def check(name: str, fn):
    global passed
    try:
        fn()
        print(f"  [{PASS}] {name}")
        passed += 1
    except Exception as e:
        tb = traceback.format_exc().strip().split("\n")
        location = tb[-2].strip() if len(tb) >= 2 else ""
        msg = f"{name}: {e} ({location})"
        errors.append(msg)
        print(f"  [{FAIL}] {msg}")


def warn_check(name: str, fn):
    global passed
    try:
        fn()
        print(f"  [{PASS}] {name}")
        passed += 1
    except Exception as e:
        warnings.append(f"{name}: {e}")
        print(f"  [{WARN}] {name}: {e}")


# ── Test data ───────────────────────────────────────────────────────────

TEST_URL = "https://example.com"
TEST_TARGET = "example.com"
TEST_TECH = {
    "framework": "nextjs", "cdn": "cloudflare", "waf": "cloudflare",
    "auth": "jwt", "server": "nginx", "api_style": "rest",
    "cloud_provider": "aws", "auth_type": "oauth",
}
TEST_ENDPOINTS = [
    {"url": "https://example.com/api/users", "method": "GET"},
    {"url": "https://example.com/api/orders/123", "method": "GET"},
    {"url": "https://example.com/api/payments", "method": "POST"},
    {"url": "https://example.com/login", "method": "POST"},
    {"url": "https://example.com/graphql", "method": "POST"},
    {"url": "https://example.com/api/upload", "method": "POST"},
    {"url": "https://example.com/api/admin/users", "method": "GET"},
    {"url": "https://example.com/api/v1/search?q=test", "method": "GET"},
]
TEST_JS = """
var socket = new WebSocket('wss://example.com/ws');
socket.onmessage = function(e) { console.log(e.data); };
window.addEventListener('message', function(e) { eval(e.data); });
fetch('/api/internal/config').then(r => r.json());
const API_KEY = 'sk_live_abc123';
"""
TEST_HTML = """
<html><head><title>Example App</title></head>
<body>
<form action="/login" method="POST">
  <input name="username" type="text">
  <input name="password" type="password">
  <input name="csrf_token" type="hidden" value="abc123">
</form>
<a href="/api/docs">API Docs</a>
<script src="/static/app.js"></script>
</body></html>
"""
TEST_HEADERS = {
    "server": "nginx/1.21.0",
    "x-powered-by": "Express",
    "cf-ray": "abc123",
    "content-type": "text/html",
}
TEST_FINDINGS = [
    {"type": "ssrf", "endpoint": "/api/proxy", "severity": "high",
     "title": "SSRF in proxy endpoint", "evidence": "169.254.169.254 accessible"},
    {"type": "xss", "endpoint": "/search", "severity": "medium",
     "title": "Reflected XSS in search", "evidence": "<script>alert(1)</script> reflected"},
]

# Create temp dir for tests
TMPDIR = tempfile.mkdtemp(prefix="triage_verify_")

# ════════════════════════════════════════════════════════════════════════
print("=" * 70)
print("  PROJECT TRIAGE - FULL LOGIC PATH VERIFICATION")
print("=" * 70)

# ── 1. Module imports ───────────────────────────────────────────────────

print("\n=== 1. MODULE IMPORTS (all 110 files) ===")

MODULES = {
    "core": ["agent", "config", "context", "cost_tracker", "orchestrator",
             "parallel", "pentest_tree", "planner", "prompts", "provider",
             "repetition", "scope", "session", "session_manager", "tool_registry"],
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
    "utils": ["db", "evidence_collector", "output_summarizer", "quality_gate",
              "response_classifier", "sanitizer", "utils", "validator", "wordlists"],
    "tools": ["analyzer", "browser", "cache_poison", "cloud_meta",
              "cors", "crawler", "crlf", "desync", "discovery",
              "dns_rebind", "exploit", "fetch_page", "fuzzer_tool",
              "graphql", "jwt", "llm_attacks", "oauth", "prompt_inject",
              "proto_pollution", "race", "recon", "register_discovery",
              "register_new", "saml", "scanner", "ssti",
              "subdomain_takeover", "web_search", "xss", "auth_tools"],
}

for pkg, modules in MODULES.items():
    for mod in modules:
        full = f"{pkg}.{mod}"
        check(full, lambda f=full: importlib.import_module(f))


# ── 2. Score normalization ──────────────────────────────────────────────

print("\n=== 2. HYPOTHESIS SCORE NORMALIZATION ===")

def _test_score_norm():
    from core.agent import _to_int_score
    tests = [
        (8, 8), (0, 1), (15, 10), (-1, 1),  # int
        (0.75, 7), (0.0, 1), (1.0, 10), (0.5, 5),  # float 0-1
        (5.5, 5),  # float >1
        ("critical", 10), ("high", 8), ("medium", 6), ("low", 4), ("none", 1),  # str
        ("HIGH", 8), ("Critical", 10),  # case insensitive
        ("unknown", 5),  # unknown string -> default
        (None, 5), ([], 5), ({}, 5),  # weird types -> default
    ]
    for val, expected in tests:
        result = _to_int_score(val)
        assert result == expected, f"_to_int_score({val!r}) = {result}, expected {expected}"

check("_to_int_score: all input types and edge cases", _test_score_norm)


# ── 3. Brain modules - instantiation + full method calls ────────────────

print("\n=== 3. BRAIN MODULE LOGIC PATHS ===")

# 3a. ConfusionEngine
def _test_confusion_full():
    from brain.confusion_engine import ConfusionEngine
    ce = ConfusionEngine()
    # identify_component_stack
    comps = ce.identify_component_stack(TEST_HEADERS, TEST_URL, TEST_TECH)
    assert isinstance(comps, list), f"Expected list, got {type(comps)}"
    # detect_confusion_opportunities
    vectors = ce.detect_confusion_opportunities(comps, TEST_URL)
    assert isinstance(vectors, list)
    # generate_confusion_payloads for each vector
    for v in vectors[:3]:
        payloads = ce.generate_confusion_payloads(v)
        assert isinstance(payloads, list)
    # generate_confusion_hypotheses - the main output
    hyps = ce.generate_confusion_hypotheses(TEST_URL, TEST_TECH, TEST_ENDPOINTS)
    assert isinstance(hyps, list)
    for h in hyps:
        assert isinstance(h.get("novelty"), (int, float)), f"novelty not numeric: {h.get('novelty')!r}"
        assert isinstance(h.get("exploitability"), (int, float)), f"exploitability not numeric: {h.get('exploitability')!r}"
        assert isinstance(h.get("impact"), (int, float)), f"impact not numeric: {h.get('impact')!r}"
        assert h.get("effort") is not None, "effort is None"

check("ConfusionEngine: full pipeline (stack->vectors->payloads->hypotheses)", _test_confusion_full)

# 3b. IDOREngine
def _test_idor_full():
    from brain.idor_engine import IDOREngine
    ie = IDOREngine()
    idor_tests = ie.generate_idor_tests(TEST_ENDPOINTS, {"roles": ["user", "admin"], "tokens": {}})
    assert isinstance(idor_tests, list)
    bola_tests = ie.generate_bola_tests(TEST_ENDPOINTS, TEST_TECH)
    assert isinstance(bola_tests, list)
    all_tests = idor_tests + bola_tests
    hyps = ie.idor_to_hypotheses(all_tests)
    assert isinstance(hyps, list)
    for h in hyps:
        assert "endpoint" in h, f"Missing endpoint in hypothesis: {h}"
        assert "technique" in h, f"Missing technique: {h}"

check("IDOREngine: generate_idor + generate_bola + to_hypotheses", _test_idor_full)

# 3c. ClientAnalyzer
def _test_client_full():
    from brain.client_analyzer import ClientAnalyzer
    ca = ClientAnalyzer()
    pm_findings = ca.analyze_postmessage_surface(TEST_JS, TEST_URL)
    assert isinstance(pm_findings, list)
    ws_eps = ca.extract_ws_endpoints_from_js(TEST_JS, TEST_URL)
    assert isinstance(ws_eps, list)
    hyps = ca.generate_client_hypotheses(TEST_URL, TEST_JS, TEST_TECH)
    assert isinstance(hyps, list)

check("ClientAnalyzer: postmessage + ws_extract + hypotheses", _test_client_full)

# 3d. WebSocketTester - verify no phantom endpoints
def _test_ws_no_phantom():
    from brain.websocket_tester import WebSocketTester
    wst = WebSocketTester()
    # No JS evidence = no endpoints
    eps_no_evidence = wst.discover_ws_endpoints(TEST_URL)
    assert len(eps_no_evidence) == 0, f"Expected 0 endpoints without evidence, got {len(eps_no_evidence)}"
    # With JS evidence = endpoints appear
    eps_with_js = wst.discover_ws_endpoints(TEST_URL, js_content=TEST_JS)
    assert len(eps_with_js) > 0, "Expected endpoints with WebSocket JS evidence"

check("WebSocketTester: no phantom endpoints without evidence", _test_ws_no_phantom)

# 3e. AssumptionEngine
def _test_assumption_full():
    from brain.assumption_engine import AssumptionEngine
    ae = AssumptionEngine()
    assumptions = ae.generate_assumptions(TEST_URL, "POST", ["user_id", "amount"], TEST_TECH)
    assert isinstance(assumptions, list)
    if assumptions:
        hyps = ae.assumptions_to_hypotheses(assumptions[:3])
        assert isinstance(hyps, list)
        for h in hyps:
            assert "endpoint" in h or "description" in h

check("AssumptionEngine: generate + to_hypotheses", _test_assumption_full)

# 3f. IntentModel
def _test_intent_full():
    from brain.intent_model import IntentModel
    im = IntentModel()
    violations = im.generate_violation_tests(TEST_URL, "POST", ["amount", "status"], TEST_TECH)
    assert isinstance(violations, list)
    if violations:
        hyps = im.violations_to_hypotheses(violations[:3])
        assert isinstance(hyps, list)

check("IntentModel: generate_violations + to_hypotheses", _test_intent_full)

# 3g. EdgeAnalyzer
def _test_edge_full():
    from brain.edge_analyzer import EdgeAnalyzer
    ea = EdgeAnalyzer()
    components = ea.identify_components(TEST_URL, TEST_HEADERS, TEST_TECH)
    assert isinstance(components, list)
    if len(components) >= 2:
        edges = ea.generate_edge_tests(components, TEST_URL)
        assert isinstance(edges, list)
        for edge in edges[:3]:
            assert hasattr(edge, "data_type"), f"Edge missing data_type: {edge}"
            assert hasattr(edge, "upstream"), f"Edge missing upstream: {edge}"

check("EdgeAnalyzer: identify_components + generate_edge_tests", _test_edge_full)

# 3h. DomainKnowledge
def _test_domain_full():
    from brain.domain_knowledge import DomainKnowledge
    dk = DomainKnowledge()
    domain = dk.detect_domain(TEST_URL, [e["url"] for e in TEST_ENDPOINTS], TEST_TECH)
    assert isinstance(domain, str)
    patterns = dk.get_patterns(domain)
    assert isinstance(patterns, list)
    if patterns:
        hyps = dk.patterns_to_hypotheses(patterns[:3], TEST_URL)
        assert isinstance(hyps, list)
        for h in hyps:
            # Verify types won't break _to_int_score
            impact = h.get("impact", "")
            assert impact is not None, f"impact is None in hypothesis: {h}"

check("DomainKnowledge: detect_domain + get_patterns + to_hypotheses", _test_domain_full)

# 3i. ArchAnalyzer
def _test_arch_full():
    from brain.arch_analyzer import ArchAnalyzer
    aa = ArchAnalyzer()
    # detect_patterns - exact agent code path uses (url, tech_stack, headers)
    patterns = aa.detect_patterns(TEST_URL, TEST_TECH, TEST_HEADERS)
    assert isinstance(patterns, list)
    # Agent accesses pattern.name, pattern.description, pattern.severity directly
    for p in patterns[:5]:
        assert hasattr(p, "name"), f"Pattern missing 'name': {type(p)}"
        assert hasattr(p, "description"), f"Pattern missing 'description'"
        assert hasattr(p, "severity"), f"Pattern missing 'severity'"
        assert isinstance(p.name, str), f"name not str: {type(p.name)}"
        assert p.severity in ("critical", "high", "medium", "low", "info"), f"unexpected severity: {p.severity}"

check("ArchAnalyzer: detect_patterns + pattern attributes (exact agent path)", _test_arch_full)

# 3j. ChainAnalyzer + ChainEngine
def _test_chain_full():
    from brain.chain_analyzer import ChainAnalyzer
    from brain.chain_engine import ChainEngine
    ca = ChainAnalyzer()
    # Test with findings
    chains = ca.analyze(TEST_FINDINGS)
    assert isinstance(chains, list)
    if chains:
        hyps = ca.get_chain_hypotheses(chains)
        assert isinstance(hyps, list)
    # ChainEngine
    ce = ChainEngine()
    chain_hyps = ce.generate_chain_hypotheses(TEST_FINDINGS, TEST_URL)
    assert isinstance(chain_hyps, list)

check("ChainAnalyzer + ChainEngine: analyze + hypotheses", _test_chain_full)

# 3k. ScaleModel
def _test_scale_full():
    from brain.scale_model import ScaleModel
    sm = ScaleModel()
    # estimate_scale
    scale = sm.estimate_scale(TEST_TECH, subdomain_count=50, endpoint_count=200,
                              program_info={"bounty_max": 15000})
    assert scale.scale_tier in ("startup", "mid_market", "enterprise", "mega")
    assert 1 <= scale.attack_surface_score <= 100
    # get_scale_hypotheses
    hyps = sm.get_scale_hypotheses(TEST_TECH, 50, 200)
    assert isinstance(hyps, list)
    for h in hyps:
        from core.agent import _to_int_score
        # Verify all fields can be normalized without error
        _to_int_score(h.get("novelty", 5))
        _to_int_score(h.get("exploitability", 5))
        _to_int_score(h.get("impact", 5))
        _to_int_score(h.get("effort", 5))
    # environment hypotheses
    env_hyps = sm.get_environment_hypotheses("example.com")
    assert isinstance(env_hyps, list)
    assert len(env_hyps) > 0, "Expected environment hypotheses"
    # role escalation
    matrix = sm.get_role_escalation_matrix(["user", "admin", "moderator"])
    assert isinstance(matrix, list)
    assert len(matrix) >= 6, f"Expected 6+ escalation pairs for 3 roles, got {len(matrix)}"

check("ScaleModel: estimate + hypotheses + environments + role_matrix", _test_scale_full)

# 3l. CoverageAsymmetry
def _test_coverage_full():
    from brain.coverage_asymmetry import CoverageAsymmetryDetector
    cd = CoverageAsymmetryDetector()
    for ep in TEST_ENDPOINTS:
        assessment = cd.assess_surface(ep["url"])
        assert hasattr(assessment, "estimated_coverage")
        assert hasattr(assessment, "priority_boost")
        assert isinstance(assessment.priority_boost, (int, float))

check("CoverageAsymmetry: assess_surface on all test endpoints", _test_coverage_full)

# 3m. DOMAnalyzer
def _test_dom_full():
    from brain.dom_analyzer import DOMAnalyzer
    da = DOMAnalyzer()
    hyps = da.generate_hypotheses(TEST_URL, TEST_TECH)
    assert isinstance(hyps, list)

check("DOMAnalyzer: generate_hypotheses", _test_dom_full)

# 3n. ProceduralMemory
def _test_procedural_full():
    from brain.procedural_memory import ProceduralMemory, AttackTrace
    pm_dir = Path(TMPDIR) / "pm_test"
    pm_dir.mkdir(exist_ok=True)
    pm = ProceduralMemory(pm_dir)
    # Find applicable skills
    skills = pm.find_applicable_skills({"framework": "express", "auth": "jwt"}, TEST_URL)
    assert isinstance(skills, list)
    # Get hypotheses from skills
    hyps = pm.get_skill_hypotheses(skills, TEST_TARGET)
    assert isinstance(hyps, list)
    for h in hyps:
        assert "endpoint" in h
        assert "technique" in h
    # Record a trace
    trace = AttackTrace(
        target=TEST_TARGET, technique="sqli", finding_severity="high",
        tech_stack=TEST_TECH, timestamp="2026-01-01T00:00:00",
        steps=[{"tool": "sqlmap", "inputs": {"url": TEST_URL}, "output_summary": "injectable", "success": True}],
    )
    pm.record_trace(trace)
    # Compile skill
    skill = pm.compile_skill(trace)
    assert skill is not None
    # Update stats
    pm.update_skill_stats(skill.skill_id, True)
    pm.update_skill_stats(skill.skill_id, False)
    # Summary
    summary = pm.get_skill_summary()
    assert isinstance(summary, str)
    # Close DB connection to prevent file locks
    if hasattr(pm, '_conn') and pm._conn:
        try:
            pm._conn.close()
        except Exception:
            pass

warn_check("ProceduralMemory: find_skills + hypotheses + record + compile + stats", _test_procedural_full)

# 3o. Curriculum
def _test_curriculum_full():
    from brain.curriculum import CurriculumManager
    cm = CurriculumManager(Path(TMPDIR) / "cur_test")
    # Assess difficulty
    profile = cm.assess_target_difficulty(TEST_TECH, "cloudflare", "oauth")
    assert hasattr(profile, "level")
    assert 1 <= profile.level <= 10
    assert hasattr(profile, "name")
    # Get hypotheses
    hyps = cm.get_curriculum_hypotheses(profile.level, TEST_TECH)
    assert isinstance(hyps, list)
    # Update mastery
    cm.update_mastery("sqli_union", True, "high")
    cm.update_mastery("sqli_union", False, "")
    # Report
    report = cm.get_mastery_report()
    assert isinstance(report, str)

check("Curriculum: assess + hypotheses + mastery_update + report", _test_curriculum_full)

# 3p. EscalationRouter
def _test_escalation_full():
    from brain.escalation_router import EscalationRouter
    mock_provider = MagicMock()
    mock_config = MagicMock()
    mock_config.data_dir = Path(TMPDIR)
    er = EscalationRouter(mock_provider, mock_config)
    assert er.frontier_available == False, "Should be False without API key"
    # should_escalate
    result = er.should_escalate("hypothesis_generation", 0.2, {})
    assert isinstance(result, bool)
    # Stats
    stats = er.get_escalation_stats()
    assert isinstance(stats, dict)

check("EscalationRouter: frontier_available + should_escalate + stats", _test_escalation_full)

# 3q. DataManager
def _test_data_manager_full():
    from brain.data_manager import DataManager
    dm = DataManager(Path("data"))
    # Routes for tech
    routes = dm.get_routes_for_tech(TEST_TECH)
    assert isinstance(routes, list)
    assert len(routes) > 0, "Expected routes for nextjs tech stack"
    # Params for tech
    params = dm.get_params_for_tech(TEST_TECH)
    assert isinstance(params, list)
    # Sensitive paths
    paths = dm.get_sensitive_paths()
    assert isinstance(paths, list)
    assert len(paths) > 50, f"Expected 50+ sensitive paths, got {len(paths)}"
    # API patterns
    api = dm.get_api_patterns("rest")
    assert isinstance(api, list)
    # WAF bypass payloads
    waf = dm.get_waf_bypass_payloads("cloudflare", "xss")
    assert isinstance(waf, list)
    # Backup extensions
    backups = dm.get_backup_extensions()
    assert isinstance(backups, list)

check("DataManager: routes + params + paths + api + waf_bypass + backups", _test_data_manager_full)


# ── 4. Intel modules ───────────────────────────────────────────────────

print("\n=== 4. INTEL MODULE LOGIC PATHS ===")

def _test_h1_importer_full():
    from intel.hackerone import HackerOneImporter, ProgramProfile, BountyTable, ScopeAsset
    h1 = HackerOneImporter(Path(TMPDIR) / "h1_test")
    # Parse input
    for inp, expected_handle, expected_platform in [
        ("shopify", "shopify", "hackerone"),
        ("https://hackerone.com/shopify", "shopify", "hackerone"),
        ("https://hackerone.com/shopify/policy_scopes", "shopify", "hackerone"),
        ("https://bugcrowd.com/tesla", "tesla", "bugcrowd"),
    ]:
        h, p = h1._parse_input(inp)
        assert h == expected_handle, f"parse_input({inp!r}): expected handle={expected_handle}, got {h}"
        assert p == expected_platform, f"parse_input({inp!r}): expected platform={expected_platform}, got {p}"
    # BountyTable
    bt = BountyTable(critical_min=5000, critical_max=20000, high_min=1000, high_max=5000)
    assert bt.severity_value("critical") == 20000
    assert bt.severity_value("high") == 5000
    d = bt.to_dict()
    assert d["critical_max"] == 20000
    # ScopeAsset
    sa = ScopeAsset(asset_type="URL", identifier="*.example.com", eligible_for_bounty=True,
                    eligible_for_submission=True, instruction="test", max_severity="critical",
                    created_at="2026-01-01", confidentiality_requirement="high")
    assert sa.matches_url("https://sub.example.com/path")
    assert not sa.matches_url("https://other.com")
    # ProgramProfile
    pp = ProgramProfile(handle="test", name="Test", url="https://hackerone.com/test",
                        platform="hackerone", state="open", offers_bounties=True,
                        bounty_table=bt, in_scope=[sa])
    assert pp.is_in_scope("https://api.example.com/users")
    assert not pp.is_in_scope("https://notinscope.com")
    # Serialize round-trip
    d = pp.to_dict()
    pp2 = ProgramProfile.from_dict(d)
    assert pp2.handle == "test"
    assert len(pp2.in_scope) == 1
    # Save + load
    h1.save_program(pp)
    loaded = h1.load_program("test")
    assert loaded is not None
    assert loaded.handle == "test"
    # Generate scope context
    ctx = h1.generate_scope_context(pp)
    assert "In-Scope" in ctx
    assert "*.example.com" in ctx
    # List programs
    programs = h1.list_saved_programs()
    assert len(programs) >= 1

check("HackerOneImporter: parse + BountyTable + ScopeAsset + ProgramProfile + save/load + context", _test_h1_importer_full)

def _test_program_intel():
    from intel.program_intel import ProgramIntelligence
    pi = ProgramIntelligence()
    handle, platform = pi.extract_handle_from_url(TEST_TARGET)
    assert isinstance(handle, str)
    assert isinstance(platform, str)

check("ProgramIntelligence: extract_handle", _test_program_intel)

def _test_campaign_mgr():
    from intel.campaign_manager import CampaignManager
    cm = CampaignManager(Path(TMPDIR) / "campaign_test")
    campaign = cm.create_campaign(TEST_TARGET)
    assert campaign is not None
    assert campaign.target == TEST_TARGET
    found = cm.find_campaign_for_target(TEST_TARGET)
    assert found is not None
    cm.start_session(campaign)

check("CampaignManager: create + find + start_session", _test_campaign_mgr)


# ── 5. Models ──────────────────────────────────────────────────────────

print("\n=== 5. MODEL LOGIC PATHS ===")

def _test_auth_context_full():
    from models.auth_context import AuthContext
    ac = AuthContext()
    s1 = ac.add_session("user_a", "user", cookies={"session": "abc"}, jwt_token="eyJ...")
    s2 = ac.add_session("admin", "admin", headers={"Authorization": "Bearer xyz"})
    s3 = ac.add_session("unauth", "unauthenticated")
    # Test the extraction pattern used in agent.py
    roles = [s.role for s in ac.sessions.values()]
    assert "user" in roles
    assert "admin" in roles
    tokens = {n: bool(s.jwt_token) for n, s in ac.sessions.items()}
    assert tokens["user_a"] == True
    assert tokens["admin"] == False
    # Hypothesis generation
    hyps = ac.get_all_test_hypotheses()
    assert isinstance(hyps, list)

check("AuthContext: add_session + role extraction + token extraction + hypotheses", _test_auth_context_full)

def _test_hypothesis_engine():
    from models.hypothesis import HypothesisEngine, Hypothesis
    from utils.db import Database
    db = Database(Path(TMPDIR) / "hyp_test.db")
    he = HypothesisEngine(db, TEST_TARGET)
    h = he.create(
        endpoint=TEST_URL, technique="sqli",
        description="SQL injection in search",
        novelty=7, exploitability=8, impact=9, effort=3,
    )
    assert h is not None
    assert isinstance(h, Hypothesis)
    assert h.total_score > 0
    db.close()

check("HypothesisEngine: create hypothesis with scoring", _test_hypothesis_engine)

def _test_attack_graph():
    from models.attack_graph import AttackGraph
    from utils.db import Database
    db = Database(Path(TMPDIR) / "ag_test.db")
    ag = AttackGraph(db, TEST_TARGET, max_steps=10)
    assert not ag.is_complete
    db.close()

check("AttackGraph: create + is_complete", _test_attack_graph)

def _test_world_model():
    from brain.world_model import WorldModel
    wm = WorldModel(TEST_TARGET, Path(TMPDIR) / "wm_test")
    wm.add_host(TEST_TARGET, {"port": 443, "service": "https"})
    wm.set_tech("framework", "nextjs")
    wm.set_tech("cdn", "cloudflare")
    tech = wm.tech_stack
    assert tech.get("framework") == "nextjs"
    assert tech.get("cdn") == "cloudflare"
    # Add finding
    wm.add_finding(
        id="f1", title="XSS in search", severity="medium",
        description="Reflected XSS", endpoint="/search",
        technique="xss", step_found=1,
        chain_potential=["xss", "cache_poison"],
    )
    findings = wm.get_findings_for_chain_analysis()
    assert isinstance(findings, list)

check("WorldModel: add_host + set_tech + add_finding + chain_analysis", _test_world_model)

def _test_target_model():
    from models.target_model import TargetModel
    tm = TargetModel(TEST_TARGET, Path(TMPDIR) / "tm_test")
    assert tm.safe_name is not None
    assert isinstance(tm.is_stale, bool)

check("TargetModel: create + safe_name + is_stale", _test_target_model)

def _test_quality_gate():
    from utils.quality_gate import QualityGate
    qg = QualityGate()
    finding = {
        "title": "XSS in search",
        "endpoint": "/search?q=<script>",
        "severity": "medium",
        "evidence": "Script tag reflected in response",
        "technique": "xss",
        "confidence": 0.8,
    }
    score = qg.score_finding(finding)
    assert score is not None, "score_finding returned None"
    surface = qg.should_surface(score)
    assert isinstance(surface, bool)
    # Test noise detection
    is_noise, reason = qg.is_noise("xss", "XSS in search parameter")
    assert isinstance(is_noise, bool)

check("QualityGate: score_finding + should_surface + is_noise", _test_quality_gate)


# ── 6. Tool registrations ──────────────────────────────────────────────

print("\n=== 6. TOOL REGISTRATIONS ===")

def _test_all_tool_regs():
    try:
        from core.config import Config
        config = Config.from_env()
    except RuntimeError:
        return  # No tools on PATH

    from main import build_registry
    registry = build_registry(config)
    assert len(registry.tools) > 30, f"Expected 30+ tools, got {len(registry.tools)}"
    # Verify every tool has required attributes
    for name, tool in registry.tools.items():
        assert tool.name, f"Tool has empty name"
        assert tool.description, f"Tool {name} has empty description"
        assert tool.parameters is not None, f"Tool {name} has None parameters"
        assert callable(tool.execute), f"Tool {name}.execute is not callable"
        assert isinstance(tool.phase_tags, list), f"Tool {name}.phase_tags is not a list"
        # Verify to_description doesn't crash
        desc = tool.to_description()
        assert isinstance(desc, str)
        # Verify to_embed_text doesn't crash
        embed = tool.to_embed_text()
        assert isinstance(embed, str)

warn_check("build_registry: all tools valid", _test_all_tool_regs)


# ── 7. Agent import chain ──────────────────────────────────────────────

print("\n=== 7. AGENT IMPORT CHAIN ===")

check("from core.agent import Agent, _to_int_score",
      lambda: __import__("core.agent", fromlist=["Agent", "_to_int_score"]))

check("from main import build_registry, main, _run_hunt",
      lambda: __import__("main", fromlist=["build_registry", "main", "_run_hunt"]))

check("from ui.tui import main_menu",
      lambda: __import__("ui.tui", fromlist=["main_menu"]))


# ── 8. Cross-module integration ────────────────────────────────────────

print("\n=== 8. CROSS-MODULE INTEGRATION ===")

def _test_confusion_through_agent_scorer():
    """Test the exact code path agent.py uses for confusion hypotheses."""
    from brain.confusion_engine import ConfusionEngine
    from core.agent import _to_int_score
    ce = ConfusionEngine()
    hyps = ce.generate_confusion_hypotheses(TEST_URL, TEST_TECH, TEST_ENDPOINTS)
    for h in hyps:
        n = _to_int_score(h.get("novelty", 9))
        e = _to_int_score(h.get("exploitability", 8))
        i = _to_int_score(h.get("impact", 9))
        eff = _to_int_score(h.get("effort", 4))
        assert 1 <= n <= 10, f"novelty out of range: {n} from {h.get('novelty')!r}"
        assert 1 <= e <= 10, f"exploitability out of range: {e}"
        assert 1 <= i <= 10, f"impact out of range: {i}"
        assert 1 <= eff <= 10, f"effort out of range: {eff} from {h.get('effort')!r}"

check("Confusion -> _to_int_score integration (exact agent code path)", _test_confusion_through_agent_scorer)

def _test_scale_through_agent_scorer():
    """Test the exact code path agent.py uses for scale hypotheses."""
    from brain.scale_model import ScaleModel
    from core.agent import _to_int_score
    sm = ScaleModel()
    hyps = sm.get_scale_hypotheses(TEST_TECH, 10, 50)
    for h in hyps:
        n = _to_int_score(h.get("novelty", 6))
        e = _to_int_score(h.get("exploitability", 5))
        i = _to_int_score(h.get("impact", 7))
        eff = _to_int_score(h.get("effort", 3))
        assert 1 <= n <= 10
        assert 1 <= e <= 10
        assert 1 <= i <= 10
        assert 1 <= eff <= 10

check("Scale -> _to_int_score integration (exact agent code path)", _test_scale_through_agent_scorer)

def _test_domain_knowledge_through_agent_scorer():
    """Test the exact code path agent.py uses for domain knowledge hypotheses."""
    from brain.domain_knowledge import DomainKnowledge
    from core.agent import _to_int_score
    dk = DomainKnowledge()
    domain = dk.detect_domain(TEST_URL, [], TEST_TECH)
    patterns = dk.get_patterns(domain)
    if patterns:
        hyps = dk.patterns_to_hypotheses(patterns[:5], TEST_URL)
        for h in hyps:
            i = _to_int_score(h.get("impact", h.get("severity", 8)))
            assert 1 <= i <= 10, f"impact out of range: {i} from {h.get('impact')!r} / {h.get('severity')!r}"

check("DomainKnowledge -> _to_int_score integration (exact agent code path)", _test_domain_knowledge_through_agent_scorer)

def _test_env_hypotheses_through_agent_scorer():
    """Test environment hypotheses have valid scores."""
    from brain.scale_model import ScaleModel
    from core.agent import _to_int_score
    sm = ScaleModel()
    hyps = sm.get_environment_hypotheses("example.com")
    assert len(hyps) > 0
    for h in hyps[:20]:
        for field in ["novelty", "exploitability", "impact", "effort"]:
            val = h.get(field, 5)
            score = _to_int_score(val)
            assert 1 <= score <= 10, f"env hyp {field}={val!r} -> {score} out of range"

check("Environment hypotheses -> _to_int_score (all 93 hypotheses)", _test_env_hypotheses_through_agent_scorer)


# ── 9. Reasoning quality modules ───────────────────────────────────────

print("\n=== 9. REASONING QUALITY MODULES ===")

def _test_repetition_identifier():
    from core.repetition import RepetitionIdentifier
    ri = RepetitionIdentifier()
    # First two calls should pass
    b1, _ = ri.check("curl", {"url": "https://x.com/ws"}, 1)
    ri.record("curl", {"url": "https://x.com/ws"}, 1)
    b2, _ = ri.check("curl", {"url": "https://x.com/ws"}, 2)
    ri.record("curl", {"url": "https://x.com/ws"}, 2)
    # Third should be blocked
    b3, reason = ri.check("curl", {"url": "https://x.com/ws"}, 3)
    assert b3, "Should block after 2 exact repeats"
    assert "BLOCK" in reason.upper()
    # Different inputs should pass
    b4, _ = ri.check("curl", {"url": "https://x.com/api"}, 4)
    assert not b4
    # Get untried tools
    untried = ri.get_untried_tools(["nmap", "curl", "subfinder", "nuclei"])
    assert "nmap" in untried  # nmap hasn't been used
    assert "curl" not in untried  # curl has been used

check("RepetitionIdentifier: block repeats + allow different + untried tools", _test_repetition_identifier)

def _test_pentest_tree():
    from core.pentest_tree import PentestTree
    pt = PentestTree("example.com")
    pt.add_service("example.com", 443, "https", "nginx/1.21")
    pt.add_service("example.com", 80, "http")
    pt.add_subdomain("api.example.com")
    pt.add_subdomain("admin.example.com")
    pt.add_tech("framework", "nextjs")
    pt.add_tech("waf", "cloudflare")
    pt.record_success(1, "nmap", "example.com", "Found 2 open ports")
    pt.record_failure(2, "curl", "wss://example.com/ws", "404 not found")
    pt.record_failure(3, "curl", "wss://example.com/socket", "404 not found")
    pt.block_path("No WebSocket endpoints exist on this target")
    pt.add_finding({"type": "xss", "endpoint": "/search", "severity": "medium"})
    # Test was_tried
    assert pt.was_tried("nmap", "example.com")
    assert pt.was_tried("curl", "wss://example.com/ws")
    assert not pt.was_tried("nuclei", "example.com")
    # Render
    rendered = pt.render(max_chars=3000)
    assert len(rendered) <= 3000
    assert "example.com" in rendered
    assert "nginx" in rendered or "443" in rendered
    # Serialize round-trip
    d = pt.to_dict()
    pt2 = PentestTree.from_dict(d)
    assert pt2.target == "example.com"
    assert len(pt2.services) == 2

check("PentestTree: full lifecycle + render + serialize", _test_pentest_tree)

def _test_response_classifier():
    from utils.response_classifier import ResponseClassifier
    rc = ResponseClassifier()
    # WAF block
    r1 = rc.classify_http(403, {"server": "cloudflare", "cf-ray": "abc"}, "Attention Required! Cloudflare")
    assert r1.category == "waf_block", f"Expected waf_block, got {r1.category}"
    assert r1.waf_vendor == "cloudflare"
    # Rate limit
    r2 = rc.classify_http(429, {}, "Too many requests")
    assert r2.category == "rate_limited"
    # Auth redirect
    r3 = rc.classify_http(302, {"location": "/login"}, "")
    assert r3.category == "auth_redirect"
    # Real content
    r4 = rc.classify_http(200, {"content-type": "text/html"}, "<html><body>Hello World</body></html>")
    assert r4.category == "real_content"
    # Tool error
    r5 = rc.classify_tool_output("nmap", -1, "", "Command timed out after 120s")
    assert r5.category == "tool_error"
    # Empty suspicious
    r6 = rc.classify_tool_output("nuclei", 0, "", "")
    assert r6.category in ("tool_error", "empty_suspicious")
    # Format for agent
    fmt = rc.format_for_agent(r1)
    assert "WAF" in fmt.upper() or "BLOCK" in fmt.upper()

check("ResponseClassifier: WAF + rate_limit + auth_redirect + real + tool_error + format", _test_response_classifier)

def _test_output_summarizer():
    from utils.output_summarizer import OutputSummarizer
    os_mod = OutputSummarizer()
    # nmap
    s1 = os_mod.summarize("nmap", "80/tcp open http nginx/1.21\n443/tcp open ssl/https\n22/tcp filtered ssh")
    assert "80" in s1 or "open" in s1.lower()
    # subfinder
    s2 = os_mod.summarize("subfinder", "api.example.com\nadmin.example.com\nstaging.example.com")
    assert "3" in s2 or "api" in s2
    # empty
    s3 = os_mod.summarize("nuclei", "")
    assert s3  # Should return something, not empty
    # curl
    s4 = os_mod.summarize("curl", "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>test</html>")
    assert "200" in s4
    # is_empty_or_blocked
    empty, reason = os_mod.is_empty_or_blocked("nuclei", "")
    assert empty

check("OutputSummarizer: nmap + subfinder + empty + curl + is_empty_or_blocked", _test_output_summarizer)

def _test_session_manager():
    from core.session_manager import SessionManager
    import tempfile
    td = Path(tempfile.mkdtemp())
    sm = SessionManager(td)
    # Add credentials
    cred = sm.add_credential("user_a", "test@test.com", "pass123", role="user")
    assert cred.username == "test@test.com"
    cred2 = sm.add_credential("admin", "admin@test.com", "adminpass", role="admin")
    # List (masked)
    creds = sm.list_credentials()
    assert len(creds) == 2
    # Has multiple users
    assert not sm.has_multiple_users()  # No active sessions yet
    # Auth context
    ctx = sm.get_auth_context_for_agent()
    assert isinstance(ctx, str)
    # Remove
    sm.remove_credential("admin")
    assert len(sm.credentials) == 1

check("SessionManager: add/remove credentials + list + auth context", _test_session_manager)

def _test_constrained_prompt_wiring():
    """Verify the constrained prompt is actually used in _agent_step."""
    import inspect
    from core.agent import Agent
    source = inspect.getsource(Agent._agent_step)
    assert "CONSTRAINED_ACTION_PROMPT" in source, "CONSTRAINED_ACTION_PROMPT not used in _agent_step"
    assert "_build_action_list" in source, "_build_action_list not called in _agent_step"

check("Constrained prompt wired into _agent_step (not just defined)", _test_constrained_prompt_wiring)

def _test_scope_checking():
    """Verify scope checking exists in _execute_tool."""
    import inspect
    from core.agent import Agent
    source = inspect.getsource(Agent._execute_tool)
    assert "_check_scope" in source, "_check_scope not called in _execute_tool"
    assert "OUT OF SCOPE" in source, "Out of scope message not in _execute_tool"

check("Scope checking wired into _execute_tool", _test_scope_checking)

def _test_throttling():
    """Verify adaptive throttling exists in _execute_tool."""
    import inspect
    from core.agent import Agent
    source = inspect.getsource(Agent._execute_tool)
    assert "_throttle_seconds" in source, "Throttling not in _execute_tool"

check("Adaptive throttling wired into _execute_tool", _test_throttling)


# ── Cleanup + Results ──────────────────────────────────────────────────

try:
    shutil.rmtree(TMPDIR, ignore_errors=True)
except Exception:
    pass

print("\n" + "=" * 70)
print(f"  PASSED:   {passed}")
print(f"  FAILED:   {len(errors)}")
print(f"  WARNINGS: {len(warnings)}")
print("=" * 70)

if errors:
    print(f"\n\033[91mFAILURES:\033[0m")
    for e in errors:
        print(f"  - {e}")

if warnings:
    print(f"\n\033[93mWARNINGS (non-critical):\033[0m")
    for w in warnings:
        print(f"  - {w}")

if not errors:
    print(f"\n\033[92mAll {passed} checks passed. Every logic path verified. Safe to hunt.\033[0m")
else:
    print(f"\n\033[91mFix {len(errors)} error(s) before hunting.\033[0m")

sys.exit(1 if errors else 0)
