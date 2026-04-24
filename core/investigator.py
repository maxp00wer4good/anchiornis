from __future__ import annotations

from models import Observable, InvestigationState, enable_relation_debug
from core.state_ops import ensure_observable, set_current
from models.projection import project_normalized_intel
from engine.inference import run_inference
from engine.rules.loader import load_rules

from connectors.virustotal import VirusTotalClient, normalize_vt
from connectors.abuseipdb import AbuseIPDBClient, normalize_abuse
from connectors.urlscan import URLScanClient, normalize_urlscan
from core.helpers import detect_type, resolve_ip, ioc_key, step_key, extract_domain


def _shared_state(local_state: InvestigationState, parent_state: InvestigationState | None) -> InvestigationState:
    return parent_state if parent_state is not None else local_state


def _project_abuse_once(
    local_state: InvestigationState,
    shared_state: InvestigationState,
    abuse: AbuseIPDBClient,
    ip: str,
) -> None:
    obs_key = ioc_key(ip, "ip")
    exec_key = step_key("abuseipdb", ip, "ip")

    cached = shared_state.evidence.get(obs_key, {}).get("abuseipdb")
    if exec_key in getattr(shared_state, "executed_steps", set()) and cached is not None:
        project_normalized_intel(local_state, normalize_abuse("ip", ip, cached))
        return

    abuse_result = abuse.get_ip(ip)
    if "error" in abuse_result:
        return

    shared_state.executed_steps.add(exec_key)
    shared_state.evidence.setdefault(obs_key, {})
    shared_state.evidence[obs_key]["abuseipdb"] = abuse_result

    project_normalized_intel(local_state, normalize_abuse("ip", ip, abuse_result))


def analyze_url(
    state: InvestigationState,
    vt: VirusTotalClient,
    abuse: AbuseIPDBClient,
    urlscan: URLScanClient,
    verbose: bool = False,
    parent_state: InvestigationState | None = None,
) -> None:
    del verbose
    value = state.input_value
    shared = _shared_state(state, parent_state)

    vt_result = vt.get_url(value)
    if "error" not in vt_result:
        project_normalized_intel(state, normalize_vt("url", value, vt_result))

    resolved_ip = None

    us_result = urlscan.scan_url(value)
    if "error" not in us_result:
        project_normalized_intel(state, normalize_urlscan("url", value, us_result))
        resolved_ip = us_result.get("ip")

    if not resolved_ip:
        domain = extract_domain(value)
        if domain:
            print(f"[graph] abuseipdb fallback: resolving domain from url -> {domain}")
            resolved_ip = resolve_ip(domain)
            if resolved_ip:
                print(f"[graph] abuseipdb fallback: resolved {domain} -> {resolved_ip}")
            else:
                print(f"[graph] abuseipdb fallback: no IP resolved for {domain}")

    if resolved_ip:
        _project_abuse_once(state, shared, abuse, resolved_ip)


def analyze_domain(
    state: InvestigationState,
    vt: VirusTotalClient,
    abuse: AbuseIPDBClient,
    verbose: bool = False,
    parent_state: InvestigationState | None = None,
) -> None:
    del verbose
    value = state.input_value
    shared = _shared_state(state, parent_state)

    vt_result = vt.get_domain(value)
    if "error" not in vt_result:
        project_normalized_intel(state, normalize_vt("domain", value, vt_result))

    ip = resolve_ip(value)
    if ip:
        _project_abuse_once(state, shared, abuse, ip)


def analyze_ip(
    state: InvestigationState,
    vt: VirusTotalClient,
    abuse: AbuseIPDBClient,
    verbose: bool = False,
    parent_state: InvestigationState | None = None,
) -> None:
    del verbose
    value = state.input_value
    shared = _shared_state(state, parent_state)

    vt_result = vt.get_ip(value)
    if "error" not in vt_result:
        project_normalized_intel(state, normalize_vt("ip", value, vt_result))

    _project_abuse_once(state, shared, abuse, value)


def analyze_hash(
    state: InvestigationState,
    vt: VirusTotalClient,
    verbose: bool = False,
) -> None:
    del verbose
    value = state.input_value

    vt_result = vt.get_hash(value)
    if "error" not in vt_result:
        project_normalized_intel(state, normalize_vt(state.input_type, value, vt_result))


def investigate(
    value: str,
    vt: VirusTotalClient,
    abuse: AbuseIPDBClient,
    urlscan: URLScanClient,
    input_type: str | None = None,
    verbose: bool = False,
    parent_state: InvestigationState | None = None,
) -> InvestigationState:
    value = value.strip()
    detected_type = input_type or detect_type(value)

    enable_relation_debug(verbose)

    state = InvestigationState(
        input_value=value,
        input_type=detected_type,
    )

    root = Observable(value=value, kind=detected_type, source="seed")
    set_current(state, root)
    ensure_observable(state, root)

    if detected_type == "url":
        analyze_url(state, vt, abuse, urlscan, verbose, parent_state=parent_state)
    elif detected_type == "domain":
        analyze_domain(state, vt, abuse, verbose, parent_state=parent_state)
    elif detected_type == "ip":
        analyze_ip(state, vt, abuse, verbose, parent_state=parent_state)
    elif detected_type in ("md5", "sha1", "sha256", "hash"):
        analyze_hash(state, vt, verbose)
    else:
        raise ValueError(f"Tipo no soportado: {detected_type}")

    rules = load_rules()
    derived = run_inference(state.relations, rules)

    existing = {(r.src, r.rel, r.dst) for r in state.relations}
    new_relations = [r for r in derived if (r.src, r.rel, r.dst) not in existing]
    state.relations.extend(new_relations)

    return state