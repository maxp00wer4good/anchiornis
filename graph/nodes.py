from __future__ import annotations

"""LangGraph nodes for the IOC investigation workflow.

Design philosophy:
- deterministic code collects and merges facts
- the LLM is used sparingly for semantic decisions
- the workflow proceeds in phases instead of treating every pivot equally
"""

from typing import Any, Dict
from datetime import UTC, datetime
from urllib.parse import urlparse, parse_qsl

from core.clients import build_clients
from core.expansion import expand_pivot
from core.investigator import investigate
from core.pivots import extract_candidate_pivots
from core.semantic_llm import (
    build_candidate_payload,
    build_final_summary_with_llm_payload,
    build_summary_context,
    choose_pivot_with_llm,
    decide_continue_with_llm,
)
from graph.state import InvestigationGraphState
from core.helpers import format_relation_brief, ioc_key, semantic_relation_key


def _log_section(title: str, subtitle: str | None = None) -> None:
    line = f"[graph] ===== {title} ====="
    if subtitle:
        line = f"{line} {subtitle}"
    print(f"\n{line}")


def _print_relations(title: str, relations, limit: int | None = None) -> None:
    print(title)
    items = relations if limit is None else relations[:limit]
    for rel in items:
        print(f"[graph]   - {format_relation_brief(rel)}")
    if limit is not None and len(relations) > limit:
        print(f"[graph]   ... {len(relations) - limit} more")





def _append_llm_trace(state: InvestigationGraphState, trace_payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Append a full LLM prompt/output record to the state-level trace."""
    traces = list(state.get("llm_trace", []) or [])
    if not trace_payload:
        return traces
    traces.append(
        {
            "index": len(traces) + 1,
            "iteration": state.get("iteration"),
            "phase": state.get("investigation_phase"),
            **trace_payload,
        }
    )
    return traces

def _append_trace_event(
    state: InvestigationGraphState,
    stage: str,
    details: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Append a compact audit event to the workflow trace."""
    events = list(state.get("execution_trace", []) or [])
    events.append(
        {
            "timestamp_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "iteration": state.get("iteration"),
            "phase": state.get("investigation_phase"),
            "stage": stage,
            "details": details or {},
        }
    )
    return events





def _safe_trace_value(value: Any) -> Any:
    """Return a JSON-friendly value for execution trace details."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _safe_trace_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_trace_value(v) for v in value]
    if isinstance(value, set):
        return sorted(_safe_trace_value(v) for v in value)
    if hasattr(value, "model_dump"):
        return _safe_trace_value(value.model_dump())
    if hasattr(value, "dict"):
        return _safe_trace_value(value.dict())
    return str(value)


def _relation_trace_key(rel: Any) -> tuple[str, str, str, str]:
    """Stable identity for relation deltas, including producer/source."""
    if isinstance(rel, dict):
        return (
            str(rel.get("src", "")),
            str(rel.get("rel", "")),
            str(rel.get("dst", "")),
            str(rel.get("source", "")),
        )
    return (
        str(getattr(rel, "src", "")),
        str(getattr(rel, "rel", "")),
        str(getattr(rel, "dst", "")),
        str(getattr(rel, "source", "")),
    )


def _serialize_relation_for_trace(rel: Any) -> dict[str, Any]:
    """Serialize a Relation-like object for step-level audit events."""
    if isinstance(rel, dict):
        metadata = _safe_trace_value(rel.get("metadata", {}) or {})
        source = str(rel.get("source", ""))
        tier = "derived" if source == "rules_engine" else "direct"
        if isinstance(metadata, dict):
            tier = str(metadata.get("relation_tier") or tier)
        return {
            "id": rel.get("id"),
            "tier": tier,
            "source": source,
            "src": rel.get("src"),
            "rel": rel.get("rel"),
            "dst": rel.get("dst"),
            "metadata": metadata,
        }

    metadata = _safe_trace_value(getattr(rel, "metadata", {}) or {})
    source = str(getattr(rel, "source", ""))
    tier = "derived" if source == "rules_engine" else "direct"
    if isinstance(metadata, dict):
        tier = str(metadata.get("relation_tier") or tier)

    return {
        "id": getattr(rel, "id", None),
        "tier": tier,
        "source": source,
        "src": getattr(rel, "src", None),
        "rel": getattr(rel, "rel", None),
        "dst": getattr(rel, "dst", None),
        "metadata": metadata,
    }


def _serialize_observable_for_trace(key: str, obs: Any) -> dict[str, Any]:
    """Serialize an observable entry for step-level audit events."""
    if isinstance(obs, dict):
        kind = obs.get("kind") or obs.get("type") or key.split(":", 1)[0]
        value = obs.get("value") or (key.split(":", 1)[1] if ":" in key else key)
        source = obs.get("source")
        data = obs.get("data", {})
    else:
        kind = getattr(obs, "kind", None) or key.split(":", 1)[0]
        value = getattr(obs, "value", None) or (key.split(":", 1)[1] if ":" in key else key)
        source = getattr(obs, "source", None)
        data = getattr(obs, "data", {})

    return {
        "key": key,
        "kind": kind,
        "value": value,
        "source": source,
        "data": _safe_trace_value(data or {}),
    }


def _evidence_provider_keys(evidence: dict[str, Any]) -> set[tuple[str, str]]:
    """Return observable/provider pairs so provider-level evidence deltas are visible."""
    keys: set[tuple[str, str]] = set()
    for obs_key, payload in (evidence or {}).items():
        if isinstance(payload, dict) and payload:
            for provider in payload.keys():
                keys.add((str(obs_key), str(provider)))
        else:
            keys.add((str(obs_key), "__value__"))
    return keys


def _serialize_evidence_delta(
    evidence: dict[str, Any],
    new_provider_keys: set[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Serialize provider-level evidence that appeared during this step."""
    items: list[dict[str, Any]] = []
    for obs_key, provider in sorted(new_provider_keys):
        payload = (evidence or {}).get(obs_key)
        if provider == "__value__":
            value = payload
        elif isinstance(payload, dict):
            value = payload.get(provider)
        else:
            value = None
        items.append(
            {
                "observable_key": obs_key,
                "provider": provider,
                "payload": _safe_trace_value(value),
            }
        )
    return items


def _relation_delta_summary(new_relations: list[Any]) -> dict[str, Any]:
    serialized = [_serialize_relation_for_trace(rel) for rel in new_relations]
    direct = [rel for rel in serialized if rel.get("tier") != "derived"]
    derived = [rel for rel in serialized if rel.get("tier") == "derived"]
    rules_fired = sorted(
        {
            str((rel.get("metadata") or {}).get("rule_id"))
            for rel in derived
            if isinstance(rel.get("metadata"), dict) and (rel.get("metadata") or {}).get("rule_id")
        }
    )
    return {
        "added_relations_count": len(serialized),
        "added_relations": serialized,
        "added_direct_relations_count": len(direct),
        "added_derived_relations_count": len(derived),
        "rules_fired": rules_fired,
    }


def _relation_semantic_stats(relations) -> dict[str, int]:
    raw_count = len(relations)
    semantic_keys = {semantic_relation_key(r.src, r.rel, r.dst) for r in relations}
    semantic_count = len(semantic_keys)
    redundant_count = raw_count - semantic_count
    return {
        "raw_count": raw_count,
        "semantic_count": semantic_count,
        "redundant_count": redundant_count,
    }


def _pivot_group(pivot: Dict[str, Any]) -> str:
    rel = pivot.get("source_relation", "")

    if rel in {"final_url", "final_domain", "resolves_to"}:
        return "landing_chain"
    if rel in {"observed_domain", "observed_ip", "observed_url"}:
        return "observed_chain"
    if rel in {"content_sha256", "observed_hash", "meta_identifier"}:
        return "artifact_chain"
    return rel or "other"


def _pivot_family(kind: str, value: str) -> str:
    value = (value or "").strip().lower()
    if kind == "domain":
        parts = value.split(".")
        if len(parts) >= 2:
            return f"domain:{'.'.join(parts[-2:])}"
    if kind == "url":
        from urllib.parse import urlparse
        host = (urlparse(value).hostname or "").lower()
        parts = host.split(".")
        if len(parts) >= 2:
            return f"url:{'.'.join(parts[-2:])}"
    if kind == "ip":
        octets = value.split(".")
        if len(octets) == 4:
            return f"ip:{'.'.join(octets[:3])}"
    return f"{kind}:{value}"


def _pivot_role(pivot: Dict[str, Any]) -> str:
    rel = pivot.get("source_relation", "")
    if rel in {"final_domain", "final_url", "resolves_to"}:
        return "core"
    if rel in {"observed_domain", "observed_ip", "observed_url"}:
        return "lateral"
    if rel in {"content_sha256", "observed_hash", "meta_identifier"}:
        return "artifact"
    return "secondary"

def _observable_provider_payload(merged, obs_key: str, provider: str) -> dict[str, Any]:
    evidence = getattr(merged, "evidence", {}) or {}
    payload = evidence.get(obs_key, {}) if isinstance(evidence.get(obs_key, {}), dict) else {}
    provider_payload = payload.get(provider, {}) if isinstance(payload, dict) else {}
    return provider_payload if isinstance(provider_payload, dict) else {}


def _family_from_value(value: str) -> str:
    clean = (value or "").strip().lower().rstrip('.')
    parts = clean.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return clean


def _same_registered_family(a: str, b: str) -> bool:
    return bool(a and b) and _family_from_value(a) == _family_from_value(b)


def _seed_key(state: InvestigationGraphState) -> str:
    return ioc_key(state['seed_value'], state['seed_type'])


def _seed_has_negative_signal(state: InvestigationGraphState) -> bool:
    merged = state.get('merged_state')
    if merged is None:
        return False
    seed_key = _seed_key(state)
    vt_payload = _observable_provider_payload(merged, seed_key, 'virustotal')
    malicious = int(vt_payload.get('malicious') or 0)
    suspicious = int(vt_payload.get('suspicious') or 0)
    if malicious > 0 or suspicious > 0:
        return True
    for rel in getattr(merged, 'relations', []) or []:
        if rel.src != seed_key:
            continue
        if rel.rel == 'has_vt_verdict' and rel.dst in {'verdict:malicious', 'verdict:suspicious'}:
            return True
        if rel.rel in {'has_certificate_divergence', 'has_consensus_signal', 'shows_parking_behavior'}:
            return True
    return False


def _url_query_count(value: str) -> int:
    try:
        return len(parse_qsl(urlparse(value).query, keep_blank_values=True))
    except Exception:
        return 0


def _observable_is_high_fanout_sink(state: InvestigationGraphState, obs_key: str) -> bool:
    merged = state.get('merged_state')
    if merged is None or not obs_key.startswith('url:'):
        return False
    if not _seed_has_negative_signal(state):
        return False

    urlscan_payload = _observable_provider_payload(merged, obs_key, 'urlscan')
    if not urlscan_payload:
        return False

    request_count = int(urlscan_payload.get('request_count') or 0)
    observed_domain_count = len(urlscan_payload.get('observed_domains') or [])
    observed_hash_count = len(urlscan_payload.get('observed_hashes') or [])
    final_domain = str(urlscan_payload.get('final_domain') or '').strip().lower()

    if request_count < 80 and observed_domain_count < 15 and observed_hash_count < 40:
        return False

    seed_domain = urlparse(state['seed_value']).hostname or state['seed_value']
    if final_domain and _same_registered_family(seed_domain, final_domain):
        return False

    vt_payload = _observable_provider_payload(merged, obs_key, 'virustotal')
    malicious = int(vt_payload.get('malicious') or 0)
    suspicious = int(vt_payload.get('suspicious') or 0)
    harmless = int(vt_payload.get('harmless') or 0)
    benign_like = (malicious == 0 and suspicious == 0) or harmless > 0

    if not benign_like and _url_query_count(obs_key.split(':', 1)[1]) < 3:
        return False

    return True


def _candidate_is_sink_context(state: InvestigationGraphState, pivot: Dict[str, Any]) -> bool:
    rel = pivot.get('source_relation', '')
    source_node = pivot.get('source_node', '')
    if rel in {'final_domain', 'final_url', 'resolves_to'}:
        source_node = source_node or _seed_key(state)
        return _observable_is_high_fanout_sink(state, source_node)
    if rel in {'observed_domain', 'observed_url', 'observed_ip', 'observed_hash'}:
        return _observable_is_high_fanout_sink(state, source_node)
    return False


def _impact_label(usefulness: int) -> str:
    if usefulness <= 0:
        return 'dead_end'
    if usefulness <= 8:
        return 'limited'
    if usefulness <= 20:
        return 'moderate'
    return 'high'


def _observable_type_breakdown(keys: set[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for key in keys:
        if ':' not in key:
            continue
        kind = key.split(':', 1)[0]
        counts[kind] = counts.get(kind, 0) + 1
    return dict(sorted(counts.items()))


def _core_characterization_complete(state: InvestigationGraphState) -> bool:
    history = state.get("pivot_history", []) or []
    explored = {item.get("source_relation") for item in history if item.get("expanded")}
    return {"resolves_to", "final_domain", "final_url"}.issubset(explored)


def _infer_phase(state: InvestigationGraphState) -> str:
    history = state.get("pivot_history", []) or []
    if not history:
        return "seed_characterization"

    if _core_characterization_complete(state):
        return "lateral_correlation"

    return "seed_characterization"


def _structural_select_next_pivot(state: InvestigationGraphState) -> dict[str, Any] | None:
    merged = state["merged_state"]
    if merged is None:
        return None

    processed = set(state["processed_pivots"])
    expanded = getattr(merged, "expanded_iocs", set()) or set()
    used_groups = set(state.get("used_pivot_groups", []))
    phase = state.get("investigation_phase", "seed_characterization")

    candidates = []
    for pivot in state["pending_pivots"]:
        key = ioc_key(pivot["value"], pivot["kind"])
        if key in processed or key in expanded:
            continue

        group = _pivot_group(pivot)
        role = _pivot_role(pivot)
        adjusted_score = pivot["score"]

        if group in used_groups:
            adjusted_score -= 15
        if pivot["source_relation"] == "observed_url":
            adjusted_score -= 5

        if phase == "seed_characterization":
            if role == "artifact":
                adjusted_score -= 40
            if role == "core":
                adjusted_score += 15
        elif phase == "lateral_correlation":
            if role == "artifact":
                adjusted_score -= 25
            if role == "lateral":
                adjusted_score += 10
            if pivot["source_relation"] == "final_url":
                adjusted_score -= 20

        candidates.append((adjusted_score, pivot))

    if not candidates:
        return None

    candidates.sort(key=lambda item: (-item[0], item[1]["kind"], item[1]["value"]))
    return candidates[0][1]


def _deterministic_continue_decision(state: InvestigationGraphState) -> tuple[str, str]:
    merged = state.get("merged_state")
    if merged is None:
        return "final_report", "No investigation state available."

    if not state.get("last_selected_pivot"):
        return "final_report", "No pivot was selected."

    if state["iteration"] >= state["max_iterations"]:
        return "final_report", "Safety iteration limit reached."

    pending = state.get("pending_pivots", []) or []
    processed = set(state.get("processed_pivots", []) or [])
    expanded = getattr(merged, "expanded_iocs", set()) or set()

    viable = []
    for pivot in pending:
        key = ioc_key(pivot["value"], pivot["kind"])
        if key not in processed and key not in expanded:
            viable.append(pivot)

    if not viable:
        return "final_report", "No viable pivots remain."

    if state.get("dead_end_count", 0) >= 2:
        return "final_report", "Too many dead-end pivots in a row."

    if state.get("stagnation_count", 0) >= 3:
        return "final_report", "The investigation appears saturated."

    return "correlate", "continue"


def _operational_llm_budget_remaining(state: InvestigationGraphState) -> int:
    budget = int(state.get("llm_operational_budget", state.get("llm_call_budget", 0)) or 0)
    used = int(state.get("llm_operational_calls_used", state.get("llm_calls_used", 0)) or 0)
    return max(0, budget - used)


def _consume_operational_llm_call(state: InvestigationGraphState) -> None:
    used = int(state.get("llm_operational_calls_used", state.get("llm_calls_used", 0)) or 0) + 1
    state["llm_operational_calls_used"] = used
    final_used = 1 if state.get("llm_final_summary_used") else 0
    state["llm_calls_used"] = used + final_used


def _can_use_final_summary_llm(state: InvestigationGraphState) -> bool:
    return bool(state.get("llm_final_summary_enabled", state.get("enable_llm_final_summary", False))) and not bool(state.get("llm_final_summary_used", False))


def _mark_final_summary_used(state: InvestigationGraphState) -> None:
    state["llm_final_summary_used"] = True
    op_used = int(state.get("llm_operational_calls_used", state.get("llm_calls_used", 0)) or 0)
    state["llm_calls_used"] = op_used + 1


def _should_use_llm_for_selection(state: InvestigationGraphState) -> bool:
    if _operational_llm_budget_remaining(state) <= 0:
        return False

    phase = state.get("investigation_phase", "seed_characterization")
    pending = state.get("pending_pivots", []) or []
    if len(pending) < 2:
        return False

    if phase == "seed_characterization" and state.get("iteration", 0) <= 3:
        return False

    top = pending[0].get("score", 0)
    second = pending[1].get("score", 0) if len(pending) > 1 else -999
    if phase == "seed_characterization" and (top - second) >= 15:
        return False

    return True


def _should_use_llm_for_continue(state: InvestigationGraphState) -> bool:
    if not state.get("enable_llm_continue", False):
        return False
    if _operational_llm_budget_remaining(state) <= 0:
        return False
    return state.get("investigation_phase") == "lateral_correlation"


def _should_use_llm_for_final_summary(state: InvestigationGraphState) -> bool:
    return _can_use_final_summary_llm(state)


def seed_intake(state: InvestigationGraphState) -> InvestigationGraphState:
    return {
        **state,
        "pending_pivots": [],
        "processed_pivots": [],
        "used_pivot_groups": [],
        "last_selected_pivot": None,
        "last_enrichment_result": None,
        "merged_state": None,
        "investigation_phase": "seed_characterization",
        "execution_trace": [],
        "llm_trace": [],
        "semantic_selection": None,
        "pivot_history": [],
        "stagnation_count": 0,
        "dead_end_count": 0,
        "stop_reason": "",
        "final_report": "",
        "iteration": 0,
        "llm_operational_calls_used": state.get("llm_operational_calls_used", 0),
        "llm_final_summary_used": False,
    }


def initial_enrichment(state: InvestigationGraphState) -> InvestigationGraphState:
    vt, abuse, urlscan = build_clients()

    _log_section("Seed Enrichment")
    print(f"[graph] Seed: {state['seed_type']} {state['seed_value']}")

    merged_state = investigate(
        value=state["seed_value"],
        input_type=state["seed_type"],
        vt=vt,
        abuse=abuse,
        urlscan=urlscan,
        verbose=False,
    )

    base_relations = [r for r in merged_state.relations if r.source != "rules_engine"]
    derived_relations = [r for r in merged_state.relations if r.source == "rules_engine"]

    base_stats = _relation_semantic_stats(base_relations)
    total_stats = _relation_semantic_stats(merged_state.relations)

    print(f"[graph] Base relations: {len(base_relations)} raw / {base_stats['semantic_count']} semantic")
    print(f"[graph] Derived relations: {len(derived_relations)}")
    print(f"[graph] Total relations: {len(merged_state.relations)} raw / {total_stats['semantic_count']} semantic")
    print(f"[graph] Semantic redundancy: {total_stats['redundant_count']}")
    print(f"[graph] Evidence items: {len(merged_state.evidence)}")

    if base_relations:
        _print_relations("[graph] Core observed relations:", base_relations, limit=12)

    if derived_relations:
        _print_relations("[graph] Derived findings:", derived_relations, limit=6)

    initial_relation_delta = _relation_delta_summary(list(merged_state.relations))
    initial_observables = [
        _serialize_observable_for_trace(key, obs)
        for key, obs in sorted((getattr(merged_state, "observables", {}) or {}).items())
    ]
    initial_evidence = _serialize_evidence_delta(
        getattr(merged_state, "evidence", {}) or {},
        _evidence_provider_keys(getattr(merged_state, "evidence", {}) or {}),
    )

    trace_events = _append_trace_event(
        state,
        "seed_enrichment_completed",
        {
            "seed": {"type": state["seed_type"], "value": state["seed_value"]},
            "base_relations": len(base_relations),
            "derived_relations": len(derived_relations),
            "semantic_relations": total_stats["semantic_count"],
            "semantic_redundancy": total_stats["redundant_count"],
            "evidence_items": len(merged_state.evidence),
            "derived_rules": sorted(
                {
                    r.metadata.get("rule_id")
                    for r in derived_relations
                    if r.metadata.get("rule_id")
                }
            ),
            # Explicit audit payload: this step starts from an empty graph,
            # so every observed relation/observable/evidence item is "new".
            "added_relations_count": initial_relation_delta["added_relations_count"],
            "added_relations": initial_relation_delta["added_relations"],
            "added_direct_relations_count": initial_relation_delta["added_direct_relations_count"],
            "added_derived_relations_count": initial_relation_delta["added_derived_relations_count"],
            "rules_fired": initial_relation_delta["rules_fired"],
            "added_observables_count": len(initial_observables),
            "added_observables": initial_observables,
            "added_evidence_count": len(initial_evidence),
            "added_evidence": initial_evidence,
        },
    )

    return {
        **state,
        "merged_state": merged_state,
        "iteration": 1,
        "investigation_phase": "seed_characterization",
        "execution_trace": trace_events,
    }


def correlate(state: InvestigationGraphState) -> InvestigationGraphState:
    new_phase = _infer_phase(state)
    if new_phase != state.get("investigation_phase"):
        _log_section("Phase Transition")
        print(f"[graph] New phase: {new_phase}")
    return {
        **state,
        "investigation_phase": new_phase,
    }


def extract_pivots_node(state: InvestigationGraphState) -> InvestigationGraphState:
    merged = state["merged_state"]
    if merged is None:
        return {**state, "pending_pivots": []}

    preview_limit = 5
    extraction_limit = 50
    pivots = extract_candidate_pivots(merged, limit=extraction_limit)
    decision_candidates = build_candidate_payload({**state, "pending_pivots": pivots}, limit=8)

    _log_section("Candidate Extraction", f"| Iteration {state['iteration']} | Phase {state.get('investigation_phase')}")
    print("[graph] Extraction policy: primary relations, minimum score 50, best candidate per destination")
    print(f"[graph] Candidates found: {len(pivots)}")
    print(f"[graph] High-value candidates after filtering: {len(decision_candidates)}")
    print("[graph] Top candidates:")
    for index, p in enumerate(pivots[:preview_limit], start=1):
        print(
            f"[graph]   {index}. {p['kind']} {p['value']} | "
            f"{p['source_relation']} | score {p['score']}"
        )

    trace_events = _append_trace_event(
        state,
        "candidate_extraction",
        {
            "candidate_count": len(pivots),
            "high_value_candidate_count": len(decision_candidates),
            "top_candidates": pivots[:10],
            "decision_view": decision_candidates,
        },
    )

    return {**state, "pending_pivots": pivots, "execution_trace": trace_events}


def select_next_pivot(state: InvestigationGraphState) -> InvestigationGraphState:
    merged = state["merged_state"]
    if merged is None:
        return {**state, "last_selected_pivot": None, "semantic_selection": None}

    _log_section("Pivot Selection", f"| Iteration {state['iteration']} | Phase {state.get('investigation_phase')}")
    candidate_view = build_candidate_payload(state, limit=8)
    print(f"[graph] Candidates available: {len(state['pending_pivots'])}")
    print(f"[graph] High-value candidate view: {len(candidate_view)}")

    llm_decision = None
    selected = None

    if _should_use_llm_for_selection(state):
        llm_decision = choose_pivot_with_llm(state)
        if llm_decision is not None:
            _consume_operational_llm_call(state)
            state["llm_trace"] = _append_llm_trace(state, llm_decision.get("llm_trace"))
        if llm_decision and llm_decision.get("selected_key"):
            selected_key = str(llm_decision["selected_key"]).strip().lower()
            for pivot in state["pending_pivots"]:
                candidate_key = ioc_key(pivot["value"], pivot["kind"])
                if candidate_key == selected_key:
                    selected = pivot
                    break
            if selected is not None:
                print("[graph] Selection mode: semantic")
                print(f"[graph] Selection rationale: {llm_decision.get('reason', '')}")

    if selected is None:
        selected = _structural_select_next_pivot(state)
        if selected is not None:
            print("[graph] Selection mode: structural")

    if selected is None:
        print("[graph] No pivot candidates remain after filtering.")
        trace_events = _append_trace_event(
            state,
            "pivot_selection",
            {
                "selection_mode": "none",
                "candidate_count": len(state.get("pending_pivots", []) or []),
                "high_value_candidate_count": len(candidate_view),
                "llm_decision": llm_decision,
                "reason": "No viable pivot candidates remained after filtering.",
            },
        )
        return {
            **state,
            "last_selected_pivot": None,
            "semantic_selection": llm_decision,
            "execution_trace": trace_events,
            "llm_trace": state.get("llm_trace", []),
            "llm_operational_calls_used": state.get("llm_operational_calls_used", 0),
            "llm_calls_used": state.get("llm_calls_used", 0),
        }

    selected_group = _pivot_group(selected)
    used_groups = set(state.get("used_pivot_groups", []))
    used_groups.add(selected_group)

    print(f"[graph] Selected pivot: {selected['kind']} {selected['value']}")
    print(f"[graph] Source relation: {selected['source_relation']} | Score: {selected['score']}")

    trace_events = _append_trace_event(
        state,
        "pivot_selection",
        {
            "selection_mode": "semantic" if llm_decision and selected is not None else "structural",
            "candidate_count": len(state.get("pending_pivots", []) or []),
            "high_value_candidate_count": len(candidate_view),
            "selected": selected,
            "selected_group": selected_group,
            "llm_decision": llm_decision,
        },
    )

    return {
        **state,
        "last_selected_pivot": selected,
        "used_pivot_groups": list(used_groups),
        "semantic_selection": llm_decision,
        "execution_trace": trace_events,
        "llm_trace": state.get("llm_trace", []),
        "llm_operational_calls_used": state.get("llm_operational_calls_used", 0),
        "llm_calls_used": state.get("llm_calls_used", 0),
    }


def enrich_pivot(state: InvestigationGraphState) -> InvestigationGraphState:
    pivot = state["last_selected_pivot"]
    merged = state["merged_state"]

    if pivot is None or merged is None:
        return state

    _log_section("Pivot Expansion", f"| Iteration {state['iteration']} | Phase {state.get('investigation_phase')}")
    print(f"[graph] Expanding: {pivot['kind']} {pivot['value']}")

    before_relations = len(merged.relations)
    before_relation_keys = {_relation_trace_key(rel) for rel in merged.relations}
    before_observable_keys = set((getattr(merged, "observables", {}) or {}).keys())
    before_observables = len(before_observable_keys)
    before_evidence_provider_keys = _evidence_provider_keys(getattr(merged, "evidence", {}) or {})
    before_evidence = len(before_evidence_provider_keys)

    result = expand_pivot(merged, pivot, verbose=False)

    after_relations = len(merged.relations)
    after_relation_objects = [
        rel
        for rel in merged.relations
        if _relation_trace_key(rel) not in before_relation_keys
    ]
    relation_delta = _relation_delta_summary(after_relation_objects)

    after_observables_map = getattr(merged, "observables", {}) or {}
    after_observable_keys = set(after_observables_map.keys())
    after_observables = len(after_observable_keys)
    new_observable_keys = after_observable_keys - before_observable_keys
    new_observables = [
        _serialize_observable_for_trace(key, after_observables_map.get(key))
        for key in sorted(new_observable_keys)
    ]

    after_evidence_map = getattr(merged, "evidence", {}) or {}
    after_evidence_provider_keys = _evidence_provider_keys(after_evidence_map)
    new_evidence_provider_keys = after_evidence_provider_keys - before_evidence_provider_keys
    new_evidence = _serialize_evidence_delta(after_evidence_map, new_evidence_provider_keys)
    after_evidence = len(after_evidence_provider_keys)

    delta_relations = after_relations - before_relations
    delta_observables = after_observables - before_observables
    delta_evidence = after_evidence - before_evidence
    usefulness = delta_relations + (delta_observables * 2) + delta_evidence
    observable_type_breakdown = _observable_type_breakdown(new_observable_keys)
    impact_label = _impact_label(usefulness)

    print(f"[graph] Expansion result: {'success' if delta_relations or delta_observables or delta_evidence else 'no new information'}")
    print(f"[graph] Added relations: {delta_relations}")
    print(f"[graph] Added observables: {delta_observables}")
    print(f"[graph] Added evidence items: {delta_evidence}")
    if observable_type_breakdown:
        print(f"[graph] Observable types added: {observable_type_breakdown}")

    if result.get("added_relation_samples"):
        _print_relations("[graph] New sample relations:", result.get("added_relation_samples", []), limit=8)

    stagnation_count = state.get("stagnation_count", 0)
    dead_end_count = state.get("dead_end_count", 0)

    if usefulness <= 1:
        stagnation_count += 1
    else:
        stagnation_count = 0

    if delta_relations == 0:
        dead_end_count += 1
    else:
        dead_end_count = 0

    processed = list(state["processed_pivots"])
    processed.append(ioc_key(pivot["value"], pivot["kind"]))

    history = list(state.get("pivot_history", []))
    pivot_key = ioc_key(pivot["value"], pivot["kind"])
    history_entry = {
        "iteration": state["iteration"],
        "phase": state.get("investigation_phase"),
        "key": pivot_key,
        "kind": pivot["kind"],
        "value": pivot["value"],
        "group": _pivot_group(pivot),
        "role": _pivot_role(pivot),
        "family": _pivot_family(pivot["kind"], pivot["value"]),
        "source_relation": pivot["source_relation"],

        # Keep history lightweight: counts and scoring only.
        # Full relation/observable/evidence deltas are stored once in
        # pivoting.expansions by core.trace.
        "added_relations_count": delta_relations,
        "added_direct_relations_count": relation_delta["added_direct_relations_count"],
        "added_derived_relations_count": relation_delta["added_derived_relations_count"],
        "added_observables_count": delta_observables,
        "added_evidence_count": delta_evidence,
        "rules_fired": relation_delta["rules_fired"],

        "usefulness": usefulness,
        "impact_label": impact_label,
        "added_observable_types": observable_type_breakdown,
        "expanded": bool(result.get("expanded")),
        "llm_reason": (state.get("semantic_selection") or {}).get("reason", ""),
        "pivot_score": pivot.get("score"),
        "pivot_base_score": pivot.get("base_score"),
        "pivot_reasons": pivot.get("reasons", []),
        "source_relation_id": pivot.get("source_relation_id"),
    }
    history.append(history_entry)

    next_phase = _infer_phase({**state, "pivot_history": history})
    trace_events = _append_trace_event(
        state,
        "pivot_expansion",
        {
            "pivot": pivot,
            "result": {
                "expanded": bool(result.get("expanded")),

                # Counts are kept explicit so they remain easy to query.
                "added_relations_count": delta_relations,
                "added_observables_count": delta_observables,
                "added_evidence_count": delta_evidence,

                # Full delta payload for auditability.
                "added_relations": relation_delta["added_relations"],
                "added_direct_relations_count": relation_delta["added_direct_relations_count"],
                "added_derived_relations_count": relation_delta["added_derived_relations_count"],
                "rules_fired": relation_delta["rules_fired"],
                "added_observables": new_observables,
                "added_evidence": new_evidence,

                "usefulness": usefulness,
                "impact_label": impact_label,
                "added_observable_types": observable_type_breakdown,
            },
            # Do not embed history_entry here: it would duplicate the same
            # pivot summary in pivoting.history and make the JSON heavier.
            "next_phase": next_phase,
            "stagnation_count": stagnation_count,
            "dead_end_count": dead_end_count,
        },
    )

    return {
        **state,
        "merged_state": merged,
        "processed_pivots": processed,
        "pivot_history": history,
        "execution_trace": trace_events,
        "stagnation_count": stagnation_count,
        "dead_end_count": dead_end_count,
        "last_enrichment_result": result,
        "iteration": state["iteration"] + 1,
        "last_selected_pivot": pivot if result.get("expanded") else None,
        "investigation_phase": next_phase,
    }


def _determine_stop_reason(state: InvestigationGraphState) -> str:
    decision, reason = _deterministic_continue_decision(state)
    if decision == "final_report":
        return reason
    if state.get("investigation_phase") == "lateral_correlation" and state.get("dead_end_count", 0) >= 1:
        return "Lateral correlation no longer yields high-value pivots."
    return "No explicit stop condition was recorded."


def stop_or_continue(state: InvestigationGraphState) -> str:
    _log_section("Continue / Stop Check")
    print(f"[graph] Iteration: {state['iteration']} / {state['max_iterations']}")
    print(f"[graph] Phase: {state.get('investigation_phase')}")
    print(f"[graph] Stagnation count: {state.get('stagnation_count', 0)}")
    print(f"[graph] Dead-end count: {state.get('dead_end_count', 0)}")

    deterministic_decision, deterministic_reason = _deterministic_continue_decision(state)
    if deterministic_decision == "final_report":
        print(f"[graph] Decision: stop")
        print(f"[graph] Stop reason: {deterministic_reason}")
        return "final_report"

    if _should_use_llm_for_continue(state):
        llm_decision = decide_continue_with_llm(state)
        if llm_decision is not None:
            _consume_operational_llm_call(state)
            state["llm_trace"] = _append_llm_trace(state, llm_decision.get("llm_trace"))
            print(f"[graph] Continue decision rationale: {llm_decision.get('reason', '')}")
            if llm_decision.get("decision") == "stop":
                return "final_report"

    print("[graph] Decision: continue")
    return "correlate"


def _format_observable_type_breakdown(type_counts: dict[str, int]) -> str:
    if not type_counts:
        return "unspecified observables"
    ordered = sorted(type_counts.items(), key=lambda item: (-item[1], item[0]))
    parts = [f"{count} {kind}{'' if count == 1 else 's'}" for kind, count in ordered]
    if len(parts) == 1:
        return parts[0]
    if len(parts) == 2:
        return f"{parts[0]} and {parts[1]}"
    return ", ".join(parts[:-1]) + f", and {parts[-1]}"


def _build_readable_final_report(state: InvestigationGraphState, stop_reason: str) -> str:
    summary_context = build_summary_context({**state, "stop_reason": stop_reason})
    seed = summary_context["seed"]

    lines = [
        "Investigation Summary",
        "",
        f"Seed: {seed['type']} {seed['value']}",
        f"Phase at stop: {summary_context['phase_at_stop']}",
        f"Iterations completed: {summary_context['iterations_completed']}",
        f"Stop reason: {stop_reason}",
        "",
    ]

    supported = summary_context.get("supported_findings", [])[:4]
    if supported:
        lines.append("Key findings:")
        for item in supported:
            lines.append(f"- {item}")
        lines.append("")

    top_pivots = summary_context.get("top_pivots", [])
    if top_pivots:
        lines.append("Most productive pivots:")
        for pivot in top_pivots[:3]:
            artifact = pivot.get("artifact")
            relations = pivot.get("added_relations", 0)
            evidence = pivot.get("added_evidence", 0)
            obs_types = _format_observable_type_breakdown(pivot.get("observable_types") or {})
            lines.append(
                f"- {artifact}: added {relations} relations and {evidence} evidence items; new observables were mainly {obs_types}."
            )
        lines.append("")

    families = summary_context.get("family_rollup", [])
    if families:
        lines.append("Recurring lateral families:")
        for fam in families[:3]:
            obs_types = _format_observable_type_breakdown(fam.get("observable_types") or {})
            examples = ", ".join(fam.get("examples") or [])
            lines.append(
                f"- {fam['family']}: {fam['expansions']} expansions, {fam['relations']} relations, {fam['evidence']} evidence items; observables included {obs_types}. Examples: {examples}."
            )
        lines.append("")

    low_value = summary_context.get("low_value_paths", [])
    if low_value:
        lines.append("Lower-value paths:")
        for item in low_value[:3]:
            lines.append(f"- {item['artifact']} ({item['kind']}): {item['reason']}")
        lines.append("")

    lines.append("Recommendation:")
    if families:
        focus_families = ", ".join(f["family"] for f in families[:2])
        lines.append(
            f"- Prioritize family-level correlation around {focus_families}. Remaining isolated candidates appear less informative than the repeated family pattern already identified."
        )
    else:
        lines.append(
            "- Continue only if a remaining pivot can add materially new context; otherwise the investigation is sufficiently characterized."
        )

    return "\n".join(lines).strip()


def final_report_node(state: InvestigationGraphState) -> InvestigationGraphState:
    merged = state["merged_state"]

    _log_section("Final Report")

    if merged is None:
        report = "Investigation was empty."
        return {**state, "final_report": report}

    relation_stats = _relation_semantic_stats(merged.relations)
    total_relations = relation_stats["raw_count"]
    total_semantic_relations = relation_stats["semantic_count"]
    total_redundant_relations = relation_stats["redundant_count"]
    total_evidence = len(merged.evidence)
    total_expanded = len(getattr(merged, "expanded_iocs", set()) or set())
    total_observables = len(getattr(merged, "observables", {}) or {})
    stop_reason = _determine_stop_reason(state)

    print(f"[graph] Seed: {state['seed_type']} {state['seed_value']}")
    print(f"[graph] Phase at stop: {state.get('investigation_phase')}")
    print(f"[graph] Stop reason: {stop_reason}")
    print(f"[graph] Observables: {total_observables}")
    print(f"[graph] Evidence items: {total_evidence}")
    print(f"[graph] Raw relations: {total_relations}")
    print(f"[graph] Semantic relations: {total_semantic_relations}")
    print(f"[graph] Semantic redundancy: {total_redundant_relations}")
    print(f"[graph] Expanded IOCs: {total_expanded}")

    llm_summary = None
    if _should_use_llm_for_final_summary(state):
        llm_payload = build_final_summary_with_llm_payload({**state, "stop_reason": stop_reason})
        if llm_payload:
            llm_summary = llm_payload.get("text")
            state["llm_trace"] = _append_llm_trace(state, llm_payload.get("llm_trace"))
            _mark_final_summary_used(state)
        else:
            print("[graph] Final LLM summary requested but could not be generated.")

    if llm_summary:
        final_report = "Analyst Closing Note\n\n" + llm_summary.strip()
    else:
        final_report = _build_readable_final_report(state, stop_reason)

    return {
        **state,
        "final_report": final_report,
        "stop_reason": stop_reason,
        "llm_trace": state.get("llm_trace", []),
        "llm_operational_calls_used": state.get("llm_operational_calls_used", 0),
        "llm_final_summary_used": state.get("llm_final_summary_used", False),
        "llm_calls_used": state.get("llm_calls_used", 0),
    }
