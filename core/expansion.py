from __future__ import annotations

from models import InvestigationState, Observable
from core.state_ops import ensure_observable, set_current
from core.clients import build_clients
from core.investigator import investigate
from core.pivots import extract_candidate_pivots
from core.helpers import ioc_key, relation_key


def _existing_ioc_keys(state: InvestigationState) -> set[str]:
    keys = set()

    if state.input_value and state.input_type:
        keys.add(ioc_key(state.input_value, state.input_type))

    observables = getattr(state, "observables", {}) or {}
    for obs in observables.values():
        value = getattr(obs, "value", None)
        kind = getattr(obs, "kind", None)
        if value and kind:
            keys.add(ioc_key(value, kind))

    current = getattr(state, "current", None)
    if current and getattr(current, "value", None) and getattr(current, "kind", None):
        keys.add(ioc_key(current.value, current.kind))

    keys.update(getattr(state, "seen", set()) or set())

    for k in (getattr(state, "evidence", {}) or {}).keys():
        if ":" in k:
            kind, value = k.split(":", 1)
            keys.add(ioc_key(value, kind))

    return keys


def _merge_state_into_state(
    target_state: InvestigationState,
    new_state: InvestigationState,
) -> dict:
    added_relations = 0
    added_observables = 0
    added_evidence = 0

    added_relation_samples = []
    existing_relation_samples = []

    existing_rel_keys = {
        relation_key(r.src, r.rel, r.dst, getattr(r, "source", ""))
        for r in target_state.relations
    }

    for rel in new_state.relations:
        key = relation_key(rel.src, rel.rel, rel.dst, getattr(rel, "source", ""))

        rel_view = {
            "id": rel.id,
            "src": rel.src,
            "rel": rel.rel,
            "dst": rel.dst,
            "source": getattr(rel, "source", ""),
        }

        if key in existing_rel_keys:
            if len(existing_relation_samples) < 15:
                existing_relation_samples.append(rel_view)
            continue

        target_state.relations.append(rel)
        existing_rel_keys.add(key)
        added_relations += 1

        if len(added_relation_samples) < 15:
            added_relation_samples.append(rel_view)

    new_obs = getattr(new_state, "observables", {}) or {}
    target_obs = getattr(target_state, "observables", {}) or {}

    for obs_key, obs in new_obs.items():
        if obs_key not in target_obs:
            target_obs[obs_key] = obs
            added_observables += 1

    target_state.observables = target_obs

    for ev_key, ev_value in (getattr(new_state, "evidence", {}) or {}).items():
        if ev_key not in target_state.evidence:
            target_state.evidence[ev_key] = ev_value
            added_evidence += 1
        else:
            if isinstance(target_state.evidence[ev_key], dict) and isinstance(ev_value, dict):
                target_state.evidence[ev_key].update(ev_value)
            else:
                target_state.evidence[ev_key] = ev_value

    target_state.seen.update(getattr(new_state, "seen", set()) or set())

    if hasattr(target_state, "expanded_iocs"):
        target_state.expanded_iocs.update(
            getattr(new_state, "expanded_iocs", set()) or set()
        )

    if hasattr(target_state, "executed_steps"):
        target_state.executed_steps.update(
            getattr(new_state, "executed_steps", set()) or set()
        )

    return {
        "added_relations": added_relations,
        "added_observables": added_observables,
        "added_evidence": added_evidence,
        "new_state_total_relations": len(new_state.relations),
        "added_relation_samples": added_relation_samples,
        "existing_relation_samples": existing_relation_samples,
    }


def _register_pivot_observable(
    state: InvestigationState,
    value: str,
    kind: str,
) -> None:
    obs = Observable(value=value, kind=kind, source="pivot")
    set_current(state, obs)
    ensure_observable(state, obs)


def expand_pivot(
    state: InvestigationState,
    pivot: dict,
    verbose: bool = False,
) -> dict:
    value = pivot["value"]
    kind = pivot["kind"]
    pivot_key = ioc_key(value, kind)

    if hasattr(state, "expanded_iocs") and pivot_key in state.expanded_iocs:
        return {
            "expanded": False,
            "reason": "already_expanded",
            "pivot": pivot,
            "added_relations": 0,
            "new_state_total_relations": 0,
            "added_relation_samples": [],
            "existing_relation_samples": [],
        }

    vt, abuse, urlscan = build_clients()

    new_state = investigate(
        value=value,
        input_type=kind,
        vt=vt,
        abuse=abuse,
        urlscan=urlscan,
        verbose=verbose,
        parent_state=state,
    )

    merge_stats = _merge_state_into_state(state, new_state)
    _register_pivot_observable(state, value, kind)

    if hasattr(state, "expanded_iocs"):
        state.expanded_iocs.add(pivot_key)

    return {
        "expanded": True,
        "reason": "ok",
        "pivot": pivot,
        "added_relations": merge_stats["added_relations"],
        "new_state_total_relations": merge_stats["new_state_total_relations"],
        "added_relation_samples": merge_stats["added_relation_samples"],
        "existing_relation_samples": merge_stats["existing_relation_samples"],
    }


def select_top_pivots(
    pivots: list[dict],
    expanded_keys: set[str] | None = None,
    limit: int = 3,
) -> list[dict]:
    expanded_keys = expanded_keys or set()
    selected: list[dict] = []

    for pivot in pivots:
        key = ioc_key(pivot["value"], pivot["kind"])

        if key in expanded_keys:
            continue

        selected.append(pivot)

        if len(selected) >= limit:
            break

    return selected


def expand_top_pivots(
    state: InvestigationState,
    limit: int = 3,
    verbose: bool = False,
) -> dict:
    pivots = extract_candidate_pivots(state, limit=50)

    expanded_keys = getattr(state, "expanded_iocs", set()) or set()
    selected = select_top_pivots(
        pivots,
        expanded_keys=expanded_keys,
        limit=limit,
    )

    results = []
    total_added = 0

    for pivot in selected:
        result = expand_pivot(state, pivot, verbose=verbose)
        results.append(result)
        total_added += result.get("added_relations", 0)

    return {
        "selected_pivots": selected,
        "results": results,
        "total_added_relations": total_added,
    }