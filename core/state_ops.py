from models import Observable, Relation, InvestigationState
from core.helpers import ioc_key, relation_key


def _canonical_obs_key(obs: Observable) -> str:
    return ioc_key(obs.value, obs.kind)


def ensure_observable(state: InvestigationState, obs: Observable) -> None:
    key = _canonical_obs_key(obs)

    if key not in state.evidence:
        state.evidence[key] = obs.data.copy() if obs.data else {}
    else:
        if obs.data:
            state.evidence[key].update(obs.data)

    if hasattr(state, "observables"):
        state.observables[key] = obs

    state.seen.add(key)


def update_evidence(state: InvestigationState, obs_key: str, data: dict) -> None:
    if ":" in obs_key:
        kind, value = obs_key.split(":", 1)
        key = ioc_key(value, kind)
    else:
        key = obs_key.strip().lower()

    if key not in state.evidence:
        state.evidence[key] = {}

    state.evidence[key].update(data)


def add_relation(state: InvestigationState, relation: Relation) -> None:
    new_key = relation_key(
        relation.src,
        relation.rel,
        relation.dst,
        getattr(relation, "source", ""),
    )

    exists = any(
        relation_key(
            r.src,
            r.rel,
            r.dst,
            getattr(r, "source", ""),
        ) == new_key
        for r in state.relations
    )

    if not exists:
        state.relations.append(relation)


def set_current(state: InvestigationState, obs: Observable) -> None:
    state.current = obs