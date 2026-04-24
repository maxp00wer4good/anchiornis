from models import Observable, Relation, InvestigationState
from models.normalized import NormalizedIntel
from core.state_ops import ensure_observable, add_relation, update_evidence


def project_normalized_intel(state: InvestigationState, intel: NormalizedIntel) -> None:
    id_to_key = {}
    role_to_key = {}

    for entity in intel.entities:
        obs = Observable(
            value=entity.value,
            kind=entity.kind,
            source=intel.source,
            data=entity.data,
        )
        ensure_observable(state, obs)
        id_to_key[entity.id] = obs.key
        role_to_key[entity.role] = obs.key

    for link in intel.links:
        src_key = id_to_key.get(link.src_id)
        dst_key = id_to_key.get(link.dst_id)

        if not src_key or not dst_key:
            continue

        add_relation(
            state,
            Relation(
                src=src_key,
                dst=dst_key,
                rel=link.rel,
                source=intel.source,
                metadata=link.metadata,
            )
        )

    root_key = role_to_key.get("root")
    if root_key and intel.attributes:
        update_evidence(state, root_key, intel.attributes)