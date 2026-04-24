from __future__ import annotations

"""Deterministic pivot extraction.

This module does *not* make the final semantic decision about which pivot should
be expanded next. Instead it provides a structural prior:

- which relations are plausible pivot sources
- what observable kind should be created from the destination
- a lightweight structural score used to build the candidate list

The optional LLM later chooses among those candidates using broader context.
"""

from dataclasses import dataclass, asdict

from core.helpers import semantic_relation_key
from models import InvestigationState


PRIMARY_PIVOT_RELATIONS = {
    # Core landing chain.
    "final_domain": ("domain", 90),
    "final_url": ("url", 90),
    "resolves_to": ("ip", 85),

    # Secondary observed infrastructure.
    "observed_domain": ("domain", 75),
    "observed_ip": ("ip", 75),
    "observed_url": ("url", 70),

    # Artifacts.
    "observed_hash": ("hash", 70),
    "content_sha256": ("hash", 65),

    # Lower-priority graph edges.
    "requested_domain": ("domain", 60),
    "requested_ip": ("ip", 60),
    "requested_url": ("url", 55),
    "linked_domain": ("domain", 55),
    "meta_identifier": ("hash", 45),
}


@dataclass
class PivotCandidate:
    value: str
    kind: str
    source_relation: str
    source_relation_id: str
    source_node: str
    relation_source: str
    base_score: int
    score: int
    derivation_count: int
    reasons: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def _split_entity_id(entity_id: str) -> tuple[str | None, str | None]:
    if ":" not in entity_id:
        return None, None

    kind, value = entity_id.split(":", 1)
    kind = kind.strip()
    value = value.strip()

    if not kind or not value:
        return None, None

    return kind, value


def _build_derivation_usage_index(state: InvestigationState) -> dict[str, list[dict]]:
    """Map relation IDs to the derived relations that reused them.

    This is a structural signal only: if a primary relation is repeatedly used by
    the rule engine, it becomes a more attractive candidate for further
    investigation.
    """

    usage: dict[str, list[dict]] = {}

    for rel in state.relations:
        if rel.source != "rules_engine":
            continue

        metadata = rel.metadata or {}
        input_relations = metadata.get("input_relations", []) or []
        evidence = metadata.get("evidence", {}) or {}
        evidence_count = evidence.get("count", 0)

        for rel_id in input_relations:
            usage.setdefault(rel_id, []).append(
                {
                    "rule_id": metadata.get("rule_id"),
                    "evidence_count": evidence_count,
                    "derived_rel": rel.rel,
                    "derived_dst": rel.dst,
                }
            )

    return usage


def extract_candidate_pivots(
    state: InvestigationState,
    exclude_root: bool = True,
    min_score: int = 50,
    limit: int = 10,
    per_semantic_limit: int = 1,
) -> list[dict]:
    """Extract structurally plausible pivots from the current graph state."""

    root_id = f"{state.input_type}:{state.input_value}"
    derivation_usage = _build_derivation_usage_index(state)

    best_by_dst: dict[str, PivotCandidate] = {}
    seen_semantic_relations: dict[str, int] = {}

    for rel in state.relations:
        if rel.source == "rules_engine":
            continue

        rel_info = PRIMARY_PIVOT_RELATIONS.get(rel.rel)
        if not rel_info:
            continue

        expected_kind, base_score = rel_info
        if base_score < min_score:
            continue

        kind, value = _split_entity_id(rel.dst)
        if kind is None or value is None:
            continue

        if exclude_root and rel.dst == root_id:
            continue

        if kind != expected_kind:
            continue

        semantic_rel_key = semantic_relation_key(rel.src, rel.rel, rel.dst)
        semantic_count = seen_semantic_relations.get(semantic_rel_key, 0)
        if semantic_count >= per_semantic_limit:
            continue

        usages = derivation_usage.get(rel.id, [])
        derivation_count = len(usages)

        score = base_score
        reasons = [f"primary:{rel.rel}"]

        if derivation_count > 0:
            score += derivation_count * 10
            reasons.append(f"used_by_derivations:{derivation_count}")

            total_evidence_bonus = sum(
                min(usage.get("evidence_count", 0), 5) for usage in usages
            )
            score += total_evidence_bonus
            reasons.append(f"derivation_evidence_bonus:{total_evidence_bonus}")

        candidate = PivotCandidate(
            value=value,
            kind=kind,
            source_relation=rel.rel,
            source_relation_id=rel.id,
            source_node=rel.src,
            relation_source=rel.source,
            base_score=base_score,
            score=score,
            derivation_count=derivation_count,
            reasons=reasons,
        )

        current = best_by_dst.get(rel.dst)
        if current is None or candidate.score > current.score:
            best_by_dst[rel.dst] = candidate
            seen_semantic_relations[semantic_rel_key] = semantic_count + 1

    ordered = sorted(
        best_by_dst.values(),
        key=lambda c: (-c.score, -c.derivation_count, c.kind, c.value),
    )

    return [candidate.to_dict() for candidate in ordered[:limit]]
