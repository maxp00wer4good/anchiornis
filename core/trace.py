from __future__ import annotations

"""Execution trace export helpers.

The CLI writes a JSON trace so a run can be audited after the fact. The trace is
split into lightweight summaries and heavyweight deltas to avoid duplicating the
same relations in multiple places:

- knowledge_graph: final graph state, once
- pivoting.history: lightweight pivot timeline with counts/scoring
- pivoting.expansions: heavy per-pivot deltas, once
- timeline: lightweight operational events, with bulky payloads stripped
- llm.calls: prompts/responses when semantic LLM calls were used
"""

from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
import json
import re

from graph.state import InvestigationGraphState
from models.relation import Relation


SCHEMA_VERSION = "0.2"
TOOL_NAME = "Anchiornis"
TOOL_VERSION = "0.2"

# Keys that can make event payloads huge. These are retained in dedicated
# sections such as pivoting.expansions, not duplicated in timeline/events.
_HEAVY_KEYS = {
    "added_relations",
    "added_direct_relations",
    "added_derived_relations",
    "added_observables",
    "added_evidence",
    "relations",
    "observables",
    "evidence",
}


def _json_safe(value: Any) -> Any:
    """Convert common Python objects into JSON-serializable structures."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, set):
        return sorted(_json_safe(v) for v in value)
    if is_dataclass(value):
        return _json_safe(asdict(value))
    if hasattr(value, "model_dump"):
        return _json_safe(value.model_dump())
    if hasattr(value, "dict"):
        return _json_safe(value.dict())
    return str(value)


def serialize_relation(rel: Relation | dict[str, Any]) -> dict[str, Any]:
    """Serialize a Relation-like object using a stable CTI-friendly shape."""
    if isinstance(rel, dict):
        metadata = _json_safe(rel.get("metadata", {}) or {})
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

    metadata = _json_safe(getattr(rel, "metadata", {}) or {})
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


def _serialize_observables_map(observables: Any) -> list[dict[str, Any]]:
    """Serialize merged_state.observables whether it is a dict or a list."""
    if not observables:
        return []

    if isinstance(observables, dict):
        items = []
        for key, value in sorted(observables.items(), key=lambda item: str(item[0])):
            if isinstance(value, dict):
                kind = value.get("kind") or value.get("type") or (str(key).split(":", 1)[0] if ":" in str(key) else None)
                val = value.get("value") or (str(key).split(":", 1)[1] if ":" in str(key) else str(key))
                source = value.get("source")
                data = value.get("data", {})
            else:
                kind = getattr(value, "kind", None) or getattr(value, "type", None) or (str(key).split(":", 1)[0] if ":" in str(key) else None)
                val = getattr(value, "value", None) or (str(key).split(":", 1)[1] if ":" in str(key) else str(key))
                source = getattr(value, "source", None)
                data = getattr(value, "data", {})

            items.append(
                {
                    "key": str(key),
                    "kind": kind,
                    "value": val,
                    "source": source,
                    "data": _json_safe(data or {}),
                }
            )
        return items

    return _json_safe(list(observables))


def _serialize_evidence_map(evidence: Any) -> list[dict[str, Any]]:
    """Serialize merged_state.evidence as provider-level evidence records."""
    if not evidence:
        return []

    if isinstance(evidence, dict):
        output = []
        for obs_key, payload in sorted(evidence.items(), key=lambda item: str(item[0])):
            if isinstance(payload, dict):
                for provider, provider_payload in sorted(payload.items(), key=lambda item: str(item[0])):
                    output.append(
                        {
                            "observable_key": str(obs_key),
                            "provider": str(provider),
                            "payload": _json_safe(provider_payload),
                        }
                    )
            else:
                output.append(
                    {
                        "observable_key": str(obs_key),
                        "provider": "__value__",
                        "payload": _json_safe(payload),
                    }
                )
        return output

    return _json_safe(list(evidence))


def _strip_heavy_payload(value: Any) -> Any:
    """Remove bulky lists from operational timeline events."""
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            if key in _HEAVY_KEYS:
                # Preserve the fact that data existed without duplicating it.
                if isinstance(item, (list, tuple, set)):
                    cleaned[f"{key}_count"] = len(item)
                elif isinstance(item, dict):
                    cleaned[f"{key}_count"] = len(item)
                else:
                    cleaned[f"{key}_present"] = item is not None
                continue
            cleaned[str(key)] = _strip_heavy_payload(item)
        return cleaned
    if isinstance(value, list):
        return [_strip_heavy_payload(item) for item in value]
    return _json_safe(value)


def _event_stage(event: dict[str, Any]) -> str:
    return str(event.get("stage") or event.get("event") or "")


def _compact_timeline_event(event: dict[str, Any], expansion_index_by_event_index: dict[int, int], index: int) -> dict[str, Any]:
    """Build a lightweight event suitable for chronological reading."""
    compact = {
        "timestamp_utc": event.get("timestamp_utc"),
        "iteration": event.get("iteration"),
        "phase": event.get("phase"),
        "stage": _event_stage(event),
    }

    details = event.get("details") or {}
    if _event_stage(event) == "pivot_expansion":
        result = details.get("result") or {}
        pivot = details.get("pivot") or {}
        compact["refs"] = {
            "pivot_key": pivot.get("key") or _pivot_key_from_dict(pivot),
            "pivot_kind": pivot.get("kind"),
            "pivot_value": pivot.get("value"),
            "expansion_index": expansion_index_by_event_index.get(index),
            "added_relations_count": result.get("added_relations_count"),
            "added_observables_count": result.get("added_observables_count"),
            "added_evidence_count": result.get("added_evidence_count"),
            "usefulness": result.get("usefulness"),
        }
        return _json_safe(compact)

    compact["details"] = _strip_heavy_payload(details)
    return _json_safe(compact)


def _pivot_key_from_dict(pivot: dict[str, Any]) -> str | None:
    kind = pivot.get("kind")
    value = pivot.get("value")
    if kind and value:
        return f"{kind}:{value}"
    return None


def _build_pivot_expansions(execution_events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[int, int]]:
    """Extract heavyweight pivot expansions from raw execution events once."""
    expansions: list[dict[str, Any]] = []
    index_by_event_index: dict[int, int] = {}

    for event_index, event in enumerate(execution_events):
        if _event_stage(event) != "pivot_expansion":
            continue

        details = event.get("details") or {}
        pivot = _json_safe(details.get("pivot") or {})
        result = _json_safe(details.get("result") or {})
        expansion_index = len(expansions)
        index_by_event_index[event_index] = expansion_index

        expansions.append(
            {
                "index": expansion_index,
                "timestamp_utc": event.get("timestamp_utc"),
                "iteration": event.get("iteration"),
                "phase": event.get("phase"),
                "pivot_key": (pivot or {}).get("key") or _pivot_key_from_dict(pivot or {}),
                "pivot": {
                    "kind": (pivot or {}).get("kind"),
                    "value": (pivot or {}).get("value"),
                    "group": (pivot or {}).get("group"),
                    "role": (pivot or {}).get("role"),
                    "score": (pivot or {}).get("score"),
                    "base_score": (pivot or {}).get("base_score"),
                    "reasons": (pivot or {}).get("reasons", []),
                    "source_relation": (pivot or {}).get("source_relation"),
                    "source_relation_id": (pivot or {}).get("source_relation_id"),
                },
                "added": {
                    "relations_count": result.get("added_relations_count", 0),
                    "direct_relations_count": result.get("added_direct_relations_count", 0),
                    "derived_relations_count": result.get("added_derived_relations_count", 0),
                    "observables_count": result.get("added_observables_count", 0),
                    "evidence_count": result.get("added_evidence_count", 0),
                    "relations": result.get("added_relations", []),
                    "observables": result.get("added_observables", []),
                    "evidence": result.get("added_evidence", []),
                },
                "rules_fired": result.get("rules_fired", []),
                "usefulness": result.get("usefulness"),
                "impact_label": result.get("impact_label"),
                "expanded": result.get("expanded"),
                "next_phase": details.get("next_phase"),
                "stagnation_count": details.get("stagnation_count"),
                "dead_end_count": details.get("dead_end_count"),
            }
        )

    return expansions, index_by_event_index


def _normalize_pivot_history(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep pivot history lightweight and backward-compatible."""
    normalized = []
    for item in history or []:
        item = dict(item)

        # Convert old numeric fields to explicit *_count names.
        for field in ("added_relations", "added_observables", "added_evidence"):
            count_field = f"{field}_count"
            if count_field not in item:
                value = item.get(field)
                if isinstance(value, list):
                    item[count_field] = len(value)
                else:
                    item[count_field] = int(value or 0)

        # Remove any heavy lists accidentally stored in history.
        for heavy in ("added_relations", "added_observables", "added_evidence"):
            if isinstance(item.get(heavy), list):
                item.pop(heavy, None)

        item.setdefault("selection", {})
        item.setdefault("expansion_summary", {})
        if not item["expansion_summary"]:
            item["expansion_summary"] = {
                "expanded": item.get("expanded"),
                "added_relations_count": item.get("added_relations_count", 0),
                "added_direct_relations_count": item.get("added_direct_relations_count", 0),
                "added_derived_relations_count": item.get("added_derived_relations_count", 0),
                "added_observables_count": item.get("added_observables_count", 0),
                "added_evidence_count": item.get("added_evidence_count", 0),
                "rules_fired": item.get("rules_fired", []),
                "usefulness": item.get("usefulness"),
                "impact_label": item.get("impact_label"),
                "added_observable_types": item.get("added_observable_types", {}),
            }

        normalized.append(_json_safe(item))
    return normalized


def build_execution_trace(state: InvestigationGraphState, executed_at: datetime | None = None) -> dict[str, Any]:
    executed_at = executed_at or datetime.now(UTC)
    merged = state.get("merged_state")

    relations = list(getattr(merged, "relations", []) or []) if merged is not None else []
    serialized_relations = [serialize_relation(r) for r in relations]
    direct_relations = [r for r in serialized_relations if r.get("tier") != "derived"]
    derived_relations = [r for r in serialized_relations if r.get("tier") == "derived"]

    observables_map = getattr(merged, "observables", {}) if merged is not None else {}
    evidence_map = getattr(merged, "evidence", {}) if merged is not None else {}
    observables = _serialize_observables_map(observables_map)
    evidence = _serialize_evidence_map(evidence_map)

    execution_events = _json_safe(state.get("execution_trace", []) or [])
    pivot_expansions, expansion_index_by_event_index = _build_pivot_expansions(execution_events)
    timeline = [
        _compact_timeline_event(event, expansion_index_by_event_index, index)
        for index, event in enumerate(execution_events)
    ]

    rules_loaded = sorted(
        {
            str((rel.get("metadata") or {}).get("rule_id"))
            for rel in derived_relations
            if isinstance(rel.get("metadata"), dict) and (rel.get("metadata") or {}).get("rule_id")
        }
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "name": TOOL_NAME,
            "version": TOOL_VERSION,
        },
        "run": {
            "timestamp_utc": executed_at.isoformat().replace("+00:00", "Z"),
            "phase_at_stop": state.get("investigation_phase"),
            "stop_reason": state.get("stop_reason"),
            "iterations_completed": state.get("iteration"),
            "max_iterations": state.get("max_iterations"),
        },
        "input": {
            "seed": {
                "type": state.get("seed_type"),
                "value": state.get("seed_value"),
            }
        },
        "summary": {
            "final_report": state.get("final_report", ""),
            "counts": {
                "observables": len(observables),
                "relations": len(serialized_relations),
                "direct_relations": len(direct_relations),
                "derived_relations": len(derived_relations),
                "evidence_items": len(evidence),
                "processed_pivots": len(state.get("processed_pivots", []) or []),
                "pending_pivots_at_stop": len(state.get("pending_pivots", []) or []),
                "pivot_expansions": len(pivot_expansions),
                "llm_calls": len(state.get("llm_trace", []) or []),
            },
        },
        "knowledge_graph": {
            "observables": observables,
            "relations": serialized_relations,
            "evidence": evidence,
        },
        "inference": {
            "engine": "yaml_dsl_poc",
            "rules_loaded_or_fired": rules_loaded,
            "rules_fired": rules_loaded,
            "derived_relations": derived_relations,
        },
        "pivoting": {
            "processed_keys": _json_safe(state.get("processed_pivots", []) or []),
            "used_groups": _json_safe(state.get("used_pivot_groups", []) or []),
            "history": _normalize_pivot_history(state.get("pivot_history", []) or []),
            "expansions": pivot_expansions,
            "pending_at_stop": _json_safe(state.get("pending_pivots", []) or []),
        },
        "llm": {
            "operational_calls_used": state.get("llm_operational_calls_used", 0),
            "operational_budget": state.get("llm_operational_budget", state.get("llm_call_budget", 0)),
            "final_summary_enabled": state.get("llm_final_summary_enabled", state.get("enable_llm_final_summary", False)),
            "final_summary_used": state.get("llm_final_summary_used", False),
            "calls": _json_safe(state.get("llm_trace", []) or []),
        },
        "timeline": timeline,
    }


def _safe_file_part(value: str, fallback: str = "ioc") -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", value.strip())[:80].strip("_")
    return safe or fallback


def write_execution_trace(state: InvestigationGraphState, output_dir: str | Path = "traces") -> Path:
    executed_at = datetime.now(UTC)
    payload = build_execution_trace(state, executed_at=executed_at)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    timestamp = executed_at.strftime("%Y%m%dT%H%M%SZ")
    seed_part = _safe_file_part(str(state.get("seed_value") or "ioc"))
    path = out_dir / f"ioc_trace_{timestamp}_{seed_part}.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
