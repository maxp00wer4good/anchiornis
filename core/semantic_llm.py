from __future__ import annotations

"""Semantic decision helpers powered by an LLM backend.

This module keeps the LLM in the interpretation loop only:
- choose the next pivot when structural ranking alone is not enough
- optionally decide whether a later-phase investigation should continue
- optionally produce a concise grounded final summary

Environment loading intentionally happens outside this module. The entrypoint
(`anchiornis.py`) should load `.env` exactly once and, if needed,
apply runtime overrides before the workflow starts.
"""

import json
import os
import re
import time
from dataclasses import dataclass
from collections import Counter
from typing import Any
from urllib.parse import parse_qsl, urlparse


@dataclass(frozen=True)
class SemanticModelConfig:
    provider: str
    model: str
    base_url: str | None
    api_key: str | None
    temperature: float
    enabled: bool


@dataclass
class SemanticBackend:
    provider: str
    model: Any
    model_name: str
    mode: str  # "chat_ollama" | "anthropic"


_CACHED_BACKEND: SemanticBackend | None = None


# ---------------------------------------------------------------------------
# Model bootstrap
# ---------------------------------------------------------------------------

def _get_required_env(name: str) -> str:
    value = os.getenv(name)
    if value is None or not value.strip():
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value.strip()


def load_semantic_model_config() -> SemanticModelConfig:
    enabled_raw = os.getenv("IOC_ENABLE_LLM", "0").strip().lower()
    enabled = enabled_raw in {"1", "true", "yes", "on"}

    provider = os.getenv("IOC_LLM_PROVIDER", "ollama").strip().lower()

    temperature_raw = os.getenv("IOC_LLM_TEMPERATURE", "0.0").strip()
    try:
        temperature = float(temperature_raw)
    except ValueError as exc:
        raise RuntimeError(f"Invalid IOC_LLM_TEMPERATURE: {temperature_raw!r}") from exc

    if not enabled:
        return SemanticModelConfig(
            provider=provider,
            model="",
            base_url=None,
            api_key=None,
            temperature=temperature,
            enabled=False,
        )

    model = os.getenv("IOC_LLM_MODEL", "").strip() or os.getenv("OLLAMA_MODEL", "").strip()
    if not model:
        raise RuntimeError("Missing required environment variable: IOC_LLM_MODEL")

    if provider == "ollama":
        return SemanticModelConfig(
            provider=provider,
            model=model,
            base_url=_get_required_env("OLLAMA_BASE_URL"),
            api_key=None,
            temperature=temperature,
            enabled=True,
        )

    if provider == "anthropic":
        return SemanticModelConfig(
            provider=provider,
            model=model,
            base_url=None,
            api_key=_get_required_env("ANTHROPIC_API_KEY"),
            temperature=temperature,
            enabled=True,
        )

    raise RuntimeError(f"Unsupported IOC_LLM_PROVIDER: {provider}")


def _build_chat_model() -> SemanticBackend | None:
    global _CACHED_BACKEND

    if _CACHED_BACKEND is not None:
        return _CACHED_BACKEND

    config = load_semantic_model_config()

    print(
        f"[llm] enabled={config.enabled} "
        f"provider={config.provider} "
        f"model={config.model or '<disabled>'} "
        f"base_url={config.base_url or '<n/a>'}"
    )

    if not config.enabled:
        print("[llm] disabled by configuration")
        return None

    if config.provider == "ollama":
        try:
            from langchain_ollama import ChatOllama
        except Exception as e:
            raise RuntimeError(f"Failed to import langchain_ollama: {e}") from e

        try:
            model = ChatOllama(
                model=config.model,
                base_url=config.base_url,
                temperature=config.temperature,
                format="json",
            )
        except Exception as e:
            raise RuntimeError(f"Failed to initialize ChatOllama: {e}") from e

        _CACHED_BACKEND = SemanticBackend(
            provider="ollama",
            model=model,
            model_name=config.model,
            mode="chat_ollama",
        )
        print("[llm] Ollama backend initialized")
        return _CACHED_BACKEND

    if config.provider == "anthropic":
        try:
            import anthropic
        except Exception as e:
            raise RuntimeError(
                "Failed to import anthropic SDK: install it with `pip install anthropic`"
            ) from e

        try:
            client = anthropic.Anthropic(api_key=config.api_key)
        except Exception as e:
            raise RuntimeError(f"Failed to initialize Anthropic client: {e}") from e

        _CACHED_BACKEND = SemanticBackend(
            provider="anthropic",
            model=client,
            model_name=config.model,
            mode="anthropic",
        )
        print("[llm] Anthropic client initialized")
        return _CACHED_BACKEND

    raise RuntimeError(f"Unsupported IOC_LLM_PROVIDER: {config.provider}")


# ---------------------------------------------------------------------------
# Compact graph views for LLM decisions
# ---------------------------------------------------------------------------

def _safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _normalize_scalar(value: Any) -> Any:
    if isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        clean = value.strip()
        if len(clean) <= 72:
            return clean
        return clean[:69] + "..."

    return None


def _extract_seen_times(payload: dict[str, Any]) -> dict[str, Any]:
    """Keep only source-provided seen times.

    We intentionally do NOT add any system collection timestamps here.
    """
    candidates = {
        "first_seen": payload.get("first_seen") or payload.get("first_submission_date"),
        "last_seen": payload.get("last_seen") or payload.get("last_submission_date") or payload.get("last_analysis_date"),
        "observed_at": payload.get("observed_at") or payload.get("date"),
    }
    return {k: v for k, v in candidates.items() if v not in (None, "", 0)}


def _compact_provider_payload(payload: dict[str, Any], limit: int = 4) -> dict[str, Any]:
    compact: dict[str, Any] = {}

    seen_times = _extract_seen_times(payload)
    if seen_times:
        compact["seen_times"] = seen_times

    for key, value in payload.items():
        if key in {"first_seen", "last_seen", "observed_at", "date", "first_submission_date", "last_submission_date", "last_analysis_date"}:
            continue

        scalar = _normalize_scalar(value)
        if scalar is not None:
            compact[key] = scalar
            if len(compact) >= limit:
                break
            continue

        if isinstance(value, list):
            compact[key] = {"count": len(value)}
            if len(compact) >= limit:
                break
            continue

        if isinstance(value, dict):
            nested_scalars: dict[str, Any] = {}
            for nested_key, nested_value in value.items():
                nested_scalar = _normalize_scalar(nested_value)
                if nested_scalar is not None:
                    nested_scalars[nested_key] = nested_scalar
                elif isinstance(nested_value, list):
                    nested_scalars[nested_key] = {"count": len(nested_value)}
                if len(nested_scalars) >= 3:
                    break
            if nested_scalars:
                compact[key] = nested_scalars
                if len(compact) >= limit:
                    break

    return compact


def _url_shape_summary(value: str) -> dict[str, Any]:
    parsed = urlparse(value)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    path = parsed.path or "/"
    suffix = path.split("/")[-1]

    return {
        "hostname": parsed.hostname,
        "path": path[:72],
        "query_param_count": len(query_pairs),
        "has_fragment": bool(parsed.fragment),
        "resource_suffix": suffix[-20:] if suffix else "",
    }


def _family_key(kind: str, value: str) -> str:
    clean = (value or "").strip().lower()

    if kind == "domain":
        parts = clean.split(".")
        if len(parts) >= 2:
            return f"domain:{'.'.join(parts[-2:])}"
        return f"domain:{clean}"

    if kind == "url":
        host = (urlparse(clean).hostname or "").lower()
        if host:
            parts = host.split(".")
            if len(parts) >= 2:
                return f"url:{'.'.join(parts[-2:])}"
            return f"url:{host}"
        return f"url:{clean}"

    if kind == "ip":
        octets = clean.split(".")
        if len(octets) == 4:
            return f"ip:{'.'.join(octets[:3])}"
        return f"ip:{clean}"

    return f"{kind}:{clean}"


def _candidate_role(kind: str, source_relation: str, value: str) -> str:
    if source_relation in {"final_domain", "final_url", "resolves_to"}:
        return "core"
    if source_relation in {"observed_domain", "observed_ip", "observed_url"}:
        return "lateral"
    if source_relation in {"content_sha256", "observed_hash"}:
        return "artifact"
    return "secondary"

def _provider_payload(merged, obs_key: str, provider: str) -> dict[str, Any]:
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


def _seed_key_from_state(state: dict[str, Any]) -> str:
    return f"{state.get('seed_type')}:{state.get('seed_value')}"


def _seed_has_negative_signal(state: dict[str, Any]) -> bool:
    merged = state.get('merged_state')
    if merged is None:
        return False
    seed_key = _seed_key_from_state(state)
    vt_payload = _provider_payload(merged, seed_key, 'virustotal')
    if int(vt_payload.get('malicious') or 0) > 0 or int(vt_payload.get('suspicious') or 0) > 0:
        return True
    for rel in getattr(merged, 'relations', []) or []:
        if rel.src != seed_key:
            continue
        if rel.rel == 'has_vt_verdict' and rel.dst in {'verdict:malicious', 'verdict:suspicious'}:
            return True
        if rel.rel in {'has_certificate_divergence', 'has_consensus_signal', 'shows_parking_behavior'}:
            return True
    return False


def _observable_is_high_fanout_sink(state: dict[str, Any], obs_key: str) -> bool:
    merged = state.get('merged_state')
    if merged is None or not obs_key.startswith('url:'):
        return False
    if not _seed_has_negative_signal(state):
        return False

    urlscan_payload = _provider_payload(merged, obs_key, 'urlscan')
    if not urlscan_payload:
        return False

    request_count = int(urlscan_payload.get('request_count') or 0)
    observed_domain_count = len(urlscan_payload.get('observed_domains') or [])
    observed_hash_count = len(urlscan_payload.get('observed_hashes') or [])
    final_domain = str(urlscan_payload.get('final_domain') or '').strip().lower()
    final_url = str(urlscan_payload.get('final_url') or '').strip()

    if request_count < 80 and observed_domain_count < 15 and observed_hash_count < 40:
        return False

    seed_value = str(state.get('seed_value') or '')
    seed_host = urlparse(seed_value).hostname or seed_value
    if final_domain and _same_registered_family(seed_host, final_domain):
        return False

    benign_like = True
    vt_payload = _provider_payload(merged, obs_key, 'virustotal')
    if vt_payload:
        benign_like = int(vt_payload.get('malicious') or 0) == 0 and int(vt_payload.get('suspicious') or 0) == 0

    query_param_count = len(parse_qsl(urlparse(final_url or obs_key.split(':', 1)[1]).query, keep_blank_values=True))
    return benign_like and (query_param_count >= 3 or request_count >= 120 or observed_domain_count >= 20)


def _candidate_is_destination_context(state: dict[str, Any], pivot: dict[str, Any]) -> bool:
    source_node = pivot.get('source_node') or _seed_key_from_state(state)
    rel = pivot.get('source_relation', '')
    if rel in {'final_domain', 'final_url', 'resolves_to'}:
        return _observable_is_high_fanout_sink(state, source_node)
    if rel in {'observed_domain', 'observed_url', 'observed_ip', 'observed_hash'}:
        return _observable_is_high_fanout_sink(state, source_node)
    return False


def _impact_label(usefulness: int) -> str:
    if usefulness <= 0:
        return 'dead end'
    if usefulness <= 8:
        return 'limited additional context'
    if usefulness <= 20:
        return 'useful supporting context'
    return 'one of the most productive pivots'


def _format_type_breakdown(type_counts: dict[str, int]) -> str:
    if not type_counts:
        return 'no new observables'
    ordered = sorted(type_counts.items(), key=lambda item: (-item[1], item[0]))
    parts = [f"{count} {kind}{'' if count == 1 else 's'}" for kind, count in ordered]
    if len(parts) == 1:
        return parts[0]
    if len(parts) == 2:
        return f"{parts[0]} and {parts[1]}"
    return ', '.join(parts[:-1]) + f", and {parts[-1]}"


def _is_invalid_or_noisy_candidate(kind: str, value: str) -> bool:
    clean = (value or "").strip().lower()
    if not clean or clean == "invalid":
        return True

    if kind == "url":
        parsed = urlparse(clean)
        path = (parsed.path or "").lower()
        if path.endswith("favicon.ico"):
            return True
        if path.endswith(".gif") and "tracker" in clean:
            return True
        if len(parse_qsl(parsed.query, keep_blank_values=True)) >= 6:
            return True
    return False


def _is_isolated_artifact(candidate: dict[str, Any]) -> bool:
    summary = candidate.get("summary", {})
    outbound = summary.get("outbound_relations", {}) or {}
    inbound = summary.get("inbound_relations", {}) or {}
    providers = summary.get("providers", {}) or {}
    derived = summary.get("derived_findings", []) or []

    if outbound:
        return False
    if derived:
        return False
    if any(payload for payload in providers.values() if payload):
        return False
    return sum(inbound.values()) <= 1


def _top_relation_counts(merged, obs_key: str) -> tuple[dict[str, int], dict[str, int], list[dict[str, str]]]:
    relations = getattr(merged, "relations", []) or []
    outbound: dict[str, int] = {}
    inbound: dict[str, int] = {}
    derived: list[dict[str, str]] = []

    for rel in relations:
        if rel.src == obs_key:
            outbound[rel.rel] = outbound.get(rel.rel, 0) + 1
        if rel.dst == obs_key:
            inbound[rel.rel] = inbound.get(rel.rel, 0) + 1
        if rel.src == obs_key and getattr(rel, "source", "") == "rules_engine":
            derived.append({"rel": rel.rel, "dst": rel.dst})

    return dict(sorted(outbound.items())), dict(sorted(inbound.items())), derived[:4]


def build_observable_snapshot(merged, obs_key: str) -> dict[str, Any]:
    evidence = getattr(merged, "evidence", {}) or {}
    observables = getattr(merged, "observables", {}) or {}

    provider_payload: dict[str, Any] = {}
    raw_payload = _safe_dict(evidence.get(obs_key))
    for provider_name, payload in raw_payload.items():
        compact = _compact_provider_payload(_safe_dict(payload))
        if compact:
            provider_payload[provider_name] = compact

    outbound, inbound, derived = _top_relation_counts(merged, obs_key)

    snapshot: dict[str, Any] = {
        "observable_present": obs_key in observables,
        "providers": provider_payload,
        "outbound_relations": outbound,
        "inbound_relations": inbound,
        "derived_findings": derived,
    }

    if obs_key.startswith("url:"):
        snapshot["url_shape"] = _url_shape_summary(obs_key.split(":", 1)[1])

    return snapshot


def build_history_payload(state: dict[str, Any], limit: int = 4) -> list[dict[str, Any]]:
    history = state.get("pivot_history", []) or []
    trimmed = history[-limit:]

    return [
        {
            "iteration": item.get("iteration"),
            "phase": item.get("phase"),
            "key": item.get("key"),
            "kind": item.get("kind"),
            "value": item.get("value"),
            "family": item.get("family"),
            "group": item.get("group"),
            "role": item.get("role"),
            "source_relation": item.get("source_relation"),
            "usefulness": item.get("usefulness"),
            "dead_end": item.get("usefulness", 0) == 0,
            "expanded": item.get("expanded"),
            "llm_reason": item.get("llm_reason", ""),
        }
        for item in trimmed
    ]


def _phase_role_priority(phase: str) -> dict[str, int]:
    if phase == "seed_characterization":
        return {"core": 0, "lateral": 1, "artifact": 4, "secondary": 5}
    if phase == "lateral_correlation":
        return {"lateral": 0, "core": 1, "artifact": 4, "secondary": 5}
    if phase == "artifact_enrichment":
        return {"artifact": 0, "core": 1, "lateral": 2, "secondary": 4}
    return {"core": 0, "lateral": 1, "artifact": 2, "secondary": 3}


def build_candidate_payload(state: dict[str, Any], limit: int = 4) -> list[dict[str, Any]]:
    """Build a small, high-signal candidate set for the semantic selector."""
    merged = state.get("merged_state")
    if merged is None:
        return []

    phase = state.get("investigation_phase", "seed_characterization")
    pending = state.get("pending_pivots", []) or []
    processed = set(state.get("processed_pivots", []) or [])
    expanded = getattr(merged, "expanded_iocs", set()) or set()
    history = state.get("pivot_history", []) or []

    explored_families: dict[str, int] = {}
    for item in history:
        family = item.get("family")
        if family:
            explored_families[family] = explored_families.get(family, 0) + 1

    raw_candidates: list[dict[str, Any]] = []

    for pivot in pending:
        obs_key = f"{pivot['kind']}:{pivot['value']}"
        if obs_key in processed or obs_key in expanded:
            continue
        if _is_invalid_or_noisy_candidate(pivot["kind"], pivot["value"]):
            continue

        family = _family_key(pivot["kind"], pivot["value"])
        role = _candidate_role(pivot["kind"], pivot["source_relation"], pivot["value"])
        summary = build_observable_snapshot(merged, obs_key)

        candidate = {
            "key": obs_key,
            "kind": pivot["kind"],
            "value": pivot["value"],
            "family": family,
            "group": pivot.get("group") or pivot["source_relation"],
            "role": role,
            "source_relation": pivot["source_relation"],
            "source_relation_id": pivot["source_relation_id"],
            "base_score": pivot["base_score"],
            "structural_score": pivot["score"],
            "already_explored_family_count": explored_families.get(family, 0),
            "summary": summary,
        }

        # Phase-aware filtering.
        if phase == "seed_characterization" and role == "artifact":
            continue
        if phase == "lateral_correlation" and role == "artifact" and _is_isolated_artifact(candidate):
            continue
        if phase == "lateral_correlation" and role == "core" and candidate["source_relation"] == "final_url":
            # Once the landing chain has been resolved, lateral correlation should
            # prefer parallel infrastructure over re-expanding the same landing URL.
            continue

        raw_candidates.append(candidate)

    role_priority = _phase_role_priority(phase)
    raw_candidates.sort(
        key=lambda c: (
            role_priority.get(c["role"], 9),
            c["already_explored_family_count"],
            -c["structural_score"],
            c["key"],
        )
    )

    selected: list[dict[str, Any]] = []
    used_families: set[str] = set()

    for candidate in raw_candidates:
        if candidate["family"] in used_families:
            continue
        selected.append(candidate)
        used_families.add(candidate["family"])
        if len(selected) >= limit:
            return selected

    for candidate in raw_candidates:
        if candidate in selected:
            continue
        selected.append(candidate)
        if len(selected) >= limit:
            break

    return selected


def build_supported_findings(state: dict[str, Any], limit: int = 12) -> list[str]:
    """Build a grounded list of reportable findings.

    The summary LLM should consume these facts instead of the full raw graph.
    """
    merged = state.get("merged_state")
    if merged is None:
        return []

    findings: list[str] = []
    for rel in getattr(merged, "relations", []) or []:
        if rel.source == "rules_engine":
            findings.append(f"Derived finding: {rel.src} --{rel.rel}--> {rel.dst}")
            continue
        if rel.rel in {"has_vt_verdict", "final_domain", "final_url", "resolves_to", "uses_certificate", "uses_asn", "owned_by", "hosted_by", "categorized_as"}:
            findings.append(f"Observed relation: {rel.src} --{rel.rel}--> {rel.dst}")

    # Keep stable order but remove duplicates.
    deduped: list[str] = []
    seen: set[str] = set()
    for item in findings:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped[:limit]


def build_core_artifacts(state: dict[str, Any]) -> list[str]:
    merged = state.get("merged_state")
    if merged is None:
        return []

    candidates = []
    for rel in getattr(merged, "relations", []) or []:
        if rel.rel in {"final_domain", "final_url", "resolves_to"}:
            candidates.append(rel.dst)

    deduped: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped[:8]



def _count_added(item: dict[str, Any], field: str) -> int:
    """Return an added_* count regardless of old or new history shape."""
    count_field = f"{field}_count"
    if count_field in item:
        return int(item.get(count_field) or 0)

    value = item.get(field)
    if isinstance(value, list):
        return len(value)

    return int(value or 0)


def build_family_rollup(state: dict[str, Any], limit: int = 4) -> list[dict[str, Any]]:
    history = state.get('pivot_history', []) or []
    grouped: dict[str, dict[str, Any]] = {}
    for item in history:
        family = item.get('family')
        if not family:
            continue
        bucket = grouped.setdefault(family, {
            'family': family.split(':', 1)[-1],
            'expansions': 0,
            'relations': 0,
            'evidence': 0,
            'type_counts': Counter(),
            'examples': [],
            'phase': item.get('phase'),
        })
        bucket['expansions'] += 1
        bucket['relations'] += _count_added(item, 'added_relations')
        bucket['evidence'] += _count_added(item, 'added_evidence')
        bucket['type_counts'].update(item.get('added_observable_types') or {})
        if len(bucket['examples']) < 3:
            bucket['examples'].append(item.get('value'))

    ranked = sorted(grouped.values(), key=lambda x: (-(x['relations'] + x['evidence']), -x['expansions'], x['family']))
    output = []
    for item in ranked[:limit]:
        output.append({
            'family': item['family'],
            'expansions': item['expansions'],
            'relations': item['relations'],
            'evidence': item['evidence'],
            'observable_types': dict(item['type_counts']),
            'examples': item['examples'],
        })
    return output


def build_top_pivot_summaries(state: dict[str, Any], limit: int = 4) -> list[dict[str, Any]]:
    history = state.get('pivot_history', []) or []
    ranked = sorted(history, key=lambda item: (-(_count_added(item, 'added_relations') + _count_added(item, 'added_evidence') + _count_added(item, 'added_observables')), item.get('iteration', 0)))
    output = []
    for item in ranked[:limit]:
        output.append({
            'artifact': item.get('value'),
            'kind': item.get('kind'),
            'phase': item.get('phase'),
            'impact': item.get('impact_label', _impact_label(int(item.get('usefulness') or 0))),
            'added_relations': _count_added(item, 'added_relations'),
            'added_evidence': _count_added(item, 'added_evidence'),
            'observable_types': item.get('added_observable_types') or {},
        })
    return output


def build_low_value_paths(state: dict[str, Any]) -> list[dict[str, Any]]:
    history = state.get('pivot_history', []) or []
    items = []
    for item in history:
        if int(item.get('usefulness') or 0) > 0:
            continue
        items.append({
            'artifact': item.get('value'),
            'kind': item.get('kind'),
            'phase': item.get('phase'),
            'reason': 'did not add meaningful new context',
        })
    return items[:4]


def build_summary_context(state: dict[str, Any]) -> dict[str, Any]:
    return {
        'seed': {'value': state.get('seed_value'), 'type': state.get('seed_type')},
        'iterations_completed': state.get('iteration'),
        'phase_at_stop': state.get('investigation_phase'),
        'stop_reason': state.get('stop_reason'),
        'supported_findings': build_supported_findings(state, limit=14),
        'core_artifacts': build_core_artifacts(state),
        'top_pivots': build_top_pivot_summaries(state),
        'family_rollup': build_family_rollup(state),
        'low_value_paths': build_low_value_paths(state),
    }


# ---------------------------------------------------------------------------
# Prompt execution
# ---------------------------------------------------------------------------

def _extract_first_json_object(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if not text:
        return None

    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        pass

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None

    try:
        parsed = json.loads(match.group(0))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def _invoke_text(prompt: str, *, json_mode: bool) -> str | None:
    try:
        backend = _build_chat_model()
    except Exception as e:
        print(f"[llm] model bootstrap failed: {type(e).__name__}: {e}")
        return None

    if backend is None:
        print("[llm] no model available")
        return None

    try:
        print("[llm] invoking semantic backend...")
        t0 = time.perf_counter()

        if backend.mode == "chat_ollama":
            response = backend.model.invoke(prompt)
            content = getattr(response, "content", response)
            if isinstance(content, list):
                text = "\n".join(str(part) for part in content)
            else:
                text = str(content)
        elif backend.mode == "anthropic":
            response = backend.model.messages.create(
                model=backend.model_name,
                max_tokens=600 if json_mode else 700,
                temperature=0.0,
                messages=[{"role": "user", "content": prompt}],
            )
            parts: list[str] = []
            for block in getattr(response, "content", []) or []:
                block_text = getattr(block, "text", None)
                if block_text:
                    parts.append(block_text)
            text = "\n".join(parts)
        else:
            raise RuntimeError(f"Unsupported backend mode: {backend.mode}")

        dt = time.perf_counter() - t0
        print(f"[llm] response received in {dt:.2f}s")
        return text.strip() or None
    except Exception as e:
        print(f"[llm] invoke failed: {type(e).__name__}: {e}")
        return None


def _invoke_json_with_raw(prompt: str) -> tuple[dict[str, Any] | None, str | None]:
    """Invoke a JSON-mode prompt and keep the raw model output for tracing."""
    text = _invoke_text(prompt, json_mode=True)
    if not text:
        return None, None

    parsed = _extract_first_json_object(text)
    if parsed is None:
        print("[llm] failed to parse JSON response")
        return None, text

    return parsed, text


def _invoke_json(prompt: str) -> dict[str, Any] | None:
    parsed, _raw_text = _invoke_json_with_raw(prompt)
    return parsed


# ---------------------------------------------------------------------------
# Public semantic decisions
# ---------------------------------------------------------------------------

def choose_pivot_with_llm(state: dict[str, Any]) -> dict[str, Any] | None:
    candidates = build_candidate_payload(state)
    print(f"[llm] choose_pivot candidates={len(candidates)}")

    if not candidates:
        print("[llm] choose_pivot skipped: no candidates")
        return None

    phase = state.get("investigation_phase", "seed_characterization")
    phase_guidance = {
        "seed_characterization": "Prioritize pivots that better explain the main landing chain, the final domain, the final URL, or the main IP infrastructure. Avoid isolated file artifacts at this stage.",
        "artifact_enrichment": "Prioritize only central artifacts that are clearly tied to the seed. Avoid isolated or weakly connected artifacts.",
        "lateral_correlation": "Prioritize parallel or related infrastructure that may reveal similar assets, related domains, or campaign overlap. Prefer domain/IP-level parallels over isolated hashes.",
        "closure": "If no candidate is clearly worth exploring, return null.",
    }.get(phase, "Prefer candidates that materially improve understanding of the case.")

    prompt = f"""
You are a CTI analyst helping choose the next pivot in an automated investigation.

Current phase: {phase}
Phase guidance: {phase_guidance}

Goal:
- Select ONE candidate that is most likely to add meaningful investigative value.
- Prefer candidates that fit the current phase objective.
- Avoid low-value telemetry, repeated family exploration, and isolated artifacts unless they are clearly justified.

Context:
- seed_value: {state.get('seed_value')}
- seed_type: {state.get('seed_type')}
- iteration: {state.get('iteration')}
- recent_history: {json.dumps(build_history_payload(state), ensure_ascii=False)}
- candidates: {json.dumps(candidates, ensure_ascii=False)}

Return strict JSON with exactly this shape:
{{
  "selected_key": "kind:value or null",
  "reason": "short explanation in English",
  "confidence": 0.0,
  "strategy": "short_label_in_english"
}}

If no candidate is worth pursuing, return selected_key=null.
Do not include any text outside the JSON.
"""

    parsed, raw_text = _invoke_json_with_raw(prompt)
    if not parsed:
        print("[llm] choose_pivot got no parsed response")
        return None

    result = {
        "selected_key": parsed.get("selected_key"),
        "reason": parsed.get("reason", ""),
        "confidence": parsed.get("confidence", 0.0),
        "strategy": parsed.get("strategy", ""),
        "llm_trace": {
            "purpose": "pivot_selection",
            "prompt": prompt.strip(),
            "raw_response": raw_text,
            "parsed_response": parsed,
        },
    }
    print("[llm] choose_pivot decision received")
    return result


def decide_continue_with_llm(state: dict[str, Any]) -> dict[str, Any] | None:
    candidates = build_candidate_payload(state, limit=4)
    print(f"[llm] decide_continue candidates={len(candidates)}")

    phase = state.get("investigation_phase", "seed_characterization")
    prompt = f"""
You are evaluating whether an automated CTI investigation still has meaningful marginal value.

Current phase: {phase}
Goal:
- decide "continue" or "stop"
- stop if the remaining pivots mostly look like low-value branches, repeated families, isolated artifacts, or exhausted lateral leads
- continue only if there are still strong pivots that can materially improve understanding of the case

Context:
- seed_value: {state.get('seed_value')}
- iteration: {state.get('iteration')}
- max_iterations: {state.get('max_iterations')}
- phase: {phase}
- stagnation_count: {state.get('stagnation_count')}
- dead_end_count: {state.get('dead_end_count')}
- recent_history: {json.dumps(build_history_payload(state), ensure_ascii=False)}
- remaining_candidates: {json.dumps(candidates, ensure_ascii=False)}

Return strict JSON with exactly this shape:
{{
  "decision": "continue or stop",
  "reason": "short explanation in English",
  "confidence": 0.0
}}

Do not include any text outside the JSON.
"""

    parsed, raw_text = _invoke_json_with_raw(prompt)
    if not parsed:
        print("[llm] decide_continue got no parsed response")
        return None

    decision = str(parsed.get("decision", "")).strip().lower()
    if decision not in {"continue", "stop"}:
        print(f"[llm] invalid decision from model: {decision!r}")
        return None

    result = {
        "decision": decision,
        "reason": parsed.get("reason", ""),
        "confidence": parsed.get("confidence", 0.0),
        "llm_trace": {
            "purpose": "continue_stop",
            "prompt": prompt.strip(),
            "raw_response": raw_text,
            "parsed_response": parsed,
        },
    }
    print("[llm] continue/stop decision received")
    return result


def _final_summary_prompt_and_context(state: dict[str, Any]) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    merged = state.get("merged_state")
    if merged is None:
        print("[llm] final_summary skipped: no merged_state")
        return None, None

    summary_context = build_summary_context(state)

    prompt = f"""
Write an analyst closing note in English for another CTI analyst.

Requirements:
- Ground every important claim in the provided case context.
- Use concrete examples from the case by name.
- Use numbers when they strengthen the conclusion.
- Do not expose internal metric names such as usefulness, impact_label, or structural_score. Translate internal impact into plain analyst language.
- When discussing new observables, say what kinds of observables they were (for example domains, IPs, URLs, hashes, certificates, categories, hostnames).
- Explain not only what was found, but also how the investigation progressed and which branches were lower value.
- Separate fact from interpretation. Use words like suggests, likely, or may indicate when needed.

Grounded case context:
{json.dumps(summary_context, ensure_ascii=False)}

Write 4 to 7 short paragraphs. Cover:
1. suspicious entrypoint and strongest signals
2. most important pivots with concrete examples and numbers
3. recurring lateral families, if any, with counts and why they matter
4. lower-value or remaining weaker paths
5. final analytic judgment and next step
"""
    return prompt, summary_context


def build_final_summary_with_llm(state: dict[str, Any]) -> str | None:
    payload = build_final_summary_with_llm_payload(state)
    if not payload:
        return None
    return payload["text"]


def build_final_summary_with_llm_payload(state: dict[str, Any]) -> dict[str, Any] | None:
    """Generate the final LLM note and return traceable prompt/output metadata."""
    prompt, summary_context = _final_summary_prompt_and_context(state)
    if not prompt:
        return None

    text = _invoke_text(prompt, json_mode=False)
    if not text:
        print("[llm] final_summary unavailable")
        return None

    final_text = text.strip()
    return {
        "text": final_text,
        "llm_trace": {
            "purpose": "final_summary",
            "prompt": prompt.strip(),
            "raw_response": final_text,
            "parsed_response": None,
            "context": summary_context,
        },
    }
