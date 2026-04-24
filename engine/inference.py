from __future__ import annotations

from collections import defaultdict
from typing import Any

from models import Relation


Bindings = dict[str, str]
Context = dict[str, Any]


def deduplicate_relations_with_discards(
    relations: list[Relation],
) -> tuple[list[Relation], list[Relation]]:
    seen = set()
    unique = []
    discarded = []

    for rel in relations:
        key = (rel.src, rel.rel, rel.dst)
        if key not in seen:
            seen.add(key)
            unique.append(rel)
        else:
            discarded.append(rel)

    return unique, discarded


def deduplicate_relations(relations: list[Relation]) -> list[Relation]:
    unique, _ = deduplicate_relations_with_discards(relations)
    return unique


def index_relations_by_src(relations: list[Relation]) -> dict[str, list[Relation]]:
    by_src: dict[str, list[Relation]] = defaultdict(list)
    for rel in relations:
        by_src[rel.src].append(rel)
    return by_src


def is_var(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("?")


def resolve_value(value: str, bindings: Bindings) -> str | None:
    if is_var(value):
        return bindings.get(value)
    return value


def resolve_values(values: list[str], bindings: Bindings) -> list[str]:
    resolved: list[str] = []
    for value in values:
        rv = resolve_value(value, bindings)
        if rv is not None:
            resolved.append(rv)
    return resolved


def bind_value(bindings: Bindings, var_name: str, value: str) -> Bindings | None:
    if var_name in bindings:
        return bindings if bindings[var_name] == value else None

    new_bindings = dict(bindings)
    new_bindings[var_name] = value
    return new_bindings


def _contains_any_casefold(haystack: str, needles: list[str]) -> bool:
    haystack_lower = haystack.lower()
    return any(needle.lower() in haystack_lower for needle in needles)


def _contains_all_casefold(haystack: str, needles: list[str]) -> bool:
    haystack_lower = haystack.lower()
    return all(needle.lower() in haystack_lower for needle in needles)


def relation_matches_step(
    rel: Relation,
    step: dict[str, Any],
    bindings: Bindings,
) -> tuple[Bindings | None, bool]:
    new_bindings = dict(bindings)

    expected_src = step.get("source")
    if expected_src is not None:
        resolved_src = resolve_value(expected_src, new_bindings)
        if resolved_src is None or rel.src != resolved_src:
            return None, False

    expected_rel = step.get("rel")
    if expected_rel is not None and rel.rel != expected_rel:
        return None, False

    expected_rel_in = step.get("rel_in")
    if expected_rel_in is not None and rel.rel not in expected_rel_in:
        return None, False

    expected_dst = step.get("dst")
    if expected_dst is not None:
        resolved_dst = resolve_value(expected_dst, new_bindings)
        if resolved_dst is None or rel.dst != resolved_dst:
            return None, False

    expected_dst_in = step.get("dst_in")
    if expected_dst_in is not None and rel.dst not in expected_dst_in:
        return None, False

    expected_dst_contains = step.get("dst_contains")
    if expected_dst_contains is not None:
        if expected_dst_contains.lower() not in rel.dst.lower():
            return None, False

    expected_dst_not_contains = step.get("dst_not_contains")
    if expected_dst_not_contains is not None:
        if expected_dst_not_contains.lower() in rel.dst.lower():
            return None, False

    expected_dst_contains_any = step.get("dst_contains_any")
    if expected_dst_contains_any is not None:
        if not _contains_any_casefold(rel.dst, expected_dst_contains_any):
            return None, False

    expected_dst_not_contains_any = step.get("dst_not_contains_any")
    if expected_dst_not_contains_any is not None:
        if _contains_any_casefold(rel.dst, expected_dst_not_contains_any):
            return None, False

    expected_dst_contains_vars = step.get("dst_contains_vars")
    if expected_dst_contains_vars is not None:
        resolved_needles = resolve_values(expected_dst_contains_vars, new_bindings)
        if len(resolved_needles) != len(expected_dst_contains_vars):
            return None, False
        if not _contains_all_casefold(rel.dst, resolved_needles):
            return None, False

    expected_dst_not_contains_vars = step.get("dst_not_contains_vars")
    if expected_dst_not_contains_vars is not None:
        resolved_needles = resolve_values(expected_dst_not_contains_vars, new_bindings)
        if len(resolved_needles) != len(expected_dst_not_contains_vars):
            return None, False
        if _contains_any_casefold(rel.dst, resolved_needles):
            return None, False

    bind_dst = step.get("bind_dst")
    if bind_dst is not None:
        updated = bind_value(new_bindings, bind_dst, rel.dst)
        if updated is None:
            return None, False
        new_bindings = updated

    bind_src = step.get("bind_src")
    if bind_src is not None:
        updated = bind_value(new_bindings, bind_src, rel.src)
        if updated is None:
            return None, False
        new_bindings = updated

    return new_bindings, True


def iter_scope_subjects(
    relations: list[Relation],
    rule: dict[str, Any],
) -> list[str]:
    scope = rule.get("scope", {})
    subject_prefix = scope.get("subject_prefix")

    subjects = sorted({rel.src for rel in relations})

    if subject_prefix:
        subjects = [subject for subject in subjects if subject.startswith(subject_prefix)]

    return subjects


def execute_match_step(
    step: dict[str, Any],
    context: Context,
    relations: list[Relation],
    by_src: dict[str, list[Relation]],
) -> list[Context]:
    del by_src

    step_name = step["name"]
    output_contexts: list[Context] = []

    for row in context["rows"]:
        bindings: Bindings = row["bindings"]
        used_relations: list[Relation] = row["used_relations"]

        matched_rows = []
        matched_relations = []

        for rel in relations:
            updated_bindings, matched = relation_matches_step(rel, step, bindings)
            if not matched or updated_bindings is None:
                continue

            matched_rows.append(
                {
                    "bindings": updated_bindings,
                    "used_relations": used_relations + [rel],
                }
            )
            matched_relations.append(rel)

        next_collections = dict(context["collections"])
        next_collections[step_name] = matched_relations

        if matched_rows:
            output_contexts.append(
                {
                    "rows": matched_rows,
                    "collections": next_collections,
                }
            )
        else:
            output_contexts.append(
                {
                    "rows": [
                        {
                            "bindings": dict(bindings),
                            "used_relations": list(used_relations),
                        }
                    ],
                    "collections": next_collections,
                }
            )

    return output_contexts


def execute_match_one_step(
    step: dict[str, Any],
    context: Context,
    relations: list[Relation],
    by_src: dict[str, list[Relation]],
) -> list[Context]:
    step_name = step["name"]
    next_contexts: list[Context] = []

    for current in context["rows"]:
        bindings: Bindings = current["bindings"]
        used_relations: list[Relation] = current["used_relations"]

        source = step.get("source")
        candidate_relations: list[Relation]

        if source is not None:
            resolved_source = resolve_value(source, bindings)
            if resolved_source is None:
                candidate_relations = []
            else:
                candidate_relations = by_src.get(resolved_source, [])
        else:
            candidate_relations = relations

        chosen_rel: Relation | None = None
        updated_bindings: Bindings | None = None

        for rel in candidate_relations:
            maybe_bindings, matched = relation_matches_step(rel, step, bindings)
            if matched and maybe_bindings is not None:
                chosen_rel = rel
                updated_bindings = maybe_bindings
                break

        collections = dict(context["collections"])
        collections[step_name] = [chosen_rel] if chosen_rel is not None else []

        next_contexts.append(
            {
                "rows": [
                    {
                        "bindings": updated_bindings if updated_bindings is not None else dict(bindings),
                        "used_relations": used_relations + ([chosen_rel] if chosen_rel is not None else []),
                    }
                ],
                "collections": collections,
            }
        )

    return next_contexts


def execute_plan(
    rule: dict[str, Any],
    relations: list[Relation],
    by_src: dict[str, list[Relation]],
    initial_bindings: Bindings,
) -> list[Context]:
    contexts: list[Context] = [
        {
            "rows": [
                {
                    "bindings": dict(initial_bindings),
                    "used_relations": [],
                }
            ],
            "collections": {},
        }
    ]

    for step in rule.get("plan", []):
        op = step["op"]
        next_contexts: list[Context] = []

        for context in contexts:
            if op == "match":
                next_contexts.extend(execute_match_step(step, context, relations, by_src))
            elif op == "match_one":
                next_contexts.extend(execute_match_one_step(step, context, relations, by_src))
            else:
                raise ValueError(f"Unsupported plan op: {op}")

        contexts = next_contexts

    return contexts


def _condition_items(condition: dict[str, Any]) -> list[dict[str, Any]]:
    items = condition.get("items")
    if items is not None:
        return items

    conditions = condition.get("conditions")
    if conditions is not None:
        return conditions

    raise ValueError(f"Condition op={condition.get('op')} requires 'items' or 'conditions'")


def evaluate_condition(condition: dict[str, Any], context: Context) -> bool:
    op = condition["op"]

    if op in {"exists", "nonempty"}:
        collection_name = condition["collection"]
        return len(context["collections"].get(collection_name, [])) > 0

    if op == "count_gte":
        collection_name = condition["collection"]
        value = condition["value"]
        return len(context["collections"].get(collection_name, [])) >= value

    if op == "distinct_count_gte":
        collection_name = condition["collection"]
        field = condition["field"]
        value = condition["value"]

        items = context["collections"].get(collection_name, [])
        distinct_values = {getattr(item, field) for item in items}
        return len(distinct_values) >= value

    if op == "count_nonempty_gte":
        collection_names = condition["collections"]
        value = condition["value"]

        nonempty_count = sum(
            1 for name in collection_names if len(context["collections"].get(name, [])) > 0
        )
        return nonempty_count >= value

    if op == "contains":
        raw_value = condition["value"]
        substring = condition["substring"]

        bindings = context["rows"][0]["bindings"] if context["rows"] else {}
        value = resolve_value(raw_value, bindings)

        if value is None:
            return False

        return substring.lower() in value.lower()

    if op == "contains_any":
        raw_value = condition["value"]
        candidates = condition["candidates"]

        bindings = context["rows"][0]["bindings"] if context["rows"] else {}
        value = resolve_value(raw_value, bindings)

        if value is None:
            return False

        return _contains_any_casefold(value, candidates)

    if op == "count_true_gte":
        items = _condition_items(condition)
        value = condition["value"]
        true_count = sum(1 for item in items if evaluate_condition(item, context))
        return true_count >= value

    if op == "all":
        return all(evaluate_condition(item, context) for item in _condition_items(condition))

    if op == "any":
        return any(evaluate_condition(item, context) for item in _condition_items(condition))

    raise ValueError(f"Unsupported condition op: {op}")


def collect_evidence_items(context: Context) -> list[str]:
    evidence_items: list[str] = []

    for collection in context["collections"].values():
        for rel in collection:
            evidence_items.append(f"{rel.rel}:{rel.dst}")

    return sorted(set(evidence_items))


def collect_used_relations(context: Context) -> list[Relation]:
    used: list[Relation] = []

    for row in context["rows"]:
        used.extend(row["used_relations"])

    for collection in context["collections"].values():
        used.extend(collection)

    unique_by_id: dict[str, Relation] = {}
    for rel in used:
        unique_by_id[rel.id] = rel

    return list(unique_by_id.values())


def build_derived_relation(
    rule: dict[str, Any],
    emit: dict[str, str],
    bindings: Bindings,
    used_relations: list[Relation],
    evidence_items: list[str],
) -> Relation:
    src = resolve_value(emit["src"], bindings)
    dst = resolve_value(emit["dst"], bindings)

    if src is None:
        raise ValueError(f"Could not resolve src={emit['src']} for rule {rule['rule_id']}")
    if dst is None:
        raise ValueError(f"Could not resolve dst={emit['dst']} for rule {rule['rule_id']}")

    return Relation(
        src=src,
        rel=emit["rel"],
        dst=dst,
        source="rules_engine",
        metadata={
            "rule_id": rule["rule_id"],
            "input_relations": sorted({rel.id for rel in used_relations}),
            "relation_tier": "derived",
            "evidence": {
                "items": evidence_items,
                "count": len(evidence_items),
            },
        },
    )


def apply_rule(
    rule: dict[str, Any],
    relations: list[Relation],
    by_src: dict[str, list[Relation]],
) -> list[Relation]:
    results: list[Relation] = []
    scope = rule.get("scope", {})
    subject_var = scope.get("subject_var", "?u")

    for subject in iter_scope_subjects(relations, rule):
        initial_bindings = {subject_var: subject}
        contexts = execute_plan(rule, relations, by_src, initial_bindings)

        for context in contexts:
            condition = rule.get("condition")
            if condition is not None and not evaluate_condition(condition, context):
                continue

            used_relations = collect_used_relations(context)
            evidence_items = collect_evidence_items(context)

            bindings_candidates = [row["bindings"] for row in context["rows"]]
            if not bindings_candidates:
                bindings_candidates = [initial_bindings]

            for bindings in bindings_candidates:
                for emit in rule.get("emit", []):
                    results.append(
                        build_derived_relation(
                            rule=rule,
                            emit=emit,
                            bindings=bindings,
                            used_relations=used_relations,
                            evidence_items=evidence_items,
                        )
                    )

    return results


def run_inference(
    relations: list[Relation],
    rules: list[dict[str, Any]],
    debug: bool = False,
):
    by_src = index_relations_by_src(relations)
    derived_raw: list[Relation] = []

    for rule in rules:
        if not rule.get("enabled", True):
            continue
        derived_raw.extend(apply_rule(rule, relations, by_src))

    derived_unique, discarded_internal = deduplicate_relations_with_discards(derived_raw)

    if debug:
        return {
            "derived": derived_unique,
            "raw": derived_raw,
            "discarded_internal": discarded_internal,
        }

    return derived_unique