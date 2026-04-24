from engine.inference import run_inference
from engine.rules.loader import load_rules


def apply_inference(state):
    relations = state.relations
    rules = load_rules()

    derived = run_inference(relations, rules)

    existing = {(r.src, r.rel, r.dst) for r in relations}

    new_relations = []
    for rel in derived:
        key = (rel.src, rel.rel, rel.dst)
        if key not in existing:
            new_relations.append(rel)

    state.relations.extend(new_relations)
    return state