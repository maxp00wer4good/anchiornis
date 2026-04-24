from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


RULES_DIR = Path(__file__).resolve().parent


def load_rules() -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []

    for path in sorted(RULES_DIR.rglob("*.yaml")):
        with path.open("r", encoding="utf-8") as f:
            rule = yaml.safe_load(f)

        if not rule:
            continue

        if not rule.get("enabled", True):
            continue

        rules.append(rule)

    return rules