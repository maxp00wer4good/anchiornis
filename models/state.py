from dataclasses import dataclass, field
from typing import Any, Dict, List, Set, Optional

from models.observable import Observable
from models.relation import Relation


@dataclass
class InvestigationState:
    # --- input inicial ---
    input_value: str
    input_type: str

    # --- inteligencia acumulada ---
    evidence: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    relations: List[Relation] = field(default_factory=list)

    # --- tracking de observables ---
    observables: Dict[str, Observable] = field(default_factory=dict)
    current: Optional[Observable] = None

    # --- control de exploración ---
    queue: List[Observable] = field(default_factory=list)
    seen: Set[str] = field(default_factory=set)

    # --- control de expansión ---
    expanded_iocs: Set[str] = field(default_factory=set)

    # --- idempotencia de herramientas ---
    executed_steps: Set[str] = field(default_factory=set)

    # --- scoring / output ---
    score: float = 0.0
    output: str = ""

    # --- resultado raíz (opcional, debugging / tracing) ---
    root_result: Dict[str, Any] = field(default_factory=dict)