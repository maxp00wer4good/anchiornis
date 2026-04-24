from dataclasses import dataclass, field
from typing import Any, Dict

from core.helpers import ioc_key


@dataclass
class Observable:
    value: str
    kind: str
    source: str = "seed"
    priority: int = 100
    depth: int = 0
    data: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return ioc_key(self.value, self.kind)