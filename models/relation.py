from dataclasses import dataclass, field
from typing import Any, Dict, Optional
import itertools
import inspect


_relation_counter = itertools.count(1)

# 🔥 flag global controlado desde main
_RELATION_DEBUG = False


def enable_relation_debug(enabled: bool):
    global _RELATION_DEBUG
    _RELATION_DEBUG = enabled


def make_relation_id() -> str:
    return f"r_{next(_relation_counter):06d}"


def _debug_relation_creation(rel: "Relation") -> None:
    if not _RELATION_DEBUG:
        return

    frame = inspect.stack()[2]
    location = f"{frame.filename}:{frame.lineno} ({frame.function})"

    print(
        "[RELATION_CREATED]",
        rel.id,
        rel.rel,
        rel.src,
        "->",
        rel.dst,
        "|",
        location,
    )


@dataclass
class Relation:
    src: str
    dst: str
    rel: str
    source: str = "derived"
    metadata: Dict[str, Any] = field(default_factory=dict)
    id: Optional[str] = None

    def __post_init__(self):
        if self.id is None:
            self.id = make_relation_id()

        _debug_relation_creation(self)