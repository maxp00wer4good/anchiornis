from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class NormalizedEntity:
    id: str
    kind: str
    value: str
    role: str
    data: Dict[str, Any] = field(default_factory=dict)
    primary: bool = False


@dataclass
class NormalizedLink:
    src_id: str
    dst_id: str
    rel: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedIntel:
    source: str
    raw: Dict[str, Any] = field(default_factory=dict)
    entities: List[NormalizedEntity] = field(default_factory=list)
    links: List[NormalizedLink] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)