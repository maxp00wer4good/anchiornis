import socket, re
from datetime import datetime, timezone
from typing import Optional, Any
from urllib.parse import urlparse


def safe_get_json(resp) -> dict:
    try:
        return resp.json()
    except Exception:
        return {}


def safe_len_or_bool(x: Any) -> int:
    if isinstance(x, list):
        return len(x)
    if isinstance(x, bool):
        return int(x)
    if isinstance(x, (int, float)):
        return int(x)
    return 0


def normalize_url(u: str) -> str:
    return u if u.startswith(("http://", "https://")) else "https://" + u


def extract_domain(value: str) -> Optional[str]:
    try:
        value = normalize_url(value)
        parsed = urlparse(value)
        return parsed.hostname
    except Exception:
        return None


def parse_iso_datetime(dt_str: Optional[str]) -> Optional[datetime]:
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return None


def days_since(dt_str: Optional[str]) -> Optional[int]:
    dt = parse_iso_datetime(dt_str)
    if not dt:
        return None
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt).days


def resolve_ip(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def detect_type(v: str) -> str:
    v = v.strip()

    if re.fullmatch(r"[a-fA-F0-9]{32}", v):
        return "md5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", v):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return "sha256"
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v):
        return "ip"
    if v.startswith(("http://", "https://")):
        return "url"
    if "." in v:
        return "domain"
    return "unknown"


def normalize_value(value: str) -> str:
    return value.strip().lower()


def normalize_kind(kind: str) -> str:
    return kind.strip().lower()


def ioc_key(value: str, kind: str) -> str:
    return f"{normalize_kind(kind)}:{normalize_value(value)}"


def observable_key(obs) -> str:
    return ioc_key(obs.value, obs.kind)


def step_key(tool: str, value: str, kind: str) -> str:
    return f"{tool.strip().lower()}:{ioc_key(value, kind)}"


def relation_key(src: str, rel: str, dst: str, source: str) -> str:
    return "||".join([
        normalize_value(src),
        normalize_value(rel),
        normalize_value(dst),
        normalize_value(source or ""),
    ])


def canonical_relation_name(rel: str) -> str:
    rel = normalize_value(rel)

    mapping = {
        "hosted_by": "owned_by",
        "owned_by": "owned_by",
        "announced_by": "uses_asn",
        "uses_asn": "uses_asn",
        "analyzed_as_url": "normalized_url",
        "final_url": "normalized_url",
    }

    return mapping.get(rel, rel)


def semantic_relation_key(src: str, rel: str, dst: str) -> str:
    return "||".join([
        normalize_value(src),
        canonical_relation_name(rel),
        normalize_value(dst),
    ])


def relation_metrics(relations) -> dict:
    raw_keys = {
        relation_key(r.src, r.rel, r.dst, r.source)
        for r in relations
    }

    semantic_keys = {
        semantic_relation_key(r.src, r.rel, r.dst)
        for r in relations
    }

    return {
        "raw_count": len(raw_keys),
        "semantic_count": len(semantic_keys),
        "semantic_redundancy": len(raw_keys) - len(semantic_keys),
    }


def log_connector_start(connector: str, action: str, value: str) -> None:
    print(f"[connector] {connector} {action} start: {value}")


def log_connector_poll(connector: str, action: str, message: str) -> None:
    print(f"[connector] {connector} {action} poll: {message}")


def log_connector_done(connector: str, action: str, ok: bool, message: str = "") -> None:
    status = "ok" if ok else "error"
    if message:
        print(f"[connector] {connector} {action} done: {status} | {message}")
    else:
        print(f"[connector] {connector} {action} done: {status}")

def format_relation_brief(r) -> str:
    if isinstance(r, dict):
        rel_id = r.get("id", "?")
        src = r.get("src", "?")
        rel = r.get("rel", "?")
        dst = r.get("dst", "?")
        source = r.get("source", "?")
        return f"[{rel_id}] {src} --{rel}--> {dst} [{source}]"

    rel_id = getattr(r, "id", "?")
    src = getattr(r, "src", "?")
    rel = getattr(r, "rel", "?")
    dst = getattr(r, "dst", "?")
    source = getattr(r, "source", "?")
    return f"[{rel_id}] {src} --{rel}--> {dst} [{source}]"