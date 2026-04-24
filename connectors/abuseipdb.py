import requests

from core.helpers import safe_get_json, days_since
from models.normalized import NormalizedIntel, NormalizedEntity, NormalizedLink


def _safe_dict(value):
    return value if isinstance(value, dict) else {}


def _safe_list(value):
    return value if isinstance(value, list) else []


def _safe_str(value):
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _normalize_asn_value(value):
    if value is None:
        return None

    if isinstance(value, dict):
        value = (
            value.get("asn")
            or value.get("number")
            or value.get("id")
            or value.get("value")
        )

    if value is None:
        return None

    s = str(value).strip().upper()
    if not s:
        return None

    if s.startswith("AS"):
        s = s[2:].strip()

    return s or None


def _normalize_entity_value(kind: str, value):
    if value is None:
        return None

    if kind == "asn":
        return _normalize_asn_value(value)

    if kind in {"domain", "hostname"}:
        return str(value).strip().lower().rstrip(".")

    if kind == "url":
        return str(value).strip()

    if kind in {
        "country",
        "server",
        "tag",
        "certificate",
        "isp",
        "usage",
        "brand",
        "category",
        "cookie",
        "hash",
    }:
        return str(value).strip()

    return str(value).strip()


def _copy_all_top_level_attributes(data: dict, exclude: set | None = None) -> dict:
    exclude = exclude or set()
    return {k: v for k, v in data.items() if k not in exclude}


def _add_entity_unique(
    intel: NormalizedIntel,
    seen_roles: set,
    seen_entities: set,
    kind: str,
    value,
    role: str,
    data: dict | None = None,
):
    normalized_value = _normalize_entity_value(kind, value)
    if normalized_value is None or normalized_value == "" or role in seen_roles:
        return False

    entity_id = f"{kind}:{normalized_value}"
    if entity_id in seen_entities:
        return False

    intel.entities.append(
        NormalizedEntity(
            id=entity_id,
            kind=kind,
            value=normalized_value,
            role=role,
            data=data or {},
        )
    )
    seen_roles.add(role)
    seen_entities.add(entity_id)
    return True


def _safe_add_link(
    intel: NormalizedIntel,
    seen_roles: set,
    src_role: str,
    dst_role: str,
    rel: str,
    metadata: dict | None = None,
):
    if not src_role or not dst_role:
        return
    if src_role == dst_role:
        return
    if src_role not in seen_roles or dst_role not in seen_roles:
        return

    src_entity = next((e for e in intel.entities if e.role == src_role), None)
    dst_entity = next((e for e in intel.entities if e.role == dst_role), None)

    if not src_entity or not dst_entity:
        return

    intel.links.append(
        NormalizedLink(
            src_id=src_entity.id,
            dst_id=dst_entity.id,
            rel=rel,
            metadata=metadata or {},
        )
    )


def _log_start(action: str, value: str) -> None:
    print(f"[connector] abuseipdb {action} start: {value}", flush=True)


def _log_done(action: str, ok: bool, summary: str = "") -> None:
    status = "ok" if ok else "error"
    if summary:
        print(f"[connector] abuseipdb {action} done: {status} | {summary}", flush=True)
    else:
        print(f"[connector] abuseipdb {action} done: {status}", flush=True)


class AbuseIPDBClient:
    REQUIRED_FIELDS = [
        "ip",
        "is_public",
        "ip_version",
        "is_whitelisted",
        "score",
        "country",
        "usage_type",
        "isp",
        "domain",
        "hostnames",
        "is_tor",
        "reports",
        "distinct_users",
        "last_reported",
        "days_since_last_report",
    ]

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            "Key": api_key,
            "Accept": "application/json",
        } if api_key else {}

    def get_ip(self, ip: str) -> dict:
        if not self.api_key:
            _log_done("get_ip", False, "missing api key")
            return {"error": "No AbuseIPDB API key"}

        _log_start("get_ip", ip)

        try:
            r = requests.get(
                f"{self.base_url}/check",
                headers=self.headers,
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                    "verbose": True,
                },
                timeout=30,
            )
        except requests.RequestException as e:
            _log_done("get_ip", False, f"request_exception={e}")
            return {
                "error": str(e),
                "_all_fields_ready": False,
            }

        if r.status_code == 429:
            _log_done("get_ip", False, "rate_limited")
            return {
                "error": "rate_limited",
                "_all_fields_ready": False,
            }

        if r.status_code != 200:
            _log_done("get_ip", False, f"http_status={r.status_code}")
            return {
                "error": f"status {r.status_code}",
                "_all_fields_ready": False,
                "body": r.text,
            }

        payload = safe_get_json(r)
        data = payload.get("data", {}) or {}

        result = {
            "ip": data.get("ipAddress"),
            "ip_address": data.get("ipAddress"),
            "is_public": data.get("isPublic"),
            "ip_version": data.get("ipVersion"),
            "is_whitelisted": data.get("isWhitelisted"),
            "score": data.get("abuseConfidenceScore"),
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "hostnames": data.get("hostnames"),
            "is_tor": data.get("isTor"),
            "reports": data.get("totalReports"),
            "total_reports": data.get("totalReports"),
            "distinct_users": data.get("numDistinctUsers"),
            "num_distinct_users": data.get("numDistinctUsers"),
            "last_reported": data.get("lastReportedAt"),
            "last_reported_at": data.get("lastReportedAt"),
            "days_since_last_report": days_since(data.get("lastReportedAt")),
            "data": data,
            "raw": payload,
        }

        result["_all_fields_ready"] = all(
            result.get(field) is not None for field in self.REQUIRED_FIELDS
        )

        missing = [f for f in self.REQUIRED_FIELDS if result.get(f) is None]

        _log_done(
            "get_ip",
            True,
            f"all_ready={result.get('_all_fields_ready')} missing={missing}",
        )

        result.pop("_all_fields_ready", None)
        return result


def normalize_abuse(root_kind: str, root_value: str, data: dict) -> NormalizedIntel:
    intel = NormalizedIntel(
        source="abuseipdb",
        raw=data,
        attributes=_copy_all_top_level_attributes(data, exclude={"raw"}),
    )

    seen_roles = set()
    seen_entities = set()

    _add_entity_unique(intel, seen_roles, seen_entities, root_kind, root_value, "root")

    ip_value = data.get("ip") or data.get("ip_address")
    if ip_value:
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "ip",
            ip_value,
            "checked_ip",
            data={
                "score": data.get("score"),
                "reports": data.get("reports"),
                "distinct_users": data.get("distinct_users"),
                "is_tor": data.get("is_tor"),
                "is_public": data.get("is_public"),
                "is_whitelisted": data.get("is_whitelisted"),
                "ip_version": data.get("ip_version"),
                "last_reported": data.get("last_reported"),
                "days_since_last_report": data.get("days_since_last_report"),
            },
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "checked_ip", "checked_as_ip")

    if data.get("isp"):
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "isp",
            data["isp"],
            "isp",
        )
        if added:
            if "checked_ip" in seen_roles:
                _safe_add_link(intel, seen_roles, "checked_ip", "isp", "hosted_by")
            else:
                _safe_add_link(intel, seen_roles, "root", "isp", "hosted_by")

    if data.get("country"):
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "country",
            data["country"],
            "country",
        )
        if added:
            if "checked_ip" in seen_roles:
                _safe_add_link(intel, seen_roles, "checked_ip", "country", "located_in")
            else:
                _safe_add_link(intel, seen_roles, "root", "country", "located_in")

    if data.get("usage_type"):
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "usage",
            data["usage_type"],
            "usage_type",
        )
        if added:
            if "checked_ip" in seen_roles:
                _safe_add_link(intel, seen_roles, "checked_ip", "usage_type", "usage_type")
            else:
                _safe_add_link(intel, seen_roles, "root", "usage_type", "usage_type")

    if data.get("domain"):
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "domain",
            data["domain"],
            "abuse_domain",
        )
        if added:
            if "checked_ip" in seen_roles:
                _safe_add_link(intel, seen_roles, "checked_ip", "abuse_domain", "associated_domain")
            else:
                _safe_add_link(intel, seen_roles, "root", "abuse_domain", "associated_domain")

    for idx, hostname in enumerate(_safe_list(data.get("hostnames"))):
        if not hostname:
            continue

        role = f"hostname_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "hostname",
            hostname,
            role,
            data={"position": idx},
        )
        if added:
            if "checked_ip" in seen_roles:
                _safe_add_link(intel, seen_roles, "checked_ip", role, "reverse_dns", {"position": idx})
            else:
                _safe_add_link(intel, seen_roles, "root", role, "reverse_dns", {"position": idx})

    return intel