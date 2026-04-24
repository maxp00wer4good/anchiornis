import base64

import requests

from core.helpers import safe_get_json, normalize_url
from core.polling import poll_until
from models.normalized import NormalizedIntel, NormalizedEntity, NormalizedLink


def _log_start(action: str, value: str) -> None:
    print(f"[connector] virustotal {action} start: {value}", flush=True)


def _log_poll(action: str, message: str) -> None:
    print(f"[connector] virustotal {action} poll: {message}", flush=True)


def _log_done(action: str, ok: bool, summary: str = "") -> None:
    status = "ok" if ok else "error"
    if summary:
        print(f"[connector] virustotal {action} done: {status} | {summary}", flush=True)
    else:
        print(f"[connector] virustotal {action} done: {status}", flush=True)


def _safe_dict(value):
    return value if isinstance(value, dict) else {}


def _safe_list(value):
    return value if isinstance(value, list) else []


def _safe_str(value):
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _is_skippable_url(value: str | None) -> bool:
    if not value:
        return True

    s = str(value).strip()
    if not s:
        return True
    if s.startswith("blob:"):
        return True
    if s.startswith("chrome-extension://"):
        return True
    if s.startswith("data:"):
        return True
    if len(s) > 2000:
        return True
    return False


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
        "engine",
        "verdict",
        "status",
        "signal",
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


def _first_present(*values):
    for value in values:
        if value is not None and value != "":
            return value
    return None


def _safe_int(value):
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_vt_stats(data: dict) -> dict:
    stats = _safe_dict(data.get("stats"))
    if stats:
        return stats

    attrs = _safe_dict(data.get("attributes"))
    return _safe_dict(attrs.get("stats"))


def _extract_vt_results(data: dict) -> dict:
    results = _safe_dict(data.get("results"))
    if results:
        return results

    attrs = _safe_dict(data.get("attributes"))
    return _safe_dict(attrs.get("results"))


def _build_vt_attributes(data: dict) -> dict:
    stats = _extract_vt_stats(data)
    results = _extract_vt_results(data)

    return {
        **_copy_all_top_level_attributes(data, exclude={"raw"}),
        "status": data.get("status"),
        "date": data.get("date"),
        "url": data.get("url"),
        "stats": stats,
        "results": results,
        "harmless": _safe_int(data.get("harmless") if data.get("harmless") is not None else stats.get("harmless")),
        "malicious": _safe_int(data.get("malicious") if data.get("malicious") is not None else stats.get("malicious")),
        "suspicious": _safe_int(data.get("suspicious") if data.get("suspicious") is not None else stats.get("suspicious")),
        "undetected": _safe_int(data.get("undetected") if data.get("undetected") is not None else stats.get("undetected")),
        "timeout": _safe_int(data.get("timeout") if data.get("timeout") is not None else stats.get("timeout")),
        "confirmed_timeout": _safe_int(
            data.get("confirmed_timeout")
            if data.get("confirmed_timeout") is not None
            else stats.get("confirmed_timeout")
        ),
        "failure": _safe_int(data.get("failure") if data.get("failure") is not None else stats.get("failure")),
        "type_unsupported": _safe_int(
            data.get("type_unsupported")
            if data.get("type_unsupported") is not None
            else stats.get("type_unsupported")
        ),
    }


class VirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": api_key} if api_key else {}

    def _vt_url_id(self, url: str) -> str:
        normalized = normalize_url(url)
        encoded = base64.urlsafe_b64encode(normalized.encode()).decode().strip("=")
        return encoded

    def submit_url(self, url: str) -> dict:
        if not self.api_key:
            _log_done("submit_url", False, "missing api key")
            return {"error": "No VT API key"}

        url = normalize_url(url)
        _log_start("submit_url", url)

        try:
            r = requests.post(
                f"{self.base_url}/urls",
                headers=self.headers,
                data={"url": url},
                timeout=30,
            )
        except requests.RequestException as e:
            _log_done("submit_url", False, f"request_exception={e}")
            return {"error": str(e)}

        if r.status_code == 409:
            data = safe_get_json(r)
            error_block = _safe_dict(data.get("error"))
            error_code = error_block.get("code") or "AlreadyExistsError"
            error_message = error_block.get("message") or "already exists"

            _log_done("submit_url", False, f"http_status=409 code={error_code}")
            return {
                "error": "already_exists",
                "status_code": 409,
                "error_code": error_code,
                "error_message": error_message,
                "body": data,
            }

        if r.status_code not in (200, 202):
            _log_done("submit_url", False, f"http_status={r.status_code}")
            return {
                "error": f"status {r.status_code}",
                "body": r.text,
            }

        data = safe_get_json(r)
        obj = data.get("data", {}) or {}
        analysis_id = obj.get("id")

        if not analysis_id:
            _log_done("submit_url", False, "missing analysis_id")
            return {"error": "no analysis_id", "body": data}

        _log_done("submit_url", True, f"analysis_id={analysis_id}")

        return {
            "analysis_id": analysis_id,
            "id": obj.get("id"),
            "type": obj.get("type"),
            "links": obj.get("links", {}) or {},
            "data": obj,
            "meta": data.get("meta", {}) or {},
            "raw": data,
        }

    def poll_analysis(
        self,
        analysis_id: str,
        timeout_seconds: int = 60,
        interval_seconds: int = 2,
    ) -> dict:
        if not self.api_key:
            _log_done("poll_analysis", False, "missing api key")
            return {"error": "No VT API key"}

        _log_start("poll_analysis", analysis_id)

        required_fields = [
            "harmless",
            "malicious",
            "suspicious",
            "undetected",
            "timeout",
        ]

        def fetch():
            try:
                r = requests.get(
                    f"{self.base_url}/analyses/{analysis_id}",
                    headers=self.headers,
                    timeout=30,
                )
            except requests.RequestException as e:
                return {
                    "error": str(e),
                    "_all_fields_ready": False,
                }

            if r.status_code == 429:
                return {
                    "error": "rate_limited",
                    "_all_fields_ready": False,
                    "status": "rate_limited",
                }

            if r.status_code != 200:
                return {
                    "error": f"status {r.status_code}",
                    "_all_fields_ready": False,
                    "status": "http_error",
                    "body": r.text,
                }

            data = safe_get_json(r)
            obj = data.get("data", {}) or {}
            attrs = obj.get("attributes", {}) or {}
            stats = attrs.get("stats", {}) or {}
            meta = data.get("meta", {}) or {}
            relationships = obj.get("relationships", {}) or {}

            result = {
                "analysis_id": obj.get("id"),
                "id": obj.get("id"),
                "type": obj.get("type"),
                "links": obj.get("links", {}) or {},
                "relationships": relationships,
                "data": obj,
                "attributes": attrs,
                "meta": meta,
                "status": attrs.get("status"),
                "date": attrs.get("date"),
                "url": attrs.get("url"),
                "stats": stats,
                "results": attrs.get("results", {}) or {},
                "harmless": stats.get("harmless"),
                "malicious": stats.get("malicious"),
                "suspicious": stats.get("suspicious"),
                "undetected": stats.get("undetected"),
                "timeout": stats.get("timeout"),
                "confirmed_timeout": stats.get("confirmed_timeout"),
                "failure": stats.get("failure"),
                "type_unsupported": stats.get("type_unsupported"),
                "raw": data,
            }

            result["_all_fields_ready"] = (
                result.get("status") == "completed"
                and all(result.get(field) is not None for field in required_fields)
            )

            return result

        def is_done(data: dict) -> bool:
            return data.get("_all_fields_ready", False) is True

        def on_tick(data: dict) -> None:
            missing = [f for f in required_fields if data.get(f) is None]
            _log_poll(
                "poll_analysis",
                (
                    f"status={data.get('status')} "
                    f"all_ready={data.get('_all_fields_ready')} "
                    f"missing={missing}"
                ),
            )

        result = poll_until(
            fetch_fn=fetch,
            is_done_fn=is_done,
            timeout_seconds=timeout_seconds,
            interval_seconds=interval_seconds,
            on_tick=on_tick,
        )

        if not result["ok"]:
            _log_done("poll_analysis", False, f"error={result['error']}")
            return {
                "error": result["error"],
                "last_data": result.get("last_data"),
            }

        data = result["data"].copy()
        data.pop("_all_fields_ready", None)

        _log_done(
            "poll_analysis",
            True,
            (
                f"status={data.get('status')} "
                f"malicious={data.get('malicious')} "
                f"suspicious={data.get('suspicious')}"
            ),
        )

        return data

    def lookup_url(self, url: str) -> dict:
        if not self.api_key:
            _log_done("lookup_url", False, "missing api key")
            return {"error": "No VT API key"}

        normalized = normalize_url(url)
        url_id = self._vt_url_id(normalized)

        _log_start("lookup_url", normalized)

        try:
            r = requests.get(
                f"{self.base_url}/urls/{url_id}",
                headers=self.headers,
                timeout=30,
            )
        except requests.RequestException as e:
            _log_done("lookup_url", False, f"request_exception={e}")
            return {"error": str(e)}

        if r.status_code != 200:
            _log_done("lookup_url", False, f"http_status={r.status_code}")
            return {"error": f"status {r.status_code}", "body": r.text}

        data = safe_get_json(r)
        obj = data.get("data", {}) or {}
        attrs = obj.get("attributes", {}) or {}
        stats = attrs.get("last_analysis_stats", {}) or {}
        results = attrs.get("last_analysis_results", {}) or {}
        meta = data.get("meta", {}) or {}
        relationships = obj.get("relationships", {}) or {}

        result = {
            "id": obj.get("id"),
            "type": obj.get("type"),
            "links": obj.get("links", {}) or {},
            "relationships": relationships,
            "data": obj,
            "attributes": attrs,
            "meta": meta,
            "status": attrs.get("last_analysis_date") and "completed" or attrs.get("status"),
            "date": attrs.get("last_analysis_date") or attrs.get("date"),
            "url": attrs.get("url"),
            "stats": stats,
            "results": results,
            "harmless": stats.get("harmless"),
            "malicious": stats.get("malicious"),
            "suspicious": stats.get("suspicious"),
            "undetected": stats.get("undetected"),
            "timeout": stats.get("timeout"),
            "confirmed_timeout": stats.get("confirmed_timeout"),
            "failure": stats.get("failure"),
            "type_unsupported": stats.get("type_unsupported"),
            "raw": data,
        }

        _log_done(
            "lookup_url",
            True,
            (
                f"id={result.get('id')} "
                f"malicious={result.get('malicious')} "
                f"suspicious={result.get('suspicious')}"
            ),
        )
        return result

    def get_url(
        self,
        url: str,
        timeout_seconds: int = 60,
        interval_seconds: int = 2,
    ) -> dict:
        normalized = normalize_url(url)
        _log_start("get_url", normalized)

        submitted = self.submit_url(normalized)

        if submitted.get("error") == "already_exists":
            _log_poll("get_url", "submit returned 409, fallback=lookup_url")
            looked_up = self.lookup_url(normalized)

            if "error" in looked_up:
                _log_done("get_url", False, f"lookup_error={looked_up.get('error')}")
                return looked_up

            _log_done("get_url", True, "mode=lookup_after_409")
            return looked_up

        if "error" in submitted:
            _log_done("get_url", False, f"submit_error={submitted.get('error')}")
            return submitted

        analysis_id = submitted["analysis_id"]

        polled = self.poll_analysis(
            analysis_id=analysis_id,
            timeout_seconds=timeout_seconds,
            interval_seconds=interval_seconds,
        )

        if "error" in polled:
            _log_done("get_url", False, f"poll_error={polled.get('error')}")
            return polled

        _log_done("get_url", True, f"analysis_id={analysis_id}")
        return polled

    def get_domain(self, domain: str) -> dict:
        if not self.api_key:
            _log_done("get_domain", False, "missing api key")
            return {"error": "No VT API key"}

        _log_start("get_domain", domain)

        try:
            r = requests.get(
                f"{self.base_url}/domains/{domain}",
                headers=self.headers,
                timeout=30,
            )
        except requests.RequestException as e:
            _log_done("get_domain", False, f"request_exception={e}")
            return {"error": str(e)}

        if r.status_code != 200:
            _log_done("get_domain", False, f"http_status={r.status_code}")
            return {"error": f"status {r.status_code}", "body": r.text}

        data = safe_get_json(r)
        obj = data.get("data", {}) or {}
        attrs = obj.get("attributes", {}) or {}
        stats = attrs.get("last_analysis_stats", {}) or {}

        result = {
            "id": obj.get("id"),
            "type": obj.get("type"),
            "links": obj.get("links", {}) or {},
            "relationships": obj.get("relationships", {}) or {},
            "data": obj,
            "attributes": attrs,
            "meta": data.get("meta", {}) or {},
            "categories": attrs.get("categories", {}) or {},
            "creation_date": attrs.get("creation_date"),
            "last_modification_date": attrs.get("last_modification_date"),
            "last_update_date": attrs.get("last_update_date"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "last_analysis_stats": stats,
            "last_analysis_results": attrs.get("last_analysis_results", {}) or {},
            "last_dns_records": attrs.get("last_dns_records", []) or [],
            "last_https_certificate": attrs.get("last_https_certificate", {}) or {},
            "last_https_certificate_date": attrs.get("last_https_certificate_date"),
            "popularity_ranks": attrs.get("popularity_ranks", {}) or {},
            "reputation": attrs.get("reputation"),
            "registrar": attrs.get("registrar"),
            "tld": attrs.get("tld"),
            "whois": attrs.get("whois"),
            "whois_date": attrs.get("whois_date"),
            "total_votes": attrs.get("total_votes", {}) or {},
            "tags": attrs.get("tags", []) or [],
            "raw": data,
            "harmless": stats.get("harmless"),
            "malicious": stats.get("malicious"),
            "suspicious": stats.get("suspicious"),
            "undetected": stats.get("undetected"),
            "timeout": stats.get("timeout"),
            "confirmed_timeout": stats.get("confirmed_timeout"),
            "failure": stats.get("failure"),
            "type_unsupported": stats.get("type_unsupported"),
        }

        _log_done(
            "get_domain",
            True,
            (
                f"id={result.get('id')} "
                f"malicious={result.get('malicious')} "
                f"suspicious={result.get('suspicious')}"
            ),
        )
        return result

    def get_ip(self, ip: str) -> dict:
        if not self.api_key:
            _log_done("get_ip", False, "missing api key")
            return {"error": "No VT API key"}

        _log_start("get_ip", ip)

        try:
            r = requests.get(
                f"{self.base_url}/ip_addresses/{ip}",
                headers=self.headers,
                timeout=30,
            )
        except requests.RequestException as e:
            _log_done("get_ip", False, f"request_exception={e}")
            return {"error": str(e)}

        if r.status_code != 200:
            _log_done("get_ip", False, f"http_status={r.status_code}")
            return {"error": f"status {r.status_code}", "body": r.text}

        data = safe_get_json(r)
        obj = data.get("data", {}) or {}
        attrs = obj.get("attributes", {}) or {}
        stats = attrs.get("last_analysis_stats", {}) or {}

        result = {
            "id": obj.get("id"),
            "type": obj.get("type"),
            "links": obj.get("links", {}) or {},
            "relationships": obj.get("relationships", {}) or {},
            "data": obj,
            "attributes": attrs,
            "meta": data.get("meta", {}) or {},
            "last_analysis_stats": stats,
            "last_analysis_results": attrs.get("last_analysis_results", {}) or {},
            "network": attrs.get("network"),
            "country": attrs.get("country"),
            "continent": attrs.get("continent"),
            "asn": _normalize_asn_value(attrs.get("asn")),
            "as_owner": attrs.get("as_owner"),
            "regional_internet_registry": attrs.get("regional_internet_registry"),
            "reputation": attrs.get("reputation"),
            "total_votes": attrs.get("total_votes", {}) or {},
            "tags": attrs.get("tags", []) or [],
            "whois": attrs.get("whois"),
            "whois_date": attrs.get("whois_date"),
            "raw": data,
            "harmless": stats.get("harmless"),
            "malicious": stats.get("malicious"),
            "suspicious": stats.get("suspicious"),
            "undetected": stats.get("undetected"),
            "timeout": stats.get("timeout"),
            "confirmed_timeout": stats.get("confirmed_timeout"),
            "failure": stats.get("failure"),
            "type_unsupported": stats.get("type_unsupported"),
        }

        _log_done(
            "get_ip",
            True,
            (
                f"id={result.get('id')} "
                f"asn={result.get('asn')} "
                f"malicious={result.get('malicious')}"
            ),
        )
        return result

    def get_hash(self, file_hash: str) -> dict:
        if not self.api_key:
            _log_done("get_hash", False, "missing api key")
            return {"error": "No VT API key"}

        _log_start("get_hash", file_hash)

        try:
            r = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers=self.headers,
                timeout=30,
            )
        except requests.RequestException as e:
            _log_done("get_hash", False, f"request_exception={e}")
            return {"error": str(e)}

        if r.status_code != 200:
            _log_done("get_hash", False, f"http_status={r.status_code}")
            return {"error": f"status {r.status_code}", "body": r.text}

        data = safe_get_json(r)
        obj = data.get("data", {}) or {}
        attrs = obj.get("attributes", {}) or {}
        stats = attrs.get("last_analysis_stats", {}) or {}

        result = {
            "id": obj.get("id"),
            "type": obj.get("type"),
            "links": obj.get("links", {}) or {},
            "relationships": obj.get("relationships", {}) or {},
            "data": obj,
            "attributes": attrs,
            "meta": data.get("meta", {}) or {},
            "last_analysis_stats": stats,
            "last_analysis_results": attrs.get("last_analysis_results", {}) or {},
            "meaningful_name": attrs.get("meaningful_name"),
            "names": attrs.get("names", []) or [],
            "size": attrs.get("size"),
            "sha256": attrs.get("sha256"),
            "sha1": attrs.get("sha1"),
            "md5": attrs.get("md5"),
            "ssdeep": attrs.get("ssdeep"),
            "tlsh": attrs.get("tlsh"),
            "vhash": attrs.get("vhash"),
            "type_description": attrs.get("type_description"),
            "type_tag": attrs.get("type_tag"),
            "magic": attrs.get("magic"),
            "first_submission_date": attrs.get("first_submission_date"),
            "last_submission_date": attrs.get("last_submission_date"),
            "times_submitted": attrs.get("times_submitted"),
            "reputation": attrs.get("reputation"),
            "total_votes": attrs.get("total_votes", {}) or {},
            "tags": attrs.get("tags", []) or [],
            "raw": data,
            "harmless": stats.get("harmless"),
            "malicious": stats.get("malicious"),
            "suspicious": stats.get("suspicious"),
            "undetected": stats.get("undetected"),
            "timeout": stats.get("timeout"),
            "confirmed_timeout": stats.get("confirmed_timeout"),
            "failure": stats.get("failure"),
            "type_unsupported": stats.get("type_unsupported"),
        }

        _log_done(
            "get_hash",
            True,
            (
                f"sha256={result.get('sha256') or result.get('id')} "
                f"malicious={result.get('malicious')} "
                f"suspicious={result.get('suspicious')}"
            ),
        )
        return result


def normalize_vt(root_kind: str, root_value: str, data: dict) -> NormalizedIntel:
    stats = _extract_vt_stats(data)
    results = _extract_vt_results(data)

    intel = NormalizedIntel(
        source="virustotal",
        raw=data,
        attributes=_build_vt_attributes(data),
    )

    seen_roles = set()
    seen_entities = set()

    _add_entity_unique(intel, seen_roles, seen_entities, root_kind, root_value, "root")

    status = _safe_str(data.get("status"))
    date = data.get("date")
    vt_type = _safe_str(data.get("type"))
    analyzed_url = _safe_str(data.get("url"))

    harmless = _safe_int(data.get("harmless") if data.get("harmless") is not None else stats.get("harmless"))
    malicious = _safe_int(data.get("malicious") if data.get("malicious") is not None else stats.get("malicious"))
    suspicious = _safe_int(data.get("suspicious") if data.get("suspicious") is not None else stats.get("suspicious"))
    undetected = _safe_int(data.get("undetected") if data.get("undetected") is not None else stats.get("undetected"))
    timeout = _safe_int(data.get("timeout") if data.get("timeout") is not None else stats.get("timeout"))
    confirmed_timeout = _safe_int(
        data.get("confirmed_timeout")
        if data.get("confirmed_timeout") is not None
        else stats.get("confirmed_timeout")
    )
    failure = _safe_int(data.get("failure") if data.get("failure") is not None else stats.get("failure"))
    type_unsupported = _safe_int(
        data.get("type_unsupported")
        if data.get("type_unsupported") is not None
        else stats.get("type_unsupported")
    )

    if analyzed_url and not _is_skippable_url(analyzed_url):
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "url",
            analyzed_url,
            "analyzed_url",
            data={
                "status": status,
                "type": vt_type,
                "date": date,
            },
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "analyzed_url", "analyzed_as_url")

    if status:
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "status",
            status,
            "analysis_status",
            data={"date": date},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "analysis_status", "analysis_status")

    verdict_value = None
    if malicious is not None and malicious > 0:
        verdict_value = "malicious"
    elif suspicious is not None and suspicious > 0:
        verdict_value = "suspicious"
    elif harmless is not None and harmless > 0 and (malicious or 0) == 0 and (suspicious or 0) == 0:
        verdict_value = "harmless"

    if verdict_value:
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "verdict",
            verdict_value,
            "vt_verdict",
            data={
                "harmless": harmless,
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
                "timeout": timeout,
                "confirmed_timeout": confirmed_timeout,
                "failure": failure,
                "type_unsupported": type_unsupported,
            },
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "vt_verdict", "has_vt_verdict")

    added = _add_entity_unique(
        intel,
        seen_roles,
        seen_entities,
        "signal",
        "vt_detection_stats",
        "vt_detection_stats",
        data={
            "harmless": harmless,
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected,
            "timeout": timeout,
            "confirmed_timeout": confirmed_timeout,
            "failure": failure,
            "type_unsupported": type_unsupported,
        },
    )
    if added:
        _safe_add_link(intel, seen_roles, "root", "vt_detection_stats", "has_detection_stats")

    if (
        malicious is not None
        and suspicious is not None
        and harmless is not None
        and ((malicious > 0 or suspicious > 0) and harmless > 0)
    ):
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "signal",
            "mixed_reputation",
            "mixed_reputation",
            data={
                "harmless": harmless,
                "malicious": malicious,
                "suspicious": suspicious,
            },
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "mixed_reputation", "has_mixed_reputation")

    analyzed_domain = data.get("domain") or data.get("id")
    if data.get("type") == "domain" and analyzed_domain:
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "domain",
            analyzed_domain,
            "analyzed_domain",
            data={
                "reputation": data.get("reputation"),
                "categories": data.get("categories"),
                "whois_date": data.get("whois_date"),
                "registrar": data.get("registrar"),
                "tld": data.get("tld"),
            },
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "analyzed_domain", "analyzed_as_domain")

    analyzed_ip = data.get("ip") or data.get("id")
    if data.get("type") == "ip_address" and analyzed_ip:
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "ip",
            analyzed_ip,
            "analyzed_ip",
            data={
                "asn": _normalize_asn_value(data.get("asn")),
                "as_owner": data.get("as_owner"),
                "country": data.get("country"),
                "network": data.get("network"),
                "reputation": data.get("reputation"),
            },
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "analyzed_ip", "analyzed_as_ip")

    file_hash = _first_present(data.get("sha256"), data.get("id"))
    if data.get("type") == "file" and file_hash:
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "hash",
            file_hash,
            "analyzed_file",
            data={
                "sha256": data.get("sha256"),
                "sha1": data.get("sha1"),
                "md5": data.get("md5"),
                "size": data.get("size"),
                "meaningful_name": data.get("meaningful_name"),
                "type_description": data.get("type_description"),
                "type_tag": data.get("type_tag"),
            },
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "analyzed_file", "analyzed_as_file")

    if data.get("as_owner"):
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "isp",
            data.get("as_owner"),
            "as_owner",
        )
        if added:
            if "analyzed_ip" in seen_roles:
                _safe_add_link(intel, seen_roles, "analyzed_ip", "as_owner", "owned_by")
            else:
                _safe_add_link(intel, seen_roles, "root", "as_owner", "owned_by")

    if data.get("asn") is not None:
        normalized_asn = _normalize_asn_value(data.get("asn"))
        if normalized_asn is not None:
            added = _add_entity_unique(
                intel,
                seen_roles,
                seen_entities,
                "asn",
                normalized_asn,
                "primary_asn",
                data={"as_owner": data.get("as_owner")},
            )
            if added:
                if "analyzed_ip" in seen_roles:
                    _safe_add_link(intel, seen_roles, "analyzed_ip", "primary_asn", "announced_by")
                else:
                    _safe_add_link(intel, seen_roles, "root", "primary_asn", "uses_asn")

    meta = _safe_dict(data.get("meta"))
    url_info = _safe_dict(meta.get("url_info"))
    file_info = _safe_dict(meta.get("file_info"))

    if url_info.get("url") and not _is_skippable_url(url_info.get("url")):
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "url",
            url_info.get("url"),
            "meta_url",
            data={"id": url_info.get("id")},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "meta_url", "meta_url")

    if url_info.get("id"):
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "hash",
            url_info.get("id"),
            "meta_url_id",
            data={"kind": "url_id"},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "meta_url_id", "meta_identifier")

    if file_info.get("sha256"):
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "hash",
            file_info.get("sha256"),
            "sha256",
            data={"algorithm": "sha256"},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "sha256", "content_sha256")

    links = _safe_dict(data.get("links"))
    self_link = links.get("self")
    if self_link and not _is_skippable_url(self_link):
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "url",
            self_link,
            "vt_self_link",
            data={"kind": "virustotal_api_link"},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "vt_self_link", "api_reference")

    engine_index = 0
    for engine_name, engine_data in results.items():
        engine_data = _safe_dict(engine_data)
        category = _safe_str(engine_data.get("category"))
        engine_result = _safe_str(engine_data.get("result"))
        method = _safe_str(engine_data.get("method"))
        normalized_engine_name = _safe_str(engine_data.get("engine_name")) or _safe_str(engine_name)

        if not normalized_engine_name or category not in {"malicious", "suspicious"}:
            continue

        role = f"engine_{engine_index}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "engine",
            normalized_engine_name,
            role,
            data={
                "category": category,
                "result": engine_result,
                "method": method,
            },
        )
        if not added:
            continue

        if category == "malicious":
            if engine_result and "malware" in engine_result.lower():
                rel = "detected_as_malware_by"
            else:
                rel = "detected_as_malicious_by"
        else:
            rel = "flagged_as_suspicious_by"

        _safe_add_link(
            intel,
            seen_roles,
            "root",
            role,
            rel,
            metadata={
                "category": category,
                "result": engine_result,
                "method": method,
            },
        )
        engine_index += 1

    tag_index = 0
    for tag in _safe_list(data.get("tags")):
        if not tag:
            continue
        role = f"tag_{tag_index}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "tag",
            tag,
            role,
            data={"position": tag_index},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "tagged_as", {"position": tag_index})
            tag_index += 1

    categories = _safe_dict(data.get("categories"))
    category_index = 0
    for provider, category_value in categories.items():
        category_value = _safe_str(category_value)
        if not category_value:
            continue
        role = f"category_{category_index}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "category",
            category_value,
            role,
            data={"provider": provider},
        )
        if added:
            _safe_add_link(
                intel,
                seen_roles,
                "root",
                role,
                "categorized_as",
                {"provider": provider},
            )
            category_index += 1

    total_votes = _safe_dict(data.get("total_votes"))
    harmless_votes = _safe_int(total_votes.get("harmless"))
    malicious_votes = _safe_int(total_votes.get("malicious"))

    if harmless_votes is not None or malicious_votes is not None:
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "signal",
            "community_votes",
            "community_votes",
            data={
                "harmless": harmless_votes,
                "malicious": malicious_votes,
            },
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "community_votes", "has_community_votes")

    return intel