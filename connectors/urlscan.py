import requests
from urllib.parse import urlparse

from core.helpers import safe_get_json, normalize_url, safe_len_or_bool
from core.polling import poll_until
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


def _is_sha256(value) -> bool:
    if value is None:
        return False
    s = str(value).strip().lower()
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def _dedupe_preserve_order(values):
    seen = set()
    out = []
    for v in values:
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def _clean_domain_list(values):
    out = []
    seen = set()
    for v in _safe_list(values):
        s = str(v).strip().lower().rstrip(".")
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _clean_url_list(values):
    out = []
    seen = set()
    for v in _safe_list(values):
        s = str(v).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _clean_ip_list(values):
    out = []
    seen = set()
    for v in _safe_list(values):
        s = str(v).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _clean_country_list(values):
    out = []
    seen = set()
    for v in _safe_list(values):
        s = str(v).strip().upper()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _clean_server_list(values):
    out = []
    seen = set()
    for v in _safe_list(values):
        s = str(v).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


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


def _clean_asn_list(values):
    out = []
    seen = set()
    for v in _safe_list(values):
        s = _normalize_asn_value(v)
        if s is None or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _clean_hash_list(values):
    out = []
    seen = set()
    for v in _safe_list(values):
        s = str(v).strip().lower()
        if not _is_sha256(s) or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _clean_certificate_list(values):
    out = []
    seen = set()

    for cert in _safe_list(values):
        cert_dict = _safe_dict(cert)
        if not cert_dict:
            continue

        key = (
            cert_dict.get("subjectName"),
            cert_dict.get("issuer"),
            cert_dict.get("validFrom"),
            cert_dict.get("validTo"),
            cert_dict.get("fingerprint"),
        )
        if key in seen:
            continue

        seen.add(key)
        out.append(cert_dict)

    return out


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


def _role_exists(seen_roles: set, role: str) -> bool:
    return role in seen_roles


def _extract_dict_value(value, *keys):
    if not isinstance(value, dict):
        return value

    for key in keys:
        if value.get(key) is not None:
            return value.get(key)

    return None


class URLScanClient:
    REQUIRED_FIELDS = [
        "final_url",
        "final_domain",
        "apex_domain",
        "overall_score",
        "overall_malicious",
        "engines_score",
        "engines_malicious",
        "observed_domains",
        "observed_urls",
        "secure_requests",
        "secure_percentage",
        "observed_hashes",
        "observed_certificates",
        "request_response_hashes",
    ]

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://urlscan.io/api/v1"
        self.headers = (
            {
                "API-Key": api_key,
                "Content-Type": "application/json",
            }
            if api_key
            else {}
        )

    def _log_start(self, action: str, value: str) -> None:
        print(f"[connector] urlscan {action} start: {value}", flush=True)

    def _log_poll(self, action: str, message: str) -> None:
        print(f"[connector] urlscan {action} poll: {message}", flush=True)

    def _log_done(self, action: str, ok: bool, summary: str = "") -> None:
        status = "ok" if ok else "error"
        if summary:
            print(f"[connector] urlscan {action} done: {status} | {summary}", flush=True)
        else:
            print(f"[connector] urlscan {action} done: {status}", flush=True)

    def _extract_request_url(self, req: dict):
        request_block = _safe_dict(req.get("request"))
        nested_request = _safe_dict(request_block.get("request"))
        response_block = _safe_dict(req.get("response"))
        nested_response = _safe_dict(response_block.get("response"))

        candidates = [
            _extract_dict_value(request_block, "url"),
            _extract_dict_value(nested_request, "url"),
            _extract_dict_value(nested_response, "url"),
            req.get("url"),
        ]

        for value in candidates:
            if value is None:
                continue
            value = str(value).strip()
            if value:
                return value

        return None

    def _extract_request_domain(self, req: dict):
        req_url = self._extract_request_url(req)
        if req_url:
            try:
                host = (urlparse(req_url).hostname or "").strip().lower().rstrip(".")
                if host:
                    return host
            except Exception:
                pass

        request_block = _safe_dict(req.get("request"))
        nested_request = _safe_dict(request_block.get("request"))
        response_block = _safe_dict(req.get("response"))
        nested_response = _safe_dict(response_block.get("response"))

        candidates = [
            _extract_dict_value(request_block, "domain", "host", "hostname"),
            _extract_dict_value(nested_request, "domain", "host", "hostname"),
            _extract_dict_value(nested_response, "domain", "host", "hostname"),
            req.get("domain"),
        ]

        for value in candidates:
            value = _extract_dict_value(value, "domain", "value", "host", "hostname")
            if value is None:
                continue
            value = str(value).strip().lower().rstrip(".")
            if value:
                return value

        return None

    def _extract_request_ip(self, req: dict):
        response_block = _safe_dict(req.get("response"))
        nested_response = _safe_dict(response_block.get("response"))
        asn_block = _safe_dict(response_block.get("asn"))

        candidates = [
            nested_response.get("remoteIPAddress"),
            _extract_dict_value(response_block, "ip", "address"),
            _extract_dict_value(asn_block, "ip", "address"),
            req.get("ip"),
        ]

        for value in candidates:
            value = _extract_dict_value(value, "ip", "value", "address")
            if value is None:
                continue
            value = str(value).strip()
            if value:
                return value

        return None

    def _extract_request_asn(self, req: dict):
        response_block = _safe_dict(req.get("response"))
        asn_block = _safe_dict(response_block.get("asn"))

        candidates = [
            asn_block.get("asn"),
            response_block.get("asn"),
            req.get("asn"),
        ]

        for candidate in candidates:
            normalized = _normalize_asn_value(candidate)
            if normalized is not None:
                return normalized

        return None

    def _extract_request_country(self, req: dict):
        response_block = _safe_dict(req.get("response"))
        geoip_block = _safe_dict(response_block.get("geoip"))

        candidates = [
            geoip_block.get("country"),
            _extract_dict_value(response_block, "geoip_country", "country"),
            req.get("country"),
        ]

        for value in candidates:
            value = _extract_dict_value(value, "code", "country", "value")
            if value is None:
                continue
            value = str(value).strip().upper()
            if value:
                return value

        return None

    def _extract_request_method(self, req: dict):
        request_block = _safe_dict(req.get("request"))
        nested_request = _safe_dict(request_block.get("request"))

        candidates = [
            _extract_dict_value(request_block, "method"),
            _extract_dict_value(nested_request, "method"),
            req.get("method"),
        ]

        for value in candidates:
            if value is None:
                continue
            value = str(value).strip().upper()
            if value:
                return value

        return None

    def _extract_request_resource_type(self, req: dict):
        request_block = _safe_dict(req.get("request"))
        response_block = _safe_dict(req.get("response"))

        candidates = [
            request_block.get("type"),
            req.get("resourceType"),
            req.get("type"),
            response_block.get("type"),
        ]

        for value in candidates:
            value = _extract_dict_value(value, "type", "value")
            if value is None:
                continue
            value = str(value).strip()
            if value:
                return value

        return None

    def _extract_request_status_code(self, req: dict):
        response_block = _safe_dict(req.get("response"))
        nested_response = _safe_dict(response_block.get("response"))

        candidates = [
            nested_response.get("status"),
            _extract_dict_value(response_block, "status", "code"),
        ]

        for value in candidates:
            value = _extract_dict_value(value, "code", "value")
            if value is None:
                continue
            value = str(value).strip()
            if value:
                return value

        return None

    def _extract_request_hash(self, req: dict):
        response_block = _safe_dict(req.get("response"))
        nested_response = _safe_dict(response_block.get("response"))

        candidates = [
            response_block.get("hash"),
            _extract_dict_value(nested_response, "hash"),
        ]

        for value in candidates:
            value = _extract_dict_value(value, "sha256", "hash", "value")
            if not _is_sha256(value):
                continue
            return str(value).strip().lower()

        return None

    def _extract_cookie_name(self, cookie):
        value = _extract_dict_value(cookie, "name")
        if value is None:
            return None
        value = str(value).strip()
        return value or None

    def _extract_cookie_domain(self, cookie):
        value = _extract_dict_value(cookie, "domain")
        value = _extract_dict_value(value, "domain", "value", "host")
        if value is None:
            return None
        value = str(value).strip().lower().rstrip(".")
        return value or None

    def _extract_link_href(self, link):
        value = _extract_dict_value(link, "href", "url")
        if value is None:
            return None
        value = str(value).strip()
        return value or None

    def _extract_link_domain(self, link):
        value = _extract_dict_value(link, "domain", "host")
        value = _extract_dict_value(value, "domain", "value", "host")
        if value is not None:
            value = str(value).strip().lower().rstrip(".")
            if value:
                return value

        href = self._extract_link_href(link)
        if href:
            try:
                host = (urlparse(href).hostname or "").strip().lower().rstrip(".")
                return host or None
            except Exception:
                return None

        return None

    def submit_url(self, url: str) -> dict:
        if not self.api_key:
            self._log_done("submit_url", False, "missing api key")
            return {"error": "No URLScan API key"}

        url = normalize_url(url)
        self._log_start("submit_url", url)

        try:
            r = requests.post(
                f"{self.base_url}/scan/",
                headers=self.headers,
                json={"url": url, "visibility": "public"},
                timeout=30,
            )
        except requests.RequestException as e:
            self._log_done("submit_url", False, f"request_exception={e}")
            return {"error": str(e)}

        if r.status_code != 200:
            self._log_done("submit_url", False, f"http_status={r.status_code}")
            return {
                "error": f"status {r.status_code}",
                "body": r.text,
            }

        data = safe_get_json(r)
        api_url = data.get("api")

        if not api_url:
            self._log_done("submit_url", False, "missing api url")
            return {"error": "no api url", "body": data}

        self._log_done(
            "submit_url",
            True,
            f"uuid={data.get('uuid')} api_url={api_url}",
        )

        return {
            "api_url": api_url,
            "uuid": data.get("uuid"),
            "result_url": data.get("result"),
            "visibility": data.get("visibility"),
            "message": data.get("message"),
            "submitted_url": data.get("url"),
            "api_response": data,
            "raw": data,
        }

    def poll_result(
        self,
        api_url: str,
        timeout_seconds: int = 90,
        interval_seconds: int = 3,
    ) -> dict:
        if not self.api_key:
            self._log_done("poll_result", False, "missing api key")
            return {"error": "No URLScan API key"}

        self._log_start("poll_result", api_url)

        required_scalar_fields = [
            "final_url",
            "final_domain",
            "apex_domain",
            "secure_requests",
            "secure_percentage",
            "overall_score",
            "overall_malicious",
            "engines_score",
            "engines_malicious",
        ]

        required_collection_fields = [
            "observed_domains",
            "observed_urls",
            "observed_hashes",
            "observed_certificates",
            "request_response_hashes",
        ]

        def fetch():
            try:
                r = requests.get(api_url, timeout=30)
            except requests.RequestException as e:
                return {
                    "error": str(e),
                    "_all_fields_ready": False,
                }

            if r.status_code == 404:
                return {
                    "_all_fields_ready": False,
                    "status_code": 404,
                }

            if r.status_code != 200:
                return {
                    "error": f"status {r.status_code}",
                    "_all_fields_ready": False,
                    "status_code": r.status_code,
                    "body": r.text,
                }

            j = safe_get_json(r)

            page = _safe_dict(j.get("page"))
            verdicts = _safe_dict(j.get("verdicts"))
            overall = _safe_dict(verdicts.get("overall"))
            engines = _safe_dict(verdicts.get("engines"))
            community = _safe_dict(verdicts.get("community"))
            urlscan_verdict = _safe_dict(verdicts.get("urlscan"))

            lists = _safe_dict(j.get("lists"))
            stats = _safe_dict(j.get("stats"))
            data_block = _safe_dict(j.get("data"))
            task = _safe_dict(j.get("task"))
            meta = _safe_dict(j.get("meta"))
            redirects = _safe_list(j.get("redirects"))

            requests_list = _safe_list(data_block.get("requests"))
            cookies_list = _safe_list(data_block.get("cookies"))
            console_list = _safe_list(data_block.get("console"))
            links_list = _safe_list(data_block.get("links"))
            storages_list = _safe_list(data_block.get("storages"))
            websockets_list = _safe_list(data_block.get("websockets"))
            data_redirects = _safe_list(data_block.get("redirects"))
            globals_list = _safe_list(data_block.get("globals"))
            timing = _safe_dict(data_block.get("timing"))

            page_countries = _safe_list(page.get("countries"))
            page_tls = _safe_dict(page.get("tls"))
            page_dom = page.get("dom", "") or ""
            page_screenshot = page.get("screenshot") or ""
            page_umbrella_rank = page.get("umbrellaRank")
            page_mime_type = page.get("mimeType")
            page_size = page.get("size")
            page_status = page.get("status")
            page_redirected = page.get("redirected")

            observed_domains = _clean_domain_list(lists.get("domains"))
            observed_urls = _clean_url_list(lists.get("urls"))
            observed_ips = _clean_ip_list(lists.get("ips"))
            observed_asns = _clean_asn_list(lists.get("asns"))
            observed_countries = _clean_country_list(lists.get("countries"))
            observed_servers = _clean_server_list(lists.get("servers"))
            observed_certificates = _clean_certificate_list(lists.get("certificates"))
            observed_hashes = _clean_hash_list(lists.get("hashes"))
            link_domains = _clean_domain_list(lists.get("linkDomains"))

            requests_secure = 0
            requests_insecure = 0
            request_methods = {}
            request_domains = set()
            request_urls = set()
            request_countries = set()
            request_ips = set()
            request_asns = set()
            response_hashes = set()
            request_resource_types = {}
            request_status_codes = {}

            for req in requests_list:
                if not isinstance(req, dict):
                    continue

                req_url = self._extract_request_url(req)
                if req_url:
                    request_urls.add(req_url)

                domain = self._extract_request_domain(req)
                if domain:
                    request_domains.add(domain)

                ip = self._extract_request_ip(req)
                if ip:
                    request_ips.add(ip)

                asn = self._extract_request_asn(req)
                if asn is not None:
                    request_asns.add(asn)

                country = self._extract_request_country(req)
                if country:
                    request_countries.add(country)

                method = self._extract_request_method(req)
                if method:
                    request_methods[method] = request_methods.get(method, 0) + 1

                resource_type = self._extract_request_resource_type(req)
                if resource_type:
                    request_resource_types[resource_type] = (
                        request_resource_types.get(resource_type, 0) + 1
                    )

                status_code = self._extract_request_status_code(req)
                if status_code is not None:
                    request_status_codes[status_code] = (
                        request_status_codes.get(status_code, 0) + 1
                    )

                response_hash = self._extract_request_hash(req)
                if response_hash:
                    response_hashes.add(response_hash)

                if isinstance(req_url, str) and req_url.startswith("https://"):
                    requests_secure += 1
                elif isinstance(req_url, str) and req_url.startswith("http://"):
                    requests_insecure += 1

            cookie_names = []
            cookie_domains = set()
            cookie_name_set = set()

            for cookie in cookies_list:
                if not isinstance(cookie, dict):
                    continue

                name = self._extract_cookie_name(cookie)
                domain = self._extract_cookie_domain(cookie)

                if name and name not in cookie_name_set:
                    cookie_name_set.add(name)
                    cookie_names.append(name)

                if domain:
                    cookie_domains.add(domain)

            link_urls = []
            link_domains_seen = set()

            for link in links_list:
                if not isinstance(link, dict):
                    continue

                href = self._extract_link_href(link)
                if href:
                    link_urls.append(href)

                domain = self._extract_link_domain(link)
                if domain:
                    link_domains_seen.add(domain)

            redirect_chain_urls = []
            redirect_chain_domains = []
            redirect_chain_statuses = []

            for redir in redirects:
                if not isinstance(redir, dict):
                    continue

                redirect_chain_urls.append(redir.get("url"))
                redirect_chain_domains.append(redir.get("domain"))
                redirect_chain_statuses.append(redir.get("status"))

            request_response_hashes = sorted(response_hashes)

            result = {
                "uuid": j.get("_id") or task.get("uuid"),
                "result": j.get("result"),
                "screenshot": j.get("screenshot"),
                "dom": j.get("dom"),
                "stats_url": api_url,
                "page": page,
                "verdicts": verdicts,
                "lists": lists,
                "stats_block": stats,
                "data_block": data_block,
                "task": task,
                "meta": meta,
                "final_url": page.get("url"),
                "final_domain": page.get("domain"),
                "apex_domain": page.get("apexDomain"),
                "ip": page.get("ip"),
                "asn": _normalize_asn_value(page.get("asn")),
                "asnname": page.get("asnname"),
                "ptr": page.get("ptr"),
                "cname": page.get("cname"),
                "country": page.get("country"),
                "countries": page_countries,
                "city": page.get("city"),
                "server": page.get("server"),
                "status": page_status,
                "mime_type": page_mime_type,
                "title": page.get("title"),
                "size": page_size,
                "tls_issuer": page.get("tlsIssuer"),
                "tls": page_tls,
                "tls_valid_days": page_tls.get("validDays"),
                "tls_age_days": page_tls.get("ageDays"),
                "tls_valid_from": page_tls.get("validFrom"),
                "tls_valid_to": page_tls.get("validTo"),
                "tls_version": page_tls.get("protocol"),
                "tls_cipher": page_tls.get("cipher"),
                "tls_subject": page_tls.get("subject"),
                "tls_issuer_dn": page_tls.get("issuer"),
                "tls_san": page_tls.get("subjectAltName"),
                "tls_fingerprint": page_tls.get("fingerprint"),
                "tls_serial_number": page_tls.get("serialNumber"),
                "tls_chain": page_tls.get("chain"),
                "domain_age_days": page.get("domainAgeDays"),
                "apex_domain_age_days": page.get("apexDomainAgeDays"),
                "redirected": page_redirected,
                "umbrella_rank": page_umbrella_rank,
                "page_dom": page_dom,
                "page_dom_length": safe_len_or_bool(page_dom),
                "page_screenshot": page_screenshot,
                "page_screenshot_present": bool(page_screenshot),
                "overall_score": overall.get("score"),
                "overall_malicious": overall.get("malicious"),
                "overall_categories": overall.get("categories"),
                "overall_brands": overall.get("brands"),
                "overall_tags": overall.get("tags"),
                "overall_has_verdicts": overall.get("hasVerdicts"),
                "engines_score": engines.get("score"),
                "engines_malicious": engines.get("malicious"),
                "engines_categories": engines.get("categories"),
                "engines_tags": engines.get("tags"),
                "engines_has_verdicts": engines.get("hasVerdicts"),
                "engines_total": engines.get("enginesTotal"),
                "engines_malicious_total": engines.get("maliciousTotal"),
                "engines_benign_total": engines.get("benignTotal"),
                "engines_malicious_verdicts": engines.get("maliciousVerdicts"),
                "engines_benign_verdicts": engines.get("benignVerdicts"),
                "community_score": community.get("score"),
                "community_malicious": community.get("malicious"),
                "community_categories": community.get("categories"),
                "community_brands": community.get("brands"),
                "community_tags": community.get("tags"),
                "community_has_verdicts": community.get("hasVerdicts"),
                "urlscan_score": urlscan_verdict.get("score"),
                "urlscan_malicious": urlscan_verdict.get("malicious"),
                "urlscan_categories": urlscan_verdict.get("categories"),
                "urlscan_brands": urlscan_verdict.get("brands"),
                "urlscan_tags": urlscan_verdict.get("tags"),
                "urlscan_has_verdicts": urlscan_verdict.get("hasVerdicts"),
                "observed_domains": observed_domains,
                "observed_urls": observed_urls,
                "observed_ips": observed_ips,
                "observed_asns": observed_asns,
                "observed_countries": observed_countries,
                "observed_servers": observed_servers,
                "observed_certificates": observed_certificates,
                "observed_hashes": observed_hashes,
                "link_domains": link_domains,
                "secure_requests": stats.get("secureRequests"),
                "secure_percentage": stats.get("securePercentage"),
                "ipv6_percentage": stats.get("IPv6Percentage"),
                "ad_blocked": stats.get("adBlocked"),
                "uniq_countries": stats.get("uniqCountries"),
                "total_links": stats.get("totalLinks"),
                "malicious": stats.get("malicious"),
                "domain_stats": stats.get("domainStats"),
                "ip_stats": stats.get("ipStats"),
                "reg_domain_stats": stats.get("regDomainStats"),
                "resource_stats": stats.get("resourceStats"),
                "protocol_stats": stats.get("protocolStats"),
                "server_stats": stats.get("serverStats"),
                "tls_stats": stats.get("tlsStats"),
                "request_count": len(requests_list),
                "cookie_count": len(cookies_list),
                "console_count": len(console_list),
                "link_count": len(links_list),
                "storage_count": len(storages_list),
                "websocket_count": len(websockets_list),
                "data_redirect_count": len(data_redirects),
                "global_count": len(globals_list),
                "requests": requests_list,
                "cookies": cookies_list,
                "console": console_list,
                "links": links_list,
                "storages": storages_list,
                "websockets": websockets_list,
                "data_redirects": data_redirects,
                "globals": globals_list,
                "timing": timing,
                "request_domains": sorted(request_domains),
                "request_urls": sorted(request_urls),
                "request_ips": sorted(request_ips),
                "request_asns": sorted(request_asns),
                "request_countries": sorted(request_countries),
                "request_methods": request_methods,
                "request_resource_types": request_resource_types,
                "request_status_codes": request_status_codes,
                "request_response_hashes": request_response_hashes,
                "request_secure_count": requests_secure,
                "request_insecure_count": requests_insecure,
                "cookie_names": cookie_names,
                "cookie_domains": sorted(cookie_domains),
                "cookie_name_count": len(cookie_names),
                "cookie_domain_count": len(cookie_domains),
                "link_urls": link_urls,
                "link_url_count": len(link_urls),
                "link_domains_seen": sorted(link_domains_seen),
                "redirects": redirects,
                "redirect_count": len(redirects),
                "redirect_chain_urls": redirect_chain_urls,
                "redirect_chain_domains": redirect_chain_domains,
                "redirect_chain_statuses": redirect_chain_statuses,
                "task_method": task.get("method"),
                "task_source": task.get("source"),
                "task_time": task.get("time"),
                "task_url": task.get("url"),
                "task_uuid": task.get("uuid"),
                "task_visibility": task.get("visibility"),
                "task_report_url": task.get("reportURL"),
                "task_screenshot_url": task.get("screenshotURL"),
                "task_dom_url": task.get("domURL"),
                "task_domain": task.get("domain"),
                "task_apex_domain": task.get("apexDomain"),
                "task_tags": task.get("tags"),
                "meta_processors": meta.get("processors"),
                "meta_problems": meta.get("problems"),
                "meta_process_time": meta.get("processTime"),
                "meta_pointer_size": meta.get("ptr"),
                "meta_countries": meta.get("countries"),
                "meta_languages": meta.get("languages"),
                "meta_extensions": meta.get("extensions"),
                "meta_runtime": meta.get("runtime"),
                "meta_errors": meta.get("errors"),
                "tags": engines.get("tags") or overall.get("tags") or [],
                "brands": overall.get("brands") or community.get("brands") or urlscan_verdict.get("brands") or [],
                "categories": overall.get("categories") or engines.get("categories") or [],
                "has_verdicts": bool(
                    overall.get("hasVerdicts")
                    or engines.get("hasVerdicts")
                    or community.get("hasVerdicts")
                    or urlscan_verdict.get("hasVerdicts")
                ),
                "is_https_final": isinstance(page.get("url"), str) and page.get("url", "").startswith("https://"),
                "has_tls": bool(
                    page_tls
                    or page.get("tlsIssuer")
                    or stats.get("tlsStats")
                    or (
                        page.get("url", "").startswith("https://")
                        if isinstance(page.get("url"), str)
                        else False
                    )
                ),
                "has_redirects": bool(
                    redirects
                    or data_redirects
                    or observed_urls
                    or observed_domains
                    or page_redirected
                ),
                "has_cookies": len(cookies_list) > 0,
                "has_console_messages": len(console_list) > 0,
                "has_websockets": len(websockets_list) > 0,
                "has_globals": len(globals_list) > 0,
                "has_links": len(links_list) > 0,
                "has_storages": len(storages_list) > 0,
                "scan_state": {
                    "lists_present": lists != {},
                    "stats_present": stats != {},
                    "data_present": data_block != {},
                    "requests_seen": len(requests_list),
                    "hashes_seen": len(observed_hashes),
                    "certificates_seen": len(observed_certificates),
                    "request_hashes_seen": len(request_response_hashes),
                },
                "raw": j,
            }

            missing_scalar = [f for f in required_scalar_fields if result.get(f) is None]
            missing_collections = [f for f in required_collection_fields if result.get(f) is None]
            missing = missing_scalar + missing_collections

            result["_all_fields_ready"] = (
                len(missing) == 0
                and result.get("request_count") is not None
                and result.get("scan_state", {}).get("lists_present") is True
            )
            result["_missing_fields"] = missing

            return result

        def is_done(data: dict) -> bool:
            return data.get("_all_fields_ready", False) is True

        def on_tick(data: dict) -> None:
            scan_state = data.get("scan_state", {}) or {}
            self._log_poll(
                "poll_result",
                (
                    f"all_ready={data.get('_all_fields_ready')} "
                    f"missing={data.get('_missing_fields', [])} "
                    f"requests={scan_state.get('requests_seen')} "
                    f"hashes={scan_state.get('hashes_seen')} "
                    f"certs={scan_state.get('certificates_seen')} "
                    f"request_hashes={scan_state.get('request_hashes_seen')}"
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
            self._log_done("poll_result", False, f"error={result['error']}")
            return {
                "error": result["error"],
                "last_data": result.get("last_data"),
            }

        data = result["data"].copy()
        data.pop("_all_fields_ready", None)
        data.pop("_missing_fields", None)

        self._log_done(
            "poll_result",
            True,
            (
                f"final_url={data.get('final_url')} "
                f"final_domain={data.get('final_domain')} "
                f"requests={data.get('request_count')} "
                f"hashes={len(data.get('observed_hashes') or [])}"
            ),
        )

        return data

    def scan_url(
        self,
        url: str,
        timeout_seconds: int = 90,
        interval_seconds: int = 3,
    ) -> dict:
        normalized = normalize_url(url)
        self._log_start("scan_url", normalized)

        submitted = self.submit_url(normalized)

        if "error" in submitted:
            self._log_done("scan_url", False, f"submit_error={submitted.get('error')}")
            return submitted

        api_url = submitted["api_url"]

        result = self.poll_result(
            api_url=api_url,
            timeout_seconds=timeout_seconds,
            interval_seconds=interval_seconds,
        )

        if "error" in result:
            self._log_done("scan_url", False, f"poll_error={result.get('error')}")
            return result

        self._log_done(
            "scan_url",
            True,
            f"uuid={submitted.get('uuid')} api_url={api_url}",
        )

        return result


def _build_urlscan_attributes(data: dict) -> dict:
    return {
        "final_url": data.get("final_url"),
        "final_domain": data.get("final_domain"),
        "apex_domain": data.get("apex_domain"),
        "title": data.get("title"),
        "ip": data.get("ip"),
        "asn": _normalize_asn_value(data.get("asn")),
        "asnname": data.get("asnname"),
        "ptr": data.get("ptr"),
        "cname": data.get("cname"),
        "country": data.get("country"),
        "countries": data.get("countries"),
        "city": data.get("city"),
        "server": data.get("server"),
        "status": data.get("status"),
        "mime_type": data.get("mime_type"),
        "size": data.get("size"),
        "tls_issuer": data.get("tls_issuer"),
        "tls": data.get("tls"),
        "tls_valid_days": data.get("tls_valid_days"),
        "tls_age_days": data.get("tls_age_days"),
        "tls_valid_from": data.get("tls_valid_from"),
        "tls_valid_to": data.get("tls_valid_to"),
        "tls_version": data.get("tls_version"),
        "tls_cipher": data.get("tls_cipher"),
        "tls_subject": data.get("tls_subject"),
        "tls_issuer_dn": data.get("tls_issuer_dn"),
        "tls_san": data.get("tls_san"),
        "tls_fingerprint": data.get("tls_fingerprint"),
        "tls_serial_number": data.get("tls_serial_number"),
        "domain_age_days": data.get("domain_age_days"),
        "apex_domain_age_days": data.get("apex_domain_age_days"),
        "redirected": data.get("redirected"),
        "umbrella_rank": data.get("umbrella_rank"),
        "overall_score": data.get("overall_score"),
        "overall_malicious": data.get("overall_malicious"),
        "overall_categories": data.get("overall_categories"),
        "overall_brands": data.get("overall_brands"),
        "overall_tags": data.get("overall_tags"),
        "overall_has_verdicts": data.get("overall_has_verdicts"),
        "engines_score": data.get("engines_score"),
        "engines_malicious": data.get("engines_malicious"),
        "engines_categories": data.get("engines_categories"),
        "engines_tags": data.get("engines_tags"),
        "engines_has_verdicts": data.get("engines_has_verdicts"),
        "engines_total": data.get("engines_total"),
        "engines_malicious_total": data.get("engines_malicious_total"),
        "engines_benign_total": data.get("engines_benign_total"),
        "engines_malicious_verdicts": data.get("engines_malicious_verdicts"),
        "engines_benign_verdicts": data.get("engines_benign_verdicts"),
        "community_score": data.get("community_score"),
        "community_malicious": data.get("community_malicious"),
        "community_categories": data.get("community_categories"),
        "community_brands": data.get("community_brands"),
        "community_tags": data.get("community_tags"),
        "community_has_verdicts": data.get("community_has_verdicts"),
        "urlscan_score": data.get("urlscan_score"),
        "urlscan_malicious": data.get("urlscan_malicious"),
        "urlscan_categories": data.get("urlscan_categories"),
        "urlscan_brands": data.get("urlscan_brands"),
        "urlscan_tags": data.get("urlscan_tags"),
        "urlscan_has_verdicts": data.get("urlscan_has_verdicts"),
        "observed_domains": data.get("observed_domains"),
        "observed_urls": data.get("observed_urls"),
        "observed_ips": data.get("observed_ips"),
        "observed_asns": [
            _normalize_asn_value(v)
            for v in _safe_list(data.get("observed_asns"))
            if _normalize_asn_value(v)
        ],
        "observed_countries": data.get("observed_countries"),
        "observed_servers": data.get("observed_servers"),
        "observed_certificates": data.get("observed_certificates"),
        "observed_hashes": data.get("observed_hashes"),
        "link_domains": data.get("link_domains"),
        "secure_requests": data.get("secure_requests"),
        "secure_percentage": data.get("secure_percentage"),
        "ipv6_percentage": data.get("ipv6_percentage"),
        "ad_blocked": data.get("ad_blocked"),
        "uniq_countries": data.get("uniq_countries"),
        "total_links": data.get("total_links"),
        "malicious": data.get("malicious"),
        "domain_stats": data.get("domain_stats"),
        "ip_stats": data.get("ip_stats"),
        "reg_domain_stats": data.get("reg_domain_stats"),
        "resource_stats": data.get("resource_stats"),
        "protocol_stats": data.get("protocol_stats"),
        "server_stats": data.get("server_stats"),
        "tls_stats": data.get("tls_stats"),
        "request_count": data.get("request_count"),
        "cookie_count": data.get("cookie_count"),
        "console_count": data.get("console_count"),
        "link_count": data.get("link_count"),
        "storage_count": data.get("storage_count"),
        "websocket_count": data.get("websocket_count"),
        "data_redirect_count": data.get("data_redirect_count"),
        "global_count": data.get("global_count"),
        "request_domains": data.get("request_domains"),
        "request_urls": data.get("request_urls"),
        "request_ips": data.get("request_ips"),
        "request_asns": [
            _normalize_asn_value(v)
            for v in _safe_list(data.get("request_asns"))
            if _normalize_asn_value(v)
        ],
        "request_countries": data.get("request_countries"),
        "request_methods": data.get("request_methods"),
        "request_resource_types": data.get("request_resource_types"),
        "request_status_codes": data.get("request_status_codes"),
        "request_response_hashes": data.get("request_response_hashes"),
        "request_secure_count": data.get("request_secure_count"),
        "request_insecure_count": data.get("request_insecure_count"),
        "cookie_names": data.get("cookie_names"),
        "cookie_domains": data.get("cookie_domains"),
        "cookie_name_count": data.get("cookie_name_count"),
        "cookie_domain_count": data.get("cookie_domain_count"),
        "link_urls": data.get("link_urls"),
        "link_url_count": data.get("link_url_count"),
        "link_domains_seen": data.get("link_domains_seen"),
        "redirect_count": data.get("redirect_count"),
        "redirects": data.get("redirects"),
        "redirect_chain_urls": data.get("redirect_chain_urls"),
        "redirect_chain_domains": data.get("redirect_chain_domains"),
        "redirect_chain_statuses": data.get("redirect_chain_statuses"),
        "uuid": data.get("uuid"),
        "result": data.get("result"),
        "screenshot": data.get("screenshot"),
        "dom": data.get("dom"),
        "stats_url": data.get("stats_url"),
        "task_method": data.get("task_method"),
        "task_source": data.get("task_source"),
        "task_time": data.get("task_time"),
        "task_uuid": data.get("task_uuid"),
        "task_visibility": data.get("task_visibility"),
        "task_report_url": data.get("task_report_url"),
        "task_screenshot_url": data.get("task_screenshot_url"),
        "task_dom_url": data.get("task_dom_url"),
        "task_domain": data.get("task_domain"),
        "task_apex_domain": data.get("task_apex_domain"),
        "task_tags": data.get("task_tags"),
        "meta_processors": data.get("meta_processors"),
        "meta_problems": data.get("meta_problems"),
        "meta_process_time": data.get("meta_process_time"),
        "meta_pointer_size": data.get("meta_pointer_size"),
        "meta_countries": data.get("meta_countries"),
        "meta_languages": data.get("meta_languages"),
        "meta_extensions": data.get("meta_extensions"),
        "meta_runtime": data.get("meta_runtime"),
        "meta_errors": data.get("meta_errors"),
        "tags": data.get("tags"),
        "brands": data.get("brands"),
        "categories": data.get("categories"),
        "has_verdicts": data.get("has_verdicts"),
        "is_https_final": data.get("is_https_final"),
        "has_tls": data.get("has_tls"),
        "has_redirects": data.get("has_redirects"),
        "has_cookies": data.get("has_cookies"),
        "has_console_messages": data.get("has_console_messages"),
        "has_websockets": data.get("has_websockets"),
        "has_globals": data.get("has_globals"),
        "has_links": data.get("has_links"),
        "has_storages": data.get("has_storages"),
    }


def normalize_urlscan(root_kind: str, root_value: str, data: dict) -> NormalizedIntel:
    intel = NormalizedIntel(
        source="urlscan",
        raw=data,
        attributes=_build_urlscan_attributes(data),
    )

    seen_roles = set()
    seen_entities = set()

    _add_entity_unique(intel, seen_roles, seen_entities, root_kind, root_value, "root")

    final_url = data.get("final_url")
    final_domain = _normalize_entity_value("domain", data.get("final_domain"))
    apex_domain = _normalize_entity_value("domain", data.get("apex_domain"))
    ip = data.get("ip")
    asn = _normalize_asn_value(data.get("asn"))
    country = data.get("country")
    server = data.get("server")
    tls_issuer = data.get("tls_issuer")
    tls_subject = data.get("tls_subject")
    cname = data.get("cname")
    ptr = data.get("ptr")

    if final_url and not _is_skippable_url(final_url):
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "url",
            final_url,
            "final_url",
            data={
                "title": data.get("title"),
                "status": data.get("status"),
                "mime_type": data.get("mime_type"),
                "is_https_final": data.get("is_https_final"),
            },
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "final_url", "final_url")

    if final_domain:
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "domain",
            final_domain,
            "final_domain",
            data={
                "title": data.get("title"),
                "domain_age_days": data.get("domain_age_days"),
                "server": server,
                "status": data.get("status"),
                "ip": ip,
                "asn": asn,
                "country": country,
            },
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "final_domain", "final_domain")

        if _role_exists(seen_roles, "final_url") and _role_exists(seen_roles, "final_domain"):
            _safe_add_link(intel, seen_roles, "final_url", "final_domain", "hosted_on")

    if apex_domain:
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "domain",
            apex_domain,
            "apex_domain",
            data={
                "apex_domain_age_days": data.get("apex_domain_age_days"),
            },
        )

        if added:
            if _role_exists(seen_roles, "final_domain") and final_domain != apex_domain:
                _safe_add_link(intel, seen_roles, "final_domain", "apex_domain", "apex_of")
            else:
                _safe_add_link(intel, seen_roles, "root", "apex_domain", "apex_domain")

    if ip:
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "ip",
            ip,
            "resolved_ip",
            data={
                "asn": asn,
                "asnname": data.get("asnname"),
                "ptr": ptr,
                "country": country,
                "city": data.get("city"),
            },
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "resolved_ip", "resolves_to")

        if _role_exists(seen_roles, "final_domain") and _role_exists(seen_roles, "resolved_ip"):
            _safe_add_link(intel, seen_roles, "final_domain", "resolved_ip", "resolves_to")

    if cname:
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "hostname",
            cname,
            "cname",
        )
        if added:
            if _role_exists(seen_roles, "final_domain"):
                _safe_add_link(intel, seen_roles, "final_domain", "cname", "aliases_to")
            else:
                _safe_add_link(intel, seen_roles, "root", "cname", "aliases_to")

    if ptr:
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "hostname",
            ptr,
            "ptr_record",
        )
        if added:
            if _role_exists(seen_roles, "resolved_ip"):
                _safe_add_link(intel, seen_roles, "resolved_ip", "ptr_record", "reverse_dns")
            else:
                _safe_add_link(intel, seen_roles, "root", "ptr_record", "reverse_dns")

    if server:
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "server",
            server,
            "primary_server",
            data={
                "status": data.get("status"),
                "mime_type": data.get("mime_type"),
            },
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "primary_server", "served_by")

    if country:
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "country",
            country,
            "primary_country",
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "primary_country", "located_in")

    if asn is not None:
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "asn",
            asn,
            "primary_asn",
            data={"asnname": data.get("asnname")},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "primary_asn", "uses_asn")

        if _role_exists(seen_roles, "resolved_ip") and _role_exists(seen_roles, "primary_asn"):
            _safe_add_link(intel, seen_roles, "resolved_ip", "primary_asn", "announced_by")

    if tls_issuer:
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "certificate",
            tls_issuer,
            "primary_certificate_issuer",
            data={
                "fingerprint": data.get("tls_fingerprint"),
                "subject": tls_subject,
                "valid_from": data.get("tls_valid_from"),
                "valid_to": data.get("tls_valid_to"),
            },
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", "primary_certificate_issuer", "uses_certificate")

    if tls_subject:
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "certificate",
            tls_subject,
            "primary_certificate_subject",
            data={
                "issuer": tls_issuer,
                "fingerprint": data.get("tls_fingerprint"),
            },
        )
        if added:
            if _role_exists(seen_roles, "final_domain"):
                _safe_add_link(intel, seen_roles, "final_domain", "primary_certificate_subject", "covered_by_certificate")
            else:
                _safe_add_link(intel, seen_roles, "root", "primary_certificate_subject", "covered_by_certificate")

    for idx, d in enumerate(_safe_list(data.get("observed_domains"))):
        if not d or d == "invalid":
            continue
        role = f"observed_domain_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "domain",
            d,
            role,
            data={"position": idx},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "observed_domain", {"position": idx})

    for idx, u in enumerate(_safe_list(data.get("observed_urls"))):
        if _is_skippable_url(u):
            continue
        role = f"observed_url_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "url",
            u,
            role,
            data={"position": idx},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "observed_url", {"position": idx})

    for idx, observed_ip in enumerate(_safe_list(data.get("observed_ips"))):
        if not observed_ip:
            continue
        role = f"observed_ip_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "ip",
            observed_ip,
            role,
            data={"position": idx},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "observed_ip", {"position": idx})

    for idx, observed_asn in enumerate(_safe_list(data.get("observed_asns"))):
        normalized_observed_asn = _normalize_asn_value(observed_asn)
        if normalized_observed_asn is None:
            continue
        role = f"observed_asn_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "asn",
            normalized_observed_asn,
            role,
            data={"position": idx},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "uses_asn", {"position": idx})

    for idx, observed_country in enumerate(_safe_list(data.get("observed_countries"))):
        if not observed_country:
            continue
        role = f"observed_country_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "country",
            observed_country,
            role,
            data={"position": idx},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "operates_in", {"position": idx})

    for idx, observed_server in enumerate(_safe_list(data.get("observed_servers"))):
        if not observed_server:
            continue
        role = f"observed_server_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "server",
            observed_server,
            role,
            data={"position": idx},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "served_by", {"position": idx})

    for idx, cert in enumerate(_safe_list(data.get("observed_certificates"))):
        cert_dict = _safe_dict(cert)
        if not cert_dict:
            continue

        cert_value = (
            cert_dict.get("subjectName")
            or cert_dict.get("issuer")
            or cert_dict.get("fingerprint")
        )
        if not cert_value:
            continue

        role = f"certificate_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "certificate",
            cert_value,
            role,
            data={
                "position": idx,
                "subject_name": cert_dict.get("subjectName"),
                "issuer": cert_dict.get("issuer"),
                "valid_from": cert_dict.get("validFrom"),
                "valid_to": cert_dict.get("validTo"),
                "fingerprint": cert_dict.get("fingerprint"),
            },
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "uses_certificate", {"position": idx})

    for idx, h in enumerate(_safe_list(data.get("observed_hashes"))):
        if not _is_sha256(h):
            continue
        role = f"observed_hash_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "hash",
            h,
            role,
            data={
                "position": idx,
                "source_field": "lists.hashes",
            },
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "observed_hash", {"position": idx})

    for idx, link_domain in enumerate(_safe_list(data.get("link_domains"))):
        if not link_domain:
            continue
        role = f"link_domain_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "domain",
            link_domain,
            role,
            data={"position": idx},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "linked_domain", {"position": idx})

    for idx, request_domain in enumerate(_safe_list(data.get("request_domains"))):
        if not request_domain:
            continue
        role = f"request_domain_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "domain",
            request_domain,
            role,
            data={"position": idx},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "requested_domain", {"position": idx})

    for idx, request_ip in enumerate(_safe_list(data.get("request_ips"))):
        if not request_ip:
            continue
        role = f"request_ip_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "ip",
            request_ip,
            role,
            data={"position": idx},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "requested_ip", {"position": idx})

    for idx, request_asn in enumerate(_safe_list(data.get("request_asns"))):
        normalized_request_asn = _normalize_asn_value(request_asn)
        if normalized_request_asn is None:
            continue
        role = f"request_asn_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "asn",
            normalized_request_asn,
            role,
            data={"position": idx},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "requested_asn", {"position": idx})

    for idx, request_country in enumerate(_safe_list(data.get("request_countries"))):
        if not request_country:
            continue
        role = f"request_country_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "country",
            request_country,
            role,
            data={"position": idx},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "requested_country", {"position": idx})

    for idx, request_url in enumerate(_safe_list(data.get("request_urls"))):
        if _is_skippable_url(request_url):
            continue
        role = f"request_url_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "url",
            request_url,
            role,
            data={"position": idx},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "requested_url", {"position": idx})

    for idx, cookie_name in enumerate(_safe_list(data.get("cookie_names"))):
        if not cookie_name:
            continue
        role = f"cookie_name_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "cookie",
            cookie_name,
            role,
            data={"position": idx},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "sets_cookie", {"position": idx})

    for idx, cookie_domain in enumerate(_safe_list(data.get("cookie_domains"))):
        if not cookie_domain:
            continue
        role = f"cookie_domain_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "domain",
            cookie_domain,
            role,
            data={"position": idx},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "cookie_domain", {"position": idx})

    for idx, tag in enumerate(_safe_list(data.get("tags"))):
        if not tag:
            continue
        role = f"tag_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "tag",
            tag,
            role,
            data={"position": idx},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "tagged_as", {"position": idx})

    for idx, brand in enumerate(_safe_list(data.get("brands"))):
        if not brand:
            continue
        role = f"brand_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "brand",
            brand,
            role,
            data={"position": idx},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "impersonates_or_mentions_brand", {"position": idx})

    for idx, category in enumerate(_safe_list(data.get("categories"))):
        if not category:
            continue
        role = f"category_{idx}"
        added = _add_entity_unique(
            intel,
            seen_roles,
            seen_entities,
            "category",
            category,
            role,
            data={"position": idx},
        )
        if added:
            _safe_add_link(intel, seen_roles, "root", role, "categorized_as", {"position": idx})

    return intel