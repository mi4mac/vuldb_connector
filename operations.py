import requests
from connectors.core.connector import ConnectorError, get_logger

logger = get_logger("vuldb")


def _get_base_url(config):
    base_url = config.get("base_url") or "https://vuldb.com/?api"
    return str(base_url).strip()


def _get_headers(config):
    api_key = config.get("api_key")
    if not api_key:
        raise ConnectorError("Missing API key in connector configuration.")
    return {"X-VulDB-ApiKey": api_key}


def _apply_common_params(payload, config, params):
    api_version = params.get("version")
    if api_version is None or api_version == "":
        api_version = config.get("api_version")
    if api_version is not None and api_version != "":
        payload["version"] = str(api_version).strip()

    fmt = params.get("format")
    if fmt:
        payload["format"] = fmt

    details = params.get("details")
    if details is True:
        payload["details"] = 1

    cti = params.get("cti")
    if cti is True:
        payload["cti"] = 1

    myfilter = params.get("myfilter")
    if myfilter is True:
        payload["myfilter"] = 1

    fields = params.get("fields")
    if fields:
        payload["fields"] = fields

    limit = params.get("limit")
    if limit is not None and limit != "":
        payload["limit"] = limit

    offset = params.get("offset")
    if offset is not None and offset != "":
        payload["offset"] = offset

    sort = params.get("sort")
    if sort:
        payload["sort"] = sort

    return payload


def _post(config, payload):
    base_url = _get_base_url(config)
    headers = _get_headers(config)
    verify_ssl = config.get("verify_ssl", True)

    try:
        response = requests.post(
            base_url, data=payload, headers=headers, verify=verify_ssl, timeout=60
        )
    except Exception as exc:
        raise ConnectorError(f"Error communicating with VulDB API: {exc}") from exc

    content_type = response.headers.get("Content-Type", "")
    if "application/json" in content_type or payload.get("format", "json") == "json":
        try:
            return response.json()
        except ValueError:
            raise ConnectorError("Failed to decode JSON response from VulDB API.")

    return {
        "raw": response.text,
        "status_code": response.status_code,
        "content_type": content_type,
    }


def _extract_from_dict(data, paths):
    for path in paths:
        current = data
        found = True
        for key in path:
            if not isinstance(current, dict) or key not in current:
                found = False
                break
            current = current[key]
        if found:
            return current
    return None


def _normalize_exploit_status(response):
    results = response.get("result")
    if not isinstance(results, list):
        return response

    for item in results:
        if not isinstance(item, dict):
            continue

        exploitability = _extract_from_dict(
            item,
            [
                ("exploit", "exploitability"),
                ("exploit", "exploitability", "name"),
            ],
        )
        epss_score = _extract_from_dict(
            item,
            [
                ("exploit", "epss", "score"),
                ("exploit", "epss_score"),
            ],
        )
        epss_percentile = _extract_from_dict(
            item,
            [
                ("exploit", "epss", "percentile"),
                ("exploit", "epss_percentile"),
            ],
        )
        kev_added = _extract_from_dict(
            item,
            [
                ("exploit", "kev", "added"),
                ("exploit", "kev", "exploit_kev_added"),
                ("exploit", "kev_added"),
                ("exploit_kev_added",),
            ],
        )
        kev_due = _extract_from_dict(
            item,
            [
                ("exploit", "kev", "due"),
                ("exploit", "kev", "exploit_kev_due"),
                ("exploit", "kev_due"),
                ("exploit_kev_due",),
            ],
        )
        kev_requiredaction = _extract_from_dict(
            item,
            [
                ("exploit", "kev", "requiredaction"),
                ("exploit", "kev", "exploit_kev_requiredaction"),
                ("exploit", "kev_requiredaction"),
                ("exploit_kev_requiredaction",),
            ],
        )
        kev_knownransomware = _extract_from_dict(
            item,
            [
                ("exploit", "kev", "knownransomware"),
                ("exploit", "kev", "exploit_kev_knownransomware"),
                ("exploit", "kev_knownransomware"),
                ("exploit_kev_knownransomware",),
            ],
        )
        kev_notes = _extract_from_dict(
            item,
            [
                ("exploit", "kev", "notes"),
                ("exploit", "kev", "exploit_kev_notes"),
                ("exploit", "kev_notes"),
                ("exploit_kev_notes",),
            ],
        )

        exploit_exists = any(
            value is not None and value != ""
            for value in [exploitability, epss_score, kev_added]
        )

        exploitability_str = str(exploitability or "").strip().lower()
        under_exploitation = False
        if exploitability_str in {"attacked", "a"}:
            under_exploitation = True
        if kev_added not in (None, ""):
            under_exploitation = True
        if str(kev_knownransomware).strip().lower() in {"yes", "true", "1"}:
            under_exploitation = True

        item["exploit_status"] = {
            "exploitability": exploitability,
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            "kev_added": kev_added,
            "kev_due": kev_due,
            "kev_requiredaction": kev_requiredaction,
            "kev_knownransomware": kev_knownransomware,
            "kev_notes": kev_notes,
            "exploit_exists": exploit_exists,
            "under_exploitation": under_exploitation,
        }

    return response


def _normalize_exploit_context(response):
    results = response.get("result")
    if not isinstance(results, list):
        return response

    for item in results:
        if not isinstance(item, dict):
            continue

        entry_id = _extract_from_dict(item, [("entry", "id")])
        entry_title = _extract_from_dict(item, [("entry", "title")])
        entry_timestamp = _extract_from_dict(item, [("entry", "timestamp")])

        source_cve = _extract_from_dict(item, [("source", "cve", "id")])

        vulnerability_risk = _extract_from_dict(item, [("vulnerability", "risk")])
        vulnerability_cwe = _extract_from_dict(item, [("vulnerability", "cwe")])

        cvss3_vuldb = _extract_from_dict(
            item, [("vulnerability", "cvss3", "vuldb")]
        )

        exploit_price = _extract_from_dict(item, [("exploit", "price")])

        countermeasure_name = _extract_from_dict(
            item, [("countermeasure", "name")]
        )
        countermeasure_remediationlevel = _extract_from_dict(
            item, [("countermeasure", "remediationlevel")]
        )

        cti_activity = _extract_from_dict(item, [("cti", "activity")])

        item["exploit_context"] = {
            "entry": {
                "id": entry_id,
                "title": entry_title,
                "timestamp": entry_timestamp,
            },
            "source": {"cve": {"id": source_cve}},
            "vulnerability": {
                "risk": vulnerability_risk,
                "cwe": vulnerability_cwe,
                "cvss3_vuldb": cvss3_vuldb,
            },
            "exploit": {
                "price": exploit_price,
            },
            "countermeasure": {
                "name": countermeasure_name,
                "remediationlevel": countermeasure_remediationlevel,
            },
            "cti": {
                "activity": cti_activity,
            },
        }

    return response


def get_entry_by_id(config, params):
    entry_id = params.get("id")
    if not entry_id:
        raise ConnectorError("Parameter 'id' is required.")

    payload = {"id": entry_id}
    payload = _apply_common_params(payload, config, params)
    response = _post(config, payload)
    if isinstance(response, dict):
        response = _normalize_exploit_status(response)
        return _normalize_exploit_context(response)
    return response


def get_recent(config, params):
    recent = params.get("recent")
    if recent is None or recent == "":
        raise ConnectorError("Parameter 'recent' is required.")

    payload = {"recent": recent}
    payload = _apply_common_params(payload, config, params)
    response = _post(config, payload)
    if isinstance(response, dict):
        response = _normalize_exploit_status(response)
        return _normalize_exploit_context(response)
    return response


def get_updates(config, params):
    updates = params.get("updates")
    if updates is None or updates == "":
        raise ConnectorError("Parameter 'updates' is required.")

    payload = {"updates": updates}
    payload = _apply_common_params(payload, config, params)
    response = _post(config, payload)
    if isinstance(response, dict):
        response = _normalize_exploit_status(response)
        return _normalize_exploit_context(response)
    return response


def search(config, params):
    query = params.get("search")
    if not query:
        raise ConnectorError("Parameter 'search' is required.")

    payload = {"search": query}
    payload = _apply_common_params(payload, config, params)
    response = _post(config, payload)
    if isinstance(response, dict):
        response = _normalize_exploit_status(response)
        return _normalize_exploit_context(response)
    return response


def advanced_search(config, params):
    query = params.get("advancedsearch")
    if query is None:
        raise ConnectorError("Parameter 'advancedsearch' is required.")

    query = str(query).strip()
    if not query:
        raise ConnectorError("Parameter 'advancedsearch' is required.")

    payload = {"advancedsearch": query}
    payload = _apply_common_params(payload, config, params)
    response = _post(config, payload)
    if isinstance(response, dict):
        response = _normalize_exploit_status(response)
        return _normalize_exploit_context(response)
    return response


def vendor_lookup(config, params):
    query = params.get("vendorlookup")
    if not query:
        raise ConnectorError("Parameter 'vendorlookup' is required.")

    payload = {"vendorlookup": query}
    payload = _apply_common_params(payload, config, params)
    return _post(config, payload)


def product_lookup(config, params):
    query = params.get("productlookup")
    if not query:
        raise ConnectorError("Parameter 'productlookup' is required.")

    payload = {"productlookup": query}
    payload = _apply_common_params(payload, config, params)
    return _post(config, payload)


def get_exploit_status(config, params):
    entry_id = params.get("id")
    if not entry_id:
        raise ConnectorError("Parameter 'id' is required.")

    fields = params.get("fields")
    if not fields:
        fields = (
            "exploit_exploitability,exploit_epss_score,exploit_epss_percentile,"
            "exploit_kev_added,exploit_kev_due,exploit_kev_requiredaction,"
            "exploit_kev_knownransomware,exploit_kev_notes"
        )

    payload = {"id": entry_id, "fields": fields}
    payload = _apply_common_params(payload, config, params)
    response = _post(config, payload)
    if isinstance(response, dict):
        return _normalize_exploit_status(response)
    return response


def get_exploit_context(config, params):
    entry_id = params.get("id")
    if not entry_id:
        raise ConnectorError("Parameter 'id' is required.")

    details = params.get("details")
    if details is None:
        params["details"] = True

    fields = params.get("fields")
    if not fields:
        fields = (
            "source_cve_id,vulnerability_risk_value,vulnerability_risk_name,"
            "vulnerability_cwe,vulnerability_cvss3_vuldb_basescore,"
            "vulnerability_cvss3_vuldb_basevector,exploit_epss_score,"
            "exploit_epss_percentile,exploit_price_0day,exploit_price_today,"
            "exploit_price_trend,countermeasure_remediationlevel,"
            "countermeasure_name"
        )

    payload = {"id": entry_id, "fields": fields}
    payload = _apply_common_params(payload, config, params)
    response = _post(config, payload)
    if isinstance(response, dict):
        response = _normalize_exploit_status(response)
        return _normalize_exploit_context(response)
    return response


def cti_ipaddr(config, params):
    ipaddr = params.get("ipaddr")
    if not ipaddr:
        raise ConnectorError("Parameter 'ipaddr' is required.")

    payload = {"ipaddr": ipaddr}
    payload = _apply_common_params(payload, config, params)
    response = _post(config, payload)
    if isinstance(response, dict):
        response = _normalize_exploit_status(response)
        return _normalize_exploit_context(response)
    return response


def cti_actor(config, params):
    actor = params.get("actor")
    if not actor:
        raise ConnectorError("Parameter 'actor' is required.")

    payload = {"actor": actor}
    payload = _apply_common_params(payload, config, params)
    response = _post(config, payload)
    if isinstance(response, dict):
        response = _normalize_exploit_status(response)
        return _normalize_exploit_context(response)
    return response


def cti_sector(config, params):
    sector = params.get("sector")
    if not sector:
        raise ConnectorError("Parameter 'sector' is required.")

    payload = {"sector": sector}
    payload = _apply_common_params(payload, config, params)
    response = _post(config, payload)
    if isinstance(response, dict):
        response = _normalize_exploit_status(response)
        return _normalize_exploit_context(response)
    return response


def cti_events(config, params):
    events = params.get("events")
    if events is None or events == "":
        raise ConnectorError("Parameter 'events' is required.")

    payload = {"events": events}
    payload = _apply_common_params(payload, config, params)
    response = _post(config, payload)
    if isinstance(response, dict):
        response = _normalize_exploit_status(response)
        return _normalize_exploit_context(response)
    return response


def cti_activities_top(config, params):
    activitiestop = params.get("activitiestop")
    if activitiestop is None or activitiestop == "":
        raise ConnectorError("Parameter 'activitiestop' is required.")

    payload = {"activitiestop": activitiestop}
    payload = _apply_common_params(payload, config, params)
    response = _post(config, payload)
    if isinstance(response, dict):
        response = _normalize_exploit_status(response)
        return _normalize_exploit_context(response)
    return response


def cti_iplist_date(config, params):
    iplist_date = params.get("iplist_date") or params.get("iplist")
    if not iplist_date:
        raise ConnectorError("Parameter 'iplist_date' is required.")

    payload = {"iplist": iplist_date}
    payload = _apply_common_params(payload, config, params)
    response = _post(config, payload)
    if isinstance(response, dict):
        response = _normalize_exploit_status(response)
        return _normalize_exploit_context(response)
    return response

