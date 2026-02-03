from connectors.core.connector import Connector, ConnectorError, get_logger

from .operations import (
    advanced_search,
    cti_activities_top,
    cti_actor,
    cti_events,
    cti_ipaddr,
    cti_iplist_date,
    cti_sector,
    get_entry_by_id,
    get_exploit_context,
    get_exploit_status,
    get_recent,
    get_updates,
    product_lookup,
    search,
    vendor_lookup,
)

logger = get_logger("vuldb")


class VulDBConnector(Connector):
    def execute(self, config, operation, params, **kwargs):
        supported_operations = {
            "get_entry_by_id": get_entry_by_id,
            "get_recent": get_recent,
            "get_updates": get_updates,
            "search": search,
            "advanced_search": advanced_search,
            "vendor_lookup": vendor_lookup,
            "product_lookup": product_lookup,
            "get_exploit_status": get_exploit_status,
            "get_exploit_context": get_exploit_context,
            "cti_ipaddr": cti_ipaddr,
            "cti_actor": cti_actor,
            "cti_sector": cti_sector,
            "cti_events": cti_events,
            "cti_activities_top": cti_activities_top,
            "cti_iplist_date": cti_iplist_date,
        }

        operation_fn = supported_operations.get(operation)
        if not operation_fn:
            raise ConnectorError(f"Unsupported operation: {operation}")

        return operation_fn(config, params)

    def check_health(self, config):
        try:
            if config.get("skip_health_check_api_call") is True:
                logger.warning(
                    "Health check skipped API call; only API key presence validated."
                )
                if not config.get("api_key"):
                    raise ConnectorError("Missing API key in connector configuration.")
                return True
            test_params = {"recent": 1, "format": "json"}
            result = get_recent(config, test_params)
        except Exception as exc:
            logger.exception("Health check failed")
            raise ConnectorError(f"Health check failed: {exc}") from exc

        if not isinstance(result, dict):
            raise ConnectorError("Unexpected response format from VulDB API.")

        response = result.get("response", {})
        status = ""
        error = ""
        if isinstance(response, dict) and response:
            status = str(response.get("status", ""))
            error = response.get("error") or response.get("status_message") or ""
        else:
            status = str(result.get("status", ""))
            error = result.get("error") or result.get("message") or ""
        if status and status != "200" and status != "204":
            raise ConnectorError(
                f"Health check returned status {status}: {error or 'Unknown error'}"
            )

        return True

