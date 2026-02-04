import importlib
import sys
import types
import unittest
import warnings
from unittest import mock

warnings.filterwarnings("ignore", message=".*urllib3 v2 only supports OpenSSL.*")


def _install_connector_stub():
    connectors_module = types.ModuleType("connectors")
    connectors_module.__path__ = []
    core_module = types.ModuleType("connectors.core")
    core_module.__path__ = []
    connector_module = types.ModuleType("connectors.core.connector")

    class ConnectorError(Exception):
        pass

    def get_logger(_name):
        class DummyLogger:
            def debug(self, *args, **kwargs):
                pass

            def info(self, *args, **kwargs):
                pass

            def warning(self, *args, **kwargs):
                pass

            def error(self, *args, **kwargs):
                pass

        return DummyLogger()

    connector_module.ConnectorError = ConnectorError
    connector_module.get_logger = get_logger

    sys.modules.setdefault("connectors", connectors_module)
    sys.modules.setdefault("connectors.core", core_module)
    sys.modules["connectors.core.connector"] = connector_module

    return ConnectorError


ConnectorError = _install_connector_stub()
operations = importlib.import_module("operations")


class AdvancedSearchTests(unittest.TestCase):
    def test_advanced_search_trims_and_includes_fields(self):
        params = {
            "advancedsearch": " vendor:Microsoft ",
            "fields": "vulnerability_cwe",
            "details": True,
        }
        config = {}

        with mock.patch.object(operations, "_post") as post:
            post.return_value = {"result": []}
            operations.advanced_search(config, params)
            payload = post.call_args[0][1]

        self.assertEqual(payload["advancedsearch"], "vendor:Microsoft")
        self.assertEqual(payload["fields"], "vulnerability_cwe")
        self.assertEqual(payload["details"], 1)

    def test_advanced_search_rejects_blank(self):
        params = {"advancedsearch": "   "}
        config = {}

        with self.assertRaises(ConnectorError):
            operations.advanced_search(config, params)


if __name__ == "__main__":
    unittest.main()
