from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.webpi import standalone


class PluginMcpConfigTests(unittest.TestCase):
    def test_plugin_mcp_config_is_fail_closed_idempotent_and_preserves_bootstrap_secret(self):
        with tempfile.TemporaryDirectory() as td:
            env_file = Path(td) / "webpi.env"
            env_file.write_text(
                "WEBPI_TOKEN=keep-secret\n"
                "WEBPI_PUBLIC_URL=https://webpi.example\n"
                "WEBPI_PUBLIC_ACTIONS_ONLY=true\n"
                "WEBPI_PUBLIC_PLUGIN_MCP_ENABLED=false\n"
                "WEBPI_OAUTH2_ENABLED=false\n"
                "WEBPI_OAUTH2_REQUIRE_PKCE=false\n"
                "WEBPI_OAUTH2_ISSUER=https://old.example\n",
                encoding="utf-8",
            )
            with patch.object(standalone, "SERVER_ENV", env_file), patch.object(
                standalone, "ensure_server_state", return_value=None
            ), patch.object(standalone, "server_is_online", return_value=True):
                first = standalone.configure_plugin_mcp()
                second = standalone.configure_plugin_mcp()

            self.assertEqual(first, second)
            self.assertTrue(first["restart_required"])
            values = standalone._env_values(env_file)
            self.assertEqual(values["WEBPI_TOKEN"], "keep-secret")
            self.assertEqual(values["WEBPI_PUBLIC_ACTIONS_ONLY"], "true")
            self.assertEqual(values["WEBPI_PUBLIC_PLUGIN_MCP_ENABLED"], "true")
            self.assertEqual(values["WEBPI_OAUTH2_ENABLED"], "true")
            self.assertEqual(values["WEBPI_OAUTH2_REQUIRE_PKCE"], "true")
            self.assertEqual(values["WEBPI_OAUTH2_ISSUER"], "https://webpi.example")
            self.assertEqual(values["WEBPI_OAUTH2_SHARED_KEY_BRIDGE"], "false")
            self.assertEqual(values["WEBPI_PROJECT_SHARE_MCP_QUERY_TOKEN_ENABLED"], "false")
            self.assertEqual(env_file.read_text(encoding="utf-8").count("WEBPI_OAUTH2_ISSUER="), 1)

    def test_plugin_mcp_config_requires_public_https_origin(self):
        with tempfile.TemporaryDirectory() as td:
            env_file = Path(td) / "webpi.env"
            env_file.write_text("WEBPI_TOKEN=keep-secret\n", encoding="utf-8")
            with patch.object(standalone, "SERVER_ENV", env_file), patch.object(
                standalone, "ensure_server_state", return_value=None
            ):
                with self.assertRaisesRegex(RuntimeError, "PUBLIC_URL"):
                    standalone.configure_plugin_mcp()


if __name__ == "__main__":
    unittest.main()
