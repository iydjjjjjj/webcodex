from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.webpi import standalone


class PluginAuthProvisioningTests(unittest.TestCase):
    def private_paths(self, root: Path):
        server_env = root / "server.env"
        server_env.write_text("WEBPI_TOKEN=test-bootstrap\n", encoding="utf-8")
        return (
            patch.object(standalone, "SERVER_ENV", server_env),
            patch.object(standalone, "PLUGIN_LOGIN_TOKEN_FILE", root / "plugin-login-token"),
            patch.object(standalone, "PLUGIN_OAUTH_CLIENT_FILE", root / "plugin-oauth-client.json"),
        )

    def test_plugin_oauth_scope_tiers_keep_default_grant_small_and_allow_explicit_escalation(self):
        default = list(standalone.PLUGIN_OAUTH_DEFAULT_SCOPES)
        allowed = list(standalone.PLUGIN_OAUTH_ALLOWED_SCOPES)
        for required in (
            "runtime:read",
            "runner:manage",
            "session:collaborate",
            "project:read",
            "project:write",
            "job:run",
            "plugin:inspect",
            "plugin:invoke",
            "computer:read",
            "computer:display_read",
            "browser:read",
            "diagnostics:read",
        ):
            self.assertIn(required, default)
            self.assertIn(required, allowed)
        for elevated in (
            "communication:read",
            "communication:manage",
            "memory:read",
            "memory:manage",
            "job:detach",
            "service:restart",
            "service:deploy",
            "browser:control",
            "browser:launch",
            "computer:control",
            "computer:launch",
            "computer:pointer_control",
            "computer:clipboard_read",
            "computer:clipboard_write",
            "mcp:local",
            "plugin:mutate",
            "plugin:manage",
            "ssh:local",
            "coding_agent:run",
        ):
            self.assertNotIn(elevated, default)
            self.assertIn(elevated, allowed)
        for forbidden in ("admin", "account:manage"):
            self.assertNotIn(forbidden, allowed)
        self.assertEqual(len(default), len(set(default)))
        self.assertEqual(len(allowed), len(set(allowed)))
        self.assertTrue(set(default).issubset(allowed))

    def test_plugin_login_pat_is_scope_empty_private_idempotent_and_revokes_stale(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            patches = self.private_paths(root)
            active = []
            calls = []
            created_token = "wc_pat_123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

            def admin_post(path, payload):
                calls.append((path, dict(payload)))
                if path == "/api/tokens/list":
                    return {"tokens": list(active)}
                if path == "/api/tokens/create":
                    self.assertEqual(payload["scopes"], [])
                    active.append(
                        {
                            "id": "current",
                            "name": standalone.PLUGIN_LOGIN_TOKEN_NAME,
                            "token_prefix": created_token[:16],
                            "scopes": [],
                            "revoked_at": None,
                        }
                    )
                    return {"token": created_token}
                if path == "/api/tokens/revoke":
                    for item in active:
                        if item.get("id") == payload["token_id"]:
                            item["revoked_at"] = 1
                    return {"success": True}
                raise AssertionError(path)

            with patches[0], patches[1], patches[2], patch.object(
                standalone, "admin_post", side_effect=admin_post
            ):
                first = standalone.provision_plugin_login_token()
                self.assertTrue(first["rotated"])
                self.assertEqual(first["scopes"], [])
                self.assertNotIn(created_token, json.dumps(first))
                self.assertEqual(
                    standalone.PLUGIN_LOGIN_TOKEN_FILE.read_text(encoding="utf-8").strip(),
                    created_token,
                )

                active.append(
                    {
                        "id": "stale",
                        "name": standalone.PLUGIN_LOGIN_TOKEN_NAME,
                        "token_prefix": "wc_pat_stale0000",
                        "scopes": [],
                        "revoked_at": None,
                    }
                )
                calls.clear()
                second = standalone.provision_plugin_login_token()
                self.assertFalse(second["rotated"])
                self.assertEqual(second["stale_revoked"], 1)
                self.assertNotIn("/api/tokens/create", [path for path, _ in calls])
                self.assertIn("/api/tokens/revoke", [path for path, _ in calls])

    def test_plugin_oauth_client_is_private_idempotent_and_revokes_stale(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            patches = self.private_paths(root)
            clients = [
                {
                    "client_id": "wc_client_stale",
                    "name": standalone.PLUGIN_OAUTH_CLIENT_NAME,
                    "redirect_uris": [standalone.PLUGIN_OAUTH_REDIRECT_URI],
                    "allowed_scopes": list(standalone.PLUGIN_OAUTH_ALLOWED_SCOPES),
                    "revoked_at": None,
                }
            ]
            calls = []
            client_id = "wc_client_" + "a" * 64
            client_secret = "wc_csec_" + "b" * 64

            def admin_post(path, payload):
                calls.append((path, dict(payload)))
                if path == "/api/oauth/clients/list":
                    return {"clients": list(clients)}
                if path == "/api/oauth/clients/create":
                    self.assertEqual(payload["redirect_uris"], [standalone.PLUGIN_OAUTH_REDIRECT_URI])
                    self.assertEqual(payload["allowed_scopes"], list(standalone.PLUGIN_OAUTH_ALLOWED_SCOPES))
                    current = {
                        "client_id": client_id,
                        "name": standalone.PLUGIN_OAUTH_CLIENT_NAME,
                        "redirect_uris": [standalone.PLUGIN_OAUTH_REDIRECT_URI],
                        "allowed_scopes": list(standalone.PLUGIN_OAUTH_ALLOWED_SCOPES),
                        "revoked_at": None,
                    }
                    clients.append(current)
                    return {"client": current, "client_secret": client_secret}
                if path == "/api/oauth/clients/revoke":
                    for item in clients:
                        if item.get("client_id") == payload["client_id"]:
                            item["revoked_at"] = 1
                    return {"success": True}
                raise AssertionError(path)

            with patches[0], patches[1], patches[2], patch.object(
                standalone, "admin_post", side_effect=admin_post
            ):
                first = standalone.provision_plugin_oauth_client()
                self.assertTrue(first["rotated"])
                self.assertNotIn(client_secret, json.dumps(first))
                stored = json.loads(
                    standalone.PLUGIN_OAUTH_CLIENT_FILE.read_text(encoding="utf-8")
                )
                self.assertEqual(stored["client_id"], client_id)
                self.assertEqual(stored["client_secret"], client_secret)
                self.assertEqual(first["stale_revoked"], 1)

                calls.clear()
                second = standalone.provision_plugin_oauth_client()
                self.assertFalse(second["rotated"])
                self.assertNotIn("/api/oauth/clients/create", [path for path, _ in calls])
                self.assertNotIn(client_secret, json.dumps(second))

    def test_existing_plugin_oauth_client_expands_scopes_in_place_without_rotating_secret(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            patches = self.private_paths(root)
            client_id = "wc_client_" + "c" * 64
            client_secret = "wc_csec_" + "d" * 64
            old_scopes = list(standalone.PLUGIN_OAUTH_DEFAULT_SCOPES)
            current = {
                "client_id": client_id,
                "name": standalone.PLUGIN_OAUTH_CLIENT_NAME,
                "redirect_uris": [standalone.PLUGIN_OAUTH_REDIRECT_URI],
                "allowed_scopes": old_scopes,
                "revoked_at": None,
            }
            calls = []

            def admin_post(path, payload):
                calls.append((path, dict(payload)))
                if path == "/api/oauth/clients/list":
                    return {"clients": [dict(current)]}
                if path == "/api/oauth/clients/update_scopes":
                    self.assertEqual(payload["client_id"], client_id)
                    self.assertEqual(payload["allowed_scopes"], list(standalone.PLUGIN_OAUTH_ALLOWED_SCOPES))
                    current["allowed_scopes"] = list(payload["allowed_scopes"])
                    return {
                        "success": True,
                        "changed": True,
                        "reauthorization_required": True,
                        "client": dict(current),
                    }
                if path == "/api/oauth/clients/revoke":
                    return {"success": True}
                raise AssertionError(path)

            with patches[0], patches[1], patches[2], patch.object(
                standalone, "admin_post", side_effect=admin_post
            ):
                standalone.PLUGIN_OAUTH_CLIENT_FILE.write_text(
                    json.dumps(
                        {
                            "client_id": client_id,
                            "client_secret": client_secret,
                            "redirect_uri": standalone.PLUGIN_OAUTH_REDIRECT_URI,
                            "allowed_scopes": old_scopes,
                        }
                    ),
                    encoding="utf-8",
                )
                result = standalone.provision_plugin_oauth_client()
                stored = json.loads(standalone.PLUGIN_OAUTH_CLIENT_FILE.read_text(encoding="utf-8"))

            self.assertFalse(result["rotated"])
            self.assertTrue(result["scopes_updated"])
            self.assertTrue(result["reauthorization_required"])
            self.assertNotIn("/api/oauth/clients/create", [path for path, _ in calls])
            self.assertEqual(stored["client_id"], client_id)
            self.assertEqual(stored["client_secret"], client_secret)
            self.assertEqual(stored["allowed_scopes"], list(standalone.PLUGIN_OAUTH_ALLOWED_SCOPES))


if __name__ == "__main__":
    unittest.main()
