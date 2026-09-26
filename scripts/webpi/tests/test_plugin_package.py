from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[3]
PLUGIN = ROOT / "plugins" / "webpi-agent"


class WebPiPluginPackageTests(unittest.TestCase):
    def test_portable_manifest_and_mcp_connection_match_openai_layout(self):
        manifest = json.loads((PLUGIN / "plugin.json").read_text(encoding="utf-8"))
        mcp = json.loads((PLUGIN / "mcp.json").read_text(encoding="utf-8"))
        self.assertEqual(
            manifest["$schema"],
            "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
        )
        self.assertEqual(manifest["name"], "webpi-agent")
        self.assertEqual(manifest["extensions"]["com.openai"]["interface"]["displayName"], "WebPi Agent")
        self.assertEqual(
            mcp["$schema"],
            "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        )
        self.assertEqual(
            mcp["mcpServers"]["webpi"],
            {"type": "streamable-http", "url": "https://webpi.piforme.vip/mcp"},
        )

    def test_skill_keeps_webpi_authority_fail_closed_and_contains_no_secret(self):
        skill = (PLUGIN / "skills" / "webpi-agent" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("WebPi as the trusted project execution gateway", skill)
        self.assertIn("Never bypass a WebPi scope or path denial", skill)
        self.assertNotRegex(skill, re.compile(r"ghp_[A-Za-z0-9]{20,}"))
        self.assertNotRegex(skill, re.compile(r"wc_pat_[A-Za-z0-9_-]{20,}"))
        self.assertNotRegex(skill, re.compile(r"-----BEGIN .*PRIVATE KEY-----"))

    def test_plugin_package_has_no_credential_files(self):
        forbidden_suffixes = {".pem", ".key", ".p12", ".pfx", ".env"}
        files = [path for path in PLUGIN.rglob("*") if path.is_file()]
        self.assertTrue(files)
        for path in files:
            self.assertNotIn(path.suffix.lower(), forbidden_suffixes, str(path))
            lower = path.name.lower()
            self.assertNotIn("token", lower, str(path))
            self.assertNotIn("secret", lower, str(path))


if __name__ == "__main__":
    unittest.main()
