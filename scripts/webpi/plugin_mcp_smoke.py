"""End-to-end WebPi Plugin MCP OAuth smoke without printing credentials or tokens."""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.cookiejar
import json
from pathlib import Path
import secrets
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from security_smoke import NoRedirect, validate_origin
from standalone import (
    PLUGIN_LOGIN_TOKEN_FILE,
    PLUGIN_OAUTH_ALLOWED_SCOPES,
    PLUGIN_OAUTH_CLIENT_FILE,
    PLUGIN_OAUTH_REDIRECT_URI,
)

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / ".webpi-state"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def _private_file(path: Path) -> Path:
    state = STATE.resolve()
    resolved = path.resolve()
    if path.is_symlink() or resolved.parent != state:
        raise RuntimeError("Plugin credential path must remain in the private WebPi state directory")
    if not path.is_file():
        raise RuntimeError("Plugin credential provisioning is incomplete")
    return path


def _bounded_read(response) -> bytes:
    payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise RuntimeError("OAuth/MCP smoke response exceeded the bounded response budget")
    return payload


def _request(
    opener: urllib.request.OpenerDirector,
    url: str,
    *,
    method: str = "GET",
    form: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
    authorization: str | None = None,
    timeout: float = 10.0,
) -> tuple[int, Any, bytes]:
    if form is not None and json_body is not None:
        raise ValueError("request cannot contain both form and JSON body")
    headers = {"User-Agent": "WebPi-Plugin-MCP-Smoke/1"}
    data = None
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Accept"] = "application/json,text/html;q=0.9,*/*;q=0.1"
        data = urllib.parse.urlencode(form).encode("utf-8")
    elif json_body is not None:
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json"
        data = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
    else:
        headers["Accept"] = "application/json,text/html;q=0.9,*/*;q=0.1"
    if authorization is not None:
        headers["Authorization"] = authorization
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = _bounded_read(response)
        return response.status, response.headers, raw


def _json(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError) as error:
        raise RuntimeError("expected a bounded JSON response") from error


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge


def run_smoke(origin: str, timeout: float = 10.0) -> dict[str, object]:
    base = validate_origin(origin)
    if urllib.parse.urlsplit(base).scheme != "https":
        raise RuntimeError("Plugin MCP OAuth smoke requires the configured public HTTPS origin")
    resource = f"{base}/mcp"

    login_token = _private_file(PLUGIN_LOGIN_TOKEN_FILE).read_text(encoding="utf-8").strip()
    client_record = json.loads(_private_file(PLUGIN_OAUTH_CLIENT_FILE).read_text(encoding="utf-8"))
    if not login_token.startswith("wc_pat_"):
        raise RuntimeError("Plugin login PAT is malformed")
    if not isinstance(client_record, dict):
        raise RuntimeError("Plugin OAuth client record is malformed")
    client_id = client_record.get("client_id")
    client_secret = client_record.get("client_secret")
    redirect_uri = client_record.get("redirect_uri")
    if not isinstance(client_id, str) or not client_id.startswith("wc_client_"):
        raise RuntimeError("Plugin OAuth client id is malformed")
    if not isinstance(client_secret, str) or not client_secret.startswith("wc_csec_"):
        raise RuntimeError("Plugin OAuth client secret is malformed")
    if redirect_uri != PLUGIN_OAUTH_REDIRECT_URI:
        raise RuntimeError("Plugin OAuth redirect URI does not match the supported ChatGPT callback")

    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(cookie_jar))
    verifier, challenge = _pkce_pair()
    state = "webpi-plugin-smoke-" + secrets.token_hex(12)
    scope = " ".join(PLUGIN_OAUTH_ALLOWED_SCOPES)
    authorize = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": resource,
    }
    return_to = "/oauth/authorize?" + urllib.parse.urlencode(authorize)

    status, headers, _ = _request(
        opener,
        f"{base}/oauth/authorize/login",
        method="POST",
        form={"return_to": return_to, "token": login_token},
        timeout=timeout,
    )
    if status != 302 or not headers.get("Location", "").startswith("/oauth/authorize"):
        raise RuntimeError("Plugin OAuth login did not establish an authorization session")
    if not list(cookie_jar):
        raise RuntimeError("Plugin OAuth login did not establish a session cookie")

    consent = dict(authorize)
    consent["decision"] = "allow"
    status, headers, _ = _request(
        opener,
        f"{base}/oauth/authorize/consent",
        method="POST",
        form=consent,
        timeout=timeout,
    )
    if status != 302:
        raise RuntimeError("Plugin OAuth consent did not produce an authorization redirect")
    location = headers.get("Location", "")
    parsed = urllib.parse.urlsplit(location)
    expected = urllib.parse.urlsplit(PLUGIN_OAUTH_REDIRECT_URI)
    if (parsed.scheme, parsed.netloc, parsed.path) != (expected.scheme, expected.netloc, expected.path):
        raise RuntimeError("Plugin OAuth consent redirect did not target the configured ChatGPT callback")
    params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    code = params.get("code")
    if not code or params.get("state") != state or params.get("iss", "").rstrip("/") != base.rstrip("/"):
        raise RuntimeError("Plugin OAuth authorization redirect is missing code/state/issuer binding")

    token_form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
        "code_verifier": verifier,
        "resource": resource,
    }
    status, _, raw = _request(
        opener,
        f"{base}/oauth/token",
        method="POST",
        form=token_form,
        timeout=timeout,
    )
    token_payload = _json(raw)
    if status != 200 or not isinstance(token_payload, dict):
        raise RuntimeError("Plugin OAuth token exchange failed")
    access_token = token_payload.get("access_token")
    refresh_token = token_payload.get("refresh_token")
    returned_scope = token_payload.get("scope")
    if not isinstance(access_token, str) or not access_token.startswith("wc_oat_"):
        raise RuntimeError("Plugin OAuth token exchange returned no access token")
    if not isinstance(refresh_token, str) or not refresh_token.startswith("wc_ort_"):
        raise RuntimeError("Plugin OAuth token exchange returned no refresh token")
    if set(str(returned_scope or "").split()) != set(PLUGIN_OAUTH_ALLOWED_SCOPES):
        raise RuntimeError("Plugin OAuth token scopes do not match the intended allowlist")

    auth_header = "Bearer " + access_token
    status, _, raw = _request(
        opener,
        resource,
        method="POST",
        json_body={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        authorization=auth_header,
        timeout=timeout,
    )
    tools_payload = _json(raw)
    tools = (
        tools_payload.get("result", {}).get("tools")
        if isinstance(tools_payload, dict) and isinstance(tools_payload.get("result"), dict)
        else None
    )
    if status != 200 or not isinstance(tools, list) or not tools:
        raise RuntimeError("Plugin MCP tools/list failed")
    runtime_tool = next((tool for tool in tools if isinstance(tool, dict) and tool.get("name") == "runtime_status"), None)
    if not isinstance(runtime_tool, dict) or not runtime_tool.get("securitySchemes"):
        raise RuntimeError("Plugin MCP runtime_status is missing OAuth security metadata")

    status, _, raw = _request(
        opener,
        resource,
        method="POST",
        json_body={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "runtime_status", "arguments": {"compact": True}},
        },
        authorization=auth_header,
        timeout=timeout,
    )
    call_payload = _json(raw)
    if status != 200 or not isinstance(call_payload, dict) or call_payload.get("error") is not None:
        raise RuntimeError("Plugin MCP authenticated runtime_status call failed")

    for token, hint in ((access_token, "access_token"), (refresh_token, "refresh_token")):
        revoke_status, _, _ = _request(
            opener,
            f"{base}/oauth/revoke",
            method="POST",
            form={
                "token": token,
                "token_type_hint": hint,
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=timeout,
        )
        if revoke_status != 200:
            raise RuntimeError("Plugin OAuth smoke could not revoke its short-lived credentials")

    return {
        "passed": True,
        "origin": base,
        "resource": resource,
        "pkce": "S256",
        "resource_bound": True,
        "issuer_bound": True,
        "scope_count": len(PLUGIN_OAUTH_ALLOWED_SCOPES),
        "tool_count": len(tools),
        "runtime_status_security_schemes_present": True,
        "tokens_revoked": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)
    report = run_smoke(args.base_url, args.timeout)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, urllib.error.URLError):
        print(json.dumps({"passed": False, "error": "plugin_mcp_oauth_smoke_failed"}))
        raise SystemExit(2)
