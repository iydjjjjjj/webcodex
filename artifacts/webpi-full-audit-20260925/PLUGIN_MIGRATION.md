# WebPi Custom GPT -> Plugin migration plan

Status: first-release PR/deploy completed; OAuth-protected Plugin MCP implementation and second-round validation are in progress. Final ChatGPT installation/linking remains a UI boundary.

## Current platform contract (2026-09-26)

- Custom GPT instructions migrate into a plugin skill; knowledge files migrate into reference files.
- GPT custom actions do not migrate automatically. Required integrations must be rebuilt as supported apps/actions or a custom MCP server.
- The migrated plugin starts private. Test before sharing or publishing.
- The original GPT becomes read-only after migration and remains usable only until its retirement date.
- Existing GPT conversations do not migrate.

Official references reviewed on 2026-09-26:
- OpenAI Help Center: Custom GPT retirement and migration FAQ
- ChatGPT Learn: Moving your custom GPT workflows to plugins

## WebPi target architecture

Keep one execution/security backend:

ChatGPT plugin skill
  -> custom MCP / WebPi gateway
  -> existing WebPi auth + scopes
  -> WebPi Server
  -> Runner / Project / Pi bridge / artifacts

Do not create a second durable state store, shared administrator token, or bypass path around WebPi scopes. Plugin references and UI affordances grant no authority by themselves.

## Implemented migration design

1. First-release review, fork/Draft PR, clean durable deployment and post-deploy smoke are complete.
2. `plugins/webpi-agent/` is a portable Plugin package: root `plugin.json`, root `mcp.json`, and a WebPi skill. It contains no credential material.
3. The bundled remote connection is streamable HTTP at `https://webpi.piforme.vip/mcp`.
4. Public MCP remains default-off. `WEBPI_PUBLIC_PLUGIN_MCP_ENABLED=true` only admits MCP plus the minimum OAuth protocol routes; `/api/tools/call`, admin, OAuth-client management, bridge and project-share routes stay hidden.
5. Public Plugin MCP fails closed before listener startup unless Actions-only remains enabled, OAuth is enabled, PKCE is required, and the OAuth issuer exactly matches the root HTTPS public origin.
6. Existing WebPi authorization-code OAuth is reused: PKCE S256, RFC 8707 resource binding, refresh/revoke support, and RFC 9207 issuer-bound success/error authorization responses.
7. Tool descriptors expose OAuth `securitySchemes` from the same canonical WebPi authority policy used for dispatch. OAuth scope failures expose `mcp/www_authenticate` metadata while retaining server-side scope enforcement.
8. A predefined ChatGPT OAuth client is used instead of adding DCR. This avoids weakening the existing explicit OAuth-client owner invariant or adding a second registration trust path. Because WebPi advertises issuer identity and binds the authorize response issuer, the stable callback is `https://chatgpt.com/connector_platform_oauth_redirect`; if that issuer contract changes, re-read the callback shown by ChatGPT before changing the allowlist.
9. A dedicated normal-user PAT is used only to sign into WebPi's OAuth authorize page. It is separate from the ChatGPT Action PAT and carries no API scopes. The OAuth client allowlist is explicitly bounded to the existing coding workflow and excludes account/admin/service/control scopes. Client secret and login PAT remain in protected `.webpi-state` files and never enter the Plugin package, repository, prompts, or chat.
10. `webpi.cmd plugin-mcp-config` idempotently enables the fail-closed public Plugin-MCP/OAuth configuration on the already configured HTTPS public origin. `webpi.cmd plugin-auth-provision` idempotently creates/rotates the dedicated login PAT and predefined OAuth client without printing secrets.
11. `python scripts/webpi/plugin_mcp_smoke.py --base-url https://webpi.piforme.vip` performs a real authorization-code + PKCE + RFC 8707 resource-bound OAuth flow, exercises MCP `tools/list` and `runtime_status`, then revokes its short-lived OAuth tokens. Its report contains no credentials or tokens.
12. After backend acceptance, migrate/install the Plugin privately in ChatGPT, enter the predefined OAuth client metadata through the Plugin UI, link OAuth, run the acceptance matrix below, and only then consider sharing/publishing.

## Acceptance matrix

- Skill selection: explicit @/plugin selection chooses WebPi workflow when requested.
- Automatic selection: a normal local-project task selects the WebPi skill when appropriate without forcing it on unrelated tasks.
- Read-only discovery: runtime status, projects, project bootstrap, bounded search/read.
- Safe editing: read_revision-fenced edit, conflict rejection, diff review.
- Execution: structured process and validation Jobs; continuation tokens survive handoff.
- Git: status/diff/log and explicit-path commit behavior; no automatic push.
- Recovery: reconnect/reconciliation/lost-job semantics stay fail-closed.
- Pi bridge: inventory -> describe -> call; no implicit extension approval.
- Authority: missing service/plugin/communication scopes remain blocked; MCP/plugin metadata never widens authority.
- Security: no secrets in skill/reference files, logs, prompts or plugin metadata.
- Output quality: familiar prompts plus one harder end-to-end coding task match or improve the custom GPT workflow.
- Performance: compare tool-call count/handoff/cleanup against the preserved baseline.
- OAuth protocol: protected-resource and authorization-server discovery, stable issuer-bound callback, PKCE S256, repeated `resource`, exact client allowlist, and post-smoke revocation all pass without emitting secrets.

## Current external boundary

- First-release Draft PR: `yyjeqhc/webcodex#689`; its exact reviewed revision was deployed successfully with clean Server/Runner source alignment and public security smoke.
- The second Plugin delta will be reviewed, pushed and deployed through the same receipt-fenced workflow before ChatGPT linking.
- Disposable Docker image smoke remains a remote-CI proof because local Docker Hub OAuth returned EOF and no base images were cached.
- Final ChatGPT Plugin installation/migration, predefined OAuth client entry and private linking require the account/workspace Plugin UI. No secret will be printed into chat; the client secret and login PAT stay in protected local state and are only entered at that UI boundary.
