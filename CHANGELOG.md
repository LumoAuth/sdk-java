# Changelog

## Unreleased

- **Fixed:** `LumoAgent.checkBudget()` and `AgentBudget.exhausted()` use the server's own verdict
  when UserInfo reports `exhausted` (any limit, any window: calls, tokens or cost per hour, day or
  month); the new `AgentBudget.reportedExhausted()` carries it. Without it (older servers), the
  daily token cap is compared with today's usage, as before. The three-argument constructor stays.
- **Fixed:** `LumoAgent.hasCapability` and `requireCapability` match capability names the way the
  server does. The server stores capabilities in lower case with `.` between the parts, so a check
  for `tool:search_web` used to fail against the stored `tool.search_web`, and a held wildcard such
  as `invoices.*` never matched `invoices.read`. The new `io.lumoauth.Capabilities` class
  (`normalize`, `covers`, `anyCovers`) holds the rules, tested against
  `sdk-contract/vectors/agent-capabilities.json`.

## 1.3.0 — 2026-11-05

- **Fixed (Spring Boot starter):** builds on JDK 23 and newer now run the Spring Boot
  annotation processors (`<proc>full</proc>` on `maven-compiler-plugin`), ensuring the starter
  jar packages `META-INF/spring-configuration-metadata.json` and
  `META-INF/spring-autoconfigure-metadata.properties` for IDE completion of `lumoauth.*`
  properties and faster auto-configuration.
- **Changed (Spring Boot starter):** updated the managed Spring Boot dependency baseline to
  `4.1.2` (along with Jackson `2.19.4`, JUnit `5.14.4` and AssertJ `3.27.7`).
- **Changed:** aligned `io.lumoauth:lumo-auth-parent`, `io.lumoauth:lumo-auth-java` and
  `io.lumoauth:lumo-auth-spring-boot-starter` with the LumoAuth `1.3.0` SDK release train.

## 1.2.0 — 2026-10-30

- **Added:** per-tool MCP checks. `mcp().authorizeTool(serverId, subjectType, subjectId, tool)`
  lets an MCP server ask whether a user or agent may run a tool. The server uses its own
  client-credentials token with the scope `mcp:authorize`, never the caller's token.
  `agents().authorizeMcpTool(serverId, tool)` and `LumoAgent.authorizeMcpTool` let an agent ask
  about itself. `serverId` is the registered MCP server ID (`mcp_...`). A deny returns
  `allowed() == false` (`McpToolDecision`, `AgentMcpToolDecision`) and does not throw.

## 1.1.0 — 2026-10-26

- **Fixed:** approvals no longer fail when the push prompt reaches no device. When the
  user has no enrolled push device (or does not exist), LumoAuth answers 202
  `email_fallback_sent` with no approval token. `approvals().create` now returns a result
  with that status and a null token (`ApprovalResult.emailFallbackSent()`); it used to throw
  `LumoAuthValidationException`. `approvals().require` throws the new
  `LumoAuthApprovalNotDeliveredException` (code `APPROVAL_NOT_DELIVERED`) with the reason
  `email_fallback_sent` and does not poll. A 428 `no_enrolled_device` reply throws the same
  exception with the reason `no_enrolled_device`. `ApprovalResult` gains `message()`.
- **Fixed:** MCP tokens are now bound to the MCP server. `mcp().token(serverId)` and
  `LumoAgent.mcpToken(serverId)` send the server ID as the RFC 8707 `resource` parameter,
  which LumoAuth uses for the token's `aud`. They used to send only `audience`, which
  LumoAuth ignores. The server ID must now be the MCP server's https URL, for example
  `https://mcp.example.com/mcp`. Other IDs, such as `urn:mcp:…`, throw
  `LumoAuthValidationException` before any request.
- **Fixed:** `jit().pending()` reads the `data` list of the server's reply. It used to look
  for `requests` and threw on the current reply shape.
- **Fixed (Spring Boot starter):** ABAC checks (`@lumo.abac` and the three-argument
  `hasPermission`) now send the user's access token, never the API key, which the ABAC routes
  refuse with 401. After an OIDC login, the starter reads the token from the login's
  `OAuth2AuthorizedClient` and refreshes it when it has expired. The login scopes need
  `abac:read`. When no user token is available, the check returns `false` and logs why.
  A new `UserAccessTokenResolver` bean type lets the app supply the token.

- **Fixed:** checks about another subject now work. `CheckOptions.forUser(id)` used to
  send `user_id`, which LumoAuth ignores, so the check silently answered for the caller
  (the API key's owner). The SDK now sends `"subject": {"type": "user", "id": …}`. The
  caller needs the `authz:check` scope or permission, and the id must be a LumoAuth user id.
  This also fixes `@RequirePermission`, the `@lumo` bean and the `PermissionEvaluator`
  after an OIDC browser login, which check with the API key on behalf of the user.
- `CheckOptions.forAgent(agentId)` and `CheckOptions.agent(...)` check an agent.
  The Spring helpers map an `agent_<id>` principal to an agent subject.
- **Fixed:** ABAC checks now reach the policies with their attributes. `AbacCheck.context`
  is sent as `environment`, the field that LumoAuth reads; it used to be sent as `context`
  and ignored.
- **Fixed:** `abac().checkBulk` sends `checks` (it sent `requests`, which LumoAuth rejected
  with 400). The new `checkBulk(checks, environment)` passes the one environment that applies
  to every check; the one-argument form requires every check to carry the same context.
- `LumoAuthPermissionDeniedException.requiredScopes()` lists the scopes a 403
  scope refusal names in `details.required_scopes`. It is empty for a plain denial.
- Javadoc and README describe the server's scope rules. A user access token needs
  `authz:read` for `permissions().list()`, `abac:read` / `abac:write` for ABAC, and
  `jit:approve` for `jit().pending()`. `agents().me()` returns no capabilities to a
  user token without `authz:read`.
- Javadoc notes other server changes: `agents().ask()` keeps caller-supplied
  request fields under `pep`, approvals refuse portal test tokens, the approval
  email no longer carries a sign-in link, and token exchange refuses inactive
  subjects and JIT task tokens.

## 1.0.0 — 2026-10-08

First release of the hand-written Java SDK and the Spring Boot starter.

- `io.lumoauth:lumo-auth-java`: `LumoAuth` client with the `auth`, `permissions`,
  `zanzibar`, `abac`, `agents`, `approvals`, `jit`, `delegation` and `mcp`
  namespaces; `LumoAgent`, `JitContext`, `DelegationChain`; AAuth RFC 9421
  signing, token flows and resource-side verification; framework-neutral
  authorization-code + PKCE sign-in; the twelve-class error taxonomy.
- `io.lumoauth:lumo-auth-spring-boot-starter`: `lumoauth.*` properties,
  `LumoAuth` / `LumoAgent` / `AAuthClient` beans, bearer-token introspection,
  OIDC login, `@RequirePermission` and the `@lumo` SpEL bean, actuator health.
