# Changelog

## Unreleased

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

## 1.0.0 — 2026-10-08>

First release of the hand-written Java SDK and the Spring Boot starter.

- `io.lumoauth:lumo-auth-java`: `LumoAuth` client with the `auth`, `permissions`,
  `zanzibar`, `abac`, `agents`, `approvals`, `jit`, `delegation` and `mcp`
  namespaces; `LumoAgent`, `JitContext`, `DelegationChain`; AAuth RFC 9421
  signing, token flows and resource-side verification; framework-neutral
  authorization-code + PKCE sign-in; the twelve-class error taxonomy.
- `io.lumoauth:lumo-auth-spring-boot-starter`: `lumoauth.*` properties,
  `LumoAuth` / `LumoAgent` / `AAuthClient` beans, bearer-token introspection,
  OIDC login, `@RequirePermission` and the `@lumo` SpEL bean, actuator health.
