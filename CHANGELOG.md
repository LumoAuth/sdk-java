# Changelog

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
