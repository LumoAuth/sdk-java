# lumo-auth-spring-boot-starter

Spring Boot 3 auto-configuration for the LumoAuth Java SDK:
`io.lumoauth:lumo-auth-spring-boot-starter`.

```yaml
lumoauth:
  url: https://app.lumoauth.dev
  org-id: acme-corp
  api-key: ${LUMOAUTH_API_KEY}
  login:
    client-id: lumo_abc
    client-secret: ${LUMOAUTH_CLIENT_SECRET}
```

| Auto-configuration | Provides | Needs on the classpath |
|---|---|---|
| `LumoAuthAutoConfiguration` | `LumoAuth`, `LumoAgent`, `AAuthClient` beans | — |
| `LumoAuthSecurityAutoConfiguration` | `OpaqueTokenIntrospector` for LumoAuth bearer tokens, the `@lumo` SpEL bean, `PermissionEvaluator`, `@RequirePermission` | Spring Security (resource server for bearer tokens) |
| `LumoAuthLoginAutoConfiguration` | `ClientRegistration` "lumoauth" and a default `SecurityFilterChain` | `spring-boot-starter-oauth2-client` |
| `LumoAuthHealthAutoConfiguration` | `/actuator/health/lumoauth` | Spring Boot Actuator |

Security dependencies are optional on purpose: add
`spring-boot-starter-oauth2-client` for sign-in and/or
`spring-boot-starter-oauth2-resource-server` for bearer tokens, and the matching
auto-configuration switches on. Every `lumoauth.*` key is documented in the
generated configuration metadata (IDE completion) and in
`LumoAuthProperties`. See the [repository README](../README.md).
