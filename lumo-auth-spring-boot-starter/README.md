# lumo-auth-spring-boot-starter

Spring Boot 3 auto-configuration for the LumoAuth Java SDK: `io.lumoauth:lumo-auth-spring-boot-starter`. It is built against Spring Boot 3.5 and brings in `lumo-auth-java`.

The starter creates the SDK clients as beans. It can also sign users in, accept LumoAuth bearer tokens and check permissions on your methods. The [Spring Boot section](../README.md#spring-boot-starter) of the repository README covers each feature in detail.

## Install

The artifact is not on Maven Central yet. Install it from the repository root, then add the dependency:

```bash
mvn -f sdk-java/pom.xml -DskipTests install
```

```xml
<dependency>
  <groupId>io.lumoauth</groupId>
  <artifactId>lumo-auth-spring-boot-starter</artifactId>
  <version>1.0.0</version>
</dependency>
```

## Quick start

```yaml
lumoauth:
  url: https://app.lumoauth.dev
  org-id: acme-corp
  api-key: ${LUMOAUTH_API_KEY}
  login:
    client-id: lumo_abc
    client-secret: ${LUMOAUTH_CLIENT_SECRET}
```

```java
@Service
class InvoiceService {
    @RequirePermission("invoice.approve")
    public void approve(String id) { /* ... */ }
}
```

The `lumoauth.url`, `org-id` and `api-key` properties also bind from `LUMOAUTH_URL`, `LUMOAUTH_ORG_ID` and `LUMOAUTH_API_KEY`.

With a bearer token, `@RequirePermission` checks run under the user's own token. After an OIDC browser login, they run with the API key and name the signed-in user, so the API key needs the `authz:check` scope.

## What each auto-configuration provides

| Auto-configuration | Provides | Needs on the classpath |
|---|---|---|
| `LumoAuthAutoConfiguration` | `LumoAuth`, `LumoAgent` and `AAuthClient` beans | nothing extra |
| `LumoAuthSecurityAutoConfiguration` | An `OpaqueTokenIntrospector` for LumoAuth bearer tokens, the `@lumo` SpEL bean, a `PermissionEvaluator` and `@RequirePermission` | Spring Security, plus `spring-boot-starter-oauth2-resource-server` for bearer tokens |
| `LumoAuthLoginAutoConfiguration` | The `ClientRegistration` "lumoauth" and a default `SecurityFilterChain` | `spring-boot-starter-oauth2-client` |
| `LumoAuthHealthAutoConfiguration` | `/actuator/health/lumoauth` | Spring Boot Actuator |

The security dependencies are optional. Add `spring-boot-starter-oauth2-client` for sign-in, and `spring-boot-starter-oauth2-resource-server` for bearer tokens. The matching auto-configuration then turns on. If you define your own bean of a provided type, the starter does not create one.

## Properties

Your IDE completes and documents every `lumoauth.*` key, because the starter includes configuration metadata. `LumoAuthProperties` holds the same list. The [property reference](../README.md#configure) in the repository README gives the defaults.

When the app lists the signed-in user's permissions or reads roles from `agents().me()`, add `authz:read` to `lumoauth.login.scopes`.
