<div align="center">

# LumoAuth Java SDK

**Authorization, agent identity and sign-in for Java services, Spring Boot apps and AI agents.**

[![lumo-auth-java on Maven Central](https://img.shields.io/maven-central/v/io.lumoauth/lumo-auth-java.svg?label=lumo-auth-java)](https://central.sonatype.com/artifact/io.lumoauth/lumo-auth-java)
[![lumo-auth-spring-boot-starter on Maven Central](https://img.shields.io/maven-central/v/io.lumoauth/lumo-auth-spring-boot-starter.svg?label=spring-boot-starter)](https://central.sonatype.com/artifact/io.lumoauth/lumo-auth-spring-boot-starter)
[![CI](https://github.com/lumoauth/sdk-java/actions/workflows/ci.yml/badge.svg)](https://github.com/lumoauth/sdk-java/actions/workflows/ci.yml)
[![Java 17+](https://img.shields.io/badge/java-17%2B-blue.svg)](#versioning-and-compatibility)
[![Spring Boot 3](https://img.shields.io/badge/spring%20boot-3.x-6DB33F.svg)](#spring-boot-starter)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

</div>

---

[LumoAuth](https://lumoauth.dev) answers one question for your code: is this person or this AI agent allowed to do this? This SDK lets a Java program ask that question and act on the answer.

You can use it to:

- check roles and permissions (RBAC), relationships (Zanzibar-style ReBAC) and attribute-based policies (ABAC);
- sign users in with OAuth 2.1 and OpenID Connect;
- give an AI agent its own identity, with capabilities, a budget, human approvals and Just-in-Time permissions;
- let an agent act on behalf of a user through token exchange (RFC 8693);
- sign agent requests and verify agent tokens with AAuth (RFC 9421 HTTP message signatures).

The SDK is plain Java 17. It uses builders, records, `Optional`, `Duration`, unchecked exceptions and `java.net.http`. Its only runtime dependency is Jackson. A Spring Boot starter turns the SDK into beans and connects it to Spring Security.

```java
LumoAuth lumo = LumoAuth.fromEnvironment();           // reads LUMOAUTH_URL, LUMOAUTH_ORG_ID, LUMOAUTH_API_KEY

if (lumo.permissions().check("invoice.approve")) {
    approve(invoice);
}
```

## Contents

- [Requirements](#requirements)
- [Install](#install)
- [Quick start](#quick-start)
- [Core concepts](#core-concepts)
- [Configuration](#configuration)
- [Guides](#guides)
  - [Check permissions](#check-permissions)
  - [List a user's permissions](#list-a-users-permissions)
  - [Check relationships (Zanzibar)](#check-relationships-zanzibar)
  - [Check attribute-based policies (ABAC)](#check-attribute-based-policies-abac)
  - [Sign users in without Spring](#sign-in-without-spring)
  - [Work with tokens directly](#work-with-tokens-directly)
  - [Spring Boot starter](#spring-boot-starter)
  - [Build an AI agent](#build-an-ai-agent)
  - [Ask a human for approval](#ask-a-human-for-approval)
  - [Use Just-in-Time permissions](#use-just-in-time-permissions)
  - [Act on behalf of a user](#act-on-behalf-of-a-user)
  - [Get a token for an MCP server](#get-a-token-for-an-mcp-server)
  - [Give an agent a cryptographic identity (AAuth)](#aauth-cryptographic-agent-identity)
  - [Verify AAuth tokens on a resource server](#verify-aauth-tokens-on-a-resource-server)
  - [Call any endpoint](#call-any-endpoint)
- [Errors](#errors)
- [API reference](#api-reference)
- [Troubleshooting](#troubleshooting)
- [Versioning and compatibility](#versioning-and-compatibility)
- [Development](#development)
- [License](#license)

## Requirements

| | Version |
|---|---|
| Java | 17 or newer. CI tests on 17 and 21. |
| Spring Boot (starter only) | 3.x. The starter is built against Spring Boot 3.5. |
| Build tool | Maven or Gradle (Groovy or Kotlin DSL) |
| LumoAuth | A LumoAuth organization on `https://app.lumoauth.dev` (US) or `https://eu.app.lumoauth.dev` (EU) |

## Install

The project has two modules. Both use the group `io.lumoauth` and the version `1.0.0`.

| Module | Coordinates | Use it when |
|---|---|---|
| [`lumo-auth-java`](lumo-auth-java) | `io.lumoauth:lumo-auth-java` | You write any Java 17+ code: a service, a CLI, an agent, a Quarkus or Micronaut app, or a plain `main()`. It depends only on the JDK and Jackson. |
| [`lumo-auth-spring-boot-starter`](lumo-auth-spring-boot-starter) | `io.lumoauth:lumo-auth-spring-boot-starter` | You build a Spring Boot 3 app. It brings in `lumo-auth-java`. |

> **Not on Maven Central yet.** The artifacts are not published to Maven Central. Until they are, install them into your local Maven repository from this repository:
>
> ```bash
> mvn -f sdk-java/pom.xml -DskipTests install
> ```

Then add the dependency.

<table>
<tr><th>Maven</th><th>Gradle (Kotlin DSL)</th></tr>
<tr>
<td>

```xml
<dependency>
  <groupId>io.lumoauth</groupId>
  <artifactId>lumo-auth-java</artifactId>
  <version>1.0.0</version>
</dependency>
```

</td>
<td>

```kotlin
implementation("io.lumoauth:lumo-auth-java:1.0.0")
```

</td>
</tr>
<tr>
<td>

```xml
<!-- Spring Boot apps: the starter brings lumo-auth-java with it -->
<dependency>
  <groupId>io.lumoauth</groupId>
  <artifactId>lumo-auth-spring-boot-starter</artifactId>
  <version>1.0.0</version>
</dependency>
```

</td>
<td>

```kotlin
implementation("io.lumoauth:lumo-auth-spring-boot-starter:1.0.0")
```

</td>
</tr>
</table>

With Gradle, add `mavenLocal()` to your repositories while the artifacts come from your local Maven repository.

## Quick start

### A service that checks a permission

Create an API key in the LumoAuth portal and set three environment variables:

```bash
export LUMOAUTH_URL=https://app.lumoauth.dev
export LUMOAUTH_ORG_ID=acme-corp          # your organization's slug
export LUMOAUTH_API_KEY=lmk_...
```

Then check a permission:

```java
import io.lumoauth.LumoAuth;

public class Main {
    public static void main(String[] args) {
        LumoAuth lumo = LumoAuth.fromEnvironment();

        boolean allowed = lumo.permissions().check("document.edit");
        System.out.println(allowed ? "allowed" : "denied");
    }
}
```

With an API key, `check` answers for the user who created the key. To ask about another user, see [Check permissions](#check-permissions).

### An agent that asks before it acts

Register the agent in the portal, then set `AGENT_CLIENT_ID`, `AGENT_CLIENT_SECRET` and `LUMOAUTH_ORG_ID`.

```java
LumoAgent agent = LumoAgent.fromEnvironment();

agent.requireCapability("tool:send_email");      // throws if the agent does not hold the capability
agent.checkBudget();                             // throws when the agent has used today's budget

if (!agent.isAllowed("send_email", Map.of("to", "cfo@acme.com"))) {
    return;                                      // LumoAuth denied the action and recorded the decision
}

ApprovalResult ok = agent.approvals().require(   // waits until a person approves or denies
    ApprovalRequest.builder("wire-7741", "Wire $4,500 to vendor INV-7741", "ada@acme.com")
        .impact(ApprovalImpact.HIGH)
        .build());

sendWire(ok.token());
```

### A Spring Boot API

```yaml
# application.yml
lumoauth:
  org-id: acme-corp
  api-key: ${LUMOAUTH_API_KEY}
```

```java
@Service
class InvoiceService {
    @RequirePermission("invoice.approve")        // answers 403 unless the caller holds the permission
    public void approve(String id) { /* ... */ }
}
```

The [Spring Boot starter](#spring-boot-starter) section shows sign-in, bearer tokens and the other annotations.

## Core concepts

### Organization and base URL

Each LumoAuth customer has an **organization**. Its slug (for example `acme-corp`) is the `orgId` setting. Most API paths start with `/orgs/{orgId}/api/v1/`, so set the slug once on the client.

The **base URL** is `https://app.lumoauth.dev` by default. Organizations in the EU region use `https://eu.app.lumoauth.dev`.

### Credentials

The SDK sends one credential per request. The credential that you use determines what you may call.

| Credential | How you get it | How the SDK sends it | What it may call |
|---|---|---|---|
| Organization API key (`lmk_…`) | Portal, **API keys** | `X-API-Key` header | The permission check routes, Zanzibar check and expand, the admin API and client registration. Not the ABAC, agent or JIT routes. |
| User access token | Sign-in ([`AuthorizationCodeFlow`](#sign-in-without-spring) or the Spring starter) | `Authorization: Bearer` | Calls about that user. Some calls also need a scope; see [Scopes](#scopes). |
| Agent credential | `LumoAgent` (client credentials), or an agent API key (`agk_…`) passed as a bearer token | `Authorization: Bearer` | The agent, approval, JIT and check routes. The agent's capabilities determine what else it may call. |

A builder that receives both an API key and a bearer token sends only the bearer token. The two are never sent together. Calls to the token endpoint send neither: they authenticate with the client ID and secret in the form body.

### Scopes

A user access token carries scopes. Some calls need a specific scope, and LumoAuth answers 403 without it.

| Call | Scope that a user access token needs |
|---|---|
| `permissions().list()`, `permissions().listSlugs()` | `authz:read` |
| ABAC checks and attribute reads | `abac:read` |
| ABAC attribute writes | `abac:write` |
| `jit().pending()` (people who review JIT requests) | `jit:approve` |
| `agents().register(...)` | `admin:agents:write` |
| Permission checks, Zanzibar check and expand, `agents().ask(...)`, `agents().me()`, `auth().userinfo()` | none |

The blanket `admin` scope satisfies every row. A check about another user (`CheckOptions.forUser(...)`) needs the `authz:check` scope or permission. Agent credentials do not use scopes: the agent's capabilities apply instead.

When a scope is missing, the SDK throws `LumoAuthPermissionDeniedException`. Its `requiredScopes()` method returns the scopes that the server named. Request those scopes when the user signs in.

### How the SDK behaves

- **Records in, records out.** Request parameters are immutable records. Small ones have static factories and "wither" methods (`AbacCheck.of("document", "read").resourceId("doc-1")`). Large ones have builders.
- **No field is lost.** Response records with an open shape implement `RawPayload`. Their `raw()` method returns every field that the server sent, including fields that are newer than the SDK.
- **Unchecked exceptions.** Methods that answer yes or no (`check`, `isAllowed`, `hasCapability`) return a boolean. Methods named `require…` throw when the answer is no.
- **Thread-safe clients.** `LumoAuth`, `LumoAgent` and `AAuthClient` are immutable and thread-safe. Build one per credential and share it.
- **Generated routes.** `Routes.java` is generated from the shared [`sdk-contract`](../sdk-contract). The build checks it against the contract, so the SDK cannot drift from the server's API unnoticed.

## Configuration

### `LumoAuth` options

```java
LumoAuth lumo = LumoAuth.builder()
    .baseUrl("https://app.lumoauth.dev")
    .orgId("acme-corp")
    .apiKey(System.getenv("LUMOAUTH_API_KEY"))
    .timeout(Duration.ofSeconds(10))
    .build();
```

| Builder method | What it sets | Default |
|---|---|---|
| `baseUrl(url)` | The LumoAuth URL | `LUMOAUTH_URL`, else `https://app.lumoauth.dev` |
| `orgId(slug)` | The organization slug | `LUMOAUTH_ORG_ID`; required for org-scoped calls |
| `apiKey(key)` | An organization API key, sent as `X-API-Key` | `LUMOAUTH_API_KEY` |
| `accessToken(token)` | A fixed bearer token, for example a user's token inside one request | none |
| `tokenProvider(() -> …)` | A function that returns a bearer token for each request. A returned token wins over the API key. | none |
| `timeout(duration)` | The timeout for each request | 30 seconds |
| `httpClient(client)` | Your own `java.net.http.HttpClient`, for proxies, custom TLS or instrumentation | a new client |
| `header(name, value)` | A header that is added to every request | none |
| `userAgent(value)` | The `User-Agent` header | `lumoauth-java/<version>` |
| `skipCertValidation(true)` | Trust any TLS certificate. Use it for local development only. | `false` |
| `withoutCredential()` | Build a client without a credential, for calls that need none | a credential is required |

`LumoAuth.fromEnvironment()` is the same as `LumoAuth.builder().build()`: every option comes from its environment variable.

### `LumoAgent` options

| Builder method | What it sets | Default |
|---|---|---|
| `clientId(id)`, `clientSecret(secret)` | The agent's OAuth client credentials | `AGENT_CLIENT_ID`, `AGENT_CLIENT_SECRET`; required |
| `orgId(slug)` | The organization slug | `LUMOAUTH_ORG_ID` |
| `baseUrl(url)` | The LumoAuth URL | `LUMOAUTH_URL`, else `https://app.lumoauth.dev` |
| `scopes(...)` | The scopes that the agent asks for when it authenticates | the agent's registered defaults |
| `redirectUri(uri)` | The redirect URI that delegation consent uses | none |
| `timeout`, `httpClient`, `skipCertValidation`, `userAgent` | As for `LumoAuth` | as for `LumoAuth` |

### Environment variables

| Variable | Spring property | Meaning | Default |
|---|---|---|---|
| `LUMOAUTH_URL` | `lumoauth.url` | LumoAuth URL | `https://app.lumoauth.dev` |
| `LUMOAUTH_ORG_ID` | `lumoauth.org-id` | Organization slug | required for org-scoped calls |
| `LUMOAUTH_API_KEY` | `lumoauth.api-key` | Organization API key, sent as `X-API-Key` | none |
| `AGENT_CLIENT_ID` | `lumoauth.agent.client-id` | Agent OAuth client ID | required for `LumoAgent` |
| `AGENT_CLIENT_SECRET` | `lumoauth.agent.client-secret` | Agent OAuth client secret | required for `LumoAgent` |

Every LumoAuth SDK reads the same variables, so one `.env` file serves services in several languages.

## Guides

### Check permissions

A permission check asks whether a principal holds a permission, such as `document.edit`. Roles grant permissions, and groups can grant roles.

```java
// The principal behind the credential: the API key's creator, or the user or agent of a bearer token
boolean canEdit = lumo.permissions().check("document.edit");

// Another user, by LumoAuth user id (a UUID). The caller needs the authz:check scope or permission.
boolean bobCanEdit = lumo.permissions().check("document.edit", CheckOptions.forUser(bobId));

// An agent, by agent id
boolean agentCanEdit = lumo.permissions().check("document.edit", CheckOptions.forAgent("agt_c8ed16883d441af8"));

// Several permissions in one round trip
boolean canPublish = lumo.permissions().checkAll(List.of("document.edit", "document.publish"));
boolean canSeeAny  = lumo.permissions().checkAny(List.of("report.view", "report.admin"));
PermissionBulkCheck each = lumo.permissions().checkBulk(List.of("document.edit", "document.delete"));
each.results();                                  // Map<String, Boolean>, one entry per permission

// The full answer for one permission
PermissionCheck detail = lumo.permissions().checkDetailed("document.edit", CheckOptions.forUser(bobId));
detail.allowed(); detail.userId(); detail.context();
```

`CheckOptions.withContext(Map)` passes extra context with the check, and `CheckOptions.forUser(id).context(Map)` combines both.

`forUser` and `forAgent` name the subject that the check is about. The SDK sends it as `"subject": {"type": "user", "id": …}`. The user id is the LumoAuth user id: the `sub` claim of that user's tokens, not your application's own id or an email address. To ask about someone else, the caller needs the `authz:check` scope (an API key can hold it) or the `authz.check` permission. Without that right, LumoAuth answers 403 `INSUFFICIENT_PERMISSIONS`. An id that is not in your organization gets 404 `SUBJECT_NOT_FOUND`.

### List a user's permissions

`list()` returns every permission that the principal holds. Each entry has a slug, a description and a source.

```java
PermissionList all = lumo.permissions().list();
for (Permission p : all.permissions()) {
    System.out.println(p.slug() + " from " + p.source());
}
List<String> slugs = lumo.permissions().listSlugs();
```

A user access token needs the `authz:read` scope for this call. An organization API key cannot hold that scope, so `list()` with an API key throws `LumoAuthPermissionDeniedException` and `requiredScopes()` returns `["authz:read"]`. Call it with the user's own token.

### Check relationships (Zanzibar)

A relationship check asks whether a subject has a relation to an object. Objects and subjects are written as `type:id`. A subject can also be a set, such as `group:finance#member`.

```java
boolean related = lumo.zanzibar().check("folder:q4", "member", "group:finance#member");
boolean canView = lumo.zanzibar().isViewer("document:readme", "user:bob");   // also isEditor, isOwner, isMember, isAdmin

ZanzibarCheck detail = lumo.zanzibar().checkDetailed("document:readme", "viewer", "user:bob");

// Who has a relation? expand returns the tree of subjects.
ZanzibarUsersetNode tree = lumo.zanzibar().expand("document:readme", "viewer");
List<String> everyone = tree.allSubjects();
```

A check about a subject other than the caller needs the `authz:check` scope or permission.

### Check attribute-based policies (ABAC)

An ABAC check evaluates your policies against attributes of the user, the resource and the request.

```java
AbacDecision decision = lumo.abac().check(
    AbacCheck.of("document", "read", "doc-123")
        .context(Map.of("pep", Map.of("ip", clientIp))));

if (!decision.allowed()) {
    log.info("denied: {} ({})", decision.reason(), decision.matchedPolicies());
}

boolean ok = lumo.abac().isAllowed(AbacCheck.of("document", "read", "doc-123"));
List<AbacDecision> many = lumo.abac().checkBulk(List.of(                      // up to 100 checks
    AbacCheck.of("document", "read", "doc-1"),
    AbacCheck.of("document", "read", "doc-2")),
    Map.of("pep", Map.of("ip", clientIp)));                                      // one environment for all checks
```

The SDK sends an `AbacCheck` context to LumoAuth as the check's `environment`. A bulk check has one environment that applies to every check in the call. Pass it as the second argument of `checkBulk`. The one-argument form sends the context that the checks carry, so every check must carry the same context or none. Otherwise it throws `LumoAuthValidationException`. Each bulk decision keeps the server's `index`, and any error for that item, in `raw()`.

LumoAuth sets four environment keys itself: `ip`, `userAgent`, `requestMethod` and `requestPath`. They describe the request that LumoAuth received from your server. If you send a value under one of those names, LumoAuth keeps it under `pep` instead. To pass the end user's IP address, send it as `pep.ip` and write your policies against `pep.ip`.

Read and set attributes:

```java
Map<String, Object> mine = lumo.abac().myAttributes();
lumo.abac().setUserAttribute("user_42", "department", "finance");
lumo.abac().setResourceAttribute("document", "doc-123", "classification", "internal");
Map<String, Object> docAttrs = lumo.abac().resourceAttributes("document", "doc-123");
List<AbacAttributeDefinition> defs = lumo.abac().attributeDefinitions(AttributeType.USER);
```

The ABAC calls need a user access token or an agent credential. They do not accept an organization API key. A user access token needs `abac:read` for checks and reads, and `abac:write` to set attributes. Setting attributes also requires the `abac.manage` permission.

<a id="sign-in-without-spring"></a>
### Sign users in without Spring

`AuthorizationCodeFlow` runs the OAuth authorization code flow with PKCE. It works with any web framework. Store the `PendingLogin` in the session between the two steps, and store the `SignedIn` value after the user returns.

```java
AuthorizationCodeFlow flow = AuthorizationCodeFlow.builder(lumo, clientId, "https://app.example.com/callback")
    .clientSecret(clientSecret)             // leave out for a public client
    .scope("openid profile email")         // add authz:read to list the user's permissions
    .build();

// GET /login
AuthorizationCodeFlow.PendingLogin pending = flow.start(returnTo);
session.put("login", pending);
redirect(pending.authorizationUrl());

// GET /callback?code=…&state=…
AuthorizationCodeFlow.SignedIn user = flow.complete(session.get("login"), queryParams);
session.put("user", user);
redirect(AuthorizationCodeFlow.sanitizeReturnTo(pending.returnTo(), "/"));

// Later requests
user.user().email();                       // the UserInfo from sign-in
LumoAuth asUser = flow.clientFor(user);     // a client that calls LumoAuth with the user's own token
flow.refresh(user).ifPresent(fresh -> session.put("user", fresh));

// Sign out
flow.revoke(user);
```

`complete` checks the `state` value and exchanges the code. `sanitizeReturnTo` accepts only a local path, so a crafted link cannot redirect the user to another site. Request `authz:read` as well when the app lists the signed-in user's permissions or reads roles from `agents().me()`.

### Work with tokens directly

The `auth()` namespace calls the token endpoint and the UserInfo endpoint.

```java
UserInfo me = lumo.auth().userinfo(userAccessToken);
me.sub(); me.email(); me.roles();              // typed fields for the stable claims
me.claim("department");                        // Optional<Object> for any other claim
me.raw();                                      // every field that the server sent

TokenResponse svc   = lumo.auth().clientCredentials(clientId, clientSecret, "read:documents");
TokenResponse fresh = lumo.auth().refreshToken(RefreshTokenRequest.of(refreshToken, clientId, clientSecret));
lumo.auth().revoke(RevokeRequest.of(token).client(clientId, clientSecret));

String url = lumo.auth().authorizationUrl(
    AuthorizationUrlRequest.builder(clientId, redirectUri).scope("openid profile").state(state).build());
TokenResponse tokens = lumo.auth().exchangeCode(
    CodeExchangeRequest.of(code, redirectUri, clientId).codeVerifier(verifier));
```

For token exchange (RFC 8693), see [Act on behalf of a user](#act-on-behalf-of-a-user).

### Spring Boot starter

The starter turns the SDK into Spring beans and connects it to Spring Security. It is built against Spring Boot 3.5 and works with Spring Boot 3.x.

#### Configure

```yaml
lumoauth:
  url: https://app.lumoauth.dev            # or LUMOAUTH_URL
  org-id: acme-corp                        # or LUMOAUTH_ORG_ID
  api-key: ${LUMOAUTH_API_KEY}             # or LUMOAUTH_API_KEY
  timeout: 10s                             # default 30s

  login:                                   # browser sign-in; needs spring-boot-starter-oauth2-client
    client-id: lumo_abc123
    client-secret: ${LUMOAUTH_CLIENT_SECRET}
    scopes: [openid, profile, email]       # add abac:read for ABAC checks; add authz:read to list permissions or read roles from agents().me()
    success-url: /dashboard                # default /
    permit-all: [/, /error, /favicon.ico, /public/**]

  agent:                                   # creates a LumoAgent bean
    client-id: ${AGENT_CLIENT_ID}
    client-secret: ${AGENT_CLIENT_SECRET}

  aauth:                                   # creates an AAuthClient bean
    agent-identifier: https://my-agent.example.com
    private-key-pem: ${AGENT_PRIVATE_KEY}

  security:
    bearer-tokens: true                    # resolve LumoAuth bearer tokens; needs oauth2-resource-server
    permissions-as-authorities: false      # also add PERMISSION_<slug> authorities
```

Your IDE completes and documents every key, because the starter includes configuration metadata.

| Property | Default | Meaning |
|---|---|---|
| `lumoauth.timeout` | `30s` | Timeout for each request |
| `lumoauth.skip-cert-validation` | `false` | Trust any TLS certificate (local development only) |
| `lumoauth.agent.scopes` | empty | Scopes that the agent asks for; empty means its registered defaults |
| `lumoauth.agent.redirect-uri` | none | Redirect URI for delegation consent |
| `lumoauth.aauth.kid` | `key-1` | Key ID of the AAuth signing key |
| `lumoauth.login.registration-id` | `lumoauth` | Spring Security client registration ID |
| `lumoauth.login.default-filter-chain` | `true` | Add the starter's `SecurityFilterChain` |
| `lumoauth.security.role-authority-prefix` | `ROLE_` | Prefix for role authorities |
| `lumoauth.security.capability-authority-prefix` | `CAPABILITY_` | Prefix for agent capability authorities |
| `lumoauth.security.permission-authority-prefix` | `PERMISSION_` | Prefix for permission authorities |

#### What you get

| Feature | Provided by | Turns on when |
|---|---|---|
| `LumoAuth` bean | `LumoAuthAutoConfiguration` | always |
| `LumoAgent` bean | `LumoAuthAutoConfiguration` | `lumoauth.agent.client-id` is set |
| `AAuthClient` bean | `LumoAuthAutoConfiguration` | `lumoauth.aauth.agent-identifier` is set |
| Bearer tokens resolved to a principal | `LumoAuthSecurityAutoConfiguration` | `spring-boot-starter-oauth2-resource-server` is on the classpath |
| `@RequirePermission`, the `@lumo` SpEL bean, a `PermissionEvaluator` | `LumoAuthSecurityAutoConfiguration` | Spring Security is on the classpath |
| OIDC sign-in and a default `SecurityFilterChain` | `LumoAuthLoginAutoConfiguration` | `spring-boot-starter-oauth2-client` is on the classpath and `lumoauth.login.client-id` is set |
| `/actuator/health/lumoauth` | `LumoAuthHealthAutoConfiguration` | Spring Boot Actuator is on the classpath |

If you define your own bean of one of these types, the starter does not create its own. A `java.net.http.HttpClient` bean, when present, is used for every request. The security starters are optional: the starter never locks down an app unless you add Spring Security yourself.

#### Protect an API with bearer tokens

Add `spring-boot-starter-oauth2-resource-server`. A request with a LumoAuth access token then gets an authenticated principal. Its authorities are `ROLE_<role>` for each role and `CAPABILITY_<slug>` for each agent capability, so standard Spring Security rules work.

```java
@Bean
SecurityFilterChain api(HttpSecurity http) throws Exception {
    return http
        .authorizeHttpRequests(a -> a
            .requestMatchers("/admin/**").hasRole("admin")
            .requestMatchers("/tools/search").hasAuthority("CAPABILITY_tool:search_web")
            .anyRequest().authenticated())
        .oauth2ResourceServer(o -> o.opaqueToken(Customizer.withDefaults()))   // the starter supplies the introspector
        .build();
}

@GetMapping("/api/me")
String me(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
    return principal.getName();   // the LumoAuth subject
}
```

#### Sign users in with LumoAuth

Add `spring-boot-starter-oauth2-client` and set `lumoauth.login.client-id` and `client-secret`. The starter registers LumoAuth as an OIDC provider at `/oauth2/authorization/lumoauth`. It also adds a filter chain with three rules:

- anonymous browsers are sent to sign in;
- bearer tokens are accepted on the same app;
- the paths in `lumoauth.login.permit-all` are open to everyone.

To use your own rules, set `lumoauth.login.default-filter-chain=false` or define your own `SecurityFilterChain`.

```java
@GetMapping("/dashboard")
String dashboard(@AuthenticationPrincipal OidcUser user) {
    return "Hello " + user.getFullName();
}
```

#### Authorize methods

The starter offers three styles. Each one asks LumoAuth at call time. A check runs with the caller's bearer token when there is one. Otherwise it runs with the API key, for the signed-in principal.

```java
@RequirePermission("document.edit")                                   // RBAC: one permission
public void edit(String id) { … }

@RequirePermission(value = {"document.edit", "document.publish"}, mode = RequirePermission.Mode.ANY)
public void publish(String id) { … }

@PreAuthorize("@lumo.isEditor('document:' + #id)")                    // Zanzibar relationship
public void rename(String id, String title) { … }

@PreAuthorize("hasPermission(#id, 'document', 'delete')")             // ABAC through PermissionEvaluator
public void delete(String id) { … }
```

`@RequirePermission` checks all of the listed permissions by default (`Mode.ALL`). It also works on a class, and it needs only `spring-aop`, which every Spring Boot app has. The `@lumo` bean offers `can`, `canAll`, `canAny`, `relation`, `isViewer`, `isEditor`, `isOwner`, `abac` and `principal()` for templates and handlers.

Which credential the checks use depends on how the user signed in:
- **Bearer token** (`oauth2ResourceServer`): the checks run under the user's own token. They need no API key and no extra scope.
- **OIDC browser login** (`lumoauth.login.*`): the checks run with the application's API key and name the signed-in user as the subject. The principal name is the `sub` claim, which is the LumoAuth user id; an `agent_<id>` sub becomes an agent subject. That API key needs the `authz:check` scope. Without it, every check fails with `LumoAuthPermissionDeniedException`.

ABAC checks (`@lumo.abac` and the three-argument `hasPermission`) work in another way. LumoAuth refuses the API key on the ABAC routes, so an ABAC check always sends the user's own access token as `Authorization: Bearer`. For a bearer request, the starter uses the incoming token. After an OIDC login, it uses the access token that Spring Security stored for the login (the `OAuth2AuthorizedClient`), and it refreshes that token when it has expired. The token needs the `abac:read` scope, so add it to the login scopes:

```yaml
lumoauth:
  login:
    scopes: [openid, profile, email, abac:read]
```

If you register LumoAuth with Spring's own properties instead, set `spring.security.oauth2.client.registration.lumoauth.scope=openid,profile,email,abac:read`. When no user access token is available, the ABAC check returns `false` and logs the reason. To supply the token yourself, define a `UserAccessTokenResolver` bean.

#### Health

With Actuator on the classpath, `/actuator/health/lumoauth` reports whether LumoAuth answers. It also reports maintenance and authentication problems with their error code.

### Build an AI agent

An agent signs in with OAuth client credentials. `LumoAgent` fetches the token on first use. It refreshes the token 60 seconds before it expires, and concurrent callers share one refresh.

```java
LumoAgent agent = LumoAgent.builder()
    .clientId(System.getenv("AGENT_CLIENT_ID"))
    .clientSecret(System.getenv("AGENT_CLIENT_SECRET"))
    .orgId("acme-corp")
    .scopes("agent:act", "read:documents")
    .build();

AgentIdentity who = agent.identity();                 // cached; identity(true) fetches it again
List<String> caps = agent.capabilities();
boolean canSearch = agent.hasCapability("tool:search_web");

AgentAskResult verdict = agent.ask("delete_file", Map.of("path", "/finance/q4.xlsx"));
verdict.allowed(); verdict.reason(); verdict.auditId();

AgentBudget budget = agent.budget();
budget.tokensUsedToday(); budget.maxTokensPerDay(); budget.exhausted();

String bearer = agent.accessToken();                   // for calls that you make yourself
```

`ask` and `isAllowed` send the action and its context to LumoAuth. LumoAuth decides with the agent's capabilities and your policies, and it records the decision. As with ABAC, LumoAuth sets `ip`, `userAgent`, `requestMethod` and `requestPath` itself and keeps any values that you send under `pep`.

Two guard methods throw when their condition fails:

```java
agent.requireCapability("tool:send_email");   // LumoAuthPermissionDeniedException
agent.checkBudget();                          // LumoAuthBudgetExceededException
```

A `LumoAgent` also exposes the namespaces with the agent's token: `agents()`, `approvals()`, `jit()`, `delegation()`, `mcp()` and `permissions()`. `agent.client()` returns the underlying `LumoAuth`.

### Ask a human for approval

Some actions need a person's approval first. `require` creates the approval and sends a push notification to the approver's phone. It then polls until the person answers, and it returns the result or throws.

```java
try {
    ApprovalResult approval = agent.approvals().require(
        ApprovalRequest.builder("wire-2026-10-08-001", "Wire $4,500 to vendor INV-7741", "ada@acme.com")
            .impact(ApprovalImpact.HIGH)
            .meta(Map.of("amount", 4500, "vendor", "INV-7741"))
            .build(),
        WaitOptions.of(Duration.ofSeconds(2), Duration.ofMinutes(3)));

    wire(approval.token());                       // the approval token authorizes the action
} catch (LumoAuthApprovalDeniedException e) {
    notify("Ada declined: " + e.approval().reason());
} catch (LumoAuthApprovalTimeoutException e) {
    notify("No answer within 3 minutes. The wire was not sent.");
} catch (LumoAuthApprovalNotDeliveredException e) {
    notify("Ada has no phone enrolled. Ask her to install the LumoAuth app."); // e.reason()
}
```

| Setting | Values | Default |
|---|---|---|
| `impact` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | `MEDIUM` |
| `WaitOptions` | poll interval and timeout | 1.5 seconds and 90 seconds |

To poll yourself, call `create`. It returns at once with a pending result. Later, `status(token)` reads the state, and `waitFor(token)` polls until the state changes. Another process can do this with the same token. If `waitFor` returns a pending result, the wait timed out. It does not mean that the person said no.

Approvals need an agent credential. A test token from the portal is refused with 403 `test_token_not_accepted`.

Sometimes the push prompt reaches no device. Nobody can approve the action then, so the SDK never treats it as approved:

- **202 `email_fallback_sent`.** The user has no enrolled push device, or the user does not exist. LumoAuth gives the same answer in both cases. It emails the user a plain notice, and that email has no approval link. There is no approval token to poll. `create` returns a result with the status `email_fallback_sent` and a null token. Its `emailFallbackSent()` is true. `require` throws `LumoAuthApprovalNotDeliveredException` with the reason `email_fallback_sent` and does not poll.
- **428 `no_enrolled_device`.** The user has no enrolled device, and the email could not be sent. `create` and `require` throw `LumoAuthApprovalNotDeliveredException` with the reason `no_enrolled_device`.

In both cases, tell the user to check their email or install the LumoAuth app. Then try again. The exception also carries `taskId()` when the response has one.

### Use Just-in-Time permissions

A JIT task limits permissions to one unit of work. Closing the task revokes every token that was issued under it. `JitContext` is `AutoCloseable`, so a `try` block covers the whole lifecycle.

```java
try (JitContext jit = new JitContext(agent)) {
    jit.createTask(CreateTaskRequest.named("Analyse the Q4 report").onBehalfOf("ada@acme.com"));

    JitRequest grant = jit.requestPermission(
        Map.of("type", "file_access", "actions", List.of("read"), "identifier", "report_q4.pdf"),
        JitContext.RequestOptions.justification("The user asked for a Q4 summary").ttl(300));

    if (grant.approved()) {
        String token = jit.token(grant.requestId());
        HttpResponse<byte[]> file = jit.call(token, "GET", "https://files.acme.com/report_q4.pdf", null);
    }
}
```

The request is a set of RFC 9396 authorization details. A person must approve a high-risk request before LumoAuth grants it. By default `requestPermission` polls every 5 seconds for up to 5 minutes. `RequestOptions.noWait()` returns at once, and `polling(WaitOptions)` changes the timing.

`callWithEscalation(method, url, body)` makes the call first. If the resource answers 403 with an `Insufficient-Authorization-Details` challenge, it requests those permissions, waits for the decision and retries once.

The lower-level `jit()` namespace offers the same steps one by one: `createTask`, `request`, `status`, `token`, `completeTask` and `evaluateTask`. `jit().pending()` lists the requests that are pending review. It is for the people who review them: it needs a user access token with the `jit:approve` scope.

### Act on behalf of a user

`DelegationChain` builds a chain of agency over RFC 8693 token exchange. The user consents once. The agent then holds a token that names the agent and the user. It can also give a narrower token to a sub-agent.

```java
DelegationChain chain = new DelegationChain(agent, "https://agent.example.com/callback");

String consentUrl = chain.consentUrl("session-1", List.of("read:documents"));
// Send the user to consentUrl. Your callback receives ?code=…
chain.handleConsentCallback("session-1", code);

Map<String, Object> docs = chain.request("session-1", "GET", "/orgs/acme-corp/api/v1/documents", null, Map.class);
String childToken = chain.delegateToSubAgent("session-1", summariserToken, "read:documents");
List<String> actors = chain.actorChain(childToken);   // ["agent:summariser", "agent:assistant"]

chain.revoke("session-1");
```

A chain can be at most 3 agents deep.

#### Token exchange in detail

`lumo.auth().tokenExchange(TokenExchangeRequest)` is the lower-level call. It declares the type of each token that it sends:

| Constant on `AuthResource` | Use it for |
|---|---|
| `TOKEN_TYPE_ACCESS_TOKEN` | An access token. This is the default. |
| `TOKEN_TYPE_JWT` | An at+jwt access token, or an external workload JWT |
| `TOKEN_TYPE_ID_TOKEN` | An OpenID Connect ID token |
| `TOKEN_TYPE_REFRESH_TOKEN` | A refresh token. It is not accepted as the subject when an agent acts for a user. |

```java
TokenResponse delegated = lumo.auth().tokenExchange(
    TokenExchangeRequest.of(userToken)
        .actorToken(agent.accessToken())
        .subjectTokenType(AuthResource.TOKEN_TYPE_ACCESS_TOKEN)
        .resource("https://api.example.com")
        .scopes(List.of("read:documents")));
```

`resource(…)` sets the RFC 8707 resource indicator. It must be an https URL, and it becomes the token's `aud`. Without it, a token for acting on a user's behalf is bound to the agent's own ID. LumoAuth does not set `aud` from `audience(…)`. `lumo.delegation().exchangeForResource(…)` is a shortcut for the same call.

### Get a token for an MCP server

```java
String token = agent.mcpToken("https://mcp.example.com/mcp");
McpToken detail = agent.mcp().tokenDetailed("https://mcp.example.com/mcp", agent.accessToken());
detail.expiresIn(); detail.scopes();
```

`mcpToken` exchanges the agent's token for a token that is bound to one MCP server. Pass the MCP server's registered Resource URI, which is its https URL and its RFC 8707 resource identifier. The SDK sends it as `resource`, and LumoAuth sets the token's `aud` from it. The SDK also sends it as `audience`, which LumoAuth ignores. The SDK checks the URI first. When it is not an absolute http(s) URL, the SDK throws `LumoAuthValidationException` and sends nothing. LumoAuth accepts `http` only for localhost and private hosts.

The token names exactly one MCP server. It works only at that server, and LumoAuth's own API rejects it. `mcpToken` does not send a DPoP proof. A server that requires DPoP needs a DPoP-bound exchange instead.

#### Check a tool call on your MCP server

Your MCP server can ask LumoAuth whether a caller may run a tool. The server asks with its own client-credentials token, which needs the scope `mcp:authorize`. Its OAuth client must also be one of the MCP server's tool authorizers. Never forward the token that the caller gave you. The MCP specification forbids this "token passthrough".

```java
// Once at startup: the MCP server's own token.
LumoAuth tokens = LumoAuth.builder().orgId("acme-corp").withoutCredential().build();
TokenResponse own = tokens.auth().clientCredentials(clientId, clientSecret, "mcp:authorize");
LumoAuth lumo = LumoAuth.builder().orgId("acme-corp").accessToken(own.accessToken()).build();

// For each tool call: the subject is the `sub` of the MCP token that you verified.
McpToolDecision d = lumo.mcp().authorizeTool("mcp_0123456789abcdef01234567", "user", sub, "search_docs");
if (!d.allowed()) {
    // refuse the tool call
}
```

The first argument is the registered MCP server ID (`mcp_...`), not its URL. The subject type is `user` or `agent`. For a user, pass the user ID from the token's `sub`. For an agent, pass the agent ID (`agt_...`) or the `sub` as it is (`agent_agt_...`). Refresh the token before it expires, or use `tokenProvider(...)` to fetch a new one.

#### Let an agent check a tool for itself

An agent can ask the same question about itself. It uses its own credential.

```java
AgentMcpToolDecision d = agent.authorizeMcpTool("mcp_0123456789abcdef01234567", "search_docs");
d.allowed(); d.agentId(); d.resource().id();   // "mcp_0123456789abcdef01234567/search_docs"
```

`lumo.agents().authorizeMcpTool(serverId, tool)` is the same call on a `LumoAuth` client.

On both calls a deny is an answer, not an error. The result has `allowed() == false`, and the SDK does not throw. Real errors throw as usual:

- a missing `mcp:authorize` scope, or a client that is not a tool authorizer, throws `LumoAuthPermissionDeniedException`;
- an unknown server throws `LumoAuthNotFoundException`;
- too many requests throw `LumoAuthRateLimitException`.

The SDK checks the input before it sends anything. The server ID and the tool must not be empty, and they must not contain `/`, `:`, `#` or `*`. A tool name has at most 80 characters. When a check fails, the SDK throws `LumoAuthValidationException`.

<a id="aauth-cryptographic-agent-identity"></a>
### Give an agent a cryptographic identity (AAuth)

With AAuth, an agent holds a key pair instead of a shared secret. The agent signs every request (RFC 9421), and each token is bound to the key (proof of possession). Anyone can find the agent's public key from its identifier.

```java
Keypair keypair = AAuthKeys.generateKeypair("key-1");      // Ed25519
// Publish keypair.jwks() at https://my-agent.example.com/.well-known/jwks.json
// Keep keypair.privateKeyPem() in your secret store

AAuthClient client = AAuthClient.builder()
    .agentIdentifier("https://my-agent.example.com")
    .privateKeyPem(System.getenv("AGENT_PRIVATE_KEY"))
    .orgId("acme-corp")
    .build();

AAuthTokenResponse grant = client.requestAuthToken(resourceToken, "read write", agentToken);
if (grant.authorizationRequired()) {
    redirect(grant.authorizationUri());                       // a person consents in the browser
    grant = client.exchangeCode(code, redirectUri, agentToken);
}

HttpResponse<byte[]> res = client.signedRequest("POST", "https://api.example.com/v1/items", grant.authToken(), body);
```

Other `AAuthClient` methods:

- `signRequest(method, url, SignOptions)` returns the `Signature`, `Signature-Input` and `Content-Digest` headers for a request that you send yourself.
- `refresh(refreshToken, resourceToken, scope, agentToken)` and `exchangeToken(authToken, resourceToken, agentToken)` renew or exchange a token.
- `revoke(token, tokenType, agentToken)` revokes an auth token or a refresh token.
- `discoverIssuer()`, `discoverAgents()`, `discoverResource(url)` and `jwks()` read the discovery documents.

LumoAuth limits an agent token's lifetime to between 60 seconds and 24 hours. Some agent servers sign tokens with their own key. Such a token must carry `iat` and `jti` claims. Its lifetime must not exceed 24 hours. If the agent publishes a JWKS document, the document must be JSON and at most 256 KB.

### Verify AAuth tokens on a resource server

An API or MCP server that accepts agent tokens verifies them locally. `JwksCache` fetches the issuer's keys once and fetches them again when the keys rotate. By default it keeps them for one hour.

```java
JwksCache keys = new JwksCache("https://app.lumoauth.dev/orgs/acme-corp/api/v1");

AAuthClaims claims = AAuthVerifier.verifyAuthToken(bearer, keys.verifyOptions("https://api.example.com"));
claims.verifyProofOfPossession(new IncomingRequest(method, uri, headers, body));   // the request must be signed with the bound key

if (!claims.hasScope("write")) {
    throw new ForbiddenException();
}
claims.agent(); claims.subject(); claims.scopes();
```

On Spring MVC, `ServletRequests.toIncomingRequest(request, body)` builds the `IncomingRequest` from an `HttpServletRequest`:

```java
@PostMapping("/v1/items")
ResponseEntity<?> create(HttpServletRequest request, @RequestBody byte[] body) {
    AAuthClaims claims = AAuthVerifier.verifyAuthToken(bearer(request), keys.verifyOptions("https://api.example.com"));
    claims.verifyProofOfPossession(ServletRequests.toIncomingRequest(request, body));
    …
}
```

### Call any endpoint

The namespaces cover the common calls. For any other endpoint, use the request methods. They use the same credentials, base URL and error mapping.

```java
Map<String, Object> page = lumo.requestMap("GET", lumo.orgPath("/admin/users?page=2"), null);
JsonNode node          = lumo.requestNode("POST", lumo.orgPath("/admin/invites"), Map.of("email", "new@acme.com"));
HttpResponse<byte[]> r = lumo.requestRaw("GET", lumo.orgPath("/export"), null);
MyType typed           = lumo.request("GET", lumo.orgPath("/something"), null, MyType.class);
```

`orgPath("/x")` returns `/orgs/{orgId}/api/v1/x`. `apiClientConfig()` returns the base path, headers and HTTP client for the generated REST client (`io.lumoauth.client`). The generated Java client is not published yet.

## Errors

Every exception is unchecked and extends `LumoAuthException`. Each one has a stable `code()`, which is the same in every LumoAuth SDK. Catch the base class to handle any failure, or catch a subclass to handle one case.

```
LumoAuthException
├── LumoAuthApiException                  any non-2xx response: statusCode(), body(), bodyAsMap(), bodyField(key)
│   ├── LumoAuthAuthenticationException   401: the credential is missing, wrong or expired
│   ├── LumoAuthPermissionDeniedException 403: the caller may not do this; requiredScopes() on a scope refusal
│   ├── LumoAuthNotFoundException         404
│   └── LumoAuthRateLimitException        429: retryAfter() is an Optional<Duration>
├── LumoAuthValidationException           bad input, or a response that the SDK cannot use (issues())
├── LumoAuthConfigException               missing or invalid configuration
├── LumoAuthNetworkException              transport failure; getCause() is the IOException
├── LumoAuthApprovalDeniedException       a person said no (approval())
├── LumoAuthApprovalTimeoutException      nobody answered in time (approval())
├── LumoAuthApprovalNotDeliveredException the prompt reached no device (reason(), taskId())
└── LumoAuthBudgetExceededException       the agent has used its budget (budget())
```

| Exception | `code()` |
|---|---|
| `LumoAuthException` | `LUMOAUTH_ERROR` |
| `LumoAuthApiException` | the body's `code` or `error` field, else `API_ERROR` |
| `LumoAuthAuthenticationException` | `AUTHENTICATION_ERROR` unless the body names a code |
| `LumoAuthPermissionDeniedException` | `PERMISSION_DENIED` unless the body names a code |
| `LumoAuthNotFoundException` | `NOT_FOUND` unless the body names a code |
| `LumoAuthRateLimitException` | `RATE_LIMITED` unless the body names a code |
| `LumoAuthValidationException` | `VALIDATION_ERROR` |
| `LumoAuthConfigException` | `CONFIG_ERROR` |
| `LumoAuthNetworkException` | `NETWORK_ERROR` |
| `LumoAuthApprovalDeniedException` | `APPROVAL_DENIED` |
| `LumoAuthApprovalTimeoutException` | `APPROVAL_TIMEOUT` |
| `LumoAuthApprovalNotDeliveredException` | `APPROVAL_NOT_DELIVERED` |
| `LumoAuthBudgetExceededException` | `BUDGET_EXCEEDED` |

A scope refusal has the code `forbidden`, because the server's body sets `error: "forbidden"`. Check the exception type, not the code, to detect a denial.

```java
try {
    List<String> slugs = lumo.permissions().listSlugs();
} catch (LumoAuthRateLimitException e) {
    e.retryAfter().ifPresent(scheduler::retryIn);
} catch (LumoAuthPermissionDeniedException e) {
    if (!e.requiredScopes().isEmpty()) {
        log.warn("sign the user in again with scopes {}", e.requiredScopes());
    }
} catch (LumoAuthApiException e) {
    log.warn("LumoAuth returned {}: {}", e.statusCode(), e.getMessage());
} catch (LumoAuthNetworkException e) {
    log.warn("LumoAuth is unreachable", e);
}
```

`requiredScopes()` returns an empty list for a plain denial and for a denial that the SDK decided locally, such as `requireCapability`.

## API reference

The tables list each method, what it does and the credential that it needs. "Any" means any credential: an API key, a user access token or an agent credential.

### `lumo.permissions()`

| Method | What it does | Credential |
|---|---|---|
| `check(permission[, options])` | Whether the principal holds a permission | any; another user needs `authz:check` |
| `checkDetailed(permission, options)` | `check` with the full answer | as `check` |
| `checkBulk(permissions[, options])` | One answer per permission | as `check` |
| `checkAny(permissions[, options])`, `checkAnyDetailed` | Whether the principal holds at least one | as `check` |
| `checkAll(permissions[, options])`, `checkAllDetailed` | Whether the principal holds all of them | as `check` |
| `list()` | Every permission of the principal | user token with `authz:read`; not an API key |
| `listSlugs()` | The slugs from `list()` | as `list()` |

### `lumo.zanzibar()`

| Method | What it does | Credential |
|---|---|---|
| `check(object, relation, subject)` | Whether the relationship exists | any; another subject needs `authz:check` |
| `checkDetailed(object, relation, subject)` | `check` with the full answer | as `check` |
| `expand(object, relation)` | The tree of subjects that hold the relation | as `check` |
| `isViewer`, `isEditor`, `isOwner`, `isMember`, `isAdmin` | `check` with that relation | as `check` |

### `lumo.abac()`

| Method | What it does | Credential |
|---|---|---|
| `check(AbacCheck)`, `isAllowed(AbacCheck)` | Evaluate your policies | user token with `abac:read`, or an agent |
| `checkBulk(List<AbacCheck>[, environment])` | Up to 100 checks in one call, under one shared environment | as `check` |
| `myAttributes()` | The caller's attributes | as `check` |
| `resourceAttributes(type, id)` | A resource's attributes | as `check` |
| `attributeDefinitions([AttributeType])` | The attribute definitions | as `check` |
| `setUserAttribute(userId, slug, value)` | Set a user attribute | user token with `abac:write` and the `abac.manage` permission |
| `setResourceAttribute(type, id, slug, value)` | Set a resource attribute | as `setUserAttribute` |

### `lumo.auth()`

| Method | What it does |
|---|---|
| `authorizationUrl(AuthorizationUrlRequest)` | Build the URL that starts sign-in |
| `exchangeCode(CodeExchangeRequest)` | Exchange an authorization code for tokens |
| `refreshToken(RefreshTokenRequest)` | Get new tokens with a refresh token |
| `clientCredentials(clientId, clientSecret, scopes...)` | Get a token for a confidential client |
| `tokenExchange(TokenExchangeRequest)` | RFC 8693 token exchange |
| `revoke(RevokeRequest)` | Revoke a token |
| `userinfo([accessToken])` | Read the OpenID Connect UserInfo |

### `lumo.agents()` and `LumoAgent`

| Method | What it does | Credential |
|---|---|---|
| `ask(action[, context])`, `isAllowed(action[, context])` | Ask whether an action is allowed | agent or user |
| `authorizeMcpTool(serverId, tool)` | Ask whether this agent may run a tool on a registered MCP server; a deny returns `allowed() == false` | agent |
| `me()` | Identity, capabilities and workspace | agent, or user (a user token without `authz:read` gets no capabilities) |
| `info()`, `capabilities()`, `budget()` | UserInfo, capability list and budget of the agent | agent |
| `register(RegisterAgentRequest)` | Register a new agent | user token with `admin:agents:write` |
| `LumoAgent.identity()`, `hasCapability`, `requireCapability`, `checkBudget` | Cached identity and guard methods | agent |
| `LumoAgent.authenticate(scopes...)`, `accessToken()`, `tokenScopes()` | Token handling | agent |

### `lumo.approvals()`

| Method | What it does | Credential |
|---|---|---|
| `create(ApprovalRequest)` | Open an approval and return at once. With no push device, the result has the status `email_fallback_sent` and no token. | agent |
| `status(token)` | Read an approval's state | any |
| `waitFor(token[, WaitOptions])` | Poll until the state changes or time runs out | any |
| `require(ApprovalRequest[, WaitOptions])` | `create` plus `waitFor`; throws unless approved, and throws `LumoAuthApprovalNotDeliveredException` when the prompt reached no device | agent |

### `lumo.jit()` and `JitContext`

| Method | What it does | Credential |
|---|---|---|
| `createTask`, `completeTask`, `evaluateTask` | Manage a task | agent |
| `request(PermissionRequest)`, `status(id)`, `token(id)` | Request a permission, read its state, get its token | agent |
| `pending()` | The requests that are pending review | user token with `jit:approve` |
| `JitContext.requestPermission`, `call`, `callWithEscalation`, `close` | The task lifecycle in one object | agent |

### `lumo.delegation()`, `DelegationChain` and `lumo.mcp()`

| Method | What it does |
|---|---|
| `delegation().consentUrl`, `exchangeCode`, `refreshUserToken` | The user's consent step |
| `delegation().exchange(subjectToken, actorToken, scopes...)` | Token exchange for acting on a user's behalf |
| `delegation().exchangeForResource(subjectToken, actorToken, resource, scopes)` | The same, bound to a resource |
| `DelegationResource.parseActorChain(token)`, `tokenSubject(token)` | Read the chain of actors from a token |
| `DelegationChain.consentUrl`, `handleConsentCallback`, `exchange`, `request`, `delegateToSubAgent`, `revoke`, `revokeAll` | The whole flow in one object |
| `mcp().token(serverId[, subjectToken])`, `tokenDetailed` | A token bound to one MCP server; `serverId` is the server's registered Resource URI (its https URL) |
| `mcp().authorizeTool(serverId, subjectType, subjectId, tool)` | For an MCP server: ask whether a user or agent may run a tool. Use the server's own token with `mcp:authorize`. A deny returns `allowed() == false`. |

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| 401 on an ABAC, agent or JIT call with an API key | Organization API keys work only on the admin API, client registration and the permission check routes. | Call these routes with a user access token or an agent credential. |
| `LumoAuthPermissionDeniedException` from `permissions().list()`, with `requiredScopes()` = `["authz:read"]` | The user token lacks `authz:read`, or you used an API key, which can never hold it. | Request `authz:read` at sign-in and call `list()` with the user's token. |
| `LumoAuthPermissionDeniedException` with `requiredScopes()` = `["abac:read"]` or `["jit:approve"]` | The user token lacks that scope. | Allow the scope on the client and request it at sign-in. |
| `agents().me()` returns an empty `capabilities` list | You called it with a user access token that lacks `authz:read`. | Request `authz:read`, or call `me()` with the agent's own credential. |
| 403 `INSUFFICIENT_PERMISSIONS` when you check another user with `CheckOptions.forUser` | The API key or token lacks `authz:check`. | Give the API key the `authz:check` scope, or the key's owner the `authz.check` permission. |
| 404 `SUBJECT_NOT_FOUND` from `CheckOptions.forUser` | The id is not a LumoAuth user id in this organization, for example your application's own user id or an email address. | Pass the user's LumoAuth id: the `sub` claim of that user's tokens. |
| 403 on every `@RequirePermission` check after an OIDC browser login | The checks use the application's API key, and the key lacks `authz:check`. | Give the API key the `authz:check` scope. |
| 400 from `abac().checkBulk` | Older SDK versions sent `requests` instead of `checks`. | Upgrade the SDK. |
| `LumoAuthValidationException` "carries a different context" from `abac().checkBulk` | The checks in one bulk call carry different contexts, but LumoAuth applies one environment to all of them. | Pass one shared environment with `checkBulk(checks, environment)`, or split the call. |
| `invalid_grant` from token exchange | The declared token type does not match the token. Other causes: the subject user is deactivated or blocked, the subject agent is suspended, or the subject is a JIT task token. | Declare the right type (an ID token as `TOKEN_TYPE_ID_TOKEN`), and use an active user's access token. |
| `invalid_request` when an agent exchanges a refresh token for a user | A refresh token is not accepted as the subject of an exchange on a user's behalf. | Send the user's access token or ID token instead. |
| 403 `test_token_not_accepted` from approvals | The token is a portal test token. Test tokens work only for read and ask calls. | Use the agent's real credential. |
| `LumoAuthValidationException` "the server did not return an approval_token" from `approvals().create` | The user has no enrolled device, so LumoAuth sent an email (202 `email_fallback_sent`) and created no approval token. | Ask the user to enroll the LumoAuth mobile app, then retry. |
| 401 `invalid_token` from `jit().pending()` with an agent | Review endpoints accept only a person's session or user token. | Call `pending()` with a reviewer's user token that holds `jit:approve`. |
| `LumoAuthRateLimitException` | Too many requests, or too many failed sign-in attempts from one IP address. | Wait for `retryAfter()`, then retry. |
| `LumoAuthConfigException` at build time | A required setting is missing, such as the org ID, a credential or the agent's client ID. | Set the environment variable or the builder option that the message names. |

## Versioning and compatibility

| | Supported |
|---|---|
| SDK version | 1.0.0 |
| Minimum LumoAuth server API | 1.0.0 |
| Java | 17, 21 and newer (CI tests on 17 and 21) |
| Spring Boot | 3.x, built against 3.5. Spring Boot 4 support is planned as starter 2.x. |
| Runtime dependencies | `jackson-databind` only for the core; the starter adds `spring-boot-starter` |
| Java modules | Automatic-Module-Name `io.lumoauth` and `io.lumoauth.spring` |

The SDK follows semantic versioning. Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## Development

You need Java 17+ and Maven 3.6.3+.

```bash
mvn verify                                             # unit tests and contract tests
python3 ../sdk-contract/scripts/gen-java-routes.py     # regenerate lumo-auth-java/.../Routes.java
mvn -P release -Dgpg.skip=true package                 # sources and javadoc jars, as Maven Central requires
```

The contract tests read [`../sdk-contract`](../sdk-contract), or the directory in `LUMO_SDK_CONTRACT`. They are skipped when neither exists. Releases follow [`playbooks/sdk-publish-maven-central.md`](../playbooks/sdk-publish-maven-central.md).

Related resources:

- [SDK overview](https://docs.lumoauth.dev/developer/sdks)
- [AI agent and MCP in five minutes](https://docs.lumoauth.dev/quickstarts/ai-agent-mcp-5min) and [Agent security](https://docs.lumoauth.dev/quickstarts/ai-agent-security)
- [`sdk-contract`](../sdk-contract): the routes, errors, features and signing vectors that every SDK is built from
- Other SDKs: [JS/TS](../sdk-js), [Python](../sdk-python), [Go](../sdk-go), [PHP](../sdk-php), [C#](../sdk-csharp)

## License

[MIT](LICENSE).
