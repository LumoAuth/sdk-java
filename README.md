<div align="center">

# LumoAuth Java SDK

**Authorization, agent identity and sign-in for Java services, Spring Boot apps and AI agents.**

[![lumo-auth-java on Maven Central](https://img.shields.io/maven-central/v/io.lumoauth/lumo-auth-java.svg?label=lumo-auth-java)](https://central.sonatype.com/artifact/io.lumoauth/lumo-auth-java)
[![lumo-auth-spring-boot-starter on Maven Central](https://img.shields.io/maven-central/v/io.lumoauth/lumo-auth-spring-boot-starter.svg?label=spring-boot-starter)](https://central.sonatype.com/artifact/io.lumoauth/lumo-auth-spring-boot-starter)
[![CI](https://github.com/lumoauth/sdk-java/actions/workflows/ci.yml/badge.svg)](https://github.com/lumoauth/sdk-java/actions/workflows/ci.yml)
[![Java 17+](https://img.shields.io/badge/java-17%2B-blue.svg)](#compatibility)
[![Spring Boot 3](https://img.shields.io/badge/spring%20boot-3.x-6DB33F.svg)](#spring-boot-starter)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

[Install](#install) · [Choose your path](#choose-your-path) · [Apps & services](#apps-and-services) · [AI agents](#ai-agents) · [Spring Boot](#spring-boot-starter) · [Docs](https://docs.lumoauth.dev/quickstarts/java)

</div>

---

[LumoAuth](https://lumoauth.dev) is the authorization layer for humans *and* AI agents: RBAC, relationship-based (Zanzibar) and attribute-based (ABAC) checks, OAuth 2.1 / OIDC sign-in, agent identities with capabilities and budgets, human-in-the-loop approvals, Just-in-Time permissions, delegation chains and AAuth cryptographic identity with RFC 9421 request signing.

This SDK brings all of that to Java the way Java developers expect it: a builder, records, `Optional`, `Duration`, unchecked exceptions and `java.net.http`. No code generation to run, no reflection magic, one runtime dependency (Jackson). On Spring Boot, three properties and a starter are all it takes.

```java
LumoAuth lumo = LumoAuth.fromEnvironment();           // LUMOAUTH_URL, LUMOAUTH_ORG_ID, LUMOAUTH_API_KEY

if (lumo.permissions().check("invoice.approve", CheckOptions.forUser(userId))) {
    approve(invoice);
}
```

## Why teams pick this SDK

- **Plain Java 17.** Immutable records in, records out. Builders where there are many options, static factories where there are few. Nothing to subclass, nothing to configure before the first call.
- **Agents are first-class.** `LumoAgent` owns its token and refreshes it for you. Approvals block until a human answers. JIT tasks are `AutoCloseable`, so a `try` block is all the cleanup you need.
- **Cryptography without extra jars.** Ed25519 and RSA-PSS signing, JWK thumbprints and JWS verification run on the JDK alone and reproduce the shared RFC 9421 conformance vector byte for byte.
- **Spring Boot that gets out of your way.** The starter provides beans, bearer-token resolution, OIDC login, `@RequirePermission`, a `@lumo` SpEL bean and an actuator health check. Every piece backs off the moment you define your own.
- **Same contract as every other LumoAuth SDK.** The [JS](../sdk-js), [Python](../sdk-python), [Go](../sdk-go) and [PHP](../sdk-php) SDKs share the same [`sdk-contract`](../sdk-contract): identical namespaces, error codes, environment variables and signatures. Switching languages never means relearning the API.
- **Escape hatches, not dead ends.** Any endpoint the curated namespaces do not wrap is one `lumo.request(...)` away, and the generated `lumoauth-api-client` plugs into the same credentials.

## Install

Both artifacts live on Maven Central under the `io.lumoauth` group.

<table>
<tr><th>Maven</th><th>Gradle</th></tr>
<tr>
<td>

```xml
<dependency>
  <groupId>io.lumoauth</groupId>
  <artifactId>lumo-auth-java</artifactId>
  <version>0.1.0</version>
</dependency>
```

</td>
<td>

```kotlin
implementation("io.lumoauth:lumo-auth-java:0.1.0")
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
  <version>0.1.0</version>
</dependency>
```

</td>
<td>

```kotlin
implementation("io.lumoauth:lumo-auth-spring-boot-starter:0.1.0")
```

</td>
</tr>
</table>

| Module | Coordinates | Use it when |
|---|---|---|
| [`lumo-auth-java`](lumo-auth-java) | `io.lumoauth:lumo-auth-java` | Any Java 17+ code: services, CLIs, agents, Quarkus, Micronaut, plain `main()`. Depends only on the JDK and Jackson. |
| [`lumo-auth-spring-boot-starter`](lumo-auth-spring-boot-starter) | `io.lumoauth:lumo-auth-spring-boot-starter` | Spring Boot 3 apps. Auto-configuration, `lumoauth.*` properties, Spring Security integration, actuator health. |

## Choose your path

| I am building… | Start with | Read |
|---|---|---|
| A Spring Boot app or REST API | the starter: `lumoauth.*` properties, `@RequirePermission` | [Spring Boot starter](#spring-boot-starter) |
| A backend service that checks what users may do | `LumoAuth` | [Apps and services](#apps-and-services) |
| An AI agent that acts under its own identity | `LumoAgent` | [AI agents](#ai-agents) |
| An agent with a signing key, or an MCP server | `AAuthClient` / `AAuthVerifier` | [AAuth](#aauth-cryptographic-agent-identity) |
| A web app on another framework that signs users in | `AuthorizationCodeFlow` | [Sign-in without Spring](#sign-in-without-spring) |

### 60 seconds: a Spring Boot API

```yaml
# application.yml
lumoauth:
  org-id: acme-corp
  api-key: ${LUMOAUTH_API_KEY}
```

```java
@RestController
class InvoiceController {
    private final InvoiceService invoices;
    InvoiceController(InvoiceService invoices) { this.invoices = invoices; }

    @PostMapping("/invoices/{id}/approve")
    void approve(@PathVariable String id) { invoices.approve(id); }
}

@Service
class InvoiceService {
    @RequirePermission("invoice.approve")        // 403 unless the caller holds the permission
    public void approve(String id) { /* ... */ }
}
```

Add `spring-boot-starter-oauth2-resource-server` and requests carrying a LumoAuth `Authorization: Bearer …` token arrive with a principal, roles and capabilities already resolved. Add `spring-boot-starter-oauth2-client` and browsers are sent to LumoAuth to sign in. Details in [Spring Boot starter](#spring-boot-starter).

### 60 seconds: an agent that asks before it acts

```java
LumoAgent agent = LumoAgent.fromEnvironment();   // AGENT_CLIENT_ID, AGENT_CLIENT_SECRET

agent.requireCapability("tool:send_email");      // throws if the agent was never granted it
agent.checkBudget();                             // throws when today's budget is spent

if (!agent.isAllowed("send_email", Map.of("to", "cfo@acme.com"))) {
    return;                                      // policy said no; the decision is audited server-side
}

ApprovalResult ok = agent.approvals().require(   // blocks until a human taps approve or deny
    ApprovalRequest.builder("wire-7741", "Wire $4,500 to vendor INV-7741", "ada@acme.com")
        .impact(ApprovalImpact.HIGH)
        .build());

sendWire(ok.token());
```

---

## Apps and services

### Configure the client

```java
LumoAuth lumo = LumoAuth.builder()
    .baseUrl("https://app.lumoauth.dev")   // default; self-hosted instances set their own
    .orgId("acme-corp")
    .apiKey(System.getenv("LUMOAUTH_API_KEY"))
    .timeout(Duration.ofSeconds(10))
    .build();
```

Every option falls back to an environment variable, so `LumoAuth.fromEnvironment()` is enough in a configured deployment.

| Option | Purpose |
|---|---|
| `apiKey(key)` | Service credential, sent as `X-API-Key`. The usual choice for backends. |
| `accessToken(token)` | A fixed bearer token, for example a user's token inside one request. |
| `tokenProvider(() -> …)` | Resolve a bearer token per request. A returned token always wins over the API key; the two are never sent together. |
| `httpClient(client)` | Bring your own `java.net.http.HttpClient` for proxies, custom TLS or instrumentation. |
| `header(name, value)` | Add a header to every request, such as a tenant or trace header. |
| `userAgent(ua)` | Replace the default `lumoauth-java/<version>` user agent. |
| `skipCertValidation(true)` | Trust any certificate. Local development only. |
| `withoutCredential()` | Only unauthenticated endpoints will be called, so do not require a credential at build time. |

`LumoAuth` is immutable and thread-safe. Build one per credential and share it.

### Check permissions three ways

```java
// RBAC: does this user hold the permission?
boolean canEdit = lumo.permissions().check("document.edit", CheckOptions.forUser(userId));
boolean canPublish = lumo.permissions().checkAll(List.of("document.edit", "document.publish"), CheckOptions.forUser(userId));
PermissionCheck detail = lumo.permissions().checkDetailed("document.edit", CheckOptions.forUser(userId));

// ReBAC (Zanzibar): is there a relationship between a subject and an object?
boolean canView = lumo.zanzibar().isViewer("document:readme", "user:bob");
boolean related = lumo.zanzibar().check("folder:q4", "member", "group:finance#member");
ZanzibarUsersetNode tree = lumo.zanzibar().expand("document:readme", "viewer");

// ABAC: does policy allow this action given attributes and context?
AbacDecision decision = lumo.abac().check(
    // ip / userAgent / requestMethod / requestPath describe the request LumoAuth received;
    // forward the end user's values under "pep" (policies read pep.ip).
    AbacCheck.of("document", "read", "doc-123").context(Map.of("pep", Map.of("ip", clientIp))));
if (!decision.allowed()) {
    log.info("denied: {} ({})", decision.reason(), decision.matchedPolicies());
}
```

Need more than one answer at a time? `checkBulk`, `checkAny`, `checkAll` and `abac().checkBulk` take lists and make a single round-trip.

### Users and tokens

```java
UserInfo me = lumo.auth().userinfo(userAccessToken);
me.sub(); me.email(); me.roles();              // typed where the shape is stable
me.claim("department");                        // Optional<Object> for anything else
me.raw();                                      // every field the server sent

TokenResponse svc = lumo.auth().clientCredentials(clientId, clientSecret, "read:documents");
TokenResponse fresh = lumo.auth().refreshToken(RefreshTokenRequest.of(refreshToken, clientId, clientSecret));
lumo.auth().revoke(RevokeRequest.of(token).client(clientId, clientSecret));
```

### Handle errors

Every exception is unchecked, extends `LumoAuthException`, and carries the same stable `code()` as the other SDKs. Catch the base class for "anything went wrong", or a subclass for a decision you want to make.

```
LumoAuthException
├── LumoAuthApiException                  any non-2xx: statusCode(), body(), bodyAsMap()
│   ├── LumoAuthAuthenticationException   401  bad or missing credential
│   ├── LumoAuthPermissionDeniedException 403  the caller may not do this
│   ├── LumoAuthNotFoundException         404
│   └── LumoAuthRateLimitException        429  retryAfter() is an Optional<Duration>
├── LumoAuthValidationException           bad input, or a response the SDK cannot use (issues())
├── LumoAuthConfigException               missing or invalid configuration
├── LumoAuthNetworkException              transport failure (getCause() is the IOException)
├── LumoAuthApprovalDeniedException       a human said no (approval())
├── LumoAuthApprovalTimeoutException      nobody answered in time
└── LumoAuthBudgetExceededException       the agent's budget is spent (budget())
```

```java
try {
    lumo.permissions().check("document.edit", CheckOptions.forUser(userId));
} catch (LumoAuthRateLimitException e) {
    e.retryAfter().ifPresent(scheduler::retryIn);
} catch (LumoAuthApiException e) {
    log.warn("LumoAuth returned {}: {}", e.statusCode(), e.getMessage());
}
```

### Reach any endpoint

The namespaces cover the everyday surface. Everything else is one call away, with the same credentials, base URL and error mapping.

```java
Map<String, Object> page = lumo.requestMap("GET", lumo.orgPath("/admin/users?page=2"), null);
JsonNode node          = lumo.requestNode("POST", lumo.orgPath("/admin/invites"), Map.of("email", "new@acme.com"));
HttpResponse<byte[]> r = lumo.requestRaw("GET", "/orgs/acme-corp/api/v1/export", null);

// Prefer typed models for the whole REST API? Hand the generated client the same configuration.
LumoAuth.ApiClientConfig cfg = lumo.apiClientConfig();
io.lumoauth.client.ApiClient api = new io.lumoauth.client.ApiClient();
api.setBasePath(cfg.basePath());
cfg.defaultHeaders().forEach(api::addDefaultHeader);
```

---

## AI agents

### `LumoAgent`: an identity that looks after itself

An agent authenticates with OAuth client credentials. `LumoAgent` fetches the token on first use, refreshes it a minute before it expires, and lets concurrent callers share a single refresh. You never see the token unless you ask for it.

```java
LumoAgent agent = LumoAgent.builder()
    .clientId(System.getenv("AGENT_CLIENT_ID"))
    .clientSecret(System.getenv("AGENT_CLIENT_SECRET"))
    .orgId("acme-corp")
    .scopes("agent:act", "read:documents")
    .build();

AgentIdentity who = agent.identity();                 // cached; identity(true) refreshes
List<String> caps = agent.capabilities();
boolean canSearch = agent.hasCapability("tool:search_web");

AgentAskResult verdict = agent.ask("delete_file", Map.of("path", "/finance/q4.xlsx"));
verdict.allowed(); verdict.reason(); verdict.auditId();

String bearer = agent.accessToken();                   // for calls you make yourself
```

Guard rails read as statements of intent and throw the matching exception when they fail:

```java
agent.requireCapability("tool:send_email");   // LumoAuthPermissionDeniedException
agent.checkBudget();                          // LumoAuthBudgetExceededException
```

### Human-in-the-loop approvals

Some actions should wait for a person. `require` creates the approval, pushes it to the approver, polls until it is answered, and returns the result or throws.

```java
try {
    ApprovalResult approval = agent.approvals().require(
        ApprovalRequest.builder("wire-2026-10-08-001", "Wire $4,500 to vendor INV-7741", "ada@acme.com")
            .impact(ApprovalImpact.HIGH)
            .meta(Map.of("amount", 4500, "vendor", "INV-7741"))
            .build(),
        WaitOptions.of(Duration.ofSeconds(2), Duration.ofMinutes(3)));

    wire(approval.token());                       // the approval token authorises the side effect
} catch (LumoAuthApprovalDeniedException e) {
    notify("Ada declined: " + e.approval().reason());
} catch (LumoAuthApprovalTimeoutException e) {
    notify("No answer within 3 minutes; the wire was not sent.");
}
```

Prefer to poll yourself? `create` returns immediately and `status` / `waitFor` pick the approval up by token later, even from a different process.

### Just-in-Time permissions

A JIT task scopes permissions to one unit of work. Closing the task revokes every token issued under it, so `JitContext` is `AutoCloseable` and a `try` block is the whole lifecycle.

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

`callWithEscalation` goes one step further: it makes the call, and if the resource answers 403 with an `Insufficient-Authorization-Details` challenge, it requests exactly those permissions, waits for the decision and retries.

### Delegation: act on behalf of a user

Chain of agency over RFC 8693 token exchange. The user consents once; the agent then holds a token that says who it is *and* who it acts for, and can hand a narrower token to a sub-agent.

The lower-level `lumo.auth().tokenExchange(TokenExchangeRequest)` declares what it exchanges through `subjectTokenType(…)` / `actorTokenType(…)`: `AuthResource.TOKEN_TYPE_ACCESS_TOKEN` (the default), `TOKEN_TYPE_JWT` (an at+jwt access token or an external workload JWT), `TOKEN_TYPE_ID_TOKEN` (an OpenID Connect ID token) or `TOKEN_TYPE_REFRESH_TOKEN` (not accepted as the subject when an agent acts on a user's behalf). The server refuses a token that does not match its declared type. `resource(…)` (or `lumo.delegation().exchangeForResource(…)`) sets the RFC 8707 resource indicator, an https URL that becomes the token's `aud`; without it an on-behalf-of token is bound to the agent's own id, and LumoAuth does not bind `aud` from `audience(…)`.

```java
DelegationChain chain = new DelegationChain(agent, "https://agent.example.com/callback");

String consentUrl = chain.consentUrl("session-1", List.of("read:documents"));
// … send the user there; your callback receives ?code=… …
chain.handleConsentCallback("session-1", code);

Map<String, Object> docs = chain.request("session-1", "GET", "/orgs/acme-corp/api/v1/documents", null, Map.class);
String childToken = chain.delegateToSubAgent("session-1", summariserToken, "read:documents");
List<String> actors = chain.actorChain(childToken);   // ["agent:summariser", "agent:assistant"]

chain.revoke("session-1");
```

### Calling MCP servers

```java
String token = agent.mcpToken("server_123");          // audience-scoped to that MCP server
McpToken detail = agent.mcp().tokenDetailed("server_123", agent.accessToken());
```

### AAuth: cryptographic agent identity

AAuth gives an agent a key pair instead of a shared secret. Every request is signed (RFC 9421), tokens are bound to the key (proof of possession), and anyone can discover the agent's public key from its identifier.

```java
Keypair keypair = AAuthKeys.generateKeypair("key-1");
// publish keypair.jwks() at https://my-agent.example.com/.well-known/jwks.json
// keep keypair.privateKeyPem() in your secret store

AAuthClient client = AAuthClient.builder()
    .agentIdentifier("https://my-agent.example.com")
    .privateKeyPem(System.getenv("AGENT_PRIVATE_KEY"))
    .orgId("acme-corp")
    .build();

AAuthTokenResponse grant = client.requestAuthToken(resourceToken, "read write", agentToken);
if (grant.authorizationRequired()) {
    redirect(grant.authorizationUri());                       // a human consents in the browser
    grant = client.exchangeCode(code, redirectUri, agentToken);
}

HttpResponse<byte[]> res = client.signedRequest("POST", "https://api.example.com/v1/items", grant.authToken(), body);
```

Signing lower-level requests yourself? `client.signRequest(method, url, options)` returns the `Signature`, `Signature-Input` and `Content-Digest` headers to attach.

### Verifying AAuth tokens on a resource server

The other side of the handshake: an API or MCP server that accepts agent tokens. Verification is local against the issuer's JWKS, which `JwksCache` fetches once and refreshes on key rotation.

```java
JwksCache keys = new JwksCache("https://app.lumoauth.dev/orgs/acme-corp/api/v1");

AAuthClaims claims = AAuthVerifier.verifyAuthToken(bearer, keys.verifyOptions("https://api.example.com"));
claims.verifyProofOfPossession(new IncomingRequest(method, uri, headers, body));   // signed by the key the token is bound to

if (!claims.hasScope("write")) {
    throw new ForbiddenException();
}
```

On Spring MVC, `ServletRequests.toIncomingRequest(request, body)` builds the `IncomingRequest` from an `HttpServletRequest`.

---

## Sign-in without Spring

A framework-neutral authorization-code flow with PKCE. Store `PendingLogin` in the session between the two steps; store `SignedIn` once the user is back.

```java
AuthorizationCodeFlow flow = AuthorizationCodeFlow.builder(lumo, clientId, "https://app.example.com/callback")
    .clientSecret(clientSecret)             // omit for public clients
    .scope("openid profile email")
    .build();

// GET /login
AuthorizationCodeFlow.PendingLogin pending = flow.start(returnTo);
session.put("login", pending);
redirect(pending.authorizationUrl());

// GET /callback?code=…&state=…
AuthorizationCodeFlow.SignedIn user = flow.complete(session.get("login"), queryParams);
session.put("user", user);
redirect(AuthorizationCodeFlow.sanitizeReturnTo(pending.returnTo(), "/"));

// later
user.user().email();
LumoAuth asUser = flow.clientFor(user);      // calls LumoAuth with the user's own token
flow.refresh(user).ifPresent(session::replace);
```

---

## Spring Boot starter

The starter turns the SDK into Spring beans and plugs it into Spring Security. It is built against Spring Boot 3.5 and works with any Spring Boot 3.x.

### Configure

```yaml
lumoauth:
  url: https://app.lumoauth.dev            # or LUMOAUTH_URL
  org-id: acme-corp                        # or LUMOAUTH_ORG_ID
  api-key: ${LUMOAUTH_API_KEY}             # or LUMOAUTH_API_KEY
  timeout: 10s

  login:                                   # browser sign-in (needs spring-boot-starter-oauth2-client)
    client-id: lumo_abc123
    client-secret: ${LUMOAUTH_CLIENT_SECRET}
    scopes: [openid, profile, email]
    success-url: /dashboard
    permit-all: [/, /error, /favicon.ico, /public/**]

  agent:                                   # LumoAgent bean
    client-id: ${AGENT_CLIENT_ID}
    client-secret: ${AGENT_CLIENT_SECRET}

  aauth:                                   # AAuthClient bean
    agent-identifier: https://my-agent.example.com
    private-key-pem: ${AGENT_PRIVATE_KEY}

  security:
    bearer-tokens: true                    # resolve LumoAuth bearer tokens (needs oauth2-resource-server)
    permissions-as-authorities: false      # also expose PERMISSION_<slug> authorities
```

Every key has IDE completion and documentation through the generated configuration metadata.

### What you get

| Feature | Provided by | Switches on when |
|---|---|---|
| `LumoAuth` bean | `LumoAuthAutoConfiguration` | always |
| `LumoAgent` bean | `LumoAuthAutoConfiguration` | `lumoauth.agent.client-id` is set |
| `AAuthClient` bean | `LumoAuthAutoConfiguration` | `lumoauth.aauth.agent-identifier` is set |
| Bearer tokens resolved to a principal | `LumoAuthSecurityAutoConfiguration` | `spring-boot-starter-oauth2-resource-server` on the classpath |
| `@RequirePermission`, `@lumo` SpEL bean, `PermissionEvaluator` | `LumoAuthSecurityAutoConfiguration` | Spring Security on the classpath |
| OIDC login and a default `SecurityFilterChain` | `LumoAuthLoginAutoConfiguration` | `spring-boot-starter-oauth2-client` on the classpath and `lumoauth.login.client-id` set |
| `/actuator/health/lumoauth` | `LumoAuthHealthAutoConfiguration` | Spring Boot Actuator on the classpath |

Define your own bean of any of these types and the starter backs off. A `java.net.http.HttpClient` bean, when present, is used for every request. Security starters are optional on purpose: the library never locks an app down unless you add Spring Security yourself.

### Protect an API with bearer tokens

Add `spring-boot-starter-oauth2-resource-server`. Requests with a LumoAuth access token get an authenticated principal whose authorities are `ROLE_<role>` and `CAPABILITY_<slug>` (agents included), so plain Spring Security works unchanged:

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

### Sign users in with LumoAuth

Add `spring-boot-starter-oauth2-client` and set `lumoauth.login.client-id` and `client-secret`. The starter registers LumoAuth as an OIDC provider (`/oauth2/authorization/lumoauth`) and contributes a filter chain that sends anonymous browsers to log in, accepts bearer tokens on the same app, and permits the paths in `lumoauth.login.permit-all`. Set `lumoauth.login.default-filter-chain=false` or define your own `SecurityFilterChain` to take over.

```java
@GetMapping("/dashboard")
String dashboard(@AuthenticationPrincipal OidcUser user) {
    return "Hello " + user.getFullName();
}
```

### Authorize methods

Three styles, all backed by live LumoAuth checks. Checks run under the caller's bearer token when they have one, otherwise with the API key on behalf of the signed-in principal.

```java
@RequirePermission("document.edit")                                   // RBAC, one permission
public void edit(String id) { … }

@RequirePermission(value = {"document.edit", "document.publish"}, mode = RequirePermission.Mode.ANY)
public void publish(String id) { … }

@PreAuthorize("@lumo.isEditor('document:' + #id)")                    // Zanzibar relationship
public void rename(String id, String title) { … }

@PreAuthorize("hasPermission(#id, 'document', 'delete')")             // ABAC via PermissionEvaluator
public void delete(String id) { … }
```

`@RequirePermission` works on classes too, and needs only `spring-aop`, which every Spring Boot app already has. The `@lumo` bean also exposes `can`, `canAll`, `canAny`, `relation`, `isViewer`, `isOwner`, `abac` and `principal()` for use in templates and handlers.

### Verify AAuth tokens in a controller

```java
@PostMapping("/v1/items")
ResponseEntity<?> create(HttpServletRequest request, @RequestBody byte[] body) {
    AAuthClaims claims = AAuthVerifier.verifyAuthToken(bearer(request), keys.verifyOptions("https://api.example.com"));
    claims.verifyProofOfPossession(ServletRequests.toIncomingRequest(request, body));
    …
}
```

### Health

With Actuator on the classpath, `/actuator/health/lumoauth` reports whether the configured instance answers, and surfaces maintenance or authentication problems with their error code.

---

## Configuration reference

| Environment variable | Spring property | Meaning | Default |
|---|---|---|---|
| `LUMOAUTH_URL` | `lumoauth.url` | LumoAuth instance URL | `https://app.lumoauth.dev` |
| `LUMOAUTH_ORG_ID` | `lumoauth.org-id` | Organization slug | required for org-scoped calls |
| `LUMOAUTH_API_KEY` | `lumoauth.api-key` | API key for `LumoAuth`, sent as `X-API-Key` | none |
| `AGENT_CLIENT_ID` | `lumoauth.agent.client-id` | Agent OAuth client ID | required for `LumoAgent` |
| `AGENT_CLIENT_SECRET` | `lumoauth.agent.client-secret` | Agent OAuth client secret | required for `LumoAgent` |

The same variables configure every LumoAuth SDK, so one `.env` serves a polyglot stack.

## Compatibility

| | Supported |
|---|---|
| Java | 17, 21 and newer (tested on 17 and 21) |
| Spring Boot | 3.x, built against 3.5. Spring Boot 4 ships as starter 2.x. |
| LumoAuth server API | 1.0.0 and newer |
| Runtime dependencies | `jackson-databind` only (core); the starter adds `spring-boot-starter` |
| Build tools | Maven, Gradle (Groovy or Kotlin DSL) |
| Modules | Automatic-Module-Name `io.lumoauth` and `io.lumoauth.spring` |

## Design notes

A few choices worth knowing before you build on the SDK.

- **Records everywhere.** Request parameters are immutable records with static factories and withers (`AbacCheck.of("document", "read").resourceId("doc-1")`) or builders for the larger ones. Responses are records. The open-ended ones implement `RawPayload` and keep every field the server sent in `raw()`, so a new server field is never lost.
- **Unchecked exceptions.** Authorization failures are not exceptional control flow in most apps, so the SDK never forces a `catch`. Boolean helpers (`check`, `isAllowed`, `hasCapability`) answer yes or no; `require…` helpers throw.
- **No hidden globals.** Clients are explicit objects. Build them once, inject them, share them across threads.
- **Credentials never collide.** A bearer token and an API key are never sent on the same request. Token endpoints are called without either.
- **Generated routes.** `Routes.java` is generated from the shared contract and checked in CI, so the Java SDK cannot drift from the server's API without the build noticing.

## Development

Java 17+ and Maven 3.6.3+:

```bash
mvn verify                                             # unit + conformance tests (skip when ../sdk-contract is absent)
python3 ../sdk-contract/scripts/gen-java-routes.py     # regenerate lumo-auth-java/.../Routes.java
mvn -P release -Dgpg.skip=true package                 # sources + javadoc jars, as Maven Central requires
```

Releases follow [`playbooks/sdk-publish-maven-central.md`](../playbooks/sdk-publish-maven-central.md). Changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## Resources

- [Java quickstart](https://docs.lumoauth.dev/quickstarts/java) and the [SDK overview](https://docs.lumoauth.dev/developer/sdks)
- [AI agent + MCP in five minutes](https://docs.lumoauth.dev/quickstarts/ai-agent-mcp-5min) and [Agent security](https://docs.lumoauth.dev/quickstarts/ai-agent-security)
- [`sdk-contract`](../sdk-contract): the routes, errors, features and signing vectors every SDK is built from
- Sibling SDKs: [JS/TS](../sdk-js), [Python](../sdk-python), [Go](../sdk-go), [PHP](../sdk-php)

## License

[MIT](LICENSE).
