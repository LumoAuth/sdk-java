# LumoAuth Java SDK

Hand-written, idiomatic Java for [LumoAuth](https://lumoauth.dev): authorization
(RBAC / Zanzibar / ABAC), agent identity and capabilities, AAuth cryptographic
identity with RFC 9421 request signing, Just-in-Time permissions, push
approvals, and browser sign-in. Built to the same contract as the
[JS](../sdk-js), [Python](../sdk-python), [Go](../sdk-go) and [PHP](../sdk-php)
SDKs ([`sdk-contract`](../sdk-contract)): the same namespaces, the same error
taxonomy, the same environment variables, byte-compatible signing.

| Module | Maven coordinates | What it is |
|---|---|---|
| [`lumo-auth-java`](lumo-auth-java) | `io.lumoauth:lumo-auth-java` | The SDK. Java 17+, depends only on the JDK and Jackson. |
| [`lumo-auth-spring-boot-starter`](lumo-auth-spring-boot-starter) | `io.lumoauth:lumo-auth-spring-boot-starter` | Spring Boot 3 auto-configuration: `lumoauth.*` properties, beans, Spring Security integration, actuator health. |

The generated client `io.lumoauth:lumoauth-api-client` (every REST endpoint,
from [`api-clients/java`](../api-clients/java)) stays separate;
`LumoAuth.apiClientConfig()` configures it.

```xml
<dependency>
  <groupId>io.lumoauth</groupId>
  <artifactId>lumo-auth-java</artifactId>
  <version>0.1.0</version>
</dependency>
<!-- or, on Spring Boot -->
<dependency>
  <groupId>io.lumoauth</groupId>
  <artifactId>lumo-auth-spring-boot-starter</artifactId>
  <version>0.1.0</version>
</dependency>
```

```groovy
implementation 'io.lumoauth:lumo-auth-java:0.1.0'
```

## Environment variables

| Variable | Description | Default |
| --- | --- | --- |
| `LUMOAUTH_URL` | LumoAuth instance URL | `https://app.lumoauth.dev` |
| `LUMOAUTH_ORG_ID` | Organization slug | *(required for org-scoped calls)* |
| `LUMOAUTH_API_KEY` | API key for `LumoAuth` (sent as `X-API-Key`) | — |
| `AGENT_CLIENT_ID` | Agent OAuth client ID | *(required for `LumoAgent`)* |
| `AGENT_CLIENT_SECRET` | Agent OAuth client secret | *(required for `LumoAgent`)* |

Every builder option falls back to these, so `LumoAuth.fromEnvironment()` and
`LumoAgent.fromEnvironment()` are enough in a configured environment. The Spring
Boot starter binds the same variables to `lumoauth.url`, `lumoauth.org-id` and
`lumoauth.api-key` through relaxed binding.

## Which entry point?

| You are… | Use |
| --- | --- |
| A backend service checking permissions | `LumoAuth` |
| An AI agent acting under its own identity | `LumoAgent` |
| An agent with a signing key (AAuth) | `io.lumoauth.aauth.AAuthClient` |
| A resource server verifying AAuth tokens | `io.lumoauth.aauth.AAuthVerifier` |
| A Spring Boot app | the starter (below) |
| Any other web app signing users in | `io.lumoauth.web.AuthorizationCodeFlow` |

---

## Quick start — `LumoAuth`

```java
import io.lumoauth.LumoAuth;
import io.lumoauth.model.*;

LumoAuth lumo = LumoAuth.builder()
    .apiKey(System.getenv("LUMOAUTH_API_KEY"))
    .orgId("acme-corp")
    .build();

// RBAC
boolean canEdit = lumo.permissions().check("document.edit");
boolean canEdit = lumo.permissions().check("document.edit", CheckOptions.forUser(userId));

// ReBAC (Zanzibar)
boolean canView = lumo.zanzibar().isViewer("document:readme", "user:bob");

// ABAC
AbacDecision decision = lumo.abac().check(AbacCheck.of("document", "read", "doc-123"));

// Agent Ask API
AgentAskResult verdict = lumo.agents().ask("send_email", Map.of("to", "cfo@acme.com"));
```

### Builder options

```java
LumoAuth.builder()
    .baseUrl(url)                 // instance URL
    .orgId(slug)                  // organization
    .apiKey(key)                  // X-API-Key credential
    .accessToken(token)           // fixed bearer token
    .tokenProvider(() -> ...)     // bearer token resolved per request
    .timeout(Duration.ofSeconds(30))
    .httpClient(httpClient)       // java.net.http.HttpClient: proxies, TLS, instrumentation
    .header(name, value)          // extra header on every request
    .userAgent(ua)
    .skipCertValidation(true)     // local development only
    .withoutCredential()          // unauthenticated endpoints only
    .build();
```

An API key and a bearer token are never sent together: a token provider that
returns a token wins.

### Namespaces

| Namespace | Covers |
| --- | --- |
| `lumo.auth()` | OAuth 2.1: authorization URLs, code exchange, refresh, client credentials, token exchange, revocation, UserInfo |
| `lumo.permissions()` | RBAC: `check`, `checkBulk`, `checkAny`, `checkAll`, `list` (+ `…Detailed` variants) |
| `lumo.zanzibar()` | ReBAC: `check`, `expand`, `isViewer` / `isEditor` / `isOwner` / `isMember` / `isAdmin` |
| `lumo.abac()` | Policy evaluation, bulk checks, user and resource attributes, attribute definitions |
| `lumo.agents()` | `ask`, `isAllowed`, `me`, `register`, `capabilities`, `budget` |
| `lumo.approvals()` | Push approvals: `create`, `status`, `waitFor`, `require` |
| `lumo.jit()` | Ephemeral tasks and scoped tokens (see also `JitContext`) |
| `lumo.delegation()` | RFC 8693 primitives (see also `DelegationChain`) |
| `lumo.mcp()` | Audience-scoped tokens for secured MCP servers |

Request parameters are immutable records with static factories and "withers"
(`AbacCheck.of("document", "read").resourceId("doc-1")`) or builders for the
larger ones (`ApprovalRequest.builder(...)`). Responses are records; the
open-ended ones keep every field the server sent in `raw()`.

### Errors

Every exception is unchecked and extends `LumoAuthException`; `code()` is the
stable code shared with the other SDKs.

```
LumoAuthException
├── LumoAuthApiException                 any non-2xx (statusCode(), body(), bodyAsMap())
│   ├── LumoAuthAuthenticationException  401
│   ├── LumoAuthPermissionDeniedException 403
│   ├── LumoAuthNotFoundException        404
│   └── LumoAuthRateLimitException       429 (retryAfter())
├── LumoAuthValidationException          bad input or unusable response
├── LumoAuthConfigException              missing or invalid configuration
├── LumoAuthNetworkException             transport failure
├── LumoAuthApprovalDeniedException      a human said no
├── LumoAuthApprovalTimeoutException     nobody answered in time
└── LumoAuthBudgetExceededException      the agent's budget is spent
```

### Escape hatches

```java
Map<String, Object> page = lumo.requestMap("GET", lumo.orgPath("/admin/users"), null);
HttpResponse<byte[]> raw = lumo.requestRaw("GET", "/orgs/acme-corp/api/v1/admin/users", null);

// The generated client for the full REST surface:
LumoAuth.ApiClientConfig cfg = lumo.apiClientConfig();
io.lumoauth.client.ApiClient api = new io.lumoauth.client.ApiClient();
api.setBasePath(cfg.basePath());
cfg.defaultHeaders().forEach(api::addDefaultHeader);
```

---

## Quick start — `LumoAgent`

An agent owns an OAuth client-credentials token and refreshes it transparently
(a minute before expiry; concurrent callers share one token request).

```java
LumoAgent agent = LumoAgent.fromEnvironment(); // AGENT_CLIENT_ID, AGENT_CLIENT_SECRET, LUMOAUTH_*

boolean allowed = agent.isAllowed("document.read", Map.of("id", "doc_99"));
agent.requireCapability("tool:search_web"); // LumoAuthPermissionDeniedException if missing
agent.checkBudget();                        // LumoAuthBudgetExceededException if spent
```

### Human approval

```java
try {
    ApprovalResult approval = agent.approvals().require(
        ApprovalRequest.builder("wire-2026-05-07-001", "Wire $4,500 to vendor INV-7741", "ada@acme.com")
            .impact(ApprovalImpact.HIGH)
            .meta(Map.of("amount", 4500, "vendor", "INV-7741"))
            .build());
    // approval.token() authorises the side-effecting call.
} catch (LumoAuthApprovalDeniedException e) {
    // a human declined
} catch (LumoAuthApprovalTimeoutException e) {
    // nobody responded in time
}
```

### JIT permissions

A task scopes permissions to one unit of work; closing it revokes every token
issued under it, so `JitContext` is `AutoCloseable`.

```java
try (JitContext jit = new JitContext(agent)) {
    jit.createTask(CreateTaskRequest.named("Analyse Q4 report"));
    JitRequest result = jit.requestPermission(
        Map.of("type", "file_access", "actions", List.of("read"), "identifier", "report_q4.pdf"),
        JitContext.RequestOptions.justification("The user asked for a Q4 summary"));
    if (result.approved()) {
        String token = jit.token(result.requestId());
        // present the token to the resource, or let jit.callWithEscalation(...) handle 403s
    }
}
```

### Delegation (Chain of Agency)

```java
DelegationChain chain = new DelegationChain(agent, "https://agent.example.com/callback");
String consentUrl = chain.consentUrl("session-1", List.of("read:documents"));
// ... the user consents, your callback receives `code` ...
chain.handleConsentCallback("session-1", code);
Map<String, Object> docs = chain.request("session-1", "GET", "/orgs/acme/api/v1/documents", null, Map.class);
chain.revoke("session-1");
```

---

## AAuth — cryptographic agent identity

```java
Keypair keypair = AAuthKeys.generateKeypair("key-1"); // publish keypair.jwks(), keep privateKeyPem() secret

AAuthClient client = AAuthClient.builder()
    .agentIdentifier("https://my-agent.example.com")
    .privateKeyPem(System.getenv("AGENT_PRIVATE_KEY"))
    .orgId("acme-corp")
    .build();

AAuthTokenResponse result = client.requestAuthToken(resourceToken, "read write", agentToken);
if (result.authorizationRequired()) {
    // redirect the user to result.authorizationUri(), then client.exchangeCode(code, redirectUri, agentToken)
}
HttpResponse<byte[]> response = client.signedRequest("POST", "https://api.example.com/v1/items", result.authToken(), body);
```

Resource servers verify tokens locally and enforce proof-of-possession:

```java
JwksCache keys = new JwksCache("https://app.lumoauth.dev/orgs/acme-corp/api/v1");
AAuthClaims claims = AAuthVerifier.verifyAuthToken(bearer, keys.verifyOptions("https://api.example.com"));
claims.verifyProofOfPossession(new IncomingRequest(method, uri, headers, body));
```

Signing uses only JDK cryptography (Ed25519 or RSA-PSS-SHA512) and reproduces
the shared RFC 9421 conformance vector byte for byte.

---

## Spring Boot starter

```yaml
lumoauth:
  url: https://app.lumoauth.dev          # or LUMOAUTH_URL
  org-id: acme-corp                      # or LUMOAUTH_ORG_ID
  api-key: ${LUMOAUTH_API_KEY}           # backend checks
  login:                                 # browser sign-in (optional)
    client-id: lumo_abc
    client-secret: ${LUMOAUTH_CLIENT_SECRET}
  agent:                                 # LumoAgent bean (optional)
    client-id: ${AGENT_CLIENT_ID}
    client-secret: ${AGENT_CLIENT_SECRET}
```

With the starter on the classpath you get:

- **Beans**: `LumoAuth` always; `LumoAgent` when `lumoauth.agent.client-id` is
  set; `AAuthClient` when `lumoauth.aauth.agent-identifier` is set. Define your
  own bean of a type and the starter backs off. A `java.net.http.HttpClient`
  bean, if present, is used for every request.
- **Bearer tokens** (with `spring-boot-starter-oauth2-resource-server`): an
  `OpaqueTokenIntrospector` resolves LumoAuth access tokens through userinfo, so
  `Authorization: Bearer …` requests get a principal with `ROLE_<role>` and
  `CAPABILITY_<slug>` authorities (and `PERMISSION_<slug>` with
  `lumoauth.security.permissions-as-authorities=true`).
- **Sign-in** (with `spring-boot-starter-oauth2-client`): `lumoauth.login.client-id`
  registers LumoAuth as an OIDC client (`/oauth2/authorization/lumoauth`) and
  contributes a default `SecurityFilterChain` (login + bearer tokens, everything
  authenticated except `lumoauth.login.permit-all`). Define your own chain or
  set `lumoauth.login.default-filter-chain=false` to take over.
- **Method security**:
  ```java
  @RequirePermission("document.edit")
  public void edit(String id) { ... }

  @PreAuthorize("@lumo.can('document.edit')")
  @PreAuthorize("@lumo.isViewer('document:' + #id)")
  @PreAuthorize("hasPermission(#id, 'document', 'read')")   // ABAC
  ```
  Checks run under the caller's bearer token when they have one, otherwise with
  the API key on behalf of the principal's `sub`.
- **Health**: `/actuator/health/lumoauth` (with actuator on the classpath).
- **IDE completion** for every `lumoauth.*` key through the generated
  configuration metadata.

The starter targets Spring Boot 3.x (built against 3.5). Spring Boot 4 support
ships as starter 2.x, per the playbook's version policy.

---

## Development

Java 17+ and Maven 3.6.3+:

```bash
mvn verify                                   # conformance tests skip when ../sdk-contract is absent
python3 ../sdk-contract/scripts/gen-java-routes.py   # regenerate lumo-auth-java/.../Routes.java
mvn -P release -Dgpg.skip=true package       # sources + javadoc jars, as Maven Central requires
```

Publishing follows [`playbooks/sdk-publish-maven-central.md`](../playbooks/sdk-publish-maven-central.md).

## License

MIT.
