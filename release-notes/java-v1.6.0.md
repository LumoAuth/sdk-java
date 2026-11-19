# LumoAuth Java SDK v1.6.0 (`java-v1.6.0`)

**Release Date:** November 18, 2026  
**Tag:** `java-v1.6.0`

## Packages Updated

| Package | Version |
| :--- | :--- |
| `io.lumoauth:lumo-auth-parent` | `1.6.0` |
| `io.lumoauth:lumo-auth-java` | `1.6.0` |
| `io.lumoauth:lumo-auth-spring-boot-starter` | `1.6.0` |

---

## Highlights & Fixes

### 1. Capabilities in `<resource>:<action>` Form (`io.lumoauth.Capabilities`)

An agent capability is one of the agent's OAuth scope values. LumoAuth now writes every capability as `<resource>:<action>`, such as `invoices:read`, with the wildcard `invoices:*`. The SDK's capability matching follows the server again.

- `Capabilities.normalize()` now returns the server's canonical form, with `:` between the parts. It trims the name, lower-cases ASCII letters, turns every `.` into `:`, collapses runs of `:` and trims `:` from both ends.
- A `-` is now part of a name, not a separator. `pull-requests:comment` is one resource and one action, and `invoices-read` is a different capability from `invoices:read`.
- A name that ends in `:*` covers every action under that prefix, at any depth, but not the prefix itself. `invoices:*` covers `invoices:read` and `invoices:read:draft`, but not `invoices` and not `invoices-archive:read`.
- A `.` is still read as `:` when the SDK compares. A dotted permission slug such as `invoices.read` matches the held `invoices:read`, and a capability stored as `invoices.*` still covers `invoices:read`.
- The same rules apply in `Capabilities.normalize()`, `Capabilities.covers()`, `Capabilities.anyCovers()`, `LumoAgent.hasCapability()` and `LumoAgent.requireCapability()`.

| Input to `Capabilities.normalize()` | 1.5.0 | 1.6.0 |
| :--- | :--- | :--- |
| `"Invoices:Read"` | `"invoices.read"` | `"invoices:read"` |
| `"Invoices.Read"` | `"invoices.read"` | `"invoices:read"` |
| `"invoices-read"` | `"invoices.read"` | `"invoices-read"` |

```java
Capabilities.normalize("Pull-Requests.Comment");     // "pull-requests:comment"
Capabilities.covers("users:*", "USERS.DELETE");      // true
Capabilities.covers("users:*", "users-delete");      // false: "-" is part of a name
Capabilities.covers("invoices:*", "invoices");       // false
```

### 2. Resource-First Default Scope for Delegation (`io.lumoauth.model.ConsentUrlRequest`)

- `ConsentUrlRequest.DEFAULT_SCOPES` is now `["documents:read"]`. Earlier releases used `["read:documents"]`.
- `lumo.delegation().consentUrl(…)` and `DelegationChain.consentUrl(…)` use this default when you pass no scopes.
- Every scope, capability and Ask action in the Javadoc and `README.md` now puts the resource first: `documents:read`, `web:search`, `email:send`, `files:delete`.

### 3. `web.checkEmail` Points to the Email-First API (`io.lumoauth.Routes`)

- The route `web.checkEmail` (`Routes.WEB_CHECK_EMAIL`) now points to `POST /orgs/{orgId}/api/v1/oauth/check-email`.
- Before, it pointed to `POST /orgs/{orgId}/check-email`. That path is the route of the hosted login page, and it does not answer other sites.
- No SDK method calls this route. The change matters only to code that reads the route table (`Routes.get`, `Routes.path`) or sends the route with `transport().call(...)` or `transport().callNode(...)`.

The endpoint is for applications that render their own sign-in form. It reports the sign-in methods that the organization offers, so that the form can show the next step after a person types an email address.

- **The request is JSON** with two required fields: `email` and `client_id`, your application's client ID.
- **Send no credential** (`ApiRequest.noAuth()`). LumoAuth refuses a request to this endpoint that carries a token or an API key.
- **A request from a browser must come from one of the application's allowed origins.**
- **The answer is the same for every address.** `exists` is always `true`, and `magic_link_enabled`, `passkey_enabled` and `password_enabled` hold the organization's methods. The answer does not say whether the address has an account, so show the same next step to everyone.

```java
LumoAuth lumo = LumoAuth.builder()
    .baseUrl("https://app.lumoauth.dev")
    .orgId("acme-corp")
    .withoutCredential()
    .build();

JsonNode methods = lumo.transport().callNode(
    Routes.WEB_CHECK_EMAIL,
    null,
    ApiRequest.json(Map.of(
        "email", "ada@example.com",
        "client_id", "my-app"))
        .noAuth());

// {"exists": true, "magic_link_enabled": true, "passkey_enabled": false, "password_enabled": true}
```

---

## Upgrade Notes

- **`Capabilities.normalize()` returns a different string.** It now returns `invoices:read` where 1.5.0 returned `invoices.read`. Update any code that stores or compares its output.
- **A `-` no longer matches a `:` or a `.`.** `hasCapability("invoices-read")` is now `false` for an agent that holds `invoices:read`, and a held `users:*` no longer covers `users-delete`. This also applies to `requireCapability()`. Write these names as `<resource>:<action>`.
- **Register capabilities and request scopes in `<resource>:<action>` form.** LumoAuth refuses the dot form (`invoices.read`) when you register a capability, request a scope for its API or call `ask()` as an agent. The SDK does not check this before it sends the request.
- **Check your Spring Security rules on capabilities.** The starter adds one `CAPABILITY_<slug>` authority for each capability, spelled exactly as LumoAuth returns it. `hasAuthority()` compares exact strings and does not use the rules above. A capability held as `web:search` gives `CAPABILITY_web:search`, so a rule for `CAPABILITY_web.search` or `CAPABILITY_tool:search_web` does not match it. The starter code did not change.
- **The default scope for delegation changed.** If your code calls `consentUrl(…)` without scopes and expects `read:documents`, pass `List.of("read:documents")`.
- **Requests built from `Routes.WEB_CHECK_EMAIL` now go to the API endpoint.** Send the JSON body above instead of the form fields of the hosted page.
- No dependency changes in this release. The SDK still targets Java 17.

---

## Documentation & Tests

- Added a dated `1.6.0` section to `CHANGELOG.md` for the capability rules and the default delegation scope.
- `README.md` explains the `<resource>:<action>` form, the `prefix:*` wildcard and why `web-search` is a different capability. The Spring Security example now uses `hasAuthority("CAPABILITY_web:search")`.
- `CapabilitiesTest` checks the new form, the `:*` wildcard and the rule for `-`. `ContractTest` runs the shared cases in `sdk-contract/vectors/agent-capabilities.json`, which are now in the `<resource>:<action>` form.
- `ResourcesTest` checks that the consent URL asks for `documents:read`. `LumoAgentTest`, `DelegationChainTest` and `LumoAuthSecurityAutoConfigurationTest` now use resource-first scopes, capabilities and actions.
- `Routes.java` is still generated from `sdk-contract/routes.json`, so the contract test checks the new check-email path.
- Added the release notes for 1.5.0 (`release-notes/java-v1.5.0.md`).

---

## Commit Log (`java-v1.5.0..java-v1.6.0`)

- `41534fa` — `release: lumo-auth-java@1.6.0`
- `39d4b91` — `feat: update capability matching to use <resource>:<action> format and adjust related scopes`
- `6006247` — `fix: update web.checkEmail route to correct endpoint`
- `35546d3` — `Merge branch 'main' of github-lumo:LumoAuth/sdk-java`
- `e8709be` — `release: add release notes for LumoAuth Java SDK v1.5.0`
- `01e9414` — `Merge pull request #5 from LumoAuth/release/java-1.5.0`
