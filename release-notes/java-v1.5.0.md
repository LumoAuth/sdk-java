# LumoAuth Java SDK v1.5.0 (`java-v1.5.0`)

**Release Date:** November 13, 2026  
**Tag:** `java-v1.5.0`

## Packages Updated

| Package | Version |
| :--- | :--- |
| `io.lumoauth:lumo-auth-parent` | `1.5.0` |
| `io.lumoauth:lumo-auth-java` | `1.5.0` |
| `io.lumoauth:lumo-auth-spring-boot-starter` | `1.5.0` |

---

## Fixes

### `web.magicLink` Points to the Endpoint for Your Own Sign-in Form (`io.lumoauth.Routes`)

The route `web.magicLink` (`Routes.WEB_MAGIC_LINK`) pointed to `POST /orgs/{orgId}/magic-link`. That path is the form endpoint of the hosted login page. It accepts a request only from the hosted page itself, so the server refused every request that came from your own code.

- `web.magicLink` now points to `POST /orgs/{orgId}/api/v1/oauth/magic-link`. This endpoint is for applications that render their own sign-in form.
- The new endpoint takes a JSON body:
  - `email` (required): the address that gets the sign-in link.
  - `client_id` (required): your application's client ID.
  - `return_to` (optional): the page of your application that the person goes to after sign-in. It must be an absolute `https` URL (`http` only on `localhost`), and its origin must be one of the application's allowed origins or the origin of one of its redirect URIs.
  - `captcha_token` (optional): the token from the CAPTCHA widget. It is required when your organization protects sign-in link requests with a CAPTCHA.
- Send the request with no credential (`ApiRequest.noAuth()`).
- The server answers `{"status": "sent"}` whether or not the address belongs to an account, so the answer does not reveal which addresses have accounts.
- When sign-in links are off for the organization, the server answers 404 with the error code `magic_link_disabled`. The SDK throws `LumoAuthNotFoundException`, and `code()` returns `magic_link_disabled`.
- The route comment in `Routes.java` now reads "Sign-in helpers for applications that render their own sign-in form".
- `web.checkEmail` (`Routes.WEB_CHECK_EMAIL`) did not change.

```java
LumoAuth lumo = LumoAuth.builder()
    .baseUrl("https://app.lumoauth.dev")
    .orgId("acme-corp")
    .withoutCredential()
    .build();

JsonNode answer = lumo.transport().callNode(
    Routes.WEB_MAGIC_LINK,
    null,
    ApiRequest.json(Map.of(
        "email", "ada@example.com",
        "client_id", "my-app",
        "return_to", "https://my-app.example.com/dashboard"))
        .noAuth());

// {"status": "sent"}
```

---

## Upgrade Notes

- **No SDK method calls this route.** The fix matters only to code that reads the route table (`Routes.get`, `Routes.path`) or sends the route with `transport().call(...)` or `transport().callNode(...)`.
- **Code that sent the old route must change its request body.** The old form endpoint took a form post from the hosted page. The new endpoint takes JSON with `email` and `client_id`.
- **The Spring Boot starter has no code changes.**
- No dependency changes in this release. The SDK still targets Java 17.

---

## Documentation & Tests

- Added a dated `1.5.0` section to `CHANGELOG.md`.
- `Routes.java` is still generated from `sdk-contract/routes.json`, so the contract test checks the new path.

---

## Commit Log (`java-v1.4.0..java-v1.5.0`)

- `be4a225` — `release: lumo-auth-java@1.5.0`
- `77d2faa` — `fix: update web.magicLink route to correct endpoint and improve request handling`
- `6bb40e8` — `fix: update comments and correct magic link endpoint in Routes`
- `aaf4097` — `release: add release notes for LumoAuth Java SDK v1.4.0`
