# lumo-auth-java

The core module of the LumoAuth Java SDK: `io.lumoauth:lumo-auth-java`. It needs Java 17 or newer and depends only on the JDK and Jackson.

Use it to check permissions, relationships and attribute-based policies, to sign users in, and to give AI agents their own identity. The [repository README](../README.md) covers every feature in detail.

## Install

The artifact is not on Maven Central yet. Install it from the repository root, then add the dependency:

```bash
mvn -f sdk-java/pom.xml -DskipTests install
```

```xml
<dependency>
  <groupId>io.lumoauth</groupId>
  <artifactId>lumo-auth-java</artifactId>
  <version>1.0.0</version>
</dependency>
```

## Quick start

```java
LumoAuth lumo = LumoAuth.builder()
    .apiKey(System.getenv("LUMOAUTH_API_KEY"))
    .orgId("acme-corp")
    .build();

boolean ok = lumo.permissions().check("document.edit");
```

`LumoAuth.fromEnvironment()` reads `LUMOAUTH_URL`, `LUMOAUTH_ORG_ID` and `LUMOAUTH_API_KEY` instead. See [Configuration](../README.md#configuration) for every option.

## Entry points

| Class | What it is for |
|---|---|
| `io.lumoauth.LumoAuth` | The client. Its namespaces are `permissions()`, `zanzibar()`, `abac()`, `auth()`, `agents()`, `approvals()`, `jit()`, `delegation()` and `mcp()`. |
| `io.lumoauth.LumoAgent` | An AI agent that signs in with client credentials and refreshes its own token |
| `io.lumoauth.JitContext` | A Just-in-Time task that revokes its tokens when you close it |
| `io.lumoauth.DelegationChain` | An agent that acts on behalf of a user through token exchange |
| `io.lumoauth.aauth.AAuthClient` | An agent that signs its requests with its own key (AAuth) |
| `io.lumoauth.aauth.AAuthVerifier`, `JwksCache` | Verification of AAuth tokens on a resource server |
| `io.lumoauth.web.AuthorizationCodeFlow` | Sign-in with the authorization code flow and PKCE, for any web framework |
| `io.lumoauth.errors.*` | The exception classes (see [Errors](../README.md#errors)) |

## Generated routes

`src/main/java/io/lumoauth/Routes.java` is generated from `sdk-contract/routes.json`. Do not edit it by hand. Regenerate it with this command:

```bash
python3 ../../sdk-contract/scripts/gen-java-routes.py
```
