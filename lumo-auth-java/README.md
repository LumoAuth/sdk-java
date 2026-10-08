# lumo-auth-java

The LumoAuth Java SDK: `io.lumoauth:lumo-auth-java`. Java 17+, depends only on
the JDK and Jackson. See the [repository README](../README.md) for the full tour.

```java
LumoAuth lumo = LumoAuth.builder().apiKey(apiKey).orgId("acme-corp").build();
boolean ok = lumo.permissions().check("document.edit");
```

Entry points: `io.lumoauth.LumoAuth`, `io.lumoauth.LumoAgent`,
`io.lumoauth.JitContext`, `io.lumoauth.DelegationChain`,
`io.lumoauth.aauth.AAuthClient`, `io.lumoauth.aauth.AAuthVerifier`,
`io.lumoauth.web.AuthorizationCodeFlow`.

`src/main/java/io/lumoauth/Routes.java` is generated from
`sdk-contract/routes.json`; regenerate it with
`python3 ../../sdk-contract/scripts/gen-java-routes.py` rather than editing it.
