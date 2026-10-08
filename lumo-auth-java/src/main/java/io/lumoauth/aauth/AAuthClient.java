package io.lumoauth.aauth;

import com.fasterxml.jackson.databind.JsonNode;
import io.lumoauth.LumoAuth;
import io.lumoauth.Routes;
import io.lumoauth.errors.LumoAuthApiException;
import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.errors.LumoAuthValidationException;
import io.lumoauth.internal.ApiRequest;
import io.lumoauth.internal.HttpTransport;
import io.lumoauth.internal.Json;

import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.security.PrivateKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Speaks the AAuth (Agent Auth) protocol, which extends OAuth 2.1 with
 * cryptographic agent identity, proof-of-possession tokens, and RFC 9421 HTTP
 * message signing.
 *
 * <pre>{@code
 * AAuthClient client = AAuthClient.builder()
 *     .agentIdentifier("https://my-agent.example.com")
 *     .privateKeyPem(System.getenv("AGENT_PRIVATE_KEY"))
 *     .orgId("acme-corp")
 *     .build();
 *
 * AAuthTokenResponse result = client.requestAuthToken(resourceToken, "read write", agentToken);
 * if (result.authorizationRequired()) {
 *     // Redirect the user to result.authorizationUri(), then exchangeCode.
 * }
 * }</pre>
 *
 * For OAuth client-credentials agents (no signing key) use {@link io.lumoauth.LumoAgent}.
 */
public final class AAuthClient {

    public static final String TOKEN_TYPE_AUTH = "auth_token";
    public static final String TOKEN_TYPE_REFRESH = "refresh_token";

    private final String agentIdentifier;
    private final String orgId;
    private final String kid;
    private final PrivateKey privateKey;
    private final HttpTransport http;

    private AAuthClient(Builder b) {
        if (b.agentIdentifier == null || b.agentIdentifier.isBlank()) {
            throw new LumoAuthConfigException("agentIdentifier is required");
        }
        if (b.privateKey == null && (b.privateKeyPem == null || b.privateKeyPem.isBlank())) {
            throw new LumoAuthConfigException("privateKeyPem is required");
        }
        this.agentIdentifier = b.agentIdentifier;
        this.privateKey = b.privateKey != null ? b.privateKey : AAuthKeys.loadPrivateKey(b.privateKeyPem);
        this.kid = b.kid == null || b.kid.isBlank() ? AAuthKeys.DEFAULT_KID : b.kid;
        String baseUrl = firstNonBlank(b.baseUrl, System.getenv(LumoAuth.ENV_BASE_URL), LumoAuth.DEFAULT_BASE_URL);
        this.orgId = firstNonBlank(b.orgId, System.getenv(LumoAuth.ENV_ORG_ID), null);
        this.http = new HttpTransport(new HttpTransport.Config(baseUrl, orgId, null, null, b.timeout, b.httpClient,
            b.skipCertValidation, null, null));
    }

    public static Builder builder() {
        return new Builder();
    }

    public String agentIdentifier() {
        return agentIdentifier;
    }

    public String baseUrl() {
        return http.baseUrl();
    }

    public Optional<String> orgId() {
        return Optional.ofNullable(orgId);
    }

    /** The organization's AAuth issuer URL: {@code {baseUrl}/orgs/{orgId}/api/v1}, the {@code iss} of issued tokens. */
    public String issuer() {
        return http.baseUrl() + http.orgPath("");
    }

    /** The agent's public key as a JWK, tagged with its kid and use "sig". */
    public Jwk publicJwk() {
        return AAuthKeys.jwkFromPublicKey(AAuthKeys.publicKeyOf(privateKey)).withUse("sig").withKid(kid);
    }

    /** The RFC 7638 thumbprint of the agent's public key: the {@code jkt} that binds tokens to this key. */
    public String publicJwkThumbprint() {
        return publicJwk().thumbprint();
    }

    /** Builds RFC 9421 signature headers with this agent's key. */
    public Map<String, String> signRequest(String method, String targetUrl, SignOptions options) {
        return AAuthSigner.signRequest(privateKey, method, targetUrl, options);
    }

    // ── Token flows ───────────────────────────────────────────────────

    /**
     * Asks for an auth token (AAuth Flow 2, direct authorization). When the
     * server requires user consent it returns a response with
     * {@link AAuthTokenResponse#authorizationRequired()} set: redirect the user to
     * its authorization URI, then call {@link #exchangeCode}.
     *
     * @param resourceToken the {@code resource+jwt} obtained from the target resource. Required.
     * @param scope         space-separated and informational; scopes bind through the resource token.
     * @param agentToken    the {@code agent+jwt} presented in Agent-Auth. Required.
     */
    public AAuthTokenResponse requestAuthToken(String resourceToken, String scope, String agentToken) {
        return requestAuthToken(resourceToken, scope, agentToken, null);
    }

    /** {@link #requestAuthToken(String, String, String)} with a redirect URI for flows that need consent to return somewhere. */
    public AAuthTokenResponse requestAuthToken(String resourceToken, String scope, String agentToken, String redirectUri) {
        if (resourceToken == null || resourceToken.isBlank()) {
            throw new LumoAuthValidationException("resourceToken is required");
        }
        requireAgentToken(agentToken);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("request_type", "auth");
        body.put("resource_token", resourceToken);
        if (scope != null && !scope.isBlank()) {
            body.put("scope", scope);
        }
        if (redirectUri != null && !redirectUri.isBlank()) {
            body.put("redirect_uri", redirectUri);
        }
        JsonNode raw;
        try {
            raw = tokenRequest(body, agentToken);
        } catch (LumoAuthApiException e) {
            // A 401 carrying a consent URL is not a failure: it is the server asking for the user's approval.
            Optional<AAuthTokenResponse> consent = consentFromError(e);
            if (consent.isPresent()) {
                return consent.get();
            }
            throw e;
        }
        String authToken = text(raw, "auth_token");
        if (authToken == null) {
            String requestToken = text(raw, "request_token");
            String uri = firstNonBlank(text(raw, "authorization_uri"), text(raw, "auth_url"), null);
            if (requestToken != null || uri != null) {
                return AAuthTokenResponse.consent(requestToken, uri, intValue(raw, "expires_in"));
            }
        }
        return mapToken(raw);
    }

    /** The user-consent URL for a pending request token. Prefer the URI returned by {@link #requestAuthToken} when present. */
    public String consentUrl(String requestToken) {
        return routeUrl(Routes.AAUTH_AGENT_AUTH) + "?request_token="
            + java.net.URLEncoder.encode(requestToken, java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * Trades an authorization code for tokens after user consent
     * (request_type=code). {@code redirectUri} must be the exact URI the code
     * was delivered to; the server redeems codes atomically and rejects a mismatch.
     */
    public AAuthTokenResponse exchangeCode(String code, String redirectUri, String agentToken) {
        if (code == null || code.isBlank()) {
            throw new LumoAuthValidationException("an authorization code is required");
        }
        if (redirectUri == null || redirectUri.isBlank()) {
            throw new LumoAuthValidationException("a redirect URI is required and must match the one the code was delivered to");
        }
        requireAgentToken(agentToken);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("request_type", "code");
        body.put("code", code);
        body.put("redirect_uri", redirectUri);
        return mapToken(tokenRequest(body, agentToken));
    }

    /**
     * A multi-hop exchange (request_type=exchange): trades an upstream auth
     * token plus a downstream resource token for a new auth token carrying an
     * {@code act} actor chain. The agent must be permitted to exchange tokens.
     */
    public AAuthTokenResponse exchangeToken(String authToken, String resourceToken, String agentToken) {
        if (isBlank(authToken) || isBlank(resourceToken)) {
            throw new LumoAuthValidationException("both an auth token and a resource token are required");
        }
        requireAgentToken(agentToken);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("request_type", "exchange");
        body.put("auth_token", authToken);
        body.put("resource_token", resourceToken);
        return mapToken(tokenRequest(body, agentToken));
    }

    /**
     * Renews an auth token (request_type=refresh). Refresh tokens are not
     * rotated, so the same one stays valid for the grant's lifetime.
     *
     * @param refreshToken  the token from a prior response. Required.
     * @param resourceToken a FRESH resource token for the target resource; the server requires one on every refresh. Required.
     * @param scope         optionally narrows the refreshed token; must be a subset of the original grant.
     * @param agentToken    the {@code agent+jwt} presented in Agent-Auth. Required.
     */
    public AAuthTokenResponse refresh(String refreshToken, String resourceToken, String scope, String agentToken) {
        if (isBlank(refreshToken)) {
            throw new LumoAuthValidationException("refreshToken is required");
        }
        if (isBlank(resourceToken)) {
            throw new LumoAuthValidationException("resourceToken is required - the server needs a fresh resource token on every refresh");
        }
        requireAgentToken(agentToken);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("request_type", "refresh");
        body.put("refresh_token", refreshToken);
        body.put("resource_token", resourceToken);
        if (!isBlank(scope)) {
            body.put("scope", scope);
        }
        return mapToken(tokenRequest(body, agentToken));
    }

    /**
     * Invalidates an auth token (by its {@code jti}) or a refresh token (by
     * value). It succeeds whether or not the token existed.
     *
     * @param tokenType {@link #TOKEN_TYPE_AUTH} (the default) or {@link #TOKEN_TYPE_REFRESH}
     */
    public void revoke(String token, String tokenType, String agentToken) {
        if (isBlank(token)) {
            throw new LumoAuthValidationException("a token is required");
        }
        requireAgentToken(agentToken);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token", token);
        body.put("token_type", isBlank(tokenType) ? TOKEN_TYPE_AUTH : tokenType);
        signedPost(routeUrl(Routes.AAUTH_TOKEN_REVOKE), body, agentToken);
    }

    // ── Signed requests to protected resources ────────────────────────

    /**
     * Makes a signed, authenticated request to a protected resource. The
     * request carries the auth token as a Bearer credential AND an RFC 9421
     * signature proving possession of the key bound in the token's
     * {@code cnf.jwk}; the signature covers the authorization component, so the
     * resource server verifies both together.
     */
    public HttpResponse<byte[]> signedRequest(String method, String targetUrl, String authToken, Object body) {
        if (isBlank(authToken)) {
            throw new LumoAuthValidationException("an auth token is required");
        }
        byte[] payload = body == null ? null : Json.encode(body);
        String authorization = "Bearer " + authToken;
        Map<String, String> headers = signRequest(method, targetUrl, SignOptions.body(payload).authorization(authorization));
        headers.put("Authorization", authorization);
        // Raw, not JSON: the Content-Digest covers these exact bytes.
        return http.sendRaw(method, targetUrl, ApiRequest.empty().withRaw(payload).headers(headers).noAuth());
    }

    // ── Discovery ─────────────────────────────────────────────────────

    /** The organization's AAuth issuer metadata. */
    public AAuthIssuerMetadata discoverIssuer() {
        return http.call(Routes.AAUTH_ISSUER_METADATA, null, ApiRequest.empty().noAuth(), AAuthIssuerMetadata.class);
    }

    /** Metadata for the organization's active agents (the endpoint returns one object or an array). */
    public List<AAuthAgentMetadata> discoverAgents() {
        return oneOrMany(http.callNode(Routes.AAUTH_AGENT_METADATA, null, ApiRequest.empty().noAuth()),
            AAuthAgentMetadata.class, "aauth.agentMetadata");
    }

    /** A resource server's AAuth metadata from {@code {resourceUrl}/.well-known/aauth-resource}. */
    public List<AAuthResourceMetadata> discoverResource(String resourceUrl) {
        String target = resourceUrl.replaceAll("/+$", "") + "/.well-known/aauth-resource";
        return oneOrMany(http.sendNode("GET", target, ApiRequest.empty().noAuth()), AAuthResourceMetadata.class, target);
    }

    /** The organization's AAuth signing keys: the keys that verify issued auth tokens. */
    public Jwks jwks() {
        return http.call(Routes.AAUTH_JWKS, null, ApiRequest.empty().noAuth(), Jwks.class);
    }

    // ── Internal ──────────────────────────────────────────────────────

    private static void requireAgentToken(String agentToken) {
        if (isBlank(agentToken)) {
            throw new LumoAuthValidationException(
                "an agent token is required - the /agent/token endpoint authenticates the agent through the Agent-Auth header, not the request body");
        }
    }

    private String routeUrl(String routeName) {
        if (orgId == null) {
            throw new LumoAuthConfigException("an org ID is required for AAuth operations - set orgId or LUMOAUTH_ORG_ID");
        }
        return http.baseUrl() + http.resolve(routeName, null).path();
    }

    private JsonNode tokenRequest(Map<String, Object> body, String agentToken) {
        return signedPost(routeUrl(Routes.AAUTH_AGENT_TOKEN), body, agentToken);
    }

    /** Signs a JSON body per the AAuth profile and posts it; the signature covers the exact bytes sent. */
    private JsonNode signedPost(String target, Map<String, Object> body, String agentToken) {
        byte[] payload = Json.encode(body);
        Map<String, String> headers = signRequest("POST", target, SignOptions.body(payload).agentToken(agentToken));
        return http.sendNode("POST", target, ApiRequest.empty().withRaw(payload).headers(headers).noAuth());
    }

    private static AAuthTokenResponse mapToken(JsonNode raw) {
        String authToken = text(raw, "auth_token");
        if (authToken == null) {
            throw new LumoAuthValidationException("the token response carried no auth_token");
        }
        return new AAuthTokenResponse(
            firstNonBlank(text(raw, "request_type"), "auth"),
            authToken,
            intValue(raw, "expires_in"),
            firstNonBlank(text(raw, "token_type"), "auth+jwt"),
            text(raw, "refresh_token"),
            false, null, null);
    }

    /** Recognises the 401 the server returns when a human must approve the request. */
    private static Optional<AAuthTokenResponse> consentFromError(LumoAuthApiException e) {
        if (e.statusCode() != 401) {
            return Optional.empty();
        }
        String uri = e.bodyField("authorization_uri").orElseGet(() -> e.bodyField("auth_url").orElse(null));
        String requestToken = e.bodyField("request_token").orElse(null);
        if (uri == null && requestToken == null) {
            return Optional.empty();
        }
        int expiresIn = e.bodyAsMap().map(m -> m.get("expires_in")).filter(Number.class::isInstance)
            .map(n -> ((Number) n).intValue()).orElse(0);
        return Optional.of(AAuthTokenResponse.consent(requestToken, uri, expiresIn));
    }

    private static <T> List<T> oneOrMany(JsonNode node, Class<T> type, String context) {
        if (node == null || node.isNull()) {
            return List.of();
        }
        List<T> out = new ArrayList<>();
        if (node.isArray()) {
            for (JsonNode item : node) {
                out.add(Json.convert(item, type, context));
            }
        } else {
            out.add(Json.convert(node, type, context));
        }
        return List.copyOf(out);
    }

    private static String text(JsonNode node, String field) {
        if (node == null) {
            return null;
        }
        JsonNode value = node.get(field);
        return value == null || value.isNull() || !value.isTextual() || value.asText().isEmpty() ? null : value.asText();
    }

    private static int intValue(JsonNode node, String field) {
        JsonNode value = node == null ? null : node.get(field);
        return value == null || !value.isNumber() ? 0 : value.asInt();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    // ── Builder ───────────────────────────────────────────────────────

    public static final class Builder {
        private String agentIdentifier;
        private String privateKeyPem;
        private PrivateKey privateKey;
        private String baseUrl;
        private String orgId;
        private String kid;
        private Duration timeout;
        private HttpClient httpClient;
        private boolean skipCertValidation;

        private Builder() {
        }

        /** The HTTPS URL uniquely identifying the agent, e.g. {@code https://my-agent.example.com}. Required. */
        public Builder agentIdentifier(String value) {
            this.agentIdentifier = value;
            return this;
        }

        /** The agent's Ed25519 (PKCS#8) or RSA private key. Required unless {@link #privateKey} is given. */
        public Builder privateKeyPem(String value) {
            this.privateKeyPem = value;
            return this;
        }

        /** An already-loaded private key (from a keystore or HSM-backed provider). */
        public Builder privateKey(PrivateKey value) {
            this.privateKey = value;
            return this;
        }

        /** The LumoAuth instance. Defaults to {@code $LUMOAUTH_URL}, then the cloud instance. */
        public Builder baseUrl(String value) {
            this.baseUrl = value;
            return this;
        }

        /** The organization slug. Defaults to {@code $LUMOAUTH_ORG_ID}. */
        public Builder orgId(String value) {
            this.orgId = value;
            return this;
        }

        /** Identifies the key in the JWKS registered with LumoAuth. Defaults to {@link AAuthKeys#DEFAULT_KID}. */
        public Builder kid(String value) {
            this.kid = value;
            return this;
        }

        public Builder timeout(Duration value) {
            this.timeout = value;
            return this;
        }

        public Builder httpClient(HttpClient value) {
            this.httpClient = value;
            return this;
        }

        /** Local development only. */
        public Builder skipCertValidation(boolean skip) {
            this.skipCertValidation = skip;
            return this;
        }

        public AAuthClient build() {
            return new AAuthClient(this);
        }
    }
}
