package io.lumoauth;

import com.fasterxml.jackson.databind.JsonNode;
import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.internal.ApiRequest;
import io.lumoauth.internal.HttpTransport;
import io.lumoauth.internal.Json;
import io.lumoauth.resources.AbacResource;
import io.lumoauth.resources.AgentsResource;
import io.lumoauth.resources.ApprovalsResource;
import io.lumoauth.resources.AuthResource;
import io.lumoauth.resources.DelegationResource;
import io.lumoauth.resources.JitResource;
import io.lumoauth.resources.McpResource;
import io.lumoauth.resources.PermissionsResource;
import io.lumoauth.resources.ZanzibarResource;

import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * The general-purpose LumoAuth API client.
 *
 * <p>Curated resource namespaces cover the common surface, the ones an
 * application actually reaches for. Everything else (admin CRUD, SCIM, audit
 * logs) is available through the {@link #request} escape hatch or the generated
 * OpenAPI client, which {@link #apiClientConfig()} configures for you.
 *
 * <pre>{@code
 * LumoAuth lumo = LumoAuth.builder()
 *     .apiKey(System.getenv("LUMOAUTH_API_KEY"))
 *     .orgId("acme-corp")
 *     .build();
 *
 * boolean ok = lumo.permissions().check("document.edit");
 * AbacDecision decision = lumo.abac().check(AbacCheck.of("document", "read", "doc-123"));
 * }</pre>
 *
 * Every builder option falls back to an environment variable
 * ({@code LUMOAUTH_URL}, {@code LUMOAUTH_ORG_ID}, {@code LUMOAUTH_API_KEY}), so
 * {@link #fromEnvironment()} is enough in a configured environment.
 *
 * <p>A {@code LumoAuth} is immutable and safe for concurrent use.
 */
public final class LumoAuth {

    /** The LumoAuth cloud instance, used when neither the builder nor {@code LUMOAUTH_URL} supplies one. */
    public static final String DEFAULT_BASE_URL = "https://app.lumoauth.dev";

    public static final String ENV_BASE_URL = "LUMOAUTH_URL";
    public static final String ENV_ORG_ID = "LUMOAUTH_ORG_ID";
    public static final String ENV_API_KEY = "LUMOAUTH_API_KEY";

    private final HttpTransport http;
    private final AuthResource auth;
    private final PermissionsResource permissions;
    private final ZanzibarResource zanzibar;
    private final AbacResource abac;
    private final AgentsResource agents;
    private final DelegationResource delegation;
    private final JitResource jit;
    private final ApprovalsResource approvals;
    private final McpResource mcp;

    private LumoAuth(HttpTransport http) {
        this.http = http;
        this.auth = new AuthResource(http);
        this.permissions = new PermissionsResource(http);
        this.zanzibar = new ZanzibarResource(http);
        this.abac = new AbacResource(http);
        this.agents = new AgentsResource(http, auth);
        this.delegation = new DelegationResource(auth);
        this.jit = new JitResource(http);
        this.approvals = new ApprovalsResource(http);
        this.mcp = new McpResource(http, auth);
    }

    public static Builder builder() {
        return new Builder();
    }

    /** A client configured entirely from {@code LUMOAUTH_*} environment variables. */
    public static LumoAuth fromEnvironment() {
        return builder().build();
    }

    // ── Namespaces ────────────────────────────────────────────────────

    /** OAuth 2.1: authorization URLs, code exchange, refresh, client credentials, token exchange, revocation, UserInfo. */
    public AuthResource auth() {
        return auth;
    }

    /** RBAC checks for the authenticated principal. */
    public PermissionsResource permissions() {
        return permissions;
    }

    /** Relationship-based (ReBAC) checks. */
    public ZanzibarResource zanzibar() {
        return zanzibar;
    }

    /** Attribute-based policy evaluation and attribute management. */
    public AbacResource abac() {
        return abac;
    }

    /** Agent identity: ask, per-tool MCP self-checks, self-inspection, registration. */
    public AgentsResource agents() {
        return agents;
    }

    /** RFC 8693 token exchange (Chain of Agency). */
    public DelegationResource delegation() {
        return delegation;
    }

    /** Just-in-Time permissions: ephemeral tasks and scoped tokens. */
    public JitResource jit() {
        return jit;
    }

    /** Push approvals for agent actions. */
    public ApprovalsResource approvals() {
        return approvals;
    }

    /** MCP: tokens bound to one secured MCP server, and per-tool checks for the MCP server itself. */
    public McpResource mcp() {
        return mcp;
    }

    // ── Configuration ─────────────────────────────────────────────────

    /** The configured instance URL, without a trailing slash. */
    public String baseUrl() {
        return http.baseUrl();
    }

    /** The configured organization slug. */
    public Optional<String> orgId() {
        return http.orgId();
    }

    /** The transport behind every namespace. Internal; exposed for framework integrations. */
    public HttpTransport transport() {
        return http;
    }

    // ── Escape hatches ────────────────────────────────────────────────

    /**
     * Sends an authenticated request to any LumoAuth endpoint and decodes the
     * JSON response into {@code type} (null to discard it). The path is joined
     * to the base URL; an absolute URL is used as-is. Non-2xx responses become
     * the typed exceptions in {@link io.lumoauth.errors}.
     *
     * <pre>{@code
     * Map<String, Object> page = lumo.request("GET", lumo.orgPath("/admin/users"), null, Map.class);
     * }</pre>
     */
    public <T> T request(String method, String path, Object body, Class<T> type) {
        return http.send(method, path, body == null ? ApiRequest.empty() : ApiRequest.json(body), type);
    }

    /** {@link #request} returning the decoded JSON tree, or null for an empty body. */
    public JsonNode requestNode(String method, String path, Object body) {
        return http.sendNode(method, path, body == null ? ApiRequest.empty() : ApiRequest.json(body));
    }

    /** {@link #request} returning the decoded object as a map; empty for no body. */
    public Map<String, Object> requestMap(String method, String path, Object body) {
        return Json.toMap(requestNode(method, path, body));
    }

    /**
     * {@link #request} without response handling: the caller gets the full
     * response. Transport failures are still wrapped; HTTP statuses are left untouched.
     */
    public HttpResponse<byte[]> requestRaw(String method, String path, Object body) {
        return http.sendRaw(method, path, body == null ? ApiRequest.empty() : ApiRequest.json(body));
    }

    /**
     * Prefixes a path with this client's org-scoped API base, so callers
     * building requests by hand do not hardcode the layout:
     * {@code lumo.orgPath("/admin/users")} is {@code /orgs/acme-corp/api/v1/admin/users}.
     */
    public String orgPath(String path) {
        return http.orgPath(path);
    }

    /**
     * What the generated OpenAPI client ({@code io.lumoauth:lumoauth-api-client})
     * needs to talk to this instance: the base path and exactly one credential
     * header. The generated client is not a dependency of this SDK, so configure
     * it yourself:
     *
     * <pre>{@code
     * ApiClientConfig cfg = lumo.apiClientConfig();
     * io.lumoauth.client.ApiClient api = new io.lumoauth.client.ApiClient();
     * api.setBasePath(cfg.basePath());
     * cfg.defaultHeaders().forEach(api::addDefaultHeader);
     * }</pre>
     *
     * The call resolves the current bearer token, so refresh it per token
     * lifetime when using short-lived agent tokens.
     */
    public ApiClientConfig apiClientConfig() {
        Map<String, String> headers = new LinkedHashMap<>();
        Optional<String> bearer = http.bearerToken();
        if (bearer.isPresent()) {
            headers.put("Authorization", "Bearer " + bearer.get());
        } else if (http.apiKey().isPresent()) {
            headers.put("X-API-Key", http.apiKey().get());
        } else {
            throw new LumoAuthConfigException(
                "no credential available for the generated API client - configure apiKey or a tokenProvider");
        }
        return new ApiClientConfig(http.baseUrl(), Map.copyOf(headers), http.httpClient());
    }

    /**
     * Settings for the generated OpenAPI client.
     *
     * @param basePath       the server URL, without a trailing slash
     * @param defaultHeaders exactly one credential header: X-API-Key or Authorization
     * @param httpClient     this client's underlying HTTP client
     */
    public record ApiClientConfig(String basePath, Map<String, String> defaultHeaders, HttpClient httpClient) {
    }

    // ── Builder ───────────────────────────────────────────────────────

    /** Builds a {@link LumoAuth}. Options are read in order; unset ones fall back to the environment. */
    public static final class Builder {
        private String baseUrl = System.getenv(ENV_BASE_URL);
        private String orgId = System.getenv(ENV_ORG_ID);
        private String apiKey = System.getenv(ENV_API_KEY);
        private TokenProvider tokenProvider;
        private Duration timeout;
        private HttpClient httpClient;
        private boolean skipCertValidation;
        private final Map<String, String> headers = new LinkedHashMap<>();
        private String userAgent;
        private boolean credentialOptional;

        private Builder() {
        }

        /** The LumoAuth instance URL. Defaults to {@code $LUMOAUTH_URL}, then {@link #DEFAULT_BASE_URL}. */
        public Builder baseUrl(String value) {
            this.baseUrl = value;
            return this;
        }

        /** The organization slug, required for org-scoped endpoints. Defaults to {@code $LUMOAUTH_ORG_ID}. */
        public Builder orgId(String value) {
            this.orgId = value;
            return this;
        }

        /** Authenticates with a tenant API key, sent as {@code X-API-Key}. Defaults to {@code $LUMOAUTH_API_KEY}. */
        public Builder apiKey(String value) {
            this.apiKey = value;
            return this;
        }

        /** Authenticates with a fixed bearer token. For tokens that expire, prefer {@link #tokenProvider}. */
        public Builder accessToken(String token) {
            return tokenProvider(TokenProvider.fixed(token));
        }

        /** Authenticates with a bearer token resolved per request. A provider that returns a token wins over an API key. */
        public Builder tokenProvider(TokenProvider provider) {
            this.tokenProvider = provider;
            return this;
        }

        /** The per-request timeout. Default: 30 seconds. */
        public Builder timeout(Duration value) {
            this.timeout = value;
            return this;
        }

        /** The {@link HttpClient} used for every request: the hook for proxies, custom TLS, and instrumentation. */
        public Builder httpClient(HttpClient client) {
            this.httpClient = client;
            return this;
        }

        /** Disables TLS certificate verification. Local development against a self-signed instance only. */
        public Builder skipCertValidation(boolean skip) {
            this.skipCertValidation = skip;
            return this;
        }

        /** Adds a header to every request. */
        public Builder header(String name, String value) {
            this.headers.put(name, value);
            return this;
        }

        /** Overrides the User-Agent sent with every request. */
        public Builder userAgent(String value) {
            this.userAgent = value;
            return this;
        }

        /**
         * Allows building without a credential, for callers that only use
         * unauthenticated endpoints (discovery, token grants, {@code userinfo(token)}).
         * Calls that need a credential then fail at the server, not at build time.
         */
        public Builder withoutCredential() {
            this.credentialOptional = true;
            return this;
        }

        /** The builder's current state as a transport config (used by the agent helpers). */
        HttpTransport.Config toConfig() {
            String url = baseUrl == null || baseUrl.isBlank() ? DEFAULT_BASE_URL : baseUrl;
            return new HttpTransport.Config(url, orgId, apiKey, tokenProvider, timeout, httpClient,
                skipCertValidation, headers, userAgent);
        }

        /** Builds the client, failing with {@link LumoAuthConfigException} when no credential is configured. */
        public LumoAuth build() {
            if (!credentialOptional && (apiKey == null || apiKey.isBlank()) && tokenProvider == null) {
                throw new LumoAuthConfigException(
                    "a credential is required: pass apiKey (or set LUMOAUTH_API_KEY), accessToken, or tokenProvider");
            }
            return new LumoAuth(new HttpTransport(toConfig()));
        }
    }
}
