package io.lumoauth;

import com.fasterxml.jackson.databind.JsonNode;
import io.lumoauth.errors.LumoAuthBudgetExceededException;
import io.lumoauth.errors.LumoAuthConfigException;
import io.lumoauth.errors.LumoAuthPermissionDeniedException;
import io.lumoauth.model.AgentAskResult;
import io.lumoauth.model.AgentBudget;
import io.lumoauth.model.AgentIdentity;
import io.lumoauth.model.AgentMcpToolDecision;
import io.lumoauth.model.AgentRegistration;
import io.lumoauth.model.RegisterAgentRequest;
import io.lumoauth.model.TokenResponse;
import io.lumoauth.model.UserInfo;
import io.lumoauth.resources.AgentsResource;
import io.lumoauth.resources.ApprovalsResource;
import io.lumoauth.resources.DelegationResource;
import io.lumoauth.resources.JitResource;
import io.lumoauth.resources.McpResource;
import io.lumoauth.resources.PermissionsResource;

import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The client for an AI agent acting under its own identity.
 *
 * <p>It owns an OAuth 2.0 client-credentials token and refreshes it
 * transparently, so no call has to be preceded by an explicit login:
 *
 * <pre>{@code
 * LumoAgent agent = LumoAgent.fromEnvironment(); // AGENT_CLIENT_ID, AGENT_CLIENT_SECRET, LUMOAUTH_*
 *
 * boolean allowed = agent.isAllowed("document.read", Map.of("id", "doc_99"));
 * agent.requireCapability("tool:search_web");     // throws LumoAuthPermissionDeniedException
 * ApprovalResult approval = agent.approvals().require(
 *     ApprovalRequest.builder("wire-001", "Wire $4,500 to INV-7741", "ada@acme.com")
 *         .impact(ApprovalImpact.HIGH).build());
 * }</pre>
 *
 * For the AAuth protocol (cryptographic agent identity and RFC 9421 message
 * signing) use {@link io.lumoauth.aauth.AAuthClient} instead.
 *
 * <p>A {@code LumoAgent} is safe for concurrent use; concurrent callers share
 * one in-flight token request, and the token is renewed a minute before it expires.
 */
public final class LumoAgent implements ConfidentialClient {

    public static final String ENV_CLIENT_ID = "AGENT_CLIENT_ID";
    public static final String ENV_CLIENT_SECRET = "AGENT_CLIENT_SECRET";

    /** Subtracted from expires_in so the agent refreshes before the token actually expires. */
    static final Duration REFRESH_BUFFER = Duration.ofSeconds(60);

    private final String baseUrl;
    private final String orgId;
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private final List<String> scopes;
    private final LumoAuth client;

    private final ReentrantLock refreshLock = new ReentrantLock();
    private volatile String accessToken;
    private volatile Instant refreshAt = Instant.EPOCH;
    private volatile List<String> tokenScopes = List.of();
    private volatile AgentIdentity identity;
    private volatile UserInfo info;

    private LumoAgent(Builder b) {
        String url = firstNonBlank(b.baseUrl, System.getenv(LumoAuth.ENV_BASE_URL), LumoAuth.DEFAULT_BASE_URL);
        while (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        this.baseUrl = url;
        this.orgId = firstNonBlank(b.orgId, System.getenv(LumoAuth.ENV_ORG_ID), null);
        this.clientId = firstNonBlank(b.clientId, System.getenv(ENV_CLIENT_ID), null);
        this.clientSecret = firstNonBlank(b.clientSecret, System.getenv(ENV_CLIENT_SECRET), null);
        this.redirectUri = b.redirectUri;
        this.scopes = b.scopes == null ? List.of() : List.copyOf(b.scopes);
        if (clientId == null || clientSecret == null) {
            throw new LumoAuthConfigException(
                "agent credentials are required: set AGENT_CLIENT_ID and AGENT_CLIENT_SECRET, "
                    + "or pass clientId and clientSecret to the builder");
        }
        LumoAuth.Builder clientBuilder = LumoAuth.builder()
            .baseUrl(baseUrl)
            .orgId(orgId)
            .apiKey(null)
            .tokenProvider(this::accessToken)
            .timeout(b.timeout)
            .httpClient(b.httpClient)
            .skipCertValidation(b.skipCertValidation);
        if (b.userAgent != null) {
            clientBuilder.userAgent(b.userAgent);
        }
        this.client = clientBuilder.build();
    }

    public static Builder builder() {
        return new Builder();
    }

    /** An agent configured entirely from environment variables. */
    public static LumoAgent fromEnvironment() {
        return builder().build();
    }

    // ── Namespaces ────────────────────────────────────────────────────

    public AgentsResource agents() {
        return client.agents();
    }

    public JitResource jit() {
        return client.jit();
    }

    public DelegationResource delegation() {
        return client.delegation();
    }

    public ApprovalsResource approvals() {
        return client.approvals();
    }

    public McpResource mcp() {
        return client.mcp();
    }

    public PermissionsResource permissions() {
        return client.permissions();
    }

    /** The underlying general-purpose client, for the other namespaces (Zanzibar, ABAC, Auth) and the escape hatch. */
    public LumoAuth client() {
        return client;
    }

    @Override
    public String baseUrl() {
        return baseUrl;
    }

    @Override
    public String orgId() {
        return orgId;
    }

    @Override
    public String clientId() {
        return clientId;
    }

    @Override
    public String clientSecret() {
        return clientSecret;
    }

    public String redirectUri() {
        return redirectUri;
    }

    // ── Authentication ────────────────────────────────────────────────

    /**
     * Performs the client-credentials grant and caches the token. Every API call
     * does this on demand, so call it directly only to fail fast at startup or to
     * request non-default scopes.
     */
    public String authenticate(String... requestedScopes) {
        List<String> requested = requestedScopes == null || requestedScopes.length == 0
            ? scopes : Arrays.asList(requestedScopes);
        TokenResponse token = client.auth().clientCredentials(clientId, clientSecret, requested);
        Duration expiresIn = token.expiresIn() > 0 ? Duration.ofSeconds(token.expiresIn()) : Duration.ofHours(1);
        refreshLock.lock();
        try {
            this.accessToken = token.accessToken();
            this.refreshAt = Instant.now().plus(expiresIn).minus(REFRESH_BUFFER);
            this.tokenScopes = token.scopes();
            return token.accessToken();
        } finally {
            refreshLock.unlock();
        }
    }

    /**
     * A valid access token, authenticating or refreshing when the cached one is
     * missing or within a minute of expiry. Doubles as the token provider for the
     * underlying client. Concurrent callers collapse onto a single token request.
     */
    @Override
    public String accessToken() {
        String cached = cachedToken();
        if (cached != null) {
            return cached;
        }
        refreshLock.lock();
        try {
            cached = cachedToken();
            if (cached != null) {
                return cached;
            }
            return authenticate(tokenScopes.toArray(new String[0]));
        } finally {
            refreshLock.unlock();
        }
    }

    private String cachedToken() {
        String token = accessToken;
        return token != null && !token.isEmpty() && Instant.now().isBefore(refreshAt) ? token : null;
    }

    /** The scopes granted by the last authentication. */
    public List<String> tokenScopes() {
        return tokenScopes;
    }

    // ── Ask API and self-inspection ───────────────────────────────────

    /** Asks whether the agent may perform an action: the preflight check before an LLM tool call. */
    public AgentAskResult ask(String action, Map<String, Object> context) {
        return client.agents().ask(action, context);
    }

    public AgentAskResult ask(String action) {
        return ask(action, null);
    }

    /** {@link #ask} reduced to a boolean. */
    public boolean isAllowed(String action, Map<String, Object> context) {
        return ask(action, context).allowed();
    }

    public boolean isAllowed(String action) {
        return isAllowed(action, null);
    }

    /** The agent's own identity, capabilities, and workspace, cached after the first call. */
    public AgentIdentity identity() {
        return identity(false);
    }

    public AgentIdentity identity(boolean refresh) {
        AgentIdentity cached = identity;
        if (cached != null && !refresh) {
            return cached;
        }
        AgentIdentity fresh = client.agents().me();
        identity = fresh;
        return fresh;
    }

    /** The agent's UserInfo claims (capabilities, budget policy), cached after the first call. */
    public UserInfo info() {
        return info(false);
    }

    public UserInfo info(boolean refresh) {
        UserInfo cached = info;
        if (cached != null && !refresh) {
            return cached;
        }
        UserInfo fresh = client.agents().info();
        info = fresh;
        return fresh;
    }

    /** The agent's capability slugs. */
    public List<String> capabilities() {
        return info().capabilities();
    }

    /** Whether the agent holds a capability. */
    public boolean hasCapability(String capability) {
        return capabilities().contains(capability);
    }

    /**
     * The guard for a capability-gated method: returns normally when the agent
     * holds the capability and throws {@link LumoAuthPermissionDeniedException}
     * (with status 0, since no request was made) when it does not.
     *
     * <pre>{@code
     * agent.requireCapability("tool:search_web");
     * }</pre>
     */
    public void requireCapability(String capability) {
        if (!hasCapability(capability)) {
            throw LumoAuthPermissionDeniedException.local(
                "agent lacks the required capability " + capability
                    + " - update the agent registration to include it");
        }
    }

    /** The agent's budget policy; {@link AgentBudget#NONE} when there is none. */
    public AgentBudget budget() {
        AgentBudget budget = info().budgetPolicy();
        return budget == null ? AgentBudget.NONE : budget;
    }

    /**
     * Throws {@link LumoAuthBudgetExceededException} when the agent's daily token
     * budget is spent. Budget state is cached with the rest of the agent info;
     * call {@code info(true)} first for a live reading.
     */
    public void checkBudget() {
        AgentBudget budget = budget();
        if (budget.exhausted()) {
            throw new LumoAuthBudgetExceededException(budget);
        }
    }

    /** Creates or updates this agent's record in the organization directory, using its own client ID when the request has none. */
    public AgentRegistration register(RegisterAgentRequest params) {
        RegisterAgentRequest request = params.clientId() == null || params.clientId().isBlank()
            ? params.withClientId(clientId) : params;
        return client.agents().register(request);
    }

    /**
     * Exchanges the agent's token for one bound to a secured MCP server. The server ID is the MCP server's
     * registered Resource URI (its https URL and RFC 8707 resource identifier), e.g.
     * {@code https://mcp.example.com/mcp}. The token names exactly one MCP server and works only at that
     * server: LumoAuth's own API rejects it. This method does not send a DPoP proof, so a server that
     * requires DPoP needs a DPoP-bound exchange instead.
     */
    public String mcpToken(String serverId) {
        return client.mcp().token(serverId);
    }

    /**
     * Asks whether this agent may run one tool on a registered MCP server. A deny returns
     * {@code allowed == false} and does not throw. See {@link AgentsResource#authorizeMcpTool}.
     *
     * @param serverId the registered MCP server ID, e.g. {@code mcp_0123456789abcdef01234567}, not its URL
     */
    public AgentMcpToolDecision authorizeMcpTool(String serverId, String tool) {
        return client.agents().authorizeMcpTool(serverId, tool);
    }

    // ── Generic requests ──────────────────────────────────────────────

    /** Sends an authenticated request to any endpoint. See {@link LumoAuth#request}. */
    public <T> T request(String method, String path, Object body, Class<T> type) {
        return client.request(method, path, body, type);
    }

    public JsonNode requestNode(String method, String path, Object body) {
        return client.requestNode(method, path, body);
    }

    public HttpResponse<byte[]> requestRaw(String method, String path, Object body) {
        return client.requestRaw(method, path, body);
    }

    static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    // ── Builder ───────────────────────────────────────────────────────

    /** Builds a {@link LumoAgent}. Every field falls back to an environment variable when left unset. */
    public static final class Builder {
        private String baseUrl;
        private String orgId;
        private String clientId;
        private String clientSecret;
        private List<String> scopes;
        private String redirectUri;
        private Duration timeout;
        private HttpClient httpClient;
        private boolean skipCertValidation;
        private String userAgent;

        private Builder() {
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

        /** The agent's OAuth client. Defaults to {@code $AGENT_CLIENT_ID}. */
        public Builder clientId(String value) {
            this.clientId = value;
            return this;
        }

        /** The agent's OAuth secret. Defaults to {@code $AGENT_CLIENT_SECRET}. */
        public Builder clientSecret(String value) {
            this.clientSecret = value;
            return this;
        }

        /** Scopes requested at authentication. Leave empty to receive the agent's registered defaults. */
        public Builder scopes(List<String> value) {
            this.scopes = value;
            return this;
        }

        public Builder scopes(String... value) {
            this.scopes = value == null ? null : Arrays.asList(value);
            return this;
        }

        /** The OAuth callback for the delegation consent flow. */
        public Builder redirectUri(String value) {
            this.redirectUri = value;
            return this;
        }

        /** The per-request timeout. Default: 30 seconds. */
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

        public Builder userAgent(String value) {
            this.userAgent = value;
            return this;
        }

        /** Builds the agent. No network call is made until the first request. */
        public LumoAgent build() {
            return new LumoAgent(this);
        }
    }
}
